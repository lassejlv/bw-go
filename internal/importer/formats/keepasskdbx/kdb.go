package keepasskdbx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// parseKDB ports format/kdb.rs (KeePass 1.x databases), which the keepass crate also opens.

const kdbHeaderSize = 4 + 4 + 4 + 4 + 16 + 16 + 4 + 4 + 32 + 32 + 4

func kdbString(b []byte) string {
	return strings.TrimRight(string(bytes.ToValidUTF8(b, []byte("�"))), "\x00")
}

func kdbGroupFieldSize(t uint16) (uint32, bool) {
	switch t {
	case 0x0001:
		return 4, true
	case 0x0003, 0x0004, 0x0005, 0x0006:
		return 5, true
	case 0x0007:
		return 4, true
	case 0x0008:
		return 2, true
	case 0x0009:
		return 4, true
	case 0xffff:
		return 0, true
	}
	return 0, false
}

func kdbEntryFieldSize(t uint16) (uint32, bool) {
	switch t {
	case 0x0001:
		return 16, true
	case 0x0002, 0x0003:
		return 4, true
	case 0x0009, 0x000a, 0x000b, 0x000c:
		return 5, true
	case 0xffff:
		return 0, true
	}
	return 0, false
}

type kdbField struct {
	typ   uint16
	value []byte
}

func nextKDBField(data []byte, expected func(uint16) (uint32, bool)) (kdbField, []byte, error) {
	if len(data) < 6 {
		return kdbField{}, nil, errUnexpectedEOF
	}
	typ := binary.LittleEndian.Uint16(data[0:2])
	size := binary.LittleEndian.Uint32(data[2:6])
	if uint64(size) > uint64(len(data)-6) {
		return kdbField{}, nil, errUnexpectedEOF
	}
	value := data[6 : 6+int(size)]
	if want, ok := expected(typ); ok && want != size {
		return kdbField{}, nil, errFormat(fmt.Sprintf("field of type %d has invalid length %d, expected %d", typ, size, want))
	}
	return kdbField{typ: typ, value: value}, data[6+int(size):], nil
}

func parseKDB(data []byte, key *databaseKey) (*database, error) {
	if len(data) < kdbHeaderSize {
		return nil, errUnexpectedEOF
	}
	flags := binary.LittleEndian.Uint32(data[8:])
	masterSeed := data[16:32]
	encryptionIV := data[32:48]
	numGroups := binary.LittleEndian.Uint32(data[48:])
	numEntries := binary.LittleEndian.Uint32(data[52:])
	contentsHash := data[56:88]
	transformSeed := data[88:120]
	transformRounds := binary.LittleEndian.Uint32(data[120:])
	payloadEncrypted := data[kdbHeaderSize:]

	elements, err := key.keyElements()
	if err != nil {
		return nil, keyError(err)
	}
	var composite []byte
	if len(elements) == 1 {
		// A single SHA-256 pass (already applied to the password). The crate panics when a lone key
		// file element is not 32 bytes long; treat that as a wrong key.
		if len(elements[0]) != 32 {
			return nil, keyError(errIncorrectKey)
		}
		composite = elements[0]
	} else {
		composite = sha256Sum(elements...)
	}
	kdf := kdfConfig{kind: kdfAES, rounds: uint64(transformRounds), seed: transformSeed}
	transformed, err := kdf.transformKey(composite)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	masterKey := sha256Sum(masterSeed, transformed)

	var outer outerCipher
	switch {
	case flags&2 != 0:
		outer = outerAES256
	case flags&8 != 0:
		outer = outerTwofish
	default:
		return nil, errFormat(fmt.Sprintf("invalid fixed cipher ID: %d", flags))
	}
	payload, err := outer.decrypt(masterKey, encryptionIV, payloadEncrypted)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	// The crate strips `last byte` more bytes after the AES decryptor already removed the PKCS#7
	// padding (for Twofish this is the padding removal itself, done by decrypt above).
	if outer == outerAES256 {
		if len(payload) == 0 {
			return nil, errUnexpectedEOF
		}
		padLen := int(payload[len(payload)-1])
		if padLen > len(payload) {
			return nil, errUnexpectedEOF
		}
		payload = payload[:len(payload)-padLen]
	}
	if !bytes.Equal(contentsHash, sha256Sum(payload)) {
		return nil, keyError(errIncorrectKey)
	}

	root := &group{name: "Root"}
	db := &database{root: root}
	rest := payload

	// Groups.
	gidMap := map[uint32]*group{0: root}
	branch := []*group{root}
	var (
		parsingName  *string
		parsingLevel *uint16
		parsingGID   *uint32
	)
	for n := uint32(0); n < numGroups; {
		f, r, err := nextKDBField(rest, kdbGroupFieldSize)
		if err != nil {
			return nil, err
		}
		switch f.typ {
		case 0x0000, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0009:
		case 0x0001:
			v := binary.LittleEndian.Uint32(f.value)
			parsingGID = &v
		case 0x0002:
			s := kdbString(f.value)
			parsingName = &s
		case 0x0008:
			v := binary.LittleEndian.Uint16(f.value)
			parsingLevel = &v
		case 0xffff:
			if parsingGID == nil {
				return nil, errFormat("invalid group ID")
			}
			if parsingLevel == nil {
				return nil, errFormat("invalid group level")
			}
			level := int(*parsingLevel)
			if level > len(branch) {
				return nil, errFormat("invalid group level")
			}
			branch = branch[:level]
			parent := root
			if len(branch) > 0 {
				parent = branch[len(branch)-1]
			}
			name := ""
			if parsingName != nil {
				name = *parsingName
			}
			g := &group{name: name}
			parent.groups = append(parent.groups, g)
			gidMap[*parsingGID] = g
			branch = append(branch, g)
			parsingGID, parsingName, parsingLevel = nil, nil, nil
			n++
		default:
			return nil, errFormat(fmt.Sprintf("invalid group field type: %d", f.typ))
		}
		rest = r
	}
	if parsingGID != nil {
		return nil, errFormat("group was not terminated before end of file")
	}

	// Entries.
	var entryGID *uint32
	fields := newEntry()
	for n := uint32(0); n < numEntries; {
		f, r, err := nextKDBField(rest, kdbEntryFieldSize)
		if err != nil {
			return nil, err
		}
		switch f.typ {
		case 0x0000, 0x0001, 0x0003, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e:
		case 0x0002:
			v := binary.LittleEndian.Uint32(f.value)
			entryGID = &v
		case 0x0004:
			fields.set("Title", kdbString(f.value), false)
		case 0x0005:
			fields.set("URL", kdbString(f.value), false)
		case 0x0006:
			fields.set("UserName", kdbString(f.value), false)
		case 0x0007:
			fields.set("Password", kdbString(f.value), true)
		case 0x0008:
			fields.set("Notes", kdbString(f.value), false)
		case 0xffff:
			if entryGID == nil {
				return nil, errFormat("invalid group ID")
			}
			g, ok := gidMap[*entryGID]
			if !ok {
				return nil, errFormat(fmt.Sprintf("invalid group ID: %d", *entryGID))
			}
			g.entries = append(g.entries, fields)
			fields = newEntry()
			entryGID = nil
			n++
		default:
			return nil, errFormat(fmt.Sprintf("invalid entry field type: %d", f.typ))
		}
		rest = r
	}
	if entryGID != nil {
		return nil, errFormat("entry was not terminated before end of file")
	}
	return db, nil
}
