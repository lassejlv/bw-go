package keepasskdbx

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// A Go port of the parts of the keepass crate (0.13.x, MIT) that the SDK's kdbx importer uses:
// Database::open for KDB (KeePass 1.x), KDBX 3.1 and KDBX 4.x files, reduced to the data the
// importer reads (group tree, entry string fields, recycle-bin metadata).

// --- Errors -----------------------------------------------------------------------------------

// openErrorKind is the part of DatabaseOpenError the SDK's map_open_error looks at.
type openErrorKind int

const (
	// openErrKey / openErrCrypto are DatabaseOpenError::Key / ::Cryptography (wrong credentials).
	openErrKey openErrorKind = iota
	openErrCrypto
	// openErrOther is every other variant (I/O, EOF, version, format): corrupt or unsupported.
	openErrOther
)

type openError struct {
	kind openErrorKind
	msg  string
}

func (e *openError) Error() string { return e.msg }

func errFormat(msg string) error { return &openError{kind: openErrOther, msg: msg} }

var errUnexpectedEOF = &openError{kind: openErrOther, msg: "unexpected end of file"}

func keyError(err error) error    { return &openError{kind: openErrKey, msg: err.Error()} }
func cryptoError(err error) error { return &openError{kind: openErrCrypto, msg: err.Error()} }

// wrap classifies an error from the crypto helpers.
func wrapCrypto(err error) error {
	if err == nil {
		return nil
	}
	var oe *openError
	if errors.As(err, &oe) {
		return err
	}
	if errors.Is(err, errArgon2TooLarge) {
		return errFormat(err.Error())
	}
	return cryptoError(err)
}

// --- Byte helpers -----------------------------------------------------------------------------

func get(data []byte, from, to int) ([]byte, bool) {
	if from < 0 || to < from || to > len(data) {
		return nil, false
	}
	return data[from:to], true
}

func readU16(b []byte) (uint16, bool) {
	if len(b) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func readU32(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func readU64(b []byte) (uint64, bool) {
	if len(b) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// --- Version ----------------------------------------------------------------------------------

const (
	keepass1ID      = 0xb54bfb65
	keepass2ID      = 0xb54bfb66
	keepassLatestID = 0xb54bfb67
	versionHeader   = 12
)

var kdbxIdentifier = []byte{0x03, 0xd9, 0xa2, 0x9a}

// openDatabase is Database::open(data, key).
func openDatabase(data []byte, key *databaseKey) (*database, error) {
	if len(data) < versionHeader {
		return nil, errFormat("unexpected end of file while reading database version")
	}
	if !bytes.Equal(data[0:4], kdbxIdentifier) {
		return nil, errFormat("invalid KDBX identifier")
	}
	version := binary.LittleEndian.Uint32(data[4:8])
	major := binary.LittleEndian.Uint16(data[10:12])
	switch {
	case version == keepass1ID:
		return parseKDB(data, key)
	case version == keepass2ID:
		return nil, errFormat("unsupported database version")
	case version == keepassLatestID && major == 3:
		return parseKDBX3(data, key)
	case version == keepassLatestID && major == 4:
		return parseKDBX4(data, key)
	}
	return nil, errFormat(fmt.Sprintf("invalid KDBX version: %d.%d", version, major))
}

func compositeKey(key *databaseKey) ([]byte, error) {
	elements, err := key.keyElements()
	if err != nil {
		return nil, keyError(err)
	}
	return sha256Sum(elements...), nil
}

// gunzip is GZipCompression::decompress (a single gzip member; trailing data is ignored).
func gunzip(b []byte) ([]byte, error) {
	if len(b) == 0 {
		// flate2's GzDecoder reads empty input as an empty stream (KeePassXC writes empty pooled
		// binaries as `<Binary ID="2" Compressed="True"/>`).
		return []byte{}, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, errFormat("gzip: " + err.Error())
	}
	r.Multistream(false)
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, errFormat("gzip: " + err.Error())
	}
	return out, nil
}

func decompress(compression uint32, b []byte) ([]byte, error) {
	if compression == 1 {
		return gunzip(b)
	}
	return append([]byte(nil), b...), nil
}

func parseCompression(b []byte) (uint32, error) {
	v, ok := readU32(b)
	if !ok {
		return 0, errUnexpectedEOF
	}
	if v > 1 {
		return 0, errFormat(fmt.Sprintf("invalid compression algorithm: %d", v))
	}
	return v, nil
}

// --- KDBX 3.1 ---------------------------------------------------------------------------------

func parseKDBX3(data []byte, key *databaseKey) (*database, error) {
	var (
		outer                                                         *outerCipher
		compression                                                   *uint32
		masterSeed, transformSeed, outerIV, streamKey, streamStart    []byte
		haveMasterSeed, haveTransformSeed, haveIV, haveKey, haveStart bool
		transformRounds                                               *uint64
		inner                                                         *uint32
	)
	pos := versionHeader
	for {
		if pos >= len(data) {
			return nil, errUnexpectedEOF
		}
		entryType := data[pos]
		lb, ok := get(data, pos+1, pos+3)
		if !ok {
			return nil, errUnexpectedEOF
		}
		length := int(binary.LittleEndian.Uint16(lb))
		buf, ok := get(data, pos+3, pos+3+length)
		if !ok {
			return nil, errUnexpectedEOF
		}
		pos += 3 + length
		if entryType == 0 {
			break
		}
		switch entryType {
		case 1:
		case 2:
			c, err := parseOuterCipher(buf)
			if err != nil {
				return nil, err
			}
			outer = &c
		case 3:
			c, err := parseCompression(buf)
			if err != nil {
				return nil, err
			}
			compression = &c
		case 4:
			masterSeed, haveMasterSeed = append([]byte(nil), buf...), true
		case 5:
			transformSeed, haveTransformSeed = append([]byte(nil), buf...), true
		case 6:
			v, ok := readU64(buf)
			if !ok {
				return nil, errUnexpectedEOF
			}
			transformRounds = &v
		case 7:
			outerIV, haveIV = append([]byte(nil), buf...), true
		case 8:
			streamKey, haveKey = append([]byte(nil), buf...), true
		case 9:
			streamStart, haveStart = append([]byte(nil), buf...), true
		case 10:
			v, ok := readU32(buf)
			if !ok {
				return nil, errUnexpectedEOF
			}
			if v != innerPlain && v != innerSalsa20 && v != innerChaCha {
				return nil, errFormat(fmt.Sprintf("invalid inner cipher ID: %d", v))
			}
			inner = &v
		default:
			return nil, errFormat(fmt.Sprintf("encountered invalid outer header entry with type %d", entryType))
		}
	}
	switch {
	case outer == nil:
		return nil, errFormat("outer header is missing Outer Cipher ID")
	case compression == nil:
		return nil, errFormat("outer header is missing Compression ID")
	case !haveMasterSeed:
		return nil, errFormat("outer header is missing Master seed")
	case !haveTransformSeed:
		return nil, errFormat("outer header is missing Transform seed")
	case transformRounds == nil:
		return nil, errFormat("outer header is missing Number of transformation rounds")
	case !haveIV:
		return nil, errFormat("outer header is missing Outer cipher IV")
	case !haveKey:
		return nil, errFormat("outer header is missing Protected stream key")
	case !haveStart:
		return nil, errFormat("outer header is missing Stream start bytes")
	case inner == nil:
		return nil, errFormat("outer header is missing Inner cipher ID")
	}

	innerStream, err := newInnerStream(*inner, streamKey)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	payloadEncrypted := data[pos:]

	composite, err := compositeKey(key)
	if err != nil {
		return nil, err
	}
	kdf := kdfConfig{kind: kdfAES, rounds: *transformRounds, seed: transformSeed}
	transformed, err := kdf.transformKey(composite)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	masterKey := sha256Sum(masterSeed, transformed)
	payload, err := outer.decrypt(masterKey, outerIV, payloadEncrypted)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	start, ok := get(payload, 0, len(streamStart))
	if !ok {
		return nil, errUnexpectedEOF
	}
	if !bytes.Equal(start, streamStart) {
		return nil, keyError(errIncorrectKey)
	}

	var buf []byte
	pos = 32
	for blockIndex := 0; ; blockIndex++ {
		hash, ok := get(payload, pos+4, pos+36)
		if !ok {
			return nil, errUnexpectedEOF
		}
		sb, ok := get(payload, pos+36, pos+40)
		if !ok {
			return nil, errUnexpectedEOF
		}
		size := int(binary.LittleEndian.Uint32(sb))
		if size == 0 {
			break
		}
		block, ok := get(payload, pos+40, pos+40+size)
		if !ok {
			return nil, errUnexpectedEOF
		}
		if !bytes.Equal(hash, sha256Sum(block)) {
			return nil, errFormat(fmt.Sprintf("block hash mismatch at block index %d", blockIndex))
		}
		buf = append(buf, block...)
		pos += 40 + size
	}
	xmlData, err := decompress(*compression, buf)
	if err != nil {
		return nil, err
	}
	return parseXMLDatabase(xmlData, innerStream)
}

// --- KDBX 4.x ---------------------------------------------------------------------------------

var (
	kdfAESKDBX3 = mustHex("c9d9f39a628a4460bf740d08c18a4fea")
	kdfAESKDBX4 = mustHex("7c02bb8279a74ac0927d114a00648238")
	kdfArgon2   = mustHex("ef636ddf8c29444b91f7a9a403e30a0c")
	kdfArgon2ID = mustHex("9e298b1956db4773b23dfc3ec6f0a1e6")
)

func parseKDBX4(data []byte, key *databaseKey) (*database, error) {
	var (
		outer       *outerCipher
		compression *uint32
		masterSeed  []byte
		outerIV     []byte
		haveSeed    bool
		haveIV      bool
		kdf         *kdfConfig
	)
	pos := versionHeader
	for {
		if pos >= len(data) {
			return nil, errUnexpectedEOF
		}
		entryType := data[pos]
		lb, ok := get(data, pos+1, pos+5)
		if !ok {
			return nil, errUnexpectedEOF
		}
		length := binary.LittleEndian.Uint32(lb)
		if uint64(length) > uint64(len(data)) {
			return nil, errUnexpectedEOF
		}
		buf, ok := get(data, pos+5, pos+5+int(length))
		if !ok {
			return nil, errUnexpectedEOF
		}
		pos += 5 + int(length)
		if entryType == 0 {
			break
		}
		switch entryType {
		case 1: // comment
		case 2:
			c, err := parseOuterCipher(buf)
			if err != nil {
				return nil, err
			}
			outer = &c
		case 3:
			c, err := parseCompression(buf)
			if err != nil {
				return nil, err
			}
			compression = &c
		case 4:
			masterSeed, haveSeed = append([]byte(nil), buf...), true
		case 7:
			outerIV, haveIV = append([]byte(nil), buf...), true
		case 11:
			vd, err := parseVariantDictionary(buf)
			if err != nil {
				return nil, err
			}
			k, err := kdfFromVariantDictionary(vd)
			if err != nil {
				return nil, err
			}
			kdf = k
		case 12:
			if _, err := parseVariantDictionary(buf); err != nil {
				return nil, err
			}
		default:
			return nil, errFormat(fmt.Sprintf("invalid outer header entry: %d", entryType))
		}
	}
	switch {
	case outer == nil:
		return nil, errFormat("outer header incomplete - missing Outer Cipher ID")
	case compression == nil:
		return nil, errFormat("outer header incomplete - missing Compression ID")
	case !haveSeed:
		return nil, errFormat("outer header incomplete - missing Master seed")
	case !haveIV:
		return nil, errFormat("outer header incomplete - missing Outer IV")
	case kdf == nil:
		return nil, errFormat("outer header incomplete - missing Key Derivation Function Parameters")
	}

	innerHeaderStart := pos
	headerData := data[0:innerHeaderStart]
	headerSHA, ok := get(data, innerHeaderStart, innerHeaderStart+32)
	if !ok {
		return nil, errUnexpectedEOF
	}
	headerHMAC, ok := get(data, innerHeaderStart+32, innerHeaderStart+64)
	if !ok {
		return nil, errUnexpectedEOF
	}
	blockStream := data[innerHeaderStart+64:]
	if !bytes.Equal(headerSHA, sha256Sum(headerData)) {
		return nil, errFormat("header hash mismatch - the header may be corrupted")
	}

	composite, err := compositeKey(key)
	if err != nil {
		return nil, err
	}
	transformed, err := kdf.transformKey(composite)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	masterKey := sha256Sum(masterSeed, transformed)
	hmacKey := sha512Sum(masterSeed, transformed, []byte{0x01})
	if !bytes.Equal(headerHMAC, hmacSHA256(hmacBlockKey(math.MaxUint64, hmacKey), headerData)) {
		return nil, keyError(errIncorrectKey)
	}

	payloadEncrypted, err := readHMACBlockStream(blockStream, hmacKey)
	if err != nil {
		return nil, err
	}
	payloadCompressed, err := outer.decrypt(masterKey, outerIV, payloadEncrypted)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	payload, err := decompress(*compression, payloadCompressed)
	if err != nil {
		return nil, err
	}

	// Inner header.
	var (
		innerID   *uint32
		innerKey  []byte
		haveInKey bool
	)
	pos = 0
	for {
		if pos >= len(payload) {
			return nil, errFormat("unexpected end of file while parsing inner header")
		}
		entryType := payload[pos]
		lb, ok := get(payload, pos+1, pos+5)
		if !ok {
			return nil, errFormat("unexpected end of file while parsing inner header")
		}
		length := binary.LittleEndian.Uint32(lb)
		if uint64(length) > uint64(len(payload)) {
			return nil, errFormat("unexpected end of file while parsing inner header")
		}
		buf, ok := get(payload, pos+5, pos+5+int(length))
		if !ok {
			return nil, errFormat("unexpected end of file while parsing inner header")
		}
		pos += 5 + int(length)
		if entryType == 0 {
			break
		}
		switch entryType {
		case 1:
			v, ok := readU32(buf)
			if !ok {
				return nil, errUnexpectedEOF
			}
			if v != innerPlain && v != innerSalsa20 && v != innerChaCha {
				return nil, errFormat(fmt.Sprintf("invalid inner cipher ID: %d", v))
			}
			innerID = &v
		case 2:
			innerKey, haveInKey = append([]byte(nil), buf...), true
		case 3:
			if len(buf) == 0 {
				return nil, errFormat("unexpected end of file while parsing inner header")
			}
			// Binary attachments are not imported.
		default:
			return nil, errFormat(fmt.Sprintf("invalid inner header entry: %d", entryType))
		}
	}
	if innerID == nil {
		return nil, errFormat("inner header incomplete - missing Inner random stream")
	}
	if !haveInKey {
		return nil, errFormat("inner header incomplete - missing Inner random stream key")
	}
	xmlData := payload[pos:]
	innerStream, err := newInnerStream(*innerID, innerKey)
	if err != nil {
		return nil, wrapCrypto(err)
	}
	return parseXMLDatabase(xmlData, innerStream)
}

func hmacBlockKey(blockIndex uint64, key []byte) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], blockIndex)
	return sha512Sum(buf[:], key)
}

// readHMACBlockStream is hmac_block_stream::read_hmac_block_stream.
func readHMACBlockStream(data, key []byte) ([]byte, error) {
	var out []byte
	pos := 0
	for blockIndex := uint64(0); pos < len(data); blockIndex++ {
		mac, ok := get(data, pos, pos+32)
		if !ok {
			return nil, errFormat("unexpected end of file")
		}
		sizeBytes, ok := get(data, pos+32, pos+36)
		if !ok {
			return nil, errFormat("unexpected end of file")
		}
		size := binary.LittleEndian.Uint32(sizeBytes)
		if uint64(size) > uint64(len(data)) {
			return nil, errFormat("unexpected end of file")
		}
		block, ok := get(data, pos+36, pos+36+int(size))
		if !ok {
			return nil, errFormat("unexpected end of file")
		}
		var idx [8]byte
		binary.LittleEndian.PutUint64(idx[:], blockIndex)
		if !bytes.Equal(mac, hmacSHA256(hmacBlockKey(blockIndex, key), idx[:], sizeBytes, block)) {
			return nil, errFormat(fmt.Sprintf("block hash mismatch for block %d", blockIndex))
		}
		pos += 36 + int(size)
		if size == 0 {
			break
		}
		out = append(out, block...)
	}
	return out, nil
}

// --- Variant dictionary (KDF parameters) ------------------------------------------------------

type vdValue struct {
	typ   byte
	u32   uint32
	u64   uint64
	bytes []byte
}

func parseVariantDictionary(buffer []byte) (map[string]vdValue, error) {
	vb, ok := get(buffer, 0, 2)
	if !ok {
		return nil, errFormat("variant dictionary: unexpected end of file")
	}
	if v := binary.LittleEndian.Uint16(vb); v != 0x100 {
		return nil, errFormat(fmt.Sprintf("variant dictionary: invalid version %d", v))
	}
	pos := 2
	out := map[string]vdValue{}
	for pos+9 < len(buffer) {
		typ := buffer[pos]
		pos++
		kl, ok := get(buffer, pos, pos+4)
		if !ok {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		keyLen := binary.LittleEndian.Uint32(kl)
		pos += 4
		if uint64(keyLen) > uint64(len(buffer)) {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		k, ok := get(buffer, pos, pos+int(keyLen))
		if !ok {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		pos += int(keyLen)
		vl, ok := get(buffer, pos, pos+4)
		if !ok {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		valLen := binary.LittleEndian.Uint32(vl)
		pos += 4
		if uint64(valLen) > uint64(len(buffer)) {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		v, ok := get(buffer, pos, pos+int(valLen))
		if !ok {
			return nil, errFormat("variant dictionary: unexpected end of file")
		}
		pos += int(valLen)
		val := vdValue{typ: typ}
		switch typ {
		case 0x04, 0x0c: // u32, i32
			n, ok := readU32(v)
			if !ok {
				return nil, errFormat("variant dictionary: short value")
			}
			val.u32 = n
		case 0x05, 0x0d: // u64, i64
			n, ok := readU64(v)
			if !ok {
				return nil, errFormat("variant dictionary: short value")
			}
			val.u64 = n
		case 0x08, 0x18, 0x42: // bool, string, bytes
			val.bytes = append([]byte(nil), v...)
		default:
			return nil, errFormat(fmt.Sprintf("variant dictionary: invalid value type %d", typ))
		}
		out[string(bytes.ToValidUTF8(k, []byte("�")))] = val
	}
	if pos >= len(buffer) || buffer[pos] != 0 {
		return nil, errFormat("variant dictionary: not terminated")
	}
	return out, nil
}

func vdBytes(vd map[string]vdValue, key string) ([]byte, error) {
	v, ok := vd[key]
	if !ok {
		return nil, errFormat("variant dictionary: missing key " + key)
	}
	if v.typ != 0x42 {
		return nil, errFormat("variant dictionary: mistyped key " + key)
	}
	return v.bytes, nil
}

func vdU64(vd map[string]vdValue, key string) (uint64, error) {
	v, ok := vd[key]
	if !ok {
		return 0, errFormat("variant dictionary: missing key " + key)
	}
	if v.typ != 0x05 {
		return 0, errFormat("variant dictionary: mistyped key " + key)
	}
	return v.u64, nil
}

func vdU32(vd map[string]vdValue, key string) (uint32, error) {
	v, ok := vd[key]
	if !ok {
		return 0, errFormat("variant dictionary: missing key " + key)
	}
	if v.typ != 0x04 {
		return 0, errFormat("variant dictionary: mistyped key " + key)
	}
	return v.u32, nil
}

// kdfFromVariantDictionary is TryFrom<VariantDictionary> for (KdfConfig, Vec<u8>).
func kdfFromVariantDictionary(vd map[string]vdValue) (*kdfConfig, error) {
	uuid, err := vdBytes(vd, "$UUID")
	if err != nil {
		return nil, err
	}
	switch {
	case bytes.Equal(uuid, kdfArgon2ID), bytes.Equal(uuid, kdfArgon2):
		kind := kdfArgon2d
		if bytes.Equal(uuid, kdfArgon2ID) {
			kind = kdfArgon2id
		}
		memory, err := vdU64(vd, "M")
		if err != nil {
			return nil, err
		}
		salt, err := vdBytes(vd, "S")
		if err != nil {
			return nil, err
		}
		iterations, err := vdU64(vd, "I")
		if err != nil {
			return nil, err
		}
		parallelism, err := vdU32(vd, "P")
		if err != nil {
			return nil, err
		}
		version, err := vdU32(vd, "V")
		if err != nil {
			return nil, err
		}
		if version != argon2Version10 && version != argon2Version13 {
			return nil, errFormat(fmt.Sprintf("invalid KDF version: %d", version))
		}
		return &kdfConfig{kind: kind, memory: memory, seed: salt, iterations: iterations, parallelism: parallelism, version: version}, nil
	case bytes.Equal(uuid, kdfAESKDBX4), bytes.Equal(uuid, kdfAESKDBX3):
		rounds, err := vdU64(vd, "R")
		if err != nil {
			return nil, err
		}
		seed, err := vdBytes(vd, "S")
		if err != nil {
			return nil, err
		}
		return &kdfConfig{kind: kdfAES, rounds: rounds, seed: seed}, nil
	}
	return nil, errFormat("invalid KDF UUID")
}
