package keepasskdbx

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// A minimal KDBX 3.1 / 4 writer used to build test databases (the role keepass's save_kdbx4 test
// feature plays in kdbx.rs's tests). Reading is validated separately against keepass-rs fixtures.

type tField struct {
	key, value string
	protected  bool
}

type tEntry struct {
	uuid    int
	fields  []tField
	history []tEntry
}

type tGroup struct {
	uuid    int
	name    string
	entries []tEntry
	groups  []tGroup
}

type tDB struct {
	root              tGroup
	recycleBinEnabled string // "" = element omitted
	recycleBinUUID    int    // 0 = element omitted
}

func uuidB64(n int) string {
	u := make([]byte, 16)
	u[0], u[14], u[15] = 0xAB, byte(n>>8), byte(n)
	return base64.StdEncoding.EncodeToString(u)
}

// streamEncryptor XORs protected values with the inner stream (XOR is its own inverse).
type streamEncryptor interface{ decrypt([]byte) []byte }

func writeXML(db tDB, enc streamEncryptor) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n<KeePassFile>\n<Meta><Generator>test</Generator>")
	if db.recycleBinEnabled != "" {
		fmt.Fprintf(&b, "<RecycleBinEnabled>%s</RecycleBinEnabled>", db.recycleBinEnabled)
	}
	if db.recycleBinUUID != 0 {
		fmt.Fprintf(&b, "<RecycleBinUUID>%s</RecycleBinUUID>", uuidB64(db.recycleBinUUID))
	}
	b.WriteString("</Meta>\n<Root>\n")
	var writeEntry func(e tEntry)
	writeEntry = func(e tEntry) {
		fmt.Fprintf(&b, "<Entry><UUID>%s</UUID>", uuidB64(e.uuid))
		for _, f := range e.fields {
			if f.protected {
				ct := enc.decrypt([]byte(f.value))
				fmt.Fprintf(&b, `<String><Key>%s</Key><Value Protected="True">%s</Value></String>`, html.EscapeString(f.key), base64.StdEncoding.EncodeToString(ct))
			} else {
				fmt.Fprintf(&b, "<String><Key>%s</Key><Value>%s</Value></String>", html.EscapeString(f.key), html.EscapeString(f.value))
			}
		}
		if len(e.history) > 0 {
			b.WriteString("<History>")
			for _, h := range e.history {
				writeEntry(h)
			}
			b.WriteString("</History>")
		}
		b.WriteString("</Entry>\n")
	}
	var writeGroup func(g tGroup)
	writeGroup = func(g tGroup) {
		fmt.Fprintf(&b, "<Group><UUID>%s</UUID><Name>%s</Name>\n", uuidB64(g.uuid), html.EscapeString(g.name))
		for _, e := range g.entries {
			writeEntry(e)
		}
		for _, sub := range g.groups {
			writeGroup(sub)
		}
		b.WriteString("</Group>\n")
	}
	writeGroup(db.root)
	b.WriteString("</Root>\n</KeePassFile>\n")
	return []byte(b.String())
}

type writeOptions struct {
	password    *string
	keyFile     []byte
	kdbx3       bool
	chachaOuter bool
	argon2      bool
}

func gz(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func padPKCS7(b []byte) []byte {
	n := 16 - len(b)%16
	return append(append([]byte(nil), b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func aesCBC(t testing.TB, key, iv, plain []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	p := padPKCS7(plain)
	out := make([]byte, len(p))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, p)
	return out
}

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func testKey(t testing.TB, o writeOptions) []byte {
	k := &databaseKey{password: o.password, keyFile: o.keyFile, haveKeyFile: o.keyFile != nil}
	c, err := compositeKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func headerField3(buf *bytes.Buffer, id byte, data []byte) {
	buf.WriteByte(id)
	binary.Write(buf, binary.LittleEndian, uint16(len(data)))
	buf.Write(data)
}

func headerField4(buf *bytes.Buffer, id byte, data []byte) {
	buf.WriteByte(id)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
}

func u32le(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func u64le(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

// buildKDBX writes db as a KDBX 4.1 (default) or 3.1 file.
func buildKDBX(t testing.TB, db tDB, o writeOptions) []byte {
	if o.kdbx3 {
		return buildKDBX3(t, db, o)
	}
	masterSeed, iv, kdfSeed, streamKey := seq(32, 1), seq(16, 50), seq(32, 100), seq(64, 150)
	outerID := cipherSuiteAES256
	if o.chachaOuter {
		outerID, iv = cipherSuiteChaCha, seq(12, 50)
	}
	var kdf kdfConfig
	vd := &bytes.Buffer{}
	binary.Write(vd, binary.LittleEndian, uint16(0x100))
	vdEntry := func(typ byte, key string, val []byte) {
		vd.WriteByte(typ)
		binary.Write(vd, binary.LittleEndian, uint32(len(key)))
		vd.WriteString(key)
		binary.Write(vd, binary.LittleEndian, uint32(len(val)))
		vd.Write(val)
	}
	if o.argon2 {
		kdf = kdfConfig{kind: kdfArgon2d, iterations: 2, memory: 64 * 1024, parallelism: 2, version: 0x13, seed: kdfSeed}
		vdEntry(0x42, "$UUID", kdfArgon2)
		vdEntry(0x05, "M", u64le(kdf.memory))
		vdEntry(0x42, "S", kdfSeed)
		vdEntry(0x05, "I", u64le(kdf.iterations))
		vdEntry(0x04, "P", u32le(kdf.parallelism))
		vdEntry(0x04, "V", u32le(kdf.version))
	} else {
		kdf = kdfConfig{kind: kdfAES, rounds: 10, seed: kdfSeed}
		vdEntry(0x42, "$UUID", kdfAESKDBX4)
		vdEntry(0x05, "R", u64le(kdf.rounds))
		vdEntry(0x42, "S", kdfSeed)
	}
	vd.WriteByte(0)

	header := &bytes.Buffer{}
	header.Write(kdbxIdentifier)
	header.Write(u32le(keepassLatestID))
	binary.Write(header, binary.LittleEndian, uint16(1))
	binary.Write(header, binary.LittleEndian, uint16(4))
	headerField4(header, 2, outerID)
	headerField4(header, 3, u32le(1))
	headerField4(header, 4, masterSeed)
	headerField4(header, 7, iv)
	headerField4(header, 11, vd.Bytes())
	headerField4(header, 0, []byte("\r\n\r\n"))
	headerData := header.Bytes()

	transformed, err := kdf.transformKey(testKey(t, o))
	if err != nil {
		t.Fatal(err)
	}
	masterKey := sha256Sum(masterSeed, transformed)
	hmacKey := sha512Sum(masterSeed, transformed, []byte{1})

	inner, err := newInnerStream(innerChaCha, streamKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := &bytes.Buffer{}
	headerField4(payload, 1, u32le(innerChaCha))
	headerField4(payload, 2, streamKey)
	headerField4(payload, 0, nil)
	payload.Write(writeXML(db, inner))
	compressed := gz(t, payload.Bytes())

	var encrypted []byte
	if o.chachaOuter {
		c, err := chacha20.NewUnauthenticatedCipher(masterKey, iv)
		if err != nil {
			t.Fatal(err)
		}
		encrypted = make([]byte, len(compressed))
		c.XORKeyStream(encrypted, compressed)
	} else {
		encrypted = aesCBC(t, masterKey, iv, compressed)
	}

	out := &bytes.Buffer{}
	out.Write(headerData)
	out.Write(sha256Sum(headerData))
	out.Write(hmacSHA256(hmacBlockKey(^uint64(0), hmacKey), headerData))
	for i, block := range [][]byte{encrypted, nil} {
		size := u32le(uint32(len(block)))
		out.Write(hmacSHA256(hmacBlockKey(uint64(i), hmacKey), u64le(uint64(i)), size, block))
		out.Write(size)
		out.Write(block)
	}
	return out.Bytes()
}

func buildKDBX3(t testing.TB, db tDB, o writeOptions) []byte {
	masterSeed, transformSeed, iv, streamKey, streamStart := seq(32, 1), seq(32, 40), seq(16, 80), seq(32, 120), seq(32, 200)
	header := &bytes.Buffer{}
	header.Write(kdbxIdentifier)
	header.Write(u32le(keepassLatestID))
	binary.Write(header, binary.LittleEndian, uint16(1))
	binary.Write(header, binary.LittleEndian, uint16(3))
	headerField3(header, 2, cipherSuiteAES256)
	headerField3(header, 3, u32le(1))
	headerField3(header, 4, masterSeed)
	headerField3(header, 5, transformSeed)
	headerField3(header, 6, u64le(10))
	headerField3(header, 7, iv)
	headerField3(header, 8, streamKey)
	headerField3(header, 9, streamStart)
	headerField3(header, 10, u32le(innerSalsa20))
	headerField3(header, 0, []byte("\r\n\r\n"))

	kdf := kdfConfig{kind: kdfAES, rounds: 10, seed: transformSeed}
	transformed, err := kdf.transformKey(testKey(t, o))
	if err != nil {
		t.Fatal(err)
	}
	masterKey := sha256Sum(masterSeed, transformed)
	inner, _ := newInnerStream(innerSalsa20, streamKey)
	data := gz(t, writeXML(db, inner))

	payload := &bytes.Buffer{}
	payload.Write(streamStart)
	payload.Write(u32le(0))
	payload.Write(sha256Sum(data))
	payload.Write(u32le(uint32(len(data))))
	payload.Write(data)
	payload.Write(u32le(1))
	payload.Write(make([]byte, 32))
	payload.Write(u32le(0))

	out := &bytes.Buffer{}
	out.Write(header.Bytes())
	out.Write(aesCBC(t, masterKey, iv, payload.Bytes()))
	return out.Bytes()
}
