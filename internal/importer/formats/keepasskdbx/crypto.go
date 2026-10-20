package keepasskdbx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/twofish"
)

// Ports of the keepass crate's crypt module (crypt/mod.rs, crypt/kdf.rs, crypt/ciphers.rs) and key
// handling (key/mod.rs).

// errCrypto is crypt::CryptographyError (invalid length, invalid padding, argon2 error). The SDK
// maps it to KdbxWrongCredentials.
var errCrypto = errors.New("cryptography error")

func sha256Sum(elements ...[]byte) []byte {
	h := sha256.New()
	for _, e := range elements {
		h.Write(e)
	}
	return h.Sum(nil)
}

func sha512Sum(elements ...[]byte) []byte {
	h := sha512.New()
	for _, e := range elements {
		h.Write(e)
	}
	return h.Sum(nil)
}

func hmacSHA256(key []byte, elements ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, e := range elements {
		m.Write(e)
	}
	return m.Sum(nil)
}

// --- KDFs -----------------------------------------------------------------------------------

type kdfKind int

const (
	kdfAES kdfKind = iota
	kdfArgon2d
	kdfArgon2id
)

// kdfConfig is config::KdfConfig plus the seed/salt.
type kdfConfig struct {
	kind        kdfKind
	rounds      uint64 // AES
	iterations  uint64 // Argon2
	memory      uint64 // Argon2, bytes
	parallelism uint32
	version     uint32
	seed        []byte
}

// transformKey is Kdf::transform_key.
func (k *kdfConfig) transformKey(compositeKey []byte) ([]byte, error) {
	switch k.kind {
	case kdfAES:
		if len(k.seed) != 32 {
			return nil, errCrypto
		}
		block, err := aes.NewCipher(k.seed)
		if err != nil {
			return nil, errCrypto
		}
		b1 := append([]byte(nil), compositeKey[:16]...)
		b2 := append([]byte(nil), compositeKey[16:32]...)
		for r := uint64(0); r < k.rounds; r++ {
			block.Encrypt(b1, b1)
			block.Encrypt(b2, b2)
		}
		return sha256Sum(b1, b2), nil
	default:
		mode := argon2d
		if k.kind == kdfArgon2id {
			mode = argon2id
		}
		key, err := argon2Key(argon2Params{
			mode:     mode,
			version:  k.version,
			time:     uint32(k.iterations),
			memory:   uint32(k.memory / 1024),
			lanes:    k.parallelism,
			salt:     k.seed,
			password: compositeKey,
		})
		if errors.Is(err, errArgon2TooLarge) {
			return nil, err
		}
		if err != nil {
			return nil, errCrypto
		}
		return key, nil
	}
}

// --- Outer ciphers --------------------------------------------------------------------------

type outerCipher int

const (
	outerAES256 outerCipher = iota
	outerTwofish
	outerChaCha20
)

var (
	cipherSuiteAES256  = mustHex("31c1f2e6bf714350be5805216afc5aff")
	cipherSuiteTwofish = mustHex("ad68f29f576f4bb9a36ad47af965346c")
	cipherSuiteChaCha  = mustHex("d6038a2b8b6f4cb5a524339a31dbb59a")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func parseOuterCipher(id []byte) (outerCipher, error) {
	switch {
	case bytes.Equal(id, cipherSuiteAES256):
		return outerAES256, nil
	case bytes.Equal(id, cipherSuiteTwofish):
		return outerTwofish, nil
	case bytes.Equal(id, cipherSuiteChaCha):
		return outerChaCha20, nil
	}
	return 0, errFormat("invalid outer cipher ID")
}

// decrypt is OuterCipherConfig::get_cipher(key, iv).decrypt(ciphertext). CBC modes remove PKCS#7
// padding (the crate's Twofish decryptor validates but keeps the padding; every caller strips it
// afterwards or ignores trailing bytes, so removing it here is equivalent).
func (c outerCipher) decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	switch c {
	case outerChaCha20:
		if len(key) != chacha20.KeySize || len(iv) != chacha20.NonceSize {
			return nil, errCrypto
		}
		s, err := chacha20.NewUnauthenticatedCipher(key, iv)
		if err != nil {
			return nil, errCrypto
		}
		out := make([]byte, len(ciphertext))
		s.XORKeyStream(out, ciphertext)
		return out, nil
	default:
		var block cipher.Block
		var err error
		if c == outerAES256 {
			if len(key) != 32 {
				return nil, errCrypto
			}
			block, err = aes.NewCipher(key)
		} else {
			block, err = twofish.NewCipher(key)
		}
		if err != nil || len(iv) != block.BlockSize() {
			return nil, errCrypto
		}
		if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
			return nil, errCrypto
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
		return unpadPKCS7(out, block.BlockSize())
	}
}

func unpadPKCS7(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errCrypto
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errCrypto
	}
	for _, p := range b[len(b)-n:] {
		if int(p) != n {
			return nil, errCrypto
		}
	}
	return b[:len(b)-n], nil
}

// --- Inner (protected value) stream ciphers -------------------------------------------------

const (
	innerPlain   = 0
	innerSalsa20 = 2
	innerChaCha  = 3
)

type innerStream interface {
	decrypt(b []byte) []byte
}

type plainStream struct{}

func (plainStream) decrypt(b []byte) []byte { return append([]byte(nil), b...) }

// salsaStream is a stateful Salsa20 keystream (key = SHA-256(protected stream key), fixed IV).
type salsaStream struct {
	key     [32]byte
	nonce   [8]byte
	counter uint64
	buf     [64]byte
	pos     int
}

func newSalsaStream(streamKey []byte) *salsaStream {
	s := &salsaStream{pos: 64}
	copy(s.key[:], sha256Sum(streamKey))
	copy(s.nonce[:], []byte{0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A})
	return s
}

func (s *salsaStream) decrypt(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		if s.pos == 64 {
			var in [16]byte
			copy(in[:8], s.nonce[:])
			binary.LittleEndian.PutUint64(in[8:], s.counter)
			var zero [64]byte
			salsa.XORKeyStream(s.buf[:], zero[:], &in, &s.key)
			s.counter++
			s.pos = 0
		}
		out[i] = b[i] ^ s.buf[s.pos]
		s.pos++
	}
	return out
}

type chachaStream struct{ c *chacha20.Cipher }

func newChaChaStream(streamKey []byte) (*chachaStream, error) {
	h := sha512Sum(streamKey)
	c, err := chacha20.NewUnauthenticatedCipher(h[0:32], h[32:44])
	if err != nil {
		return nil, errCrypto
	}
	return &chachaStream{c: c}, nil
}

func (s *chachaStream) decrypt(b []byte) []byte {
	out := make([]byte, len(b))
	s.c.XORKeyStream(out, b)
	return out
}

func newInnerStream(id uint32, key []byte) (innerStream, error) {
	switch id {
	case innerPlain:
		return plainStream{}, nil
	case innerSalsa20:
		return newSalsaStream(key), nil
	case innerChaCha:
		return newChaChaStream(key)
	}
	return nil, errFormat("invalid inner cipher ID")
}

// --- Database key (key/mod.rs) --------------------------------------------------------------

// databaseKey is keepass::DatabaseKey with an optional password and key file.
type databaseKey struct {
	password    *string
	keyFile     []byte
	haveKeyFile bool
}

// errEmptyKey / errIncorrectKey are DatabaseKeyError::EmptyKey / IncorrectKey.
var (
	errEmptyKey     = errors.New("the key contains no components")
	errIncorrectKey = errors.New("incorrect key")
)

// keyElements is DatabaseKey::get_key_elements.
func (k *databaseKey) keyElements() ([][]byte, error) {
	var out [][]byte
	if k.password != nil {
		out = append(out, sha256Sum([]byte(*k.password)))
	}
	if k.haveKeyFile {
		out = append(out, parseKeyFile(k.keyFile))
	}
	if len(out) == 0 {
		return nil, errEmptyKey
	}
	return out, nil
}

// parseKeyFile is key::parse_keyfile: an XML key file (v1 base64 / v2 hex), a 32-byte binary key,
// a 64-character hex key, or else the SHA-256 of the whole file.
func parseKeyFile(buffer []byte) []byte {
	if v, ok := parseXMLKeyFile(buffer); ok {
		return v
	}
	if len(buffer) == 32 {
		return append([]byte(nil), buffer...)
	}
	if len(buffer) == 64 {
		if b, err := hex.DecodeString(string(buffer)); err == nil {
			return b
		}
	}
	return sha256Sum(buffer)
}

// parseXMLKeyFile is key::parse_xml_keyfile (quick-xml event reader): the text of
// KeyFile/Meta/Version and KeyFile/Key/Data (exact element paths, prefixes included).
func parseXMLKeyFile(data []byte) ([]byte, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var stack []string
	var version, value *string
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, qualified(t.Name))
		case xml.EndElement:
			// quick-xml checks that end tags match their start tags.
			if len(stack) == 0 || stack[len(stack)-1] != qualified(t.Name) {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			s := string(t)
			if pathIs(stack, "KeyFile", "Meta", "Version") {
				version = &s
			} else if pathIs(stack, "KeyFile", "Key", "Data") {
				value = &s
			}
		}
	}
	if value == nil {
		return nil, false
	}
	keyValue := *value
	keyBytes := []byte(keyValue)
	if version != nil && *version == "2.0" {
		trimmed := strings.TrimSpace(keyValue)
		for _, c := range []string{" ", "\n", "\t", "\r"} {
			trimmed = strings.ReplaceAll(trimmed, c, "")
		}
		if key, err := hex.DecodeString(trimmed); err == nil {
			return key, true
		}
		return keyBytes, true
	}
	if key, ok := decodeBase64Strict(keyValue); ok {
		return key, true
	}
	return keyBytes, true
}

func qualified(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

func pathIs(stack []string, path ...string) bool {
	if len(stack) != len(path) {
		return false
	}
	for i := range path {
		if stack[i] != path[i] {
			return false
		}
	}
	return true
}

// decodeBase64Strict mirrors the base64 crate's STANDARD engine: canonical padding, no trailing
// bits and no embedded line breaks (Go's decoder would skip \r and \n).
func decodeBase64Strict(s string) ([]byte, bool) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}
