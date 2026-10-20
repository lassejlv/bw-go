// Package crypto implements the Bitwarden client-side cryptography used by the CLI:
// symmetric keys, EncString/EncArrayBuffer formats, KDFs and RSA operations.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// EncryptionType mirrors the Bitwarden EncryptionType enum.
type EncryptionType int

const (
	AesCbc256_B64                     EncryptionType = 0
	AesCbc256_HmacSha256_B64          EncryptionType = 2
	Rsa2048_OaepSha256_B64            EncryptionType = 3
	Rsa2048_OaepSha1_B64              EncryptionType = 4
	Rsa2048_OaepSha256_HmacSha256_B64 EncryptionType = 5
	Rsa2048_OaepSha1_HmacSha256_B64   EncryptionType = 6
	CoseEncrypt0                      EncryptionType = 7
)

var ErrMacMismatch = errors.New("MAC comparison failed. Key or payload has changed.")

// SymmetricKey is an AES-256 key with optional HMAC-SHA256 key (legacy, EncType 0/2), or a v2 COSE
// key (EncType CoseEncrypt0) whose 32 byte key material is in EncKey and whose algorithm, key id and
// allowed key operations are in Algorithm, KeyID and KeyOps.
type SymmetricKey struct {
	EncKey  []byte
	MacKey  []byte
	EncType EncryptionType

	// Algorithm is the key algorithm. For legacy keys it may be left zero (AlgUnknown); use
	// KeyAlgorithm() which derives it from EncType.
	Algorithm SymmetricKeyAlgorithm
	// KeyID is the 16 byte COSE key id (COSE keys only).
	KeyID []byte
	// KeyOps are the COSE key operations the key allows (COSE keys only).
	KeyOps []KeyOperation
}

// NewSymmetricKey builds a key from its encoded bytes (SDK SymmetricCryptoKey::try_from(&[u8])):
// 32 bytes is legacy AES-only, 64 bytes is enc+mac, more than 64 bytes is a padded COSE key
// (XChaCha20-Poly1305, AES-256-GCM or XAES-256-GCM).
func NewSymmetricKey(b []byte) (*SymmetricKey, error) {
	switch len(b) {
	case 32:
		return &SymmetricKey{EncKey: clone(b), EncType: AesCbc256_B64, Algorithm: AlgAes256Cbc}, nil
	case 64:
		return &SymmetricKey{EncKey: clone(b[:32]), MacKey: clone(b[32:]), EncType: AesCbc256_HmacSha256_B64, Algorithm: AlgAes256CbcHmac}, nil
	default:
		if len(b) > 64 {
			unpadded, err := unpadBytes(b)
			if err != nil {
				return nil, errors.New("invalid key")
			}
			return ParseCoseSymmetricKey(unpadded)
		}
		return nil, fmt.Errorf("unsupported key length %d", len(b))
	}
}

// KeyFromB64 decodes a base64 encoded symmetric key.
func KeyFromB64(s string) (*SymmetricKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

// GenerateKey creates a new random 64 byte AES-256-CBC-HMAC key.
func GenerateKey() *SymmetricKey {
	k, _ := NewSymmetricKey(RandomBytes(64))
	return k
}

// Bytes returns the encoded key (SDK to_encoded): the raw key material for legacy keys, or the
// COSE key padded to at least 65 bytes for COSE keys. NewSymmetricKey(k.Bytes()) round-trips.
func (k *SymmetricKey) Bytes() []byte {
	if k.IsCose() {
		b, _ := padBytes(k.CoseKeyBytes(), 65)
		return b
	}
	return append(clone(k.EncKey), k.MacKey...)
}

// B64 returns the base64 encoded key material.
func (k *SymmetricKey) B64() string {
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ---------- KDF ----------

type KdfType int

const (
	KdfPBKDF2   KdfType = 0
	KdfArgon2id KdfType = 1
)

// KdfConfig describes how a master key is derived.
type KdfConfig struct {
	Type        KdfType `json:"kdfType"`
	Iterations  int     `json:"iterations"`
	Memory      *int    `json:"memory,omitempty"`
	Parallelism *int    `json:"parallelism,omitempty"`
}

// MakeMasterKey derives the 32 byte master key from the password and salt (normally the email).
func MakeMasterKey(password, salt string, kdf KdfConfig) ([]byte, error) {
	switch kdf.Type {
	case KdfPBKDF2:
		if kdf.Iterations < 5000 {
			return nil, errors.New("PBKDF2 iteration minimum is 5000.")
		}
		return pbkdf2.Key(sha256.New, password, []byte(salt), kdf.Iterations, 32)
	case KdfArgon2id:
		mem, par := 64, 4
		if kdf.Memory != nil {
			mem = *kdf.Memory
		}
		if kdf.Parallelism != nil {
			par = *kdf.Parallelism
		}
		if kdf.Iterations < 2 {
			return nil, errors.New("Argon2 iteration minimum is 2.")
		}
		saltHash := sha256.Sum256([]byte(salt))
		return argon2.IDKey([]byte(password), saltHash[:], uint32(kdf.Iterations), uint32(mem*1024), uint8(par), 32), nil
	default:
		return nil, fmt.Errorf("unknown kdf type %d", kdf.Type)
	}
}

// HashPurpose selects server (1 iteration) or local (2 iterations) master password hashes.
type HashPurpose int

const (
	HashServerAuthorization HashPurpose = 1
	HashLocalAuthorization  HashPurpose = 2
)

// HashMasterPassword produces the base64 master password hash.
func HashMasterPassword(password string, masterKey []byte, purpose HashPurpose) string {
	h, _ := pbkdf2.Key(sha256.New, string(masterKey), []byte(password), int(purpose), 32)
	return base64.StdEncoding.EncodeToString(h)
}

// StretchKey expands a 32 byte key into a 64 byte enc+mac key using HKDF-Expand.
func StretchKey(key []byte) *SymmetricKey {
	enc, _ := hkdf.Expand(sha256.New, key, "enc", 32)
	mac, _ := hkdf.Expand(sha256.New, key, "mac", 32)
	return &SymmetricKey{EncKey: enc, MacKey: mac, EncType: AesCbc256_HmacSha256_B64}
}

// HKDF performs full HKDF (extract+expand) with SHA-256.
func HKDF(ikm []byte, salt, info string, length int) []byte {
	out, _ := hkdf.Key(sha256.New, ikm, []byte(salt), info, length)
	return out
}

// HKDFExpand performs HKDF-Expand with SHA-256.
func HKDFExpand(prk []byte, info string, length int) []byte {
	out, _ := hkdf.Expand(sha256.New, prk, info, length)
	return out
}

// PBKDF2 derives a key using PBKDF2 with SHA-256.
func PBKDF2(password, salt []byte, iterations, length int) []byte {
	out, _ := pbkdf2.Key(sha256.New, string(password), salt, iterations, length)
	return out
}

// ---------- AES ----------

func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	return append(clone(b), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, errors.New("invalid padding")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("invalid padding")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-n], nil
}

func computeMac(macKey, iv, data []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(iv)
	m.Write(data)
	return m.Sum(nil)
}

// AesEncrypt encrypts with the key and returns iv, ciphertext and mac (nil for AES-only keys).
func AesEncrypt(plain []byte, key *SymmetricKey) (iv, ct, mac []byte, err error) {
	if key.IsCose() {
		return nil, nil, nil, errors.New("AesEncrypt: key is not an AES-CBC key")
	}
	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		return nil, nil, nil, err
	}
	iv = RandomBytes(16)
	padded := pkcs7Pad(plain)
	ct = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	if key.MacKey != nil {
		mac = computeMac(key.MacKey, iv, ct)
	}
	return iv, ct, mac, nil
}

// AesDecrypt verifies the mac (when present) and decrypts.
func AesDecrypt(encType EncryptionType, iv, ct, mac []byte, key *SymmetricKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("no key provided for decryption")
	}
	if key.EncType != encType {
		return nil, fmt.Errorf("encryption type mismatch: key %d, data %d", key.EncType, encType)
	}
	if encType == AesCbc256_HmacSha256_B64 {
		if !hmac.Equal(mac, computeMac(key.MacKey, iv, ct)) {
			return nil, ErrMacMismatch
		}
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext")
	}
	block, err := aes.NewCipher(key.EncKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	return pkcs7Unpad(out)
}

// ---------- EncString ----------

// EncString is a parsed Bitwarden encrypted string ("2.iv|data|mac").
type EncString struct {
	Type EncryptionType
	IV   []byte
	Data []byte
	Mac  []byte
	raw  string
}

// ParseEncString parses the serialized format. Strings without a type prefix are treated as type 0 or 3
// depending on the number of parts (legacy behaviour).
func ParseEncString(s string) (*EncString, error) {
	if s == "" {
		return nil, errors.New("empty EncString")
	}
	e := &EncString{raw: s}
	headerPieces := strings.SplitN(s, ".", 2)
	var body string
	if len(headerPieces) == 2 {
		t, err := strconv.Atoi(headerPieces[0])
		if err != nil {
			return nil, fmt.Errorf("invalid EncString type: %w", err)
		}
		e.Type = EncryptionType(t)
		body = headerPieces[1]
	} else {
		body = s
		if len(strings.Split(s, "|")) == 3 {
			e.Type = AesCbc256_HmacSha256_B64
		} else {
			e.Type = AesCbc256_B64
		}
	}
	parts := strings.Split(body, "|")
	dec := func(p string) ([]byte, error) { return base64.StdEncoding.DecodeString(p) }
	var err error
	switch e.Type {
	case AesCbc256_B64:
		if len(parts) != 2 {
			return nil, errors.New("invalid EncString parts")
		}
		if e.IV, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if e.Data, err = dec(parts[1]); err != nil {
			return nil, err
		}
	case AesCbc256_HmacSha256_B64:
		if len(parts) != 3 {
			return nil, errors.New("invalid EncString parts")
		}
		if e.IV, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if e.Data, err = dec(parts[1]); err != nil {
			return nil, err
		}
		if e.Mac, err = dec(parts[2]); err != nil {
			return nil, err
		}
	case Rsa2048_OaepSha256_B64, Rsa2048_OaepSha1_B64, CoseEncrypt0:
		if len(parts) != 1 {
			return nil, errors.New("invalid EncString parts")
		}
		if e.Data, err = dec(parts[0]); err != nil {
			return nil, err
		}
	case Rsa2048_OaepSha256_HmacSha256_B64, Rsa2048_OaepSha1_HmacSha256_B64:
		if len(parts) != 2 {
			return nil, errors.New("invalid EncString parts")
		}
		if e.Data, err = dec(parts[0]); err != nil {
			return nil, err
		}
		if e.Mac, err = dec(parts[1]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported encryption type %d", e.Type)
	}
	return e, nil
}

// IsEncString reports whether s looks like a serialized EncString.
func IsEncString(s string) bool {
	_, err := ParseEncString(s)
	return err == nil && strings.Contains(s, ".")
}

// String serializes the EncString.
func (e *EncString) String() string {
	if e.raw != "" {
		return e.raw
	}
	b := base64.StdEncoding.EncodeToString
	switch e.Type {
	case AesCbc256_B64:
		return fmt.Sprintf("%d.%s|%s", e.Type, b(e.IV), b(e.Data))
	case AesCbc256_HmacSha256_B64:
		return fmt.Sprintf("%d.%s|%s|%s", e.Type, b(e.IV), b(e.Data), b(e.Mac))
	case Rsa2048_OaepSha256_HmacSha256_B64, Rsa2048_OaepSha1_HmacSha256_B64:
		return fmt.Sprintf("%d.%s|%s", e.Type, b(e.Data), b(e.Mac))
	default:
		return fmt.Sprintf("%d.%s", e.Type, b(e.Data))
	}
}

// Encrypt encrypts bytes into an EncString.
func Encrypt(plain []byte, key *SymmetricKey) (*EncString, error) {
	if key == nil {
		return nil, errors.New("no encryption key provided")
	}
	if key.IsCose() {
		return EncryptWithFormat(plain, key, ContentFormatOctetStream)
	}
	iv, ct, mac, err := AesEncrypt(plain, key)
	if err != nil {
		return nil, err
	}
	e := &EncString{Type: key.EncType, IV: iv, Data: ct, Mac: mac}
	e.raw = e.String()
	return e, nil
}

// EncryptString encrypts a UTF-8 string and returns the serialized EncString.
func EncryptString(plain string, key *SymmetricKey) (string, error) {
	e, err := EncryptWithFormat([]byte(plain), key, ContentFormatUtf8)
	if err != nil {
		return "", err
	}
	return e.String(), nil
}

// Decrypt decrypts a symmetric EncString.
func (e *EncString) Decrypt(key *SymmetricKey) ([]byte, error) {
	switch e.Type {
	case AesCbc256_B64, AesCbc256_HmacSha256_B64:
		return AesDecrypt(e.Type, e.IV, e.Data, e.Mac, key)
	case CoseEncrypt0:
		b, _, err := decryptCoseEncString(e.Data, key)
		return b, err
	default:
		return nil, fmt.Errorf("cannot symmetrically decrypt encryption type %d", e.Type)
	}
}

// DecryptString parses and decrypts a serialized EncString into a string.
func DecryptString(s string, key *SymmetricKey) (string, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return "", err
	}
	b, err := e.Decrypt(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecryptToKey decrypts an EncString that wraps a symmetric key (SDK unwrap_symmetric_key). Type 7
// EncStrings must declare the BitwardenLegacyKey or CoseKey content format; see WrapKey.
func DecryptToKey(s string, key *SymmetricKey) (*SymmetricKey, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	if e.Type == CoseEncrypt0 {
		return unwrapCoseKey(e.Data, key)
	}
	b, err := e.Decrypt(key)
	if err != nil {
		return nil, err
	}
	return NewSymmetricKey(b)
}

// ---------- EncArrayBuffer (binary attachments, session storage) ----------

// EncryptBytes encrypts binary data into the EncArrayBuffer layout: type|iv|mac|data.
// For COSE keys the layout is 0x07 || COSE_Encrypt0 (content format OctetStream), matching the
// SDK's EncString::to_buffer.
func EncryptBytes(plain []byte, key *SymmetricKey) ([]byte, error) {
	if key != nil && key.IsCose() {
		e, err := EncryptWithFormat(plain, key, ContentFormatOctetStream)
		if err != nil {
			return nil, err
		}
		return append([]byte{byte(CoseEncrypt0)}, e.Data...), nil
	}
	iv, ct, mac, err := AesEncrypt(plain, key)
	if err != nil {
		return nil, err
	}
	out := []byte{byte(key.EncType)}
	out = append(out, iv...)
	out = append(out, mac...)
	return append(out, ct...), nil
}

// DecryptBytes decrypts the EncArrayBuffer layout.
func DecryptBytes(buf []byte, key *SymmetricKey) ([]byte, error) {
	if len(buf) < 1 {
		return nil, errors.New("Error parsing encrypted ArrayBuffer: data is corrupted or has an invalid format.")
	}
	t := EncryptionType(buf[0])
	switch t {
	case AesCbc256_HmacSha256_B64:
		if len(buf) < 1+16+32+1 {
			return nil, errors.New("Error parsing encrypted ArrayBuffer: data is corrupted or has an invalid format.")
		}
		return AesDecrypt(t, buf[1:17], buf[49:], buf[17:49], key)
	case AesCbc256_B64:
		if len(buf) < 1+16+1 {
			return nil, errors.New("Error parsing encrypted ArrayBuffer: data is corrupted or has an invalid format.")
		}
		return AesDecrypt(t, buf[1:17], buf[17:], nil, key)
	case CoseEncrypt0:
		if len(buf) < 2 {
			return nil, errors.New("Error parsing encrypted ArrayBuffer: data is corrupted or has an invalid format.")
		}
		b, _, err := decryptCoseEncString(buf[1:], key)
		return b, err
	default:
		return nil, errors.New("Error parsing encrypted ArrayBuffer: data is corrupted or has an invalid format.")
	}
}

// ---------- RSA ----------

// ParsePrivateKey parses a PKCS8 DER RSA private key.
func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// ParsePublicKey parses a SPKI DER RSA public key.
func ParsePublicKey(der []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rk, nil
}

// RsaDecrypt decrypts an asymmetric EncString with the private key.
func RsaDecrypt(s string, priv *rsa.PrivateKey) ([]byte, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return nil, err
	}
	switch e.Type {
	case Rsa2048_OaepSha256_B64, Rsa2048_OaepSha256_HmacSha256_B64:
		return rsa.DecryptOAEP(sha256.New(), nil, priv, e.Data, nil)
	case Rsa2048_OaepSha1_B64, Rsa2048_OaepSha1_HmacSha256_B64:
		return rsa.DecryptOAEP(sha1.New(), nil, priv, e.Data, nil)
	default:
		return nil, fmt.Errorf("cannot asymmetrically decrypt encryption type %d", e.Type)
	}
}

// RsaEncrypt encrypts data for the public key using RSA-OAEP-SHA1 (type 4).
func RsaEncrypt(data []byte, pub *rsa.PublicKey) (string, error) {
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return "", err
	}
	return (&EncString{Type: Rsa2048_OaepSha1_B64, Data: ct}).String(), nil
}

// SHA256 returns the SHA-256 digest of data.
func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
