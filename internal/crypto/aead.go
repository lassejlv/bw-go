package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Low-level AEAD primitives used as COSE content-encryption algorithms (SDK hazmat module).

var errAeadDecrypt = errors.New("decryption failed: key, nonce or data is invalid")

// aeadNonceSize returns the nonce size for a COSE content-encryption algorithm.
func aeadNonceSize(alg int64) (int, error) {
	switch alg {
	case coseAlgXChaCha20Poly1305, coseAlgXAes256Gcm:
		return 24, nil
	case coseAlgA256GCM:
		return 12, nil
	case coseAlgAes256CbcHmacAead:
		return 16, nil
	}
	return 0, fmt.Errorf("unsupported COSE content encryption algorithm %d", alg)
}

// aeadKeySize returns the CEK size for a COSE content-encryption algorithm.
func aeadKeySize(alg int64) int {
	if alg == coseAlgAes256CbcHmacAead {
		return 64
	}
	return 32
}

func aeadSeal(alg int64, key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(key) != aeadKeySize(alg) {
		return nil, errors.New("invalid key length")
	}
	switch alg {
	case coseAlgAes256CbcHmacAead:
		return cbcHmacAeadSeal(key, nonce, plaintext, aad)
	}
	a, n, err := newAEAD(alg, key, nonce)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, n, plaintext, aad), nil
}

func aeadOpen(alg int64, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != aeadKeySize(alg) {
		return nil, errors.New("invalid key length")
	}
	switch alg {
	case coseAlgAes256CbcHmacAead:
		return cbcHmacAeadOpen(key, nonce, ciphertext, aad)
	}
	a, n, err := newAEAD(alg, key, nonce)
	if err != nil {
		return nil, err
	}
	out, err := a.Open(nil, n, ciphertext, aad)
	if err != nil {
		return nil, errAeadDecrypt
	}
	return out, nil
}

// newAEAD returns the AEAD and the nonce to pass to it (XAES consumes the first 12 nonce bytes in
// its key derivation).
func newAEAD(alg int64, key, nonce []byte) (cipher.AEAD, []byte, error) {
	size, err := aeadNonceSize(alg)
	if err != nil {
		return nil, nil, err
	}
	if len(nonce) != size {
		return nil, nil, errors.New("invalid nonce length")
	}
	switch alg {
	case coseAlgXChaCha20Poly1305:
		a, err := chacha20poly1305.NewX(key)
		return a, nonce, err
	case coseAlgA256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		a, err := cipher.NewGCM(block)
		return a, nonce, err
	case coseAlgXAes256Gcm:
		a, err := xaesDerive(key, nonce)
		return a, nonce[12:], err
	}
	return nil, nil, fmt.Errorf("unsupported COSE content encryption algorithm %d", alg)
}

// xaesDerive implements the XAES-256-GCM key derivation (https://c2sp.org/XAES-256-GCM): an
// SP 800-108r1 counter-mode KDF with CMAC-AES256 keyed with the input key over the first 96 bits
// of the 192-bit nonce. The returned AES-256-GCM AEAD must be used with the last 96 nonce bits.
func xaesDerive(key, nonce []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var l, k1 [16]byte
	block.Encrypt(l[:], l[:])
	for i := 0; i < 15; i++ {
		k1[i] = l[i]<<1 | l[i+1]>>7
	}
	k1[15] = l[15] << 1
	if l[0]&0x80 != 0 {
		k1[15] ^= 0x87
	}
	derived := make([]byte, 32)
	for i, counter := range []byte{1, 2} {
		var m [16]byte
		m[1], m[2] = counter, 'X'
		copy(m[4:], nonce[:12])
		for j := range m {
			m[j] ^= k1[j]
		}
		block.Encrypt(derived[i*16:(i+1)*16], m[:])
	}
	dblock, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(dblock)
}

// AES-256-CBC-HMAC-SHA256 used as an Encrypt-then-MAC AEAD (COSE alg -70011). The MAC covers
// "bitwarden.aes256-cbc-hmac-sha256-aead.v1" || iv || be64(len(ct)) || ct || be64(len(aad)) || aad.
const cbcHmacAeadDomain = "bitwarden.aes256-cbc-hmac-sha256-aead.v1"

func cbcHmacAeadMac(macKey, iv, ct, aad []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte(cbcHmacAeadDomain))
	m.Write(iv)
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(ct))))
	m.Write(ct)
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(aad))))
	m.Write(aad)
	return m.Sum(nil)
}

func cbcHmacAeadSeal(key, iv, plaintext, aad []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("invalid nonce length")
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append(ct, cbcHmacAeadMac(key[32:], iv, ct, aad)...), nil
}

func cbcHmacAeadOpen(key, iv, data, aad []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("invalid nonce length")
	}
	if len(data) < 32 {
		return nil, errAeadDecrypt
	}
	ct, mac := data[:len(data)-32], data[len(data)-32:]
	if !hmac.Equal(mac, cbcHmacAeadMac(key[32:], iv, ct, aad)) {
		return nil, errAeadDecrypt
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errAeadDecrypt
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pt, err := pkcs7Unpad(out)
	if err != nil {
		return nil, errAeadDecrypt
	}
	return pt, nil
}

// padBytes implements the SDK's PKCS7-like padding (keys/utils.rs pad_bytes): pads to at least
// minLength with at least one byte; each padding byte holds the padding length (max 255).
func padBytes(b []byte, minLength int) ([]byte, error) {
	pad := max(minLength-len(b), 1)
	if pad > 255 {
		return nil, errors.New("invalid padding")
	}
	out := make([]byte, len(b), len(b)+pad)
	copy(out, b)
	for i := 0; i < pad; i++ {
		out = append(out, byte(pad))
	}
	return out, nil
}

// unpadBytes reverses padBytes. Like the SDK it only checks the last byte.
func unpadBytes(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("invalid padding")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > len(b) {
		return nil, errors.New("invalid padding")
	}
	return b[:len(b)-n], nil
}
