package sshkey

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/blowfish"
)

// bcryptPBKDF is bcrypt_pbkdf (OpenBSD's bcrypt_pbkdf.c, as in the bcrypt-pbkdf 0.11 crate),
// used to derive the key and IV of encrypted OpenSSH private keys.
func bcryptPBKDF(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	const blockSize = 32
	if len(password) == 0 || len(salt) == 0 {
		return nil, errors.New("bcrypt_pbkdf: invalid parameter length")
	}
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: invalid rounds")
	}
	if keyLen == 0 || keyLen > blockSize*blockSize {
		return nil, errors.New("bcrypt_pbkdf: invalid output length")
	}
	numBlocks := (keyLen + blockSize - 1) / blockSize
	key := make([]byte, numBlocks*blockSize)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	var cnt [4]byte
	tmp := make([]byte, blockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0], cnt[1], cnt[2], cnt[3] = byte(block>>24), byte(block>>16), byte(block>>8), byte(block)
		h.Write(cnt[:])
		bcryptHash(tmp, shapass, h.Sum(nil))

		out := make([]byte, blockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			bcryptHash(tmp, shapass, h.Sum(nil))
			for j := range out {
				out[j] ^= tmp[j]
			}
		}
		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

var bcryptMagic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapass, shasalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, bcryptMagic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
