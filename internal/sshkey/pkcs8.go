package sshkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// --- Encrypted PKCS#8 (pkcs8::EncryptedPrivateKeyInfo + pkcs5 0.8 PBES2) ---

// decryptEncryptedPrivateKeyInfo returns the decrypted PrivateKeyInfo document. Errors are
// ErrWrongPassword for pkcs5::Error::DecryptFailed and ErrParsing for everything else, like
// import.rs parse_pkcs8_pem.
func decryptEncryptedPrivateKeyInfo(der []byte, password []byte) ([]byte, error) {
	seq, err := parseSequence(der)
	if err != nil {
		return nil, ErrParsing
	}
	alg, err := seq.algorithmIdentifier()
	if err != nil {
		return nil, ErrParsing
	}
	ciphertext, err := seq.expect(tagOctetString)
	if err != nil || !seq.finished() {
		return nil, ErrParsing
	}
	// Only PBES2 can decrypt (PBES1 is parse-only upstream; PKCS#12 PBE OIDs are unknown).
	if !oidEqual(alg.oid, oidPBES2) || alg.params == nil {
		return nil, ErrParsing
	}
	p, err := parsePBES2Params(alg.params)
	if err != nil {
		return nil, ErrParsing
	}
	key, err := p.deriveKey(password)
	if err != nil {
		return nil, ErrParsing
	}
	plain, err := p.decrypt(key, ciphertext)
	if err != nil {
		return nil, ErrWrongPassword
	}
	// from_pkcs8_der on the plaintext: it must be a PrivateKeyInfo.
	if _, err := parsePrivateKeyInfo(plain); err != nil {
		return nil, ErrParsing
	}
	return plain, nil
}

type pbes2Params struct {
	// KDF
	scrypt     bool
	salt       []byte
	iterations uint64
	keyLength  int // 0 = absent
	prf        func() hash.Hash
	prfSHA1    bool
	cost       uint64
	blockSize  uint64
	parallel   uint64
	// encryption scheme
	gcm     bool
	keySize int
	iv      []byte
}

func parsePBES2Params(params []byte) (*pbes2Params, error) {
	seq, err := parseSequence(params)
	if err != nil {
		return nil, err
	}
	kdf, err := seq.algorithmIdentifier()
	if err != nil {
		return nil, err
	}
	enc, err := seq.algorithmIdentifier()
	if err != nil || !seq.finished() {
		return nil, errDER
	}
	p := &pbes2Params{}
	if kdf.params == nil {
		return nil, errDER
	}
	kp, err := parseSequence(kdf.params)
	if err != nil {
		return nil, err
	}
	saltParam := func() error {
		salt, err := kp.expect(tagOctetString)
		if err != nil || len(salt) > 32 { // pkcs5 Salt::MAX_LEN
			return errDER
		}
		p.salt = salt
		return nil
	}
	keyLengthParam := func() error {
		if t, ok := kp.peekTag(); ok && t == tagInteger {
			v, err := kp.smallUint(16)
			if err != nil {
				return err
			}
			p.keyLength = int(v)
			if p.keyLength == 0 {
				p.keyLength = -1 // present but zero: never matches a key size
			}
		}
		return nil
	}
	switch {
	case oidEqual(kdf.oid, oidPBKDF2):
		if err := saltParam(); err != nil {
			return nil, err
		}
		if p.iterations, err = kp.smallUint(32); err != nil {
			return nil, err
		}
		if err := keyLengthParam(); err != nil {
			return nil, err
		}
		p.prfSHA1 = true // DEFAULT algid-hmacWithSHA1
		if !kp.finished() {
			prf, err := kp.algorithmIdentifier()
			if err != nil {
				return nil, err
			}
			if prf.params != nil && !bytes.Equal(prf.params, derNullEncoding) {
				return nil, errDER
			}
			p.prfSHA1 = false
			switch {
			case oidEqual(prf.oid, oidHmacSHA1):
				p.prfSHA1 = true
			case oidEqual(prf.oid, oidHmacSHA224):
				p.prf = sha256.New224
			case oidEqual(prf.oid, oidHmacSHA256):
				p.prf = sha256.New
			case oidEqual(prf.oid, oidHmacSHA384):
				p.prf = sha512.New384
			case oidEqual(prf.oid, oidHmacSHA512):
				p.prf = sha512.New
			default:
				return nil, errDER
			}
		}
	case oidEqual(kdf.oid, oidScrypt):
		p.scrypt = true
		if err := saltParam(); err != nil {
			return nil, err
		}
		if p.cost, err = kp.smallUint(64); err != nil {
			return nil, err
		}
		if p.blockSize, err = kp.smallUint(16); err != nil {
			return nil, err
		}
		if p.parallel, err = kp.smallUint(16); err != nil {
			return nil, err
		}
		if err := keyLengthParam(); err != nil {
			return nil, err
		}
	default:
		return nil, errDER
	}
	if !kp.finished() {
		return nil, errDER
	}

	if enc.params == nil {
		return nil, errDER
	}
	el, rest, err := readDER(enc.params)
	if err != nil || el.tag != tagOctetString || len(rest) != 0 {
		return nil, errDER
	}
	p.iv = el.content
	ivLen := 16
	switch {
	case oidEqual(enc.oid, oidAES128CBC):
		p.keySize = 16
	case oidEqual(enc.oid, oidAES192CBC):
		p.keySize = 24
	case oidEqual(enc.oid, oidAES256CBC):
		p.keySize = 32
	case oidEqual(enc.oid, oidAES128GCM):
		p.keySize, p.gcm, ivLen = 16, true, 12
	case oidEqual(enc.oid, oidAES256GCM):
		p.keySize, p.gcm, ivLen = 32, true, 12
	default:
		return nil, errDER // DES / 3DES are not enabled in the SDK build
	}
	if len(p.iv) != ivLen {
		return nil, errDER
	}
	return p, nil
}

func (p *pbes2Params) deriveKey(password []byte) ([]byte, error) {
	if p.keyLength != 0 && p.keyLength != p.keySize {
		return nil, errDER
	}
	if p.scrypt {
		if p.cost < 2 || p.cost&(p.cost-1) != 0 {
			return nil, errDER
		}
		logN := bits.TrailingZeros64(p.cost)
		if logN >= 64 || p.blockSize == 0 || p.parallel == 0 {
			return nil, errDER
		}
		key, err := scrypt.Key(password, p.salt, int(p.cost), int(p.blockSize), int(p.parallel), p.keySize)
		if err != nil {
			return nil, errDER
		}
		return key, nil
	}
	if p.prfSHA1 {
		// The SDK is built without pkcs5's "sha1-insecure" feature.
		return nil, errDER
	}
	if p.iterations == 0 {
		return nil, errDER
	}
	return pbkdf2.Key(password, p.salt, int(p.iterations), p.keySize, p.prf), nil
}

func (p *pbes2Params) decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if p.gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(ciphertext) < aead.Overhead() {
			return nil, errDER
		}
		return aead.Open(nil, p.iv, ciphertext, nil)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errDER
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, p.iv).CryptBlocks(out, ciphertext)
	n := int(out[len(out)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, errDER
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			return nil, errDER
		}
	}
	return out[:len(out)-n], nil
}

// --- PrivateKeyInfo → SSH keypair ---

// ed25519FromPKCS8 is ed25519::KeypairBytes::try_from(PrivateKeyInfo) followed by
// Ed25519Keypair::from(&secret_key): the public key is always derived from the seed.
func ed25519FromPKCS8(info *privateKeyInfo) (*keypair, error) {
	if info.algorithm.params != nil {
		return nil, errDER
	}
	pk := info.privateKey
	if len(pk) != 34 || pk[0] != 0x04 || pk[1] != 0x20 {
		return nil, errDER
	}
	if info.publicKey != nil && info.publicKey[0] == 0 && len(info.publicKey)-1 != 32 {
		return nil, errDER
	}
	return ed25519Keypair(pk[2:]), nil
}

func ed25519Keypair(seed []byte) *keypair {
	priv := ed25519.NewKeyFromSeed(seed)
	kp := &keypair{kind: kindEd25519, alg: algEd25519}
	copy(kp.edSeed[:], seed)
	copy(kp.edPub[:], priv[32:])
	return kp
}

// rsaFromPKCS8 is rsa::RsaPrivateKey::try_from(PrivateKeyInfo) (PKCS#1 parsing and
// RsaPrivateKey::from_components validation) followed by ssh-key's RsaKeypair::try_from.
func rsaFromPKCS8(info *privateKeyInfo) (*keypair, error) {
	if !bytes.Equal(info.algorithm.params, derNullEncoding) {
		return nil, errDER
	}
	seq, err := parseSequence(info.privateKey)
	if err != nil {
		return nil, err
	}
	version, err := seq.smallUint(8)
	if err != nil || version > 1 {
		return nil, errDER
	}
	var parts [8][]byte // n, e, d, p, q, dp, dq, qinv
	for i := range parts {
		if parts[i], err = seq.uint(); err != nil {
			return nil, err
		}
	}
	if !seq.finished() {
		if _, err := seq.sequence(); err != nil || !seq.finished() { // otherPrimeInfos
			return nil, errDER
		}
		if version != 1 {
			return nil, errDER
		}
	}
	if version != 0 { // multi-prime keys are not supported
		return nil, errDER
	}
	nBytes := len(parts[0])
	for _, i := range []int{2, 3, 4} { // d, p, q must fit the modulus precision
		if len(parts[i]) > nBytes {
			return nil, errDER
		}
	}
	n := new(big.Int).SetBytes(parts[0])
	e := new(big.Int).SetBytes(parts[1])
	d := new(big.Int).SetBytes(parts[2])
	p := new(big.Int).SetBytes(parts[3])
	q := new(big.Int).SetBytes(parts[4])
	one := big.NewInt(1)
	if len(parts[1]) == 0 || e.Sign() == 0 { // Option::from(e) for a zero-width exponent
		return nil, errDER
	}
	if n.Bit(0) == 0 || n.Sign() == 0 {
		return nil, errDER
	}
	if new(big.Int).Mul(p, q).Cmp(n) != 0 {
		return nil, errDER
	}
	// validate(): check_public + validate_private_key_parts
	if e.Cmp(n) >= 0 || e.Bit(0) == 0 || e.Cmp(big.NewInt(2)) < 0 || e.Cmp(big.NewInt(1<<33-1)) > 0 {
		return nil, errDER
	}
	if p.Cmp(one) <= 0 || q.Cmp(one) <= 0 {
		return nil, errDER
	}
	de := new(big.Int).Mul(d, e)
	for _, prime := range []*big.Int{p, q} {
		if new(big.Int).Mod(de, new(big.Int).Sub(prime, one)).Cmp(one) != 0 {
			return nil, errDER
		}
	}
	// precompute(): the CRT coefficient q^-1 mod p (missing → Error::Crypto in ssh-key).
	if p.Bit(0) == 0 || q.Bit(0) == 0 {
		return nil, errDER
	}
	iqmp := new(big.Int).ModInverse(new(big.Int).Mod(q, p), p)
	if iqmp == nil {
		return nil, errDER
	}
	return &keypair{
		kind: kindRSA, alg: algRSA,
		rsaN: mpintFromBig(n), rsaE: mpintFromBig(e), rsaD: mpintFromBig(d),
		rsaIQMP: mpintFromBig(iqmp), rsaP: mpintFromBig(p), rsaQ: mpintFromBig(q),
	}, nil
}

type ecCurve struct {
	name  string // ssh curve id
	oid   []byte
	size  int
	curve ecdh.Curve
}

var ecCurves = []ecCurve{
	{"nistp256", oidP256, 32, ecdh.P256()},
	{"nistp384", oidP384, 48, ecdh.P384()},
	{"nistp521", oidP521, 66, ecdh.P521()},
}

// ecdsaFromPKCS8 is import.rs import_ecdsa_pkcs8_der: try P-256, P-384 and P-521
// SecretKey::from_pkcs8_der in turn; UnsupportedKeyType when none of them accepts the key.
func ecdsaFromPKCS8(info *privateKeyInfo) (*keypair, error) {
	for _, c := range ecCurves {
		if kp, err := ecSecretKeyFromPKCS8(info, c); err == nil {
			return kp, nil
		}
	}
	return nil, ErrUnsupportedKeyType
}

func ecSecretKeyFromPKCS8(info *privateKeyInfo, c ecCurve) (*keypair, error) {
	// assert_oids(id-ecPublicKey, curve OID)
	el, rest, err := readDER(info.algorithm.params)
	if err != nil || el.tag != tagOID || len(rest) != 0 || !oidEqual(el.content, c.oid) {
		return nil, errDER
	}
	// SEC1 ECPrivateKey
	seq, err := parseSequence(info.privateKey)
	if err != nil {
		return nil, err
	}
	if v, err := seq.smallUint(8); err != nil || v != 1 {
		return nil, errDER
	}
	secret, err := seq.expect(tagOctetString)
	if err != nil {
		return nil, err
	}
	if params, ok, err := seq.optional(0xa0); err != nil {
		return nil, err
	} else if ok {
		el, rest, err := readDER(params)
		if err != nil || el.tag != tagOID || len(rest) != 0 {
			return nil, errDER
		}
		if !oidEqual(el.content, c.oid) {
			return nil, errDER
		}
	}
	pubWrapped, hasPub, err := seq.optional(0xa1)
	if err != nil || !seq.finished() {
		return nil, errDER
	}
	// SecretKey::from_slice: exact size, or MIN_SIZE (24) ..< size bytes left-padded.
	if len(secret) > c.size || len(secret) < 24 {
		return nil, errDER
	}
	scalar := make([]byte, c.size)
	copy(scalar[c.size-len(secret):], secret)
	priv, err := c.curve.NewPrivateKey(scalar)
	if err != nil {
		return nil, errDER
	}
	point := priv.PublicKey().Bytes() // uncompressed SEC1
	if hasPub {
		el, rest, err := readDER(pubWrapped)
		if err != nil || el.tag != tagBitString || len(rest) != 0 || len(el.content) < 1 || el.content[0] != 0 {
			return nil, errDER
		}
		if !sameECPoint(c, el.content[1:], point) {
			return nil, errDER
		}
	}
	return &keypair{kind: kindECDSA, alg: "ecdsa-sha2-" + c.name, curve: c.name, ecPoint: point, ecPriv: scalar}, nil
}

// sameECPoint compares a SEC1 encoded point (compressed or uncompressed) with the derived
// uncompressed point.
func sameECPoint(c ecCurve, encoded, uncompressed []byte) bool {
	switch {
	case len(encoded) == 1+2*c.size && encoded[0] == 0x04:
		return bytes.Equal(encoded, uncompressed)
	case len(encoded) == 1+c.size && (encoded[0] == 0x02 || encoded[0] == 0x03):
		x := uncompressed[1 : 1+c.size]
		yOdd := uncompressed[len(uncompressed)-1]&1 == 1
		return bytes.Equal(encoded[1:], x) && (encoded[0] == 0x03) == yOdd
	}
	return false
}
