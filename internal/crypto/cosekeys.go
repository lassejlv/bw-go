package crypto

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// SymmetricKeyAlgorithm identifies the algorithm of a SymmetricKey (SDK SymmetricKeyAlgorithm).
type SymmetricKeyAlgorithm int

const (
	// AlgUnknown is the zero value; KeyAlgorithm() derives legacy algorithms from EncType.
	AlgUnknown SymmetricKeyAlgorithm = iota
	// AlgAes256Cbc is the deprecated, unauthenticated 32 byte AES-256-CBC key (EncType 0).
	AlgAes256Cbc
	// AlgAes256CbcHmac is the v1 64 byte AES-256-CBC + HMAC-SHA256 key (EncType 2).
	AlgAes256CbcHmac
	// AlgXChaCha20Poly1305 is a COSE key (alg -70000) producing type 7 EncStrings.
	AlgXChaCha20Poly1305
	// AlgAes256Gcm is a COSE key (alg A256GCM = 3); only used as DataEnvelope content-encryption key.
	AlgAes256Gcm
	// AlgXAes256Gcm is a COSE key (alg -70010); the v2 user key algorithm, producing type 7 EncStrings.
	AlgXAes256Gcm
)

func (a SymmetricKeyAlgorithm) String() string {
	switch a {
	case AlgAes256Cbc:
		return "AES-256-CBC"
	case AlgAes256CbcHmac:
		return "AES-256-CBC-HMAC-SHA256"
	case AlgXChaCha20Poly1305:
		return "XChaCha20-Poly1305"
	case AlgAes256Gcm:
		return "AES-256-GCM"
	case AlgXAes256Gcm:
		return "XAES-256-GCM"
	}
	return "unknown"
}

func (a SymmetricKeyAlgorithm) coseAlg() (int64, bool) {
	switch a {
	case AlgXChaCha20Poly1305:
		return coseAlgXChaCha20Poly1305, true
	case AlgAes256Gcm:
		return coseAlgA256GCM, true
	case AlgXAes256Gcm:
		return coseAlgXAes256Gcm, true
	}
	return 0, false
}

func algFromCose(alg int64) (SymmetricKeyAlgorithm, bool) {
	switch alg {
	case coseAlgXChaCha20Poly1305:
		return AlgXChaCha20Poly1305, true
	case coseAlgA256GCM:
		return AlgAes256Gcm, true
	case coseAlgXAes256Gcm:
		return AlgXAes256Gcm, true
	case coseAlgAes256CbcHmacAead:
		return AlgAes256CbcHmac, true
	}
	return AlgUnknown, false
}

// defaultKeyOps are the operations of freshly generated COSE keys (SDK make()).
var defaultKeyOps = []KeyOperation{KeyOpDecrypt, KeyOpEncrypt, KeyOpWrapKey, KeyOpUnwrapKey}

// KeyAlgorithm returns the algorithm of the key, deriving it from EncType for legacy keys.
func (k *SymmetricKey) KeyAlgorithm() SymmetricKeyAlgorithm {
	switch k.EncType {
	case AesCbc256_B64:
		return AlgAes256Cbc
	case AesCbc256_HmacSha256_B64:
		return AlgAes256CbcHmac
	case CoseEncrypt0:
		return k.Algorithm
	}
	return AlgUnknown
}

// IsCose reports whether k is a v2 COSE key (XChaCha20-Poly1305, AES-256-GCM or XAES-256-GCM).
func (k *SymmetricKey) IsCose() bool { return k != nil && k.EncType == CoseEncrypt0 }

// AllowsOp reports whether a COSE key allows the given operation (legacy keys allow everything).
func (k *SymmetricKey) AllowsOp(op KeyOperation) bool {
	if !k.IsCose() {
		return true
	}
	return slices.Contains(k.KeyOps, op)
}

// GenerateKeyFor creates a new random key for the algorithm (SDK SymmetricCryptoKey::make).
// AlgAes256CbcHmac is equivalent to GenerateKey(). COSE keys get a random 16 byte key id and the
// operations Decrypt, Encrypt, WrapKey and UnwrapKey.
func GenerateKeyFor(alg SymmetricKeyAlgorithm) (*SymmetricKey, error) {
	switch alg {
	case AlgAes256CbcHmac:
		return GenerateKey(), nil
	case AlgXChaCha20Poly1305, AlgAes256Gcm, AlgXAes256Gcm:
		return &SymmetricKey{
			EncKey:    RandomBytes(32),
			EncType:   CoseEncrypt0,
			Algorithm: alg,
			KeyID:     RandomBytes(16),
			KeyOps:    slices.Clone(defaultKeyOps),
		}, nil
	}
	return nil, fmt.Errorf("cannot generate key for algorithm %s", alg)
}

// CoseKeyBytes returns the unpadded COSE_Key serialization of a COSE key (nil for legacy keys).
// This is the plaintext of a key wrapped with the CoseKey content format.
func (k *SymmetricKey) CoseKeyBytes() []byte {
	alg, ok := k.Algorithm.coseAlg()
	if !k.IsCose() || !ok {
		return nil
	}
	ops := make([]int64, len(k.KeyOps))
	for i, op := range k.KeyOps {
		ops[i] = int64(op)
	}
	ck := &coseKey{
		Kty: coseKtySymmetric, KeyID: k.KeyID, HasAlg: true, Alg: alg, KeyOps: ops,
		Params: cborMap{{int64(-1), k.EncKey}},
	}
	return ck.encode()
}

// ParseCoseSymmetricKey parses an unpadded COSE_Key into a SymmetricKey (SDK
// TryFrom<&CoseKey> for SymmetricCryptoKey). Supported algorithms are XChaCha20-Poly1305 (-70000),
// XAES-256-GCM (-70010) and A256GCM (3); the key must be 32 bytes, the key id 16 bytes and the
// key_ops limited to encrypt/decrypt/wrapKey/unwrapKey.
func ParseCoseSymmetricKey(b []byte) (*SymmetricKey, error) {
	ck, err := parseCoseKey(b)
	if err != nil {
		return nil, errors.New("invalid key")
	}
	kb, ok := ck.bytesParam(-1)
	if !ok || !ck.HasAlg {
		return nil, errors.New("invalid key")
	}
	ops := make([]KeyOperation, 0, len(ck.KeyOps))
	for _, op := range sortedUniqueOps(ck.KeyOps) {
		switch KeyOperation(op) {
		case KeyOpEncrypt, KeyOpDecrypt, KeyOpWrapKey, KeyOpUnwrapKey:
			ops = append(ops, KeyOperation(op))
		default:
			return nil, errors.New("invalid key: unsupported key operation")
		}
	}
	var alg SymmetricKeyAlgorithm
	switch ck.Alg {
	case coseAlgXChaCha20Poly1305:
		alg = AlgXChaCha20Poly1305
	case coseAlgXAes256Gcm:
		alg = AlgXAes256Gcm
	case coseAlgA256GCM:
		alg = AlgAes256Gcm
	default:
		return nil, errors.New("invalid key: unsupported algorithm")
	}
	if len(kb) != 32 || len(ck.KeyID) != 16 {
		return nil, errors.New("invalid key")
	}
	return &SymmetricKey{EncKey: clone(kb), EncType: CoseEncrypt0, Algorithm: alg, KeyID: clone(ck.KeyID), KeyOps: ops}, nil
}

// Thumbprint returns the RFC 9679 SHA-256 COSE key thumbprint ({kty: Symmetric, k: key bytes}; for
// AES-256-CBC-HMAC keys k is the 64 byte enc||mac key). AES-256-CBC keys have no thumbprint.
func (k *SymmetricKey) Thumbprint() ([]byte, error) {
	var material []byte
	switch k.KeyAlgorithm() {
	case AlgAes256CbcHmac:
		material = append(clone(k.EncKey), k.MacKey...)
	case AlgXChaCha20Poly1305, AlgAes256Gcm, AlgXAes256Gcm:
		material = k.EncKey
	default:
		return nil, errors.New("unauthenticated AES-CBC keys are not COSE keys and have no thumbprint")
	}
	return coseThumbprint(cborMap{{coseKeyKty, coseKtySymmetric}, {int64(-1), material}}), nil
}

// ID returns the key id (SDK SymmetricCryptoKey::key_id): the COSE key id for COSE keys, the first
// 16 bytes of the thumbprint for AES-256-CBC-HMAC keys, nil for AES-256-CBC keys.
func (k *SymmetricKey) ID() []byte {
	if k.IsCose() {
		return clone(k.KeyID)
	}
	tp, err := k.Thumbprint()
	if err != nil {
		return nil
	}
	return tp[:16]
}

// IDHex returns ID() as the lowercase hex string used on the wire ("" when there is no id).
func (k *SymmetricKey) IDHex() string {
	if id := k.ID(); id != nil {
		return hex.EncodeToString(id)
	}
	return ""
}

// ---------- type 7 EncStrings ----------

// EncryptWithFormat encrypts plain into an EncString. Legacy keys produce type 2 (or 0) EncStrings
// and ignore cf; XChaCha20-Poly1305 and XAES-256-GCM keys produce type 7 COSE_Encrypt0 EncStrings
// with cf in the protected header (Utf8 content is padded to 32 byte blocks). AES-256-GCM keys
// cannot encrypt EncStrings (as in the SDK). COSE keys must allow the Encrypt operation.
func EncryptWithFormat(plain []byte, key *SymmetricKey, cf ContentFormat) (*EncString, error) {
	if key == nil {
		return nil, errors.New("no encryption key provided")
	}
	if !key.IsCose() {
		return Encrypt(plain, key)
	}
	alg, ok := key.Algorithm.coseAlg()
	if !ok || key.Algorithm == AlgAes256Gcm {
		return nil, fmt.Errorf("encryption not implemented for %s keys", key.Algorithm)
	}
	if !key.AllowsOp(KeyOpEncrypt) {
		return nil, errors.New("key operation Encrypt not supported by key")
	}
	ct, err := cf.headerValue()
	if err != nil {
		return nil, err
	}
	msg, err := coseEncrypt0Seal(alg, key.EncKey, &coseHeader{ContentType: ct, KeyID: clone(key.KeyID)}, plain)
	if err != nil {
		return nil, err
	}
	e := &EncString{Type: CoseEncrypt0, Data: msg.encode()}
	e.raw = e.String()
	return e, nil
}

// decryptCoseEncString decrypts the COSE_Encrypt0 bytes of a type 7 EncString (SDK
// decrypt_xchacha20_poly1305 / decrypt_xaes256_gcm).
func decryptCoseEncString(data []byte, key *SymmetricKey) ([]byte, ContentFormat, error) {
	if key == nil {
		return nil, ContentFormatUnknown, errors.New("no key provided for decryption")
	}
	if !key.IsCose() || (key.Algorithm != AlgXChaCha20Poly1305 && key.Algorithm != AlgXAes256Gcm) {
		return nil, ContentFormatUnknown, fmt.Errorf("encryption type mismatch: key %d cannot decrypt type 7", key.EncType)
	}
	alg, _ := key.Algorithm.coseAlg()
	msg, err := parseCoseEncrypt0(data)
	if err != nil {
		return nil, ContentFormatUnknown, err
	}
	if !msg.Protected.HasAlg {
		return nil, ContentFormatUnknown, errors.New("COSE message is missing the algorithm")
	}
	if msg.Protected.Alg != alg {
		return nil, ContentFormatUnknown, errors.New("wrong key type for COSE message algorithm")
	}
	cf, err := contentFormatFromHeader(msg.Protected)
	if err != nil {
		return nil, ContentFormatUnknown, err
	}
	if !bytes.Equal(msg.Protected.KeyID, key.KeyID) {
		return nil, ContentFormatUnknown, errors.New("wrong COSE key id")
	}
	pt, err := coseEncrypt0Open(msg, alg, key.EncKey)
	if err != nil {
		return nil, ContentFormatUnknown, err
	}
	return pt, cf, nil
}

// DecryptWithFormat decrypts the EncString and also returns its content format
// (ContentFormatUnknown for legacy types).
func (e *EncString) DecryptWithFormat(key *SymmetricKey) ([]byte, ContentFormat, error) {
	if e.Type == CoseEncrypt0 {
		return decryptCoseEncString(e.Data, key)
	}
	b, err := e.Decrypt(key)
	return b, ContentFormatUnknown, err
}

// KeyID returns the id of the key a type 7 EncString was encrypted with (nil otherwise).
func (e *EncString) KeyID() []byte {
	if e.Type != CoseEncrypt0 {
		return nil
	}
	msg, err := parseCoseEncrypt0(e.Data)
	if err != nil || len(msg.Protected.KeyID) != 16 {
		return nil
	}
	return msg.Protected.KeyID
}

// KeyAlgorithm returns the algorithm of the key the EncString was encrypted with (AlgUnknown for
// type 0 or unparseable COSE).
func (e *EncString) KeyAlgorithm() SymmetricKeyAlgorithm {
	switch e.Type {
	case AesCbc256_HmacSha256_B64:
		return AlgAes256CbcHmac
	case CoseEncrypt0:
		msg, err := parseCoseEncrypt0(e.Data)
		if err != nil || !msg.Protected.HasAlg {
			return AlgUnknown
		}
		a, _ := algFromCose(msg.Protected.Alg)
		return a
	}
	return AlgUnknown
}

// WrapKey encrypts keyToWrap with wrappingKey exactly like the SDK's wrap_symmetric_key:
//   - AES-256-CBC-HMAC wrapping key: type 2 EncString of keyToWrap.Bytes() (legacy bytes or padded
//     COSE key).
//   - XChaCha20-Poly1305 / XAES-256-GCM wrapping key: type 7 EncString of the unpadded COSE key with
//     content format CoseKey, or of the raw legacy key bytes with content format BitwardenLegacyKey.
//   - other wrapping keys (AES-256-CBC, AES-256-GCM): error.
func WrapKey(keyToWrap, wrappingKey *SymmetricKey) (string, error) {
	if keyToWrap == nil || wrappingKey == nil {
		return "", errors.New("no key provided")
	}
	switch wrappingKey.KeyAlgorithm() {
	case AlgAes256CbcHmac:
		e, err := Encrypt(keyToWrap.Bytes(), wrappingKey)
		if err != nil {
			return "", err
		}
		return e.String(), nil
	case AlgXChaCha20Poly1305, AlgXAes256Gcm:
		var e *EncString
		var err error
		if keyToWrap.IsCose() {
			e, err = EncryptWithFormat(keyToWrap.CoseKeyBytes(), wrappingKey, ContentFormatCoseKey)
		} else {
			e, err = EncryptWithFormat(keyToWrap.Bytes(), wrappingKey, ContentFormatBitwardenLegacyKey)
		}
		if err != nil {
			return "", err
		}
		return e.String(), nil
	}
	return "", fmt.Errorf("wrapping not implemented for %s keys", wrappingKey.KeyAlgorithm())
}

// UnwrapKey is an alias of DecryptToKey.
func UnwrapKey(wrapped string, wrappingKey *SymmetricKey) (*SymmetricKey, error) {
	return DecryptToKey(wrapped, wrappingKey)
}

func unwrapCoseKey(data []byte, key *SymmetricKey) (*SymmetricKey, error) {
	pt, cf, err := decryptCoseEncString(data, key)
	if err != nil {
		return nil, err
	}
	switch cf {
	case ContentFormatBitwardenLegacyKey:
		return NewSymmetricKey(pt)
	case ContentFormatCoseKey:
		return ParseCoseSymmetricKey(pt)
	}
	return nil, errors.New("invalid key: wrapped key has unsupported content format")
}

// WrapPrivateKey encrypts a PKCS#8 DER private key (content format Pkcs8PrivateKey for COSE keys;
// SDK wrap_private_key).
func WrapPrivateKey(pkcs8 []byte, wrappingKey *SymmetricKey) (string, error) {
	e, err := EncryptWithFormat(pkcs8, wrappingKey, ContentFormatPkcs8PrivateKey)
	if err != nil {
		return "", err
	}
	return e.String(), nil
}

// DecryptPrivateKey decrypts a wrapped (type 2 or 7) PKCS#8 RSA private key, e.g. the account's
// encrypted private key.
func DecryptPrivateKey(wrapped string, key *SymmetricKey) (*rsa.PrivateKey, error) {
	e, err := ParseEncString(wrapped)
	if err != nil {
		return nil, err
	}
	der, err := e.Decrypt(key)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(der)
}
