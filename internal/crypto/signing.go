package crypto

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// Signing (SDK crates/bitwarden-crypto/src/signing), signed public keys and the signed security
// state used by v2 accounts.
//
// Signed objects are untagged COSE_Sign1 messages with protected header
// {1 (alg): -8 (EdDSA) | -48 (ML-DSA-44), 3 (content type): 60 (CBOR), 4 (kid): <signing key id>,
// -80000: <SigningNamespace>} and an empty unprotected header; the payload is a CBOR (serde) map.

// SignatureAlgorithm is a signature scheme supported by SigningKey/VerifyingKey.
type SignatureAlgorithm int

const (
	SignatureAlgorithmEd25519 SignatureAlgorithm = iota + 1
	SignatureAlgorithmMlDsa44
)

func (a SignatureAlgorithm) String() string {
	switch a {
	case SignatureAlgorithmEd25519:
		return "ed25519"
	case SignatureAlgorithmMlDsa44:
		return "mldsa44"
	}
	return "unknown"
}

// SigningNamespace domain-separates signatures (SDK SigningNamespace).
type SigningNamespace int64

const (
	SigningNamespaceSignedPublicKey SigningNamespace = 1
	SigningNamespaceSecurityState   SigningNamespace = 2
)

var ErrInvalidSignature = errors.New("invalid signature")

// SigningKey is a private signature key with its 16 byte key id.
type SigningKey struct {
	KeyID     []byte
	Algorithm SignatureAlgorithm
	ed        ed25519.PrivateKey
	ml        *mldsa.PrivateKey
}

// VerifyingKey is the public half of a SigningKey (same key id).
type VerifyingKey struct {
	KeyID     []byte
	Algorithm SignatureAlgorithm
	ed        ed25519.PublicKey
	ml        *mldsa.PublicKey
}

// GenerateSigningKey creates a new signing key (the SDK uses ML-DSA-44 for new v2 accounts).
func GenerateSigningKey(alg SignatureAlgorithm) (*SigningKey, error) {
	switch alg {
	case SignatureAlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &SigningKey{KeyID: RandomBytes(16), Algorithm: alg, ed: priv}, nil
	case SignatureAlgorithmMlDsa44:
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), RandomBytes(32))
		if err != nil {
			return nil, err
		}
		return &SigningKey{KeyID: RandomBytes(16), Algorithm: alg, ml: priv}, nil
	}
	return nil, fmt.Errorf("unsupported signature algorithm %d", alg)
}

// ParseSigningKey parses a COSE_Key signing key: OKP/EdDSA/Ed25519 (d = -4, crv = -1) or
// AKP/ML-DSA-44 (seed in priv = -2).
func ParseSigningKey(b []byte) (*SigningKey, error) {
	ck, err := parseCoseKey(b)
	if err != nil {
		return nil, err
	}
	if len(ck.KeyID) != 16 {
		return nil, errors.New("invalid signing key: key id length")
	}
	switch {
	case ck.HasAlg && ck.Alg == coseAlgEdDSA && ck.Kty == coseKtyOKP:
		d, ok := ck.bytesParam(-4)
		if !ok {
			return nil, errors.New("invalid signing key: missing OKP private key")
		}
		if crv, _ := ck.param(-1); crv != coseCrvEd25519 {
			return nil, errors.New("invalid signing key: unsupported OKP curve")
		}
		if len(d) != ed25519.SeedSize {
			return nil, errors.New("invalid signing key")
		}
		return &SigningKey{KeyID: clone(ck.KeyID), Algorithm: SignatureAlgorithmEd25519, ed: ed25519.NewKeyFromSeed(d)}, nil
	case ck.HasAlg && ck.Alg == coseAlgMLDSA44 && ck.Kty == coseKtyAKP:
		seed, ok := ck.bytesParam(-2)
		if !ok || len(seed) != 32 {
			return nil, errors.New("invalid signing key: ML-DSA seed")
		}
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
		if err != nil {
			return nil, err
		}
		return &SigningKey{KeyID: clone(ck.KeyID), Algorithm: SignatureAlgorithmMlDsa44, ml: priv}, nil
	}
	return nil, errors.New("invalid signing key: unsupported COSE key type or algorithm")
}

// Bytes returns the COSE_Key serialization (content of a wrapped signing key).
func (k *SigningKey) Bytes() []byte {
	switch k.Algorithm {
	case SignatureAlgorithmEd25519:
		return (&coseKey{Kty: coseKtyOKP, KeyID: k.KeyID, HasAlg: true, Alg: coseAlgEdDSA, KeyOps: []int64{int64(KeyOpSign)},
			Params: cborMap{{int64(-4), []byte(k.ed.Seed())}, {int64(-1), coseCrvEd25519}}}).encode()
	case SignatureAlgorithmMlDsa44:
		return (&coseKey{Kty: coseKtyAKP, KeyID: k.KeyID, HasAlg: true, Alg: coseAlgMLDSA44, KeyOps: []int64{int64(KeyOpSign)},
			Params: cborMap{{int64(-1), k.ml.PublicKey().Bytes()}, {int64(-2), k.ml.Bytes()}}}).encode()
	}
	return nil
}

// VerifyingKey derives the verifying key.
func (k *SigningKey) VerifyingKey() *VerifyingKey {
	switch k.Algorithm {
	case SignatureAlgorithmEd25519:
		return &VerifyingKey{KeyID: clone(k.KeyID), Algorithm: k.Algorithm, ed: k.ed.Public().(ed25519.PublicKey)}
	case SignatureAlgorithmMlDsa44:
		return &VerifyingKey{KeyID: clone(k.KeyID), Algorithm: k.Algorithm, ml: k.ml.PublicKey()}
	}
	return nil
}

func (k *SigningKey) coseAlg() int64 {
	if k.Algorithm == SignatureAlgorithmMlDsa44 {
		return coseAlgMLDSA44
	}
	return coseAlgEdDSA
}

func (k *SigningKey) signRaw(data []byte) ([]byte, error) {
	switch k.Algorithm {
	case SignatureAlgorithmEd25519:
		return ed25519.Sign(k.ed, data), nil
	case SignatureAlgorithmMlDsa44:
		return k.ml.Sign(rand.Reader, data, &mldsa.Options{})
	}
	return nil, errors.New("unsupported signature algorithm")
}

// ParseVerifyingKey parses a COSE_Key verifying key: OKP/EdDSA/Ed25519 (x = -2) or AKP/ML-DSA-44
// (pub = -1).
func ParseVerifyingKey(b []byte) (*VerifyingKey, error) {
	ck, err := parseCoseKey(b)
	if err != nil {
		return nil, err
	}
	if !ck.HasAlg {
		return nil, errors.New("invalid verifying key: missing algorithm")
	}
	if len(ck.KeyID) != 16 {
		return nil, errors.New("invalid verifying key: key id length")
	}
	switch {
	case ck.Kty == coseKtyOKP && ck.Alg == coseAlgEdDSA:
		x, ok := ck.bytesParam(-2)
		if !ok || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("invalid verifying key: ed25519 OKP verifying key")
		}
		if crv, _ := ck.param(-1); crv != coseCrvEd25519 {
			return nil, errors.New("invalid verifying key: unsupported OKP curve")
		}
		return &VerifyingKey{KeyID: clone(ck.KeyID), Algorithm: SignatureAlgorithmEd25519, ed: ed25519.PublicKey(clone(x))}, nil
	case ck.Kty == coseKtyAKP && ck.Alg == coseAlgMLDSA44:
		pub, ok := ck.bytesParam(-1)
		if !ok {
			return nil, errors.New("invalid verifying key: missing AKP public key")
		}
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pub)
		if err != nil {
			return nil, errors.New("invalid verifying key: ML-DSA-44 verifying key length")
		}
		return &VerifyingKey{KeyID: clone(ck.KeyID), Algorithm: SignatureAlgorithmMlDsa44, ml: pk}, nil
	}
	return nil, errors.New("invalid verifying key: unsupported COSE key type or algorithm")
}

// Bytes returns the COSE_Key serialization of the verifying key.
func (v *VerifyingKey) Bytes() []byte {
	switch v.Algorithm {
	case SignatureAlgorithmEd25519:
		return (&coseKey{Kty: coseKtyOKP, KeyID: v.KeyID, HasAlg: true, Alg: coseAlgEdDSA, KeyOps: []int64{int64(KeyOpVerify)},
			Params: cborMap{{int64(-1), coseCrvEd25519}, {int64(-2), []byte(v.ed)}}}).encode()
	case SignatureAlgorithmMlDsa44:
		return (&coseKey{Kty: coseKtyAKP, KeyID: v.KeyID, HasAlg: true, Alg: coseAlgMLDSA44, KeyOps: []int64{int64(KeyOpVerify)},
			Params: cborMap{{int64(-1), v.ml.Bytes()}}}).encode()
	}
	return nil
}

// Thumbprint returns the RFC 9679 SHA-256 COSE key thumbprint.
func (v *VerifyingKey) Thumbprint() []byte {
	switch v.Algorithm {
	case SignatureAlgorithmEd25519:
		return coseThumbprint(cborMap{{coseKeyKty, coseKtyOKP}, {int64(-1), coseCrvEd25519}, {int64(-2), []byte(v.ed)}})
	case SignatureAlgorithmMlDsa44:
		return coseThumbprint(cborMap{{coseKeyKty, coseKtyAKP}, {coseKeyAlg, coseAlgMLDSA44}, {int64(-1), v.ml.Bytes()}})
	}
	return nil
}

func (v *VerifyingKey) verifyRaw(sig, data []byte) error {
	switch v.Algorithm {
	case SignatureAlgorithmEd25519:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(v.ed, data, sig) {
			return ErrInvalidSignature
		}
		return nil
	case SignatureAlgorithmMlDsa44:
		if mldsa.Verify(v.ml, data, sig, &mldsa.Options{}) != nil {
			return ErrInvalidSignature
		}
		return nil
	}
	return ErrInvalidSignature
}

// ---------- signed objects ----------

// SignedObject is a COSE_Sign1 with embedded payload (SDK SignedObject) or, for detached
// signatures, without (SDK Signature).
type SignedObject struct {
	msg *coseSign1
}

// ParseSignedObject parses a serialized COSE_Sign1.
func ParseSignedObject(b []byte) (*SignedObject, error) {
	msg, err := parseCoseSign1(b)
	if err != nil {
		return nil, err
	}
	return &SignedObject{msg: msg}, nil
}

// Bytes returns the COSE_Sign1 serialization.
func (o *SignedObject) Bytes() []byte { return o.msg.encode() }

// SignedBy returns the signing key id from the protected header.
func (o *SignedObject) SignedBy() []byte { return clone(o.msg.Protected.KeyID) }

// Namespace returns the signing namespace from the protected header.
func (o *SignedObject) Namespace() (SigningNamespace, error) {
	v, ok, err := o.msg.Protected.restInt(coseLabelSigningNamespace)
	if err != nil || !ok {
		return 0, errors.New("invalid signature namespace")
	}
	return SigningNamespace(v), nil
}

// UnverifiedPayload returns the payload without verifying it. Only for debugging.
func (o *SignedObject) UnverifiedPayload() []byte { return o.msg.Payload }

func (o *SignedObject) verify(payload []byte, vk *VerifyingKey, ns SigningNamespace) error {
	if vk == nil {
		return errors.New("no verifying key provided")
	}
	if !o.msg.Protected.HasAlg {
		return ErrInvalidSignature
	}
	got, err := o.Namespace()
	if err != nil {
		return err
	}
	if got != ns {
		return errors.New("invalid signature namespace")
	}
	return vk.verifyRaw(o.msg.Signature, sigStructure1(o.msg.ProtectedRaw, payload))
}

// VerifyAndUnwrap verifies the signature (protected alg present, namespace == ns, signature valid)
// and returns the CBOR payload. The content type must be CBOR (60).
func (o *SignedObject) VerifyAndUnwrap(vk *VerifyingKey, ns SigningNamespace) ([]byte, error) {
	if err := o.verify(o.msg.Payload, vk, ns); err != nil {
		return nil, err
	}
	if o.msg.Payload == nil {
		return nil, ErrInvalidSignature
	}
	if ct, ok := o.msg.Protected.ContentType.(int64); !ok || ct != coapCbor {
		return nil, errors.New("signed object: unsupported content type")
	}
	return o.msg.Payload, nil
}

// VerifyDetached verifies a detached signature (payload not embedded) over payload.
func (o *SignedObject) VerifyDetached(payload []byte, vk *VerifyingKey, ns SigningNamespace) error {
	return o.verify(payload, vk, ns)
}

// Sign signs a CBOR payload under the namespace, producing a COSE_Sign1 with embedded payload.
func (k *SigningKey) Sign(cborPayload []byte, ns SigningNamespace) ([]byte, error) {
	return k.sign(cborPayload, ns, false)
}

// SignDetached signs a CBOR payload, producing a COSE_Sign1 without embedded payload.
func (k *SigningKey) SignDetached(cborPayload []byte, ns SigningNamespace) ([]byte, error) {
	return k.sign(cborPayload, ns, true)
}

func (k *SigningKey) sign(payload []byte, ns SigningNamespace, detached bool) ([]byte, error) {
	h := &coseHeader{HasAlg: true, Alg: k.coseAlg(), ContentType: coapCbor, KeyID: clone(k.KeyID)}
	h.setRest(coseLabelSigningNamespace, int64(ns))
	raw := h.encodeProtected()
	sig, err := k.signRaw(sigStructure1(raw, payload))
	if err != nil {
		return nil, err
	}
	msg := &coseSign1{ProtectedRaw: raw, Protected: h, Unprotected: &coseHeader{}, Signature: sig}
	if !detached {
		msg.Payload = payload
	}
	return msg.encode(), nil
}

// ---------- signed public key ----------

// VerifySignedPublicKey verifies a SignedPublicKey (base64 COSE_Sign1, namespace SignedPublicKey,
// payload {"algorithm": 0 (RsaOaepSha1), "contentFormat": 0 (SPKI), "publicKey": bstr}) and returns
// the RSA public key and its SPKI DER.
func VerifySignedPublicKey(signedPublicKey string, vk *VerifyingKey) (*rsa.PublicKey, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(signedPublicKey)
	if err != nil {
		return nil, nil, err
	}
	obj, err := ParseSignedObject(raw)
	if err != nil {
		return nil, nil, err
	}
	payload, err := obj.VerifyAndUnwrap(vk, SigningNamespaceSignedPublicKey)
	if err != nil {
		return nil, nil, err
	}
	v, err := cborDecode(payload)
	if err != nil {
		return nil, nil, err
	}
	m, ok := v.(cborMap)
	if !ok {
		return nil, nil, errors.New("signed public key: invalid payload")
	}
	alg, _ := m.get("algorithm")
	format, _ := m.get("contentFormat")
	spki, _ := m.get("publicKey")
	der, isBytes := spki.([]byte)
	if alg != int64(0) || format != int64(0) || !isBytes {
		return nil, nil, errors.New("signed public key: unsupported algorithm or format")
	}
	pub, err := ParsePublicKey(der)
	if err != nil {
		return nil, nil, errors.New("signed public key: invalid public key")
	}
	return pub, der, nil
}

// MakeSignedPublicKey signs an RSA public key (SDK SignedPublicKeyMessage::sign), returning base64.
func MakeSignedPublicKey(pub *rsa.PublicKey, sk *SigningKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	payload := cborMustEncode(cborMap{{"algorithm", int64(0)}, {"contentFormat", int64(0)}, {"publicKey", der}})
	signed, err := sk.Sign(payload, SigningNamespaceSignedPublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signed), nil
}

// ---------- security state ----------

// SecurityState is the signed account security state; Version gates features (>= 2 enables blob
// cipher encryption and icon URI hash enforcement in the SDK).
type SecurityState struct {
	Version uint64
}

func parseSecurityStatePayload(payload []byte) (*SecurityState, error) {
	v, err := cborDecode(payload)
	if err != nil {
		return nil, err
	}
	m, ok := v.(cborMap)
	if !ok {
		return nil, errors.New("security state: invalid payload")
	}
	ver, ok := m.get("version")
	switch x := ver.(type) {
	case int64:
		if x >= 0 {
			return &SecurityState{Version: uint64(x)}, nil
		}
	case uint64:
		return &SecurityState{Version: x}, nil
	}
	return nil, errors.New("security state: missing version")
}

// VerifySecurityState verifies a SignedSecurityState (base64 COSE_Sign1, namespace SecurityState)
// and returns its content.
func VerifySecurityState(signedSecurityState string, vk *VerifyingKey) (*SecurityState, error) {
	raw, err := base64.StdEncoding.DecodeString(signedSecurityState)
	if err != nil {
		return nil, err
	}
	obj, err := ParseSignedObject(raw)
	if err != nil {
		return nil, err
	}
	payload, err := obj.VerifyAndUnwrap(vk, SigningNamespaceSecurityState)
	if err != nil {
		return nil, err
	}
	return parseSecurityStatePayload(payload)
}

// UnverifiedSecurityStateVersion reads the version of a SignedSecurityState WITHOUT verifying the
// signature (for diagnostics only; use VerifySecurityState for decisions).
func UnverifiedSecurityStateVersion(signedSecurityState string) (uint64, error) {
	raw, err := base64.StdEncoding.DecodeString(signedSecurityState)
	if err != nil {
		return 0, err
	}
	obj, err := ParseSignedObject(raw)
	if err != nil {
		return 0, err
	}
	st, err := parseSecurityStatePayload(obj.msg.Payload)
	if err != nil {
		return 0, err
	}
	return st.Version, nil
}

// MakeSecurityState signs a security state ({"version": n}) and returns it base64 encoded.
func MakeSecurityState(version uint64, sk *SigningKey) (string, error) {
	signed, err := sk.Sign(cborMustEncode(cborMap{{"version", version}}), SigningNamespaceSecurityState)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signed), nil
}

// ---------- wrapped signing keys ----------

// WrapSigningKey encrypts the COSE signing key with wrappingKey (content format CoseKey; SDK
// wrap_signing_key).
func WrapSigningKey(sk *SigningKey, wrappingKey *SymmetricKey) (string, error) {
	e, err := EncryptWithFormat(sk.Bytes(), wrappingKey, ContentFormatCoseKey)
	if err != nil {
		return "", err
	}
	return e.String(), nil
}

// DecryptSigningKey decrypts a wrapped signing key (SDK unwrap_signing_key).
func DecryptSigningKey(wrapped string, key *SymmetricKey) (*SigningKey, error) {
	e, err := ParseEncString(wrapped)
	if err != nil {
		return nil, err
	}
	b, err := e.Decrypt(key)
	if err != nil {
		return nil, err
	}
	return ParseSigningKey(b)
}

// ---------- account cryptographic state ----------

// AccountKeys is the unlocked account cryptographic state.
type AccountKeys struct {
	UserKey *SymmetricKey
	// PrivateKey may be nil for V1 accounts with an unreadable private key (the SDK tolerates this).
	PrivateKey *rsa.PrivateKey
	// V2 only:
	SigningKey    *SigningKey
	VerifyingKey  *VerifyingKey
	PublicKey     *rsa.PublicKey // verified from the signed public key
	SecurityState *SecurityState
}

// IsV2 reports whether the state is a v2 (signing key + security state) state.
func (a *AccountKeys) IsV2() bool { return a.SigningKey != nil }

// UnlockAccountCryptographicState mirrors the SDK's WrappedAccountCryptographicState::set_to_context.
// The account is V2 when wrappedPrivateKey is a type 7 EncString; then wrappedSigningKey,
// signedPublicKey and signedSecurityState are required, the user key must be XAES-256-GCM, the
// private and signing keys must decrypt, and the signed public key and security state must verify
// against the signing key. Otherwise the account is V1: the user key must be AES-256-CBC-HMAC, the
// V2 fields must be empty and an undecryptable private key is tolerated (PrivateKey nil).
//
// Server fields (PrivateKeysResponseModel, "accountKeys" in token/sync responses):
// publicKeyEncryptionKeyPair.wrappedPrivateKey, publicKeyEncryptionKeyPair.signedPublicKey,
// signatureKeyPair.wrappedSigningKey, securityState.securityState.
func UnlockAccountCryptographicState(userKey *SymmetricKey, wrappedPrivateKey, wrappedSigningKey, signedPublicKey, signedSecurityState string) (*AccountKeys, error) {
	if userKey == nil {
		return nil, errors.New("no user key provided")
	}
	pk, err := ParseEncString(wrappedPrivateKey)
	if err != nil {
		return nil, err
	}
	if pk.Type != CoseEncrypt0 {
		if wrappedSigningKey != "" || signedSecurityState != "" {
			return nil, errors.New("inconsistent account cryptographic state")
		}
		if userKey.KeyAlgorithm() != AlgAes256CbcHmac {
			return nil, errors.New("the encryption type of the user key does not match the account cryptographic state")
		}
		acc := &AccountKeys{UserKey: userKey}
		if priv, err := DecryptPrivateKey(wrappedPrivateKey, userKey); err == nil {
			acc.PrivateKey = priv
		}
		return acc, nil
	}
	if wrappedSigningKey == "" || signedPublicKey == "" || signedSecurityState == "" {
		return nil, errors.New("inconsistent account cryptographic state")
	}
	if userKey.KeyAlgorithm() != AlgXAes256Gcm {
		return nil, errors.New("the encryption type of the user key does not match the account cryptographic state")
	}
	priv, err := DecryptPrivateKey(wrappedPrivateKey, userKey)
	if err != nil {
		return nil, fmt.Errorf("wrong user key: %w", err)
	}
	sk, err := DecryptSigningKey(wrappedSigningKey, userKey)
	if err != nil {
		return nil, fmt.Errorf("wrong user key: %w", err)
	}
	vk := sk.VerifyingKey()
	pub, _, err := VerifySignedPublicKey(signedPublicKey, vk)
	if err != nil {
		return nil, fmt.Errorf("signature or mac verification failed, the data may have been tampered with: %w", err)
	}
	st, err := VerifySecurityState(signedSecurityState, vk)
	if err != nil {
		return nil, fmt.Errorf("signature or mac verification failed, the data may have been tampered with: %w", err)
	}
	return &AccountKeys{UserKey: userKey, PrivateKey: priv, SigningKey: sk, VerifyingKey: vk, PublicKey: pub, SecurityState: st}, nil
}
