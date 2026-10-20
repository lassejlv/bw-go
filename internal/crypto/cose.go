package crypto

import (
	"errors"
	"fmt"
)

// COSE (RFC 9052) framing as used by the Bitwarden SDK (crates/bitwarden-crypto/src/cose).
// Encodings mirror coset: header fields are written in the order alg(1), content type(3), kid(4),
// iv(5), followed by private labels in insertion order; COSE keys are written as kty(1), kid(2),
// alg(3), key_ops(4, sorted ascending), then key parameters in insertion order. Messages are
// untagged arrays.

const (
	// COSE algorithm identifiers.
	coseAlgA256GCM           int64 = 3
	coseAlgEdDSA             int64 = -8
	coseAlgMLDSA44           int64 = -48
	coseAlgXChaCha20Poly1305 int64 = -70000 // private use
	coseAlgXAes256Gcm        int64 = -70010 // private use
	coseAlgAes256CbcHmacAead int64 = -70011 // private use

	// Header labels.
	coseHdrAlg         int64 = 1
	coseHdrContentType int64 = 3
	coseHdrKid         int64 = 4
	coseHdrIV          int64 = 5

	// Bitwarden private header labels.
	coseLabelSigningNamespace     int64 = -80000
	coseLabelSafeContentNamespace int64 = -80001
	coseLabelSafeObjectNamespace  int64 = -80002

	// COSE key labels.
	coseKeyKty    int64 = 1
	coseKeyKid    int64 = 2
	coseKeyAlg    int64 = 3
	coseKeyKeyOps int64 = 4

	coseKtyOKP       int64 = 1
	coseKtySymmetric int64 = 4
	coseKtyAKP       int64 = 7

	coseCrvEd25519 int64 = 6

	// CoAP content formats used in COSE content type headers.
	coapCoseEncrypt0 int64 = 16
	coapCoseSign1    int64 = 18
	coapOctetStream  int64 = 42
	coapCbor         int64 = 60
	coapCoseKey      int64 = 101
	coapPkcs8        int64 = 284

	contentTypePaddedUtf8    = "application/x.bitwarden.utf8-padded"
	contentTypePaddedCbor    = "application/x.bitwarden.cbor-padded"
	contentTypeLegacyKey     = "application/x.bitwarden.legacy-key"
	contentTypeSpkiPublicKey = "application/x.bitwarden.spki-public-key"

	// Safe object namespaces (cose/mod.rs SafeObjectNamespace).
	safeObjectNamespaceDataEnvelope int64 = 2

	// Utf8 content is padded to multiples of this block size before COSE encryption.
	textPadBlockSize = 32
)

// KeyOperation is a COSE key operation (RFC 9052 table 5).
type KeyOperation int

const (
	KeyOpSign      KeyOperation = 1
	KeyOpVerify    KeyOperation = 2
	KeyOpEncrypt   KeyOperation = 3
	KeyOpDecrypt   KeyOperation = 4
	KeyOpWrapKey   KeyOperation = 5
	KeyOpUnwrapKey KeyOperation = 6
)

// ContentFormat describes the format of the plaintext inside a COSE (type 7) EncString. It is stored
// in the authenticated protected header and lets the SDK distinguish e.g. wrapped legacy keys from
// wrapped COSE keys. Legacy (type 0/2) EncStrings carry no content format (ContentFormatUnknown).
type ContentFormat int

const (
	ContentFormatUnknown ContentFormat = iota
	// ContentFormatUtf8 is UTF-8 text; it is padded to 32 byte blocks before encryption.
	ContentFormatUtf8
	// ContentFormatPkcs8PrivateKey is a PKCS#8 DER private key (CoAP 284).
	ContentFormatPkcs8PrivateKey
	// ContentFormatSPKIPublicKeyDer is an SPKI DER public key.
	ContentFormatSPKIPublicKeyDer
	// ContentFormatCoseKey is an unpadded serialized COSE key (CoAP 101).
	ContentFormatCoseKey
	// ContentFormatCoseSign1 is a COSE_Sign1 message (CoAP 18).
	ContentFormatCoseSign1
	// ContentFormatCoseEncrypt0 is a COSE_Encrypt0 message (CoAP 16).
	ContentFormatCoseEncrypt0
	// ContentFormatBitwardenLegacyKey is a 32/64 byte legacy key or a padded (>64 byte) COSE key.
	ContentFormatBitwardenLegacyKey
	// ContentFormatOctetStream is arbitrary bytes (CoAP 42).
	ContentFormatOctetStream
	// ContentFormatCbor is CBOR data (CoAP 60).
	ContentFormatCbor
)

func (cf ContentFormat) headerValue() (any, error) {
	switch cf {
	case ContentFormatUtf8:
		return contentTypePaddedUtf8, nil
	case ContentFormatPkcs8PrivateKey:
		return coapPkcs8, nil
	case ContentFormatSPKIPublicKeyDer:
		return contentTypeSpkiPublicKey, nil
	case ContentFormatCoseKey:
		return coapCoseKey, nil
	case ContentFormatCoseSign1:
		return coapCoseSign1, nil
	case ContentFormatCoseEncrypt0:
		return coapCoseEncrypt0, nil
	case ContentFormatBitwardenLegacyKey:
		return contentTypeLegacyKey, nil
	case ContentFormatOctetStream:
		return coapOctetStream, nil
	case ContentFormatCbor:
		return coapCbor, nil
	}
	return nil, fmt.Errorf("unknown content format %d", cf)
}

// contentFormatFromHeader mirrors the SDK's TryFrom<&Header> for ContentFormat (which does not
// recognise CoseSign1/CoseEncrypt0).
func contentFormatFromHeader(h *coseHeader) (ContentFormat, error) {
	switch ct := h.ContentType.(type) {
	case string:
		switch ct {
		case contentTypePaddedUtf8:
			return ContentFormatUtf8, nil
		case contentTypeLegacyKey:
			return ContentFormatBitwardenLegacyKey, nil
		case contentTypeSpkiPublicKey:
			return ContentFormatSPKIPublicKeyDer, nil
		}
	case int64:
		switch ct {
		case coapPkcs8:
			return ContentFormatPkcs8PrivateKey, nil
		case coapCoseKey:
			return ContentFormatCoseKey, nil
		case coapOctetStream:
			return ContentFormatOctetStream, nil
		case coapCbor:
			return ContentFormatCbor, nil
		}
	}
	return ContentFormatUnknown, errors.New("COSE message is missing a supported content type")
}

// ---------- headers ----------

type coseHeader struct {
	HasAlg      bool
	Alg         int64
	ContentType any // nil, int64 or string
	KeyID       []byte
	IV          []byte
	Rest        cborMap
}

func (h *coseHeader) toMap() cborMap {
	m := cborMap{}
	if h.HasAlg {
		m = append(m, cborPair{coseHdrAlg, h.Alg})
	}
	if h.ContentType != nil {
		m = append(m, cborPair{coseHdrContentType, h.ContentType})
	}
	if len(h.KeyID) > 0 {
		m = append(m, cborPair{coseHdrKid, h.KeyID})
	}
	if len(h.IV) > 0 {
		m = append(m, cborPair{coseHdrIV, h.IV})
	}
	return append(m, h.Rest...)
}

// encodeProtected serializes a protected header; an empty header is an empty byte string.
func (h *coseHeader) encodeProtected() []byte {
	m := h.toMap()
	if len(m) == 0 {
		return []byte{}
	}
	return cborMustEncode(m)
}

// setRest sets (or replaces) a private integer-labelled header value.
func (h *coseHeader) setRest(label int64, v any) {
	for i, p := range h.Rest {
		if cborKeyEqual(p.K, label) {
			h.Rest[i].V = v
			return
		}
	}
	h.Rest = append(h.Rest, cborPair{label, v})
}

// restInt returns an integer private header value; ok is false when absent.
func (h *coseHeader) restInt(label int64) (v int64, ok bool, err error) {
	raw, ok := h.Rest.get(label)
	if !ok {
		return 0, false, nil
	}
	i, isInt := raw.(int64)
	if !isInt {
		return 0, true, errors.New("COSE header value is not an integer")
	}
	return i, true, nil
}

func parseCoseHeader(v any) (*coseHeader, error) {
	m, ok := v.(cborMap)
	if !ok {
		return nil, errors.New("COSE header is not a map")
	}
	h := &coseHeader{}
	seen := map[string]bool{}
	for _, p := range m {
		key := fmt.Sprintf("%T:%v", p.K, p.K)
		if seen[key] {
			return nil, errors.New("duplicate COSE header label")
		}
		seen[key] = true
		label, isInt := p.K.(int64)
		if !isInt {
			if _, isText := p.K.(string); !isText {
				return nil, errors.New("invalid COSE header label")
			}
			h.Rest = append(h.Rest, p)
			continue
		}
		switch label {
		case coseHdrAlg:
			a, ok := p.V.(int64)
			if !ok {
				return nil, errors.New("unsupported COSE algorithm")
			}
			h.HasAlg, h.Alg = true, a
		case coseHdrContentType:
			switch ct := p.V.(type) {
			case int64:
				if ct < 0 || ct > 0xffff {
					return nil, errors.New("invalid COSE content type")
				}
				h.ContentType = ct
			case string:
				h.ContentType = ct
			default:
				return nil, errors.New("invalid COSE content type")
			}
		case coseHdrKid:
			b, ok := p.V.([]byte)
			if !ok {
				return nil, errors.New("invalid COSE key id")
			}
			h.KeyID = b
		case coseHdrIV:
			b, ok := p.V.([]byte)
			if !ok {
				return nil, errors.New("invalid COSE iv")
			}
			h.IV = b
		default:
			h.Rest = append(h.Rest, p)
		}
	}
	return h, nil
}

func parseProtected(v any) (raw []byte, h *coseHeader, err error) {
	raw, ok := v.([]byte)
	if !ok {
		return nil, nil, errors.New("COSE protected header is not a byte string")
	}
	if len(raw) == 0 {
		return raw, &coseHeader{}, nil
	}
	dv, err := cborDecode(raw)
	if err != nil {
		return nil, nil, err
	}
	h, err = parseCoseHeader(dv)
	return raw, h, err
}

func untag(v any, tag uint64) any {
	if t, ok := v.(cborTag); ok && t.Num == tag {
		return t.Val
	}
	return v
}

// ---------- COSE_Encrypt0 ----------

type coseEncrypt0 struct {
	ProtectedRaw []byte
	Protected    *coseHeader
	Unprotected  *coseHeader
	Ciphertext   []byte // nil when detached/absent
}

func parseCoseEncrypt0(b []byte) (*coseEncrypt0, error) {
	v, err := cborDecode(b)
	if err != nil {
		return nil, fmt.Errorf("invalid COSE_Encrypt0: %w", err)
	}
	arr, ok := untag(v, 16).([]any)
	if !ok || len(arr) != 3 {
		return nil, errors.New("invalid COSE_Encrypt0 structure")
	}
	msg := &coseEncrypt0{}
	if msg.ProtectedRaw, msg.Protected, err = parseProtected(arr[0]); err != nil {
		return nil, err
	}
	if msg.Unprotected, err = parseCoseHeader(arr[1]); err != nil {
		return nil, err
	}
	switch ct := arr[2].(type) {
	case nil:
	case []byte:
		msg.Ciphertext = ct
	default:
		return nil, errors.New("invalid COSE_Encrypt0 ciphertext")
	}
	return msg, nil
}

func (m *coseEncrypt0) encode() []byte {
	var ct any
	if m.Ciphertext != nil {
		ct = m.Ciphertext
	}
	return cborMustEncode([]any{m.ProtectedRaw, m.Unprotected.toMap(), ct})
}

// encStructure0 is the AEAD associated data: ["Encrypt0", protected, external_aad = h”].
func encStructure0(protectedRaw []byte) []byte {
	return cborMustEncode([]any{"Encrypt0", protectedRaw, []byte{}})
}

// coseEncrypt0Seal encrypts plaintext into a COSE_Encrypt0 with the given content-encryption
// algorithm (set into the protected header), a fresh random nonce in the unprotected iv header,
// and Utf8 padding when the protected content type is the padded UTF-8 type.
func coseEncrypt0Seal(alg int64, cek []byte, protected *coseHeader, plaintext []byte) (*coseEncrypt0, error) {
	if cf, err := contentFormatFromHeader(protected); err == nil && cf == ContentFormatUtf8 {
		var perr error
		if plaintext, perr = padBytes(plaintext, textPadBlockSize*(1+len(plaintext)/textPadBlockSize)); perr != nil {
			return nil, perr
		}
	}
	protected.HasAlg, protected.Alg = true, alg
	size, err := aeadNonceSize(alg)
	if err != nil {
		return nil, err
	}
	nonce := RandomBytes(size)
	raw := protected.encodeProtected()
	ct, err := aeadSeal(alg, cek, nonce, plaintext, encStructure0(raw))
	if err != nil {
		return nil, err
	}
	return &coseEncrypt0{ProtectedRaw: raw, Protected: protected, Unprotected: &coseHeader{IV: nonce}, Ciphertext: ct}, nil
}

// coseEncrypt0Open authenticates and decrypts msg. The protected algorithm must be present and equal
// expectedAlg (SDK CoseAlgorithmPolicy::Exactly). Utf8 padding is removed.
func coseEncrypt0Open(msg *coseEncrypt0, expectedAlg int64, cek []byte) ([]byte, error) {
	if !msg.Protected.HasAlg {
		return nil, errors.New("COSE message is missing the algorithm")
	}
	if msg.Protected.Alg != expectedAlg {
		return nil, errors.New("wrong key type for COSE message algorithm")
	}
	size, err := aeadNonceSize(expectedAlg)
	if err != nil {
		return nil, err
	}
	if len(msg.Unprotected.IV) != size {
		return nil, errors.New("invalid nonce length")
	}
	if msg.Ciphertext == nil {
		return nil, errors.New("missing ciphertext")
	}
	pt, err := aeadOpen(expectedAlg, cek, msg.Unprotected.IV, msg.Ciphertext, encStructure0(msg.ProtectedRaw))
	if err != nil {
		return nil, err
	}
	if cf, err := contentFormatFromHeader(msg.Protected); err == nil && cf == ContentFormatUtf8 {
		return unpadBytes(pt)
	}
	return pt, nil
}

// ---------- COSE_Sign1 ----------

type coseSign1 struct {
	ProtectedRaw []byte
	Protected    *coseHeader
	Unprotected  *coseHeader
	Payload      []byte // nil when detached
	Signature    []byte
}

func parseCoseSign1(b []byte) (*coseSign1, error) {
	v, err := cborDecode(b)
	if err != nil {
		return nil, fmt.Errorf("invalid COSE_Sign1: %w", err)
	}
	arr, ok := untag(v, 18).([]any)
	if !ok || len(arr) != 4 {
		return nil, errors.New("invalid COSE_Sign1 structure")
	}
	msg := &coseSign1{}
	if msg.ProtectedRaw, msg.Protected, err = parseProtected(arr[0]); err != nil {
		return nil, err
	}
	if msg.Unprotected, err = parseCoseHeader(arr[1]); err != nil {
		return nil, err
	}
	switch p := arr[2].(type) {
	case nil:
	case []byte:
		msg.Payload = p
	default:
		return nil, errors.New("invalid COSE_Sign1 payload")
	}
	sig, ok := arr[3].([]byte)
	if !ok {
		return nil, errors.New("invalid COSE_Sign1 signature")
	}
	msg.Signature = sig
	return msg, nil
}

func (m *coseSign1) encode() []byte {
	var payload any
	if m.Payload != nil {
		payload = m.Payload
	}
	return cborMustEncode([]any{m.ProtectedRaw, m.Unprotected.toMap(), payload, m.Signature})
}

// sigStructure1 is the signed data: ["Signature1", protected, external_aad = h”, payload].
func sigStructure1(protectedRaw, payload []byte) []byte {
	return cborMustEncode([]any{"Signature1", protectedRaw, []byte{}, payload})
}

// ---------- COSE keys ----------

type coseKey struct {
	Kty    int64
	KeyID  []byte
	HasAlg bool
	Alg    int64
	KeyOps []int64
	Params cborMap // remaining labels in order
}

func parseCoseKey(b []byte) (*coseKey, error) {
	v, err := cborDecode(b)
	if err != nil {
		return nil, fmt.Errorf("invalid COSE key: %w", err)
	}
	m, ok := v.(cborMap)
	if !ok {
		return nil, errors.New("invalid COSE key: not a map")
	}
	k := &coseKey{}
	hasKty := false
	for _, p := range m {
		label, isInt := p.K.(int64)
		if !isInt {
			k.Params = append(k.Params, p)
			continue
		}
		switch label {
		case coseKeyKty:
			kty, ok := p.V.(int64)
			if !ok {
				return nil, errors.New("invalid COSE key type")
			}
			k.Kty, hasKty = kty, true
		case coseKeyKid:
			kid, ok := p.V.([]byte)
			if !ok {
				return nil, errors.New("invalid COSE key id")
			}
			k.KeyID = kid
		case coseKeyAlg:
			alg, ok := p.V.(int64)
			if !ok {
				return nil, errors.New("unsupported COSE key algorithm")
			}
			k.HasAlg, k.Alg = true, alg
		case coseKeyKeyOps:
			arr, ok := p.V.([]any)
			if !ok {
				return nil, errors.New("invalid COSE key_ops")
			}
			for _, op := range arr {
				i, ok := op.(int64)
				if !ok {
					return nil, errors.New("unsupported COSE key operation")
				}
				k.KeyOps = append(k.KeyOps, i)
			}
		default:
			k.Params = append(k.Params, p)
		}
	}
	if !hasKty {
		return nil, errors.New("invalid COSE key: missing kty")
	}
	return k, nil
}

func (k *coseKey) param(label int64) (any, bool) { return k.Params.get(label) }

func (k *coseKey) bytesParam(label int64) ([]byte, bool) {
	v, ok := k.param(label)
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

func (k *coseKey) encode() []byte {
	m := cborMap{{coseKeyKty, k.Kty}}
	if len(k.KeyID) > 0 {
		m = append(m, cborPair{coseKeyKid, k.KeyID})
	}
	if k.HasAlg {
		m = append(m, cborPair{coseKeyAlg, k.Alg})
	}
	if len(k.KeyOps) > 0 {
		ops := sortedUniqueOps(k.KeyOps)
		arr := make([]any, len(ops))
		for i, op := range ops {
			arr[i] = op
		}
		m = append(m, cborPair{coseKeyKeyOps, arr})
	}
	return cborMustEncode(append(m, k.Params...))
}

// sortedUniqueOps mirrors coset's BTreeSet<KeyOperation> ordering.
func sortedUniqueOps(ops []int64) []int64 {
	out := append([]int64{}, ops...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	uniq := out[:0]
	for i, v := range out {
		if i == 0 || v != out[i-1] {
			uniq = append(uniq, v)
		}
	}
	return uniq
}

// coseThumbprint computes an RFC 9679 COSE key thumbprint over the required parameters.
func coseThumbprint(params cborMap) []byte {
	return SHA256(cborCanonicalMap(params))
}
