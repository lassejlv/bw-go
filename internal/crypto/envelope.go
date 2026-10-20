package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Data envelopes (SDK crates/bitwarden-crypto/src/safe/data_envelope.rs) and the sealed blob
// container used by "blob" ciphers and Item sends.
//
// # Wire format
//
// A DataEnvelope is a standard-base64 encoded, untagged COSE_Encrypt0:
//
//	protected   = { 1 (alg): 3 (A256GCM) | -70010 (XAES) | -70000 (XChaCha20-Poly1305, legacy),
//	                3 (content type): "application/x.bitwarden.cbor-padded",
//	                4 (kid): <16 byte key id of the CEK>,
//	                -80002 (safe object namespace): 2 (DataEnvelope),
//	                -80001 (safe content namespace): <DataEnvelopeNamespace, e.g. 1 = VaultItem> }
//	unprotected = { 5 (iv): <nonce, 12 bytes for AES-256-GCM> }
//	ciphertext  = AEAD(CEK, nonce, pad(CBOR(content), 64), Enc_structure("Encrypt0", protected, h''))
//
// The content is the serde/ciborium CBOR serialization of a versioned enum, adjacently tagged as
// {"version": "<n>", "content": {...}}. Padding is the SDK's PKCS7-like scheme to at least 64
// bytes (always at least one padding byte). New envelopes use a fresh single-use AES-256-GCM
// content-encryption key (CEK) whose key_ops are restricted to [Decrypt] after sealing; opening
// accepts AES-256-GCM, XAES-256-GCM and (legacy) XChaCha20-Poly1305 CEKs. When opening, the kid must
// equal the CEK id, the object/content namespaces must match when present (missing namespaces are
// accepted for backward compatibility), the content type must be cbor-padded, and the protected
// algorithm must equal the CEK's algorithm.
//
// # Sealed blob (cipher.data and SendItem.data)
//
// The SDK stores a DataEnvelope together with its wrapped CEK as a JSON string (bitwarden-vault
// cipher/blob/sealed.rs SealedCipherBlob):
//
//	{"format_version":1,"wrapped_cek":"<EncString>","envelope":"<base64 DataEnvelope>"}
//
// format_version must be 1; a JSON object without a "format_version" key is not a blob (legacy
// field-level cipher data). The DataEnvelope namespace is VaultItem (1) and the CEK is wrapped with
// WrapKey(cek, wrappingKey) — with an AES-256-CBC-HMAC wrapping key that is a type 2 EncString of
// the padded COSE CEK.
//
// Ciphers (bitwarden-vault cipher/blob/encryption.rs): a cipher is blob-encrypted when its "data"
// field parses as a sealed blob (IsSealedBlob). The wrapping key is the cipher key
// (cipher.key unwrapped with the user/org key; ciphers in this format always have a cipher key,
// which the SDK generates as an AES-256-CBC-HMAC key even for v2 users). The legacy encrypted
// fields (name, notes, login, card, identity, secureNote, sshKey, fields, passwordHistory, ...)
// are null; attachments are still field-encrypted with the cipher key as before. The SDK only
// writes blob ciphers for personal (organizationId == null) ciphers when the account's security
// state version is >= 2 (BLOB_SECURITY_VERSION), but it reads blob ciphers unconditionally.
// The versioned content is
//
//	{"version":"1","content":CipherBlobV1}
//	CipherBlobV1 = {"name": string, "notes": string|null, "typeData": TypeData,
//	                "fields"?: [{"name": s|null, "value": s|null, "type": int (FieldType),
//	                             "linkedId": int|null}],          // omitted when empty
//	                "passwordHistory"?: [{"password": s, "lastUsedDate": RFC3339}]} // omitted when empty
//	TypeData (internally tagged by "type"):
//	  {"type":"login", "username", "password", "passwordRevisionDate" (RFC3339|null),
//	   "uris"?: [{"uri": s|null, "match": int|null}], "totp", "autofillOnPageLoad": bool|null,
//	   "fido2Credentials"?: [{"credentialId","keyType","keyAlgorithm","keyCurve","keyValue","rpId",
//	      "userHandle"|null,"userName"|null,"counter": uint,"rpName"|null,"userDisplayName"|null,
//	      "discoverable": bool,"creationDate": RFC3339}]}
//	  {"type":"card", "cardholderName","expMonth","expYear","code","brand","number"}
//	  {"type":"identity", "title","firstName","middleName","lastName","address1","address2",
//	   "address3","city","state","postalCode","country","company","email","phone","ssn",
//	   "username","passportNumber","licenseNumber"}
//	  {"type":"secureNote", "secureNoteType": int}
//	  {"type":"sshKey", "privateKey","publicKey","fingerprint"}   (strings, required)
//	  {"type":"bankAccount", "bankName","nameOnAccount","accountType","accountNumber",
//	   "routingNumber","branchNumber","pin","swiftCode","iban","bankContactPhone"}
//	  {"type":"passport", "surname","givenName","dateOfBirth","sex","birthPlace","nationality",
//	   "issuingCountry","passportNumber","passportType","nationalIdentificationNumber",
//	   "issuingAuthority","issueDate","expirationDate"}
//	  {"type":"driversLicense", "firstName","middleName","lastName","dateOfBirth","licenseNumber",
//	   "issuingCountry","issuingState","issueDate","expirationDate","issuingAuthority","licenseClass"}
//
// (unlisted value types are string|null; every Option field is written as null when empty).
//
// Sends (bitwarden-send send.rs): Item sends (type 2) carry
// "data": {"encryptionVersion": 1, "data": "<sealed blob JSON string>", "metadata": {"itemId": uuid}}
// where the sealed blob is produced exactly as for ciphers (same CipherBlob content and VaultItem
// namespace) but the wrapping key is the send key, i.e. HKDF(salt "bitwarden-send", info "send",
// 64 bytes) of the 16 byte send seed (Send.key decrypted with the user key). Text and file sends do
// not use envelopes.

// DataEnvelopeNamespace domain-separates data envelopes (SDK DataEnvelopeNamespace).
type DataEnvelopeNamespace int64

const (
	DataEnvelopeNamespaceVaultItem                     DataEnvelopeNamespace = 1
	DataEnvelopeNamespaceOrganizationInvite            DataEnvelopeNamespace = 2
	DataEnvelopeNamespaceRegistrationOpenOrgInviteData DataEnvelopeNamespace = 3
	DataEnvelopeNamespacePamTargetSystem               DataEnvelopeNamespace = 4
	DataEnvelopeNamespacePamRotationConfig             DataEnvelopeNamespace = 5
)

const dataEnvelopePaddingSize = 64

var (
	ErrDataEnvelopeInvalidNamespace = errors.New("data envelope: invalid namespace")
	ErrDataEnvelopeWrongKey         = errors.New("data envelope: wrong key used for decryption")
	ErrDataEnvelopeUnsupported      = errors.New("data envelope: unsupported content format")
	ErrDataEnvelopeDecryption       = errors.New("data envelope: decryption error")
)

// SealDataEnvelope encrypts CBOR content into a DataEnvelope (base64) under a fresh AES-256-GCM CEK,
// which is returned restricted to the Decrypt operation (SDK DataEnvelope::seal).
func SealDataEnvelope(cborContent []byte, ns DataEnvelopeNamespace) (envelope string, cek *SymmetricKey, err error) {
	cek, err = GenerateKeyFor(AlgAes256Gcm)
	if err != nil {
		return "", nil, err
	}
	envelope, err = sealDataEnvelopeWith(cborContent, ns, cek)
	if err != nil {
		return "", nil, err
	}
	cek.KeyOps = []KeyOperation{KeyOpDecrypt}
	return envelope, cek, nil
}

func sealDataEnvelopeWith(cborContent []byte, ns DataEnvelopeNamespace, cek *SymmetricKey) (string, error) {
	if _, err := cborDecode(cborContent); err != nil {
		return "", fmt.Errorf("data envelope: content is not valid CBOR: %w", err)
	}
	padded, err := padBytes(cborContent, dataEnvelopePaddingSize)
	if err != nil {
		return "", err
	}
	alg, ok := cek.Algorithm.coseAlg()
	if !cek.IsCose() || !ok {
		return "", ErrDataEnvelopeUnsupported
	}
	h := &coseHeader{ContentType: contentTypePaddedCbor, KeyID: clone(cek.KeyID)}
	h.setRest(coseLabelSafeObjectNamespace, safeObjectNamespaceDataEnvelope)
	h.setRest(coseLabelSafeContentNamespace, int64(ns))
	msg, err := coseEncrypt0Seal(alg, cek.EncKey, h, padded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(msg.encode()), nil
}

// OpenDataEnvelope decrypts a DataEnvelope (base64) with its CEK and returns the CBOR content
// (SDK DataEnvelope::unseal). The CEK must be an AES-256-GCM, XAES-256-GCM or XChaCha20-Poly1305
// COSE key.
func OpenDataEnvelope(envelope string, ns DataEnvelopeNamespace, cek *SymmetricKey) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return nil, fmt.Errorf("data envelope: %w", err)
	}
	if cek == nil || !cek.IsCose() {
		return nil, ErrDataEnvelopeUnsupported
	}
	alg, ok := cek.Algorithm.coseAlg()
	if !ok {
		return nil, ErrDataEnvelopeUnsupported
	}
	msg, err := parseCoseEncrypt0(raw)
	if err != nil {
		return nil, fmt.Errorf("data envelope: %w", err)
	}
	ct, isText := msg.Protected.ContentType.(string)
	if !isText {
		return nil, errors.New("data envelope: failed to decode content type")
	}
	if !bytes.Equal(msg.Protected.KeyID, cek.KeyID) {
		return nil, ErrDataEnvelopeWrongKey
	}
	if err := validateSafeNamespaces(msg.Protected, safeObjectNamespaceDataEnvelope, int64(ns)); err != nil {
		return nil, err
	}
	if ct != contentTypePaddedCbor {
		return nil, ErrDataEnvelopeUnsupported
	}
	pt, err := coseEncrypt0Open(msg, alg, cek.EncKey)
	if err != nil {
		return nil, ErrDataEnvelopeDecryption
	}
	content, err := unpadBytes(pt)
	if err != nil {
		return nil, ErrDataEnvelopeDecryption
	}
	return content, nil
}

// validateSafeNamespaces mirrors safe/helpers.rs: present namespaces must match, missing ones are
// accepted.
func validateSafeNamespaces(h *coseHeader, objectNS, contentNS int64) error {
	if v, ok, err := h.restInt(coseLabelSafeObjectNamespace); err != nil || (ok && v != objectNS) {
		return ErrDataEnvelopeInvalidNamespace
	}
	if v, ok, err := h.restInt(coseLabelSafeContentNamespace); err != nil || (ok && v != contentNS) {
		return ErrDataEnvelopeInvalidNamespace
	}
	return nil
}

// SealDataEnvelopeWithWrappingKey seals content and wraps the fresh CEK with wrappingKey (WrapKey),
// returning the envelope and the wrapped CEK EncString (SDK seal_with_wrapping_key).
func SealDataEnvelopeWithWrappingKey(cborContent []byte, ns DataEnvelopeNamespace, wrappingKey *SymmetricKey) (envelope, wrappedCEK string, err error) {
	envelope, cek, err := SealDataEnvelope(cborContent, ns)
	if err != nil {
		return "", "", err
	}
	wrappedCEK, err = WrapKey(cek, wrappingKey)
	if err != nil {
		return "", "", err
	}
	return envelope, wrappedCEK, nil
}

// OpenDataEnvelopeWithWrappingKey unwraps the CEK with wrappingKey and opens the envelope.
func OpenDataEnvelopeWithWrappingKey(envelope, wrappedCEK string, ns DataEnvelopeNamespace, wrappingKey *SymmetricKey) ([]byte, error) {
	cek, err := DecryptToKey(wrappedCEK, wrappingKey)
	if err != nil {
		return nil, ErrDataEnvelopeDecryption
	}
	return OpenDataEnvelope(envelope, ns, cek)
}

// ---------- sealed blob container ----------

// SealedBlobFormatVersion is the only supported SealedCipherBlob format_version.
const SealedBlobFormatVersion = 1

// SealedBlob is the JSON container stored in cipher.data / SendItem.data.
type SealedBlob struct {
	FormatVersion int    `json:"format_version"`
	WrappedCEK    string `json:"wrapped_cek"`
	Envelope      string `json:"envelope"`
}

// ParseSealedBlob parses the opaque blob string; it must be a JSON object with a "format_version"
// key (SDK SealedCipherBlob::from_opaque_string).
func ParseSealedBlob(s string) (*SealedBlob, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &probe); err != nil {
		return nil, errors.New("sealed blob: JSON decoding error")
	}
	if _, ok := probe["format_version"]; !ok {
		return nil, errors.New("sealed blob: JSON decoding error")
	}
	var b SealedBlob
	if err := json.Unmarshal([]byte(s), &b); err != nil {
		return nil, errors.New("sealed blob: JSON decoding error")
	}
	if _, ok := probe["wrapped_cek"]; !ok {
		return nil, errors.New("sealed blob: JSON decoding error")
	}
	if _, ok := probe["envelope"]; !ok {
		return nil, errors.New("sealed blob: JSON decoding error")
	}
	return &b, nil
}

// IsSealedBlob reports whether s (e.g. a cipher's "data" field) is a sealed blob.
func IsSealedBlob(s string) bool {
	_, err := ParseSealedBlob(s)
	return err == nil
}

// String serializes the container like serde_json ({"format_version":..,"wrapped_cek":..,"envelope":..}).
func (b *SealedBlob) String() string {
	out, _ := json.Marshal(b)
	return string(out)
}

// SealBlob seals versioned JSON content (e.g. {"version":"1","content":{...CipherBlobV1...}}) into
// the opaque sealed blob string, using the VaultItem namespace and wrapping the CEK with
// wrappingKey (the cipher key, or the send key for Item sends).
func SealBlob(versionedJSON []byte, wrappingKey *SymmetricKey) (string, error) {
	content, err := JSONToCBOR(versionedJSON)
	if err != nil {
		return "", err
	}
	envelope, wrapped, err := SealDataEnvelopeWithWrappingKey(content, DataEnvelopeNamespaceVaultItem, wrappingKey)
	if err != nil {
		return "", err
	}
	return (&SealedBlob{FormatVersion: SealedBlobFormatVersion, WrappedCEK: wrapped, Envelope: envelope}).String(), nil
}

// OpenBlob opens a sealed blob string with wrappingKey and returns its content as JSON (e.g.
// {"version":"1","content":{...}}).
func OpenBlob(s string, wrappingKey *SymmetricKey) ([]byte, error) {
	b, err := ParseSealedBlob(s)
	if err != nil {
		return nil, err
	}
	if b.FormatVersion != SealedBlobFormatVersion {
		return nil, fmt.Errorf("sealed blob: unsupported format version: %d", b.FormatVersion)
	}
	content, err := OpenDataEnvelopeWithWrappingKey(b.Envelope, b.WrappedCEK, DataEnvelopeNamespaceVaultItem, wrappingKey)
	if err != nil {
		return nil, err
	}
	return CBORToJSON(content)
}
