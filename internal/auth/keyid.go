package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// keyIDSize is KEY_ID_SIZE.
const keyIDSize = 16

// SymmetricKeyID returns the SDK key id of a symmetric key (SymmetricCryptoKey::key_id) in its
// wire form, lowercase hex of the 16 id bytes. COSE keys carry their id; an AES-256-CBC-HMAC key
// has none stored, so its id is derived as the first 16 bytes of its RFC 9679 thumbprint (SHA-256
// of the canonical CBOR map {1 (kty): 4 (Symmetric), -1 (k): enc_key || mac_key}). The legacy
// AES-256-CBC key has no id.
func SymmetricKeyID(k *crypto.SymmetricKey) (string, bool) {
	if k == nil {
		return "", false
	}
	if k.IsCose() {
		if len(k.KeyID) != keyIDSize {
			return "", false
		}
		return hex.EncodeToString(k.KeyID), true
	}
	if len(k.EncKey) != 32 || len(k.MacKey) != 32 {
		return "", false
	}
	// a2 (map, 2 entries) 01 04 (kty: Symmetric) 20 58 40 (k: 64 byte bstr)
	buf := append([]byte{0xa2, 0x01, 0x04, 0x20, 0x58, 0x40}, k.EncKey...)
	buf = append(buf, k.MacKey...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:keyIDSize]), true
}

// ParseKeyID validates a key id in its wire form (KeyId::from_str) and returns it normalized.
func ParseKeyID(s string) (string, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != keyIDSize {
		return "", false
	}
	return strings.ToLower(s), true
}
