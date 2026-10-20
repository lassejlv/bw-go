// Package sshkey is a Go port of the Bitwarden SDK's SSH key import (sdk-internal
// crates/bitwarden-ssh, src/import.rs and lib.rs): it parses PKCS#8 (optionally encrypted) and
// OpenSSH private keys and returns the key re-encoded as an unencrypted OpenSSH private key, its
// OpenSSH public key and its SHA256 fingerprint, byte-for-byte like the SDK (which builds on the
// RustCrypto ssh-key, pkcs8, pkcs5, rsa, ed25519 and p256/p384/p521 crates).
//
// Importing this package assigns importer.ImportSSHKey (the hook used by the 1Password 1pux and
// Keeper JSON importers); internal/importer/all blank-imports it.
package sshkey

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.ImportSSHKey = func(privateKey, password string) (*model.SshKeyView, error) {
		// The TS callers pass `undefined` (Rust None) when there is no password; the hook cannot
		// distinguish undefined from "", so "" means "no password".
		var pw *string
		if password != "" {
			pw = &password
		}
		data, err := ImportKey(privateKey, pw)
		if err != nil {
			return nil, err
		}
		return &model.SshKeyView{
			PrivateKey:     data.PrivateKey,
			PublicKey:      data.PublicKey,
			KeyFingerprint: data.Fingerprint,
		}, nil
	}
}

// Variant is the SshKeyImportError variant name (the `variant` property the SDK's WASM error
// carries).
type Variant string

// SshKeyImportError variants (bitwarden-ssh src/error.rs).
const (
	VariantParsing            Variant = "Parsing"
	VariantPasswordRequired   Variant = "PasswordRequired"
	VariantWrongPassword      Variant = "WrongPassword"
	VariantUnsupportedKeyType Variant = "UnsupportedKeyType"
)

// ImportError is bitwarden_ssh::error::SshKeyImportError.
type ImportError struct{ Kind Variant }

// Error returns the SDK's Display text.
func (e *ImportError) Error() string {
	switch e.Kind {
	case VariantParsing:
		return "Failed to parse key"
	case VariantPasswordRequired:
		return "Password required"
	case VariantWrongPassword:
		return "Wrong password"
	case VariantUnsupportedKeyType:
		return "Unsupported key type"
	}
	return string(e.Kind)
}

// Variant returns the variant name ("Parsing", "PasswordRequired", "WrongPassword",
// "UnsupportedKeyType"); importers use it the way TS reads `error.variant`.
func (e *ImportError) Variant() string { return string(e.Kind) }

// Is makes errors.Is(err, ErrParsing) etc. work.
func (e *ImportError) Is(target error) bool {
	t, ok := target.(*ImportError)
	return ok && t.Kind == e.Kind
}

// Sentinel errors, one per variant.
var (
	ErrParsing            = &ImportError{VariantParsing}
	ErrPasswordRequired   = &ImportError{VariantPasswordRequired}
	ErrWrongPassword      = &ImportError{VariantWrongPassword}
	ErrUnsupportedKeyType = &ImportError{VariantUnsupportedKeyType}
)

// KeyData is bitwarden_ssh::SshKeyData.
type KeyData struct {
	// PrivateKey is the unencrypted OpenSSH private key (LF line endings, trailing LF).
	PrivateKey string
	// PublicKey is the OpenSSH public key ("<alg> <base64>[ <comment>]").
	PublicKey string
	// Fingerprint is "SHA256:<unpadded base64>".
	Fingerprint string
}

const (
	labelPKCS8          = "PRIVATE KEY"
	labelPKCS8Encrypted = "ENCRYPTED PRIVATE KEY"
	labelOpenSSH        = "OPENSSH PRIVATE KEY"
)

// ImportKey is import::import_key: it imports a PKCS#8 or OpenSSH PEM private key. password is
// Option<String> (nil = None). Errors are *ImportError values.
func ImportKey(encodedKey string, password *string) (*KeyData, error) {
	enc, err := parseEncapsulation([]byte(encodedKey))
	if err != nil {
		return nil, ErrParsing
	}
	switch enc.label {
	case labelPKCS8:
		return importPKCS8Key(encodedKey, nil)
	case labelPKCS8Encrypted:
		if password == nil {
			return nil, ErrPasswordRequired
		}
		return importPKCS8Key(encodedKey, password)
	case labelOpenSSH:
		return importOpenSSHKey(encodedKey, password)
	}
	return nil, ErrUnsupportedKeyType
}

func importPKCS8Key(encodedKey string, password *string) (*KeyData, error) {
	data, err := parsePKCS8PEM(encodedKey, password)
	if err == ErrParsing {
		// Some exporters (e.g. 1Password's 1PUX) emit the base64 body on a single line, which
		// the strict RFC 7468 parser rejects. Re-wrap to 64-character lines and retry once.
		rewrapped, ok := rewrapPEM(encodedKey)
		if !ok {
			return nil, ErrParsing
		}
		return parsePKCS8PEM(rewrapped, password)
	}
	return data, err
}

func parsePKCS8PEM(encodedKey string, password *string) (*KeyData, error) {
	var der []byte
	if password != nil {
		label, doc, err := decodePEMDocument([]byte(encodedKey))
		if err != nil || label != labelPKCS8Encrypted {
			return nil, ErrParsing
		}
		plain, err := decryptEncryptedPrivateKeyInfo(doc, []byte(*password))
		if err != nil {
			return nil, err // ErrWrongPassword or ErrParsing
		}
		der = plain
	} else {
		enc, err := parseEncapsulation([]byte(encodedKey))
		if err != nil || enc.label != labelPKCS8 {
			return nil, ErrParsing
		}
		_, doc, err := decodePEMDocument([]byte(encodedKey))
		if err != nil {
			return nil, ErrParsing
		}
		der = doc
	}
	// from_pkcs8_der: the document must be a valid PrivateKeyInfo.
	if _, err := parsePrivateKeyInfo(der); err != nil {
		return nil, ErrParsing
	}
	return ImportPKCS8DERKey(der)
}

// ImportPKCS8DERKey is import::import_pkcs8_der_key: it imports a DER encoded PKCS#8
// PrivateKeyInfo (Ed25519, RSA or ECDSA P-256/P-384/P-521).
func ImportPKCS8DERKey(der []byte) (*KeyData, error) {
	info, err := parsePrivateKeyInfo(der)
	if err != nil {
		return nil, ErrParsing
	}
	var kp *keypair
	switch {
	case oidEqual(info.algorithm.oid, oidEd25519):
		kp, err = ed25519FromPKCS8(info)
		if err != nil {
			return nil, ErrParsing
		}
	case oidEqual(info.algorithm.oid, oidRSA):
		kp, err = rsaFromPKCS8(info)
		if err != nil {
			return nil, ErrParsing
		}
	case oidEqual(info.algorithm.oid, oidECPublicKey):
		kp, err = ecdsaFromPKCS8(info)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedKeyType
	}
	return toKeyData(&privateKey{keypair: kp})
}

func importOpenSSHKey(encodedKey string, password *string) (*KeyData, error) {
	pk, err := decodeOpenSSHPEM([]byte(encodedKey))
	if err != nil {
		if isAlgorithmUnknown(err) {
			return nil, ErrUnsupportedKeyType
		}
		return nil, ErrParsing
	}
	if !isSupportedAlgorithm(pk.publicKind) {
		return nil, ErrUnsupportedKeyType
	}
	if pk.encrypted() {
		if password == nil {
			return nil, ErrPasswordRequired
		}
		dec, err := pk.decrypt([]byte(*password))
		if err != nil {
			return nil, ErrWrongPassword
		}
		pk = dec
	}
	return toKeyData(pk)
}

// isSupportedAlgorithm: Ed25519, RSA and ECDSA keys can be used once they are in the vault.
func isSupportedAlgorithm(k keyKind) bool {
	return k == kindEd25519 || k == kindRSA || k == kindECDSA
}

// toKeyData is ssh_private_key_to_data.
func toKeyData(pk *privateKey) (*KeyData, error) {
	priv, err := pk.toOpenSSH()
	if err != nil {
		return nil, ErrParsing
	}
	return &KeyData{
		PrivateKey:  priv,
		PublicKey:   pk.keypair.publicKeyString(pk.comment),
		Fingerprint: pk.keypair.fingerprint(),
	}, nil
}
