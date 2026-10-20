package bitwarden

import (
	"encoding/json"
	"errors"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// ErrBlobCipher is returned by LegacyDecryptor for v2 "blob" ciphers (content sealed in `data`),
// which only the vault package's decryptor understands.
var ErrBlobCipher = errors.New("this export contains v2 (blob) items, which require the vault decryptor")

// LegacyDecryptor is an importer.Decryptor for account-encrypted exports whose items use
// field-level EncStrings (every export written before blob ciphers). It wraps the account keys
// and decrypts each field with the item's cipher key (when present) or the user/organization key.
// The import command should prefer the vault package's full cipher decryption when available.
type LegacyDecryptor struct {
	importer.AccountKeys
}

// DecryptExportCipher implements importer.Decryptor.
func (d LegacyDecryptor) DecryptExportCipher(item json.RawMessage, organizationID string) (*model.CipherView, error) {
	c, err := parseCipherExport(item)
	if err != nil {
		return nil, err
	}
	if c.Data != nil {
		return nil, ErrBlobCipher
	}
	var key *crypto.SymmetricKey
	if organizationID != "" {
		if key, err = d.OrgKey(organizationID); err != nil {
			return nil, err
		}
		if key == nil {
			return nil, errors.New("no key for organization " + organizationID)
		}
	} else if key, err = d.UserKey(); err != nil {
		return nil, err
	}
	if c.Key != nil && *c.Key != "" {
		if key, err = crypto.DecryptToKey(string(*c.Key), key); err != nil {
			return nil, err
		}
	}
	return c.toView(func(s string) (string, error) { return crypto.DecryptString(s, key) })
}
