package vault

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// ErrNoKey is returned when the key needed to decrypt/encrypt an item is not available.
var ErrNoKey = errors.New("No key available for decryption.")

// Keys resolves the keys of the active account, following key.service.ts semantics:
// the user key, the RSA private key (wrapped by the user key), organization keys (RSA-OAEP
// encapsulated with the user's public key, or wrapped by a provider key for provider orgs) and
// provider keys (RSA-OAEP encapsulated).
type Keys struct {
	userKey    *crypto.SymmetricKey
	privateKey *rsa.PrivateKey
	privErr    error
	orgKeys    map[string]*crypto.SymmetricKey
	orgErrs    map[string]error
	provKeys   map[string]*crypto.SymmetricKey
	// SecurityVersion is the account security state version (2 = v2 encryption account).
	SecurityVersion int
}

// NewKeys builds the key set. encPrivateKey is the account's private key wrapped by the user key
// (state.Account.EncPrivateKey, type 2 or 7); accountKeys is the raw AccountKeys JSON
// (state.Account.AccountKeys, may be nil: the profile's accountKeys is used then); profile may be
// nil. Organization keys that fail to decrypt are recorded and reported by OrgKey; they don't
// fail construction (upstream skips such orgs).
func NewKeys(userKey *crypto.SymmetricKey, encPrivateKey string, accountKeys json.RawMessage, profile *Profile) *Keys {
	var ak *AccountKeys
	if len(accountKeys) > 0 && string(accountKeys) != "null" {
		ak = &AccountKeys{}
		if json.Unmarshal(accountKeys, ak) != nil {
			ak = nil
		}
	}
	if ak == nil && profile != nil {
		ak = profile.AccountKeys
	}
	k := &Keys{
		userKey:         userKey,
		orgKeys:         map[string]*crypto.SymmetricKey{},
		orgErrs:         map[string]error{},
		provKeys:        map[string]*crypto.SymmetricKey{},
		SecurityVersion: securityVersion(ak),
	}
	if encPrivateKey == "" {
		if ak != nil && ak.PublicKeyEncryptionKeyPair != nil && ak.PublicKeyEncryptionKeyPair.WrappedPrivateKey != nil {
			encPrivateKey = *ak.PublicKeyEncryptionKeyPair.WrappedPrivateKey
		} else if profile != nil && profile.PrivateKey != nil {
			encPrivateKey = *profile.PrivateKey
		}
	}
	if encPrivateKey != "" && userKey != nil {
		k.privateKey, k.privErr = decryptPrivateKey(encPrivateKey, userKey)
	} else {
		k.privErr = errors.New("no private key available")
	}
	if profile == nil {
		return k
	}
	if k.privateKey != nil {
		for _, p := range profile.Providers {
			if p.Key == nil {
				continue
			}
			if b, err := crypto.RsaDecrypt(*p.Key, k.privateKey); err == nil {
				if pk, err := crypto.NewSymmetricKey(b); err == nil {
					k.provKeys[p.ID] = pk
				}
			}
		}
	}
	for _, o := range profile.MemberOrganizations() {
		k.addOrgKey(o.ID, o.Key, nil)
	}
	for _, o := range profile.ProviderOrganizations {
		if _, ok := k.orgKeys[o.ID]; ok {
			continue
		}
		if _, ok := k.orgErrs[o.ID]; ok {
			continue
		}
		k.addOrgKey(o.ID, o.Key, o.ProviderID)
	}
	return k
}

func decryptPrivateKey(enc string, userKey *crypto.SymmetricKey) (*rsa.PrivateKey, error) {
	return crypto.DecryptPrivateKey(enc, userKey)
}

// securityVersion returns the account security state version: the (unverified) version inside
// the signed security state, else the explicit securityVersion, else 2 when a signature key pair
// exists, else 1.
func securityVersion(ak *AccountKeys) int {
	if ak == nil {
		return 1
	}
	if s := ak.SecurityState; s != nil {
		if s.SecurityState != nil && *s.SecurityState != "" {
			if v, err := crypto.UnverifiedSecurityStateVersion(*s.SecurityState); err == nil {
				return int(v)
			}
		}
		if s.SecurityVersion != nil {
			return *s.SecurityVersion
		}
	}
	if len(ak.SignatureKeyPair) > 0 && string(ak.SignatureKeyPair) != "null" {
		return 2
	}
	return 1
}

func (k *Keys) addOrgKey(orgID string, encKey *string, providerID *string) {
	if encKey == nil || *encKey == "" {
		k.orgErrs[orgID] = errors.New("organization key missing")
		return
	}
	if providerID != nil && *providerID != "" {
		pk := k.provKeys[*providerID]
		if pk == nil {
			k.orgErrs[orgID] = errors.New("provider key not available")
			return
		}
		ok, err := crypto.DecryptToKey(*encKey, pk)
		if err != nil {
			k.orgErrs[orgID] = fmt.Errorf("Failed to decrypt organization key: %w", err)
			return
		}
		k.orgKeys[orgID] = ok
		return
	}
	if k.privateKey == nil {
		k.orgErrs[orgID] = k.privErr
		return
	}
	b, err := crypto.RsaDecrypt(*encKey, k.privateKey)
	if err != nil {
		k.orgErrs[orgID] = err
		return
	}
	ok, err := crypto.NewSymmetricKey(b)
	if err != nil {
		k.orgErrs[orgID] = err
		return
	}
	k.orgKeys[orgID] = ok
}

// UserKey returns the user key.
func (k *Keys) UserKey() *crypto.SymmetricKey { return k.userKey }

// PrivateKey returns the user's RSA private key.
func (k *Keys) PrivateKey() (*rsa.PrivateKey, error) {
	if k.privateKey == nil {
		return nil, k.privErr
	}
	return k.privateKey, nil
}

// OrgKey returns the organization key.
func (k *Keys) OrgKey(orgID string) (*crypto.SymmetricKey, error) {
	if key := k.orgKeys[orgID]; key != nil {
		return key, nil
	}
	if err := k.orgErrs[orgID]; err != nil {
		return nil, err
	}
	return nil, ErrNoKey
}

// HasOrgKey reports whether the organization key is available.
func (k *Keys) HasOrgKey(orgID string) bool { return k.orgKeys[orgID] != nil }

// OrgKeys returns all decrypted organization keys.
func (k *Keys) OrgKeys() map[string]*crypto.SymmetricKey {
	out := make(map[string]*crypto.SymmetricKey, len(k.orgKeys))
	for id, key := range k.orgKeys {
		out[id] = key
	}
	return out
}

// ProviderKey returns a provider key.
func (k *Keys) ProviderKey(providerID string) (*crypto.SymmetricKey, error) {
	if key := k.provKeys[providerID]; key != nil {
		return key, nil
	}
	return nil, ErrNoKey
}

// SetOrgKey installs an organization key (e.g. from an organization fetched outside sync).
func (k *Keys) SetOrgKey(orgID string, key *crypto.SymmetricKey) {
	k.orgKeys[orgID] = key
	delete(k.orgErrs, orgID)
}

// OwnerKey returns the key that owns items of the given organization (nil/"" = user key).
func (k *Keys) OwnerKey(orgID *string) (*crypto.SymmetricKey, error) {
	if orgID == nil || *orgID == "" {
		if k.userKey == nil {
			return nil, ErrNoKey
		}
		return k.userKey, nil
	}
	return k.OrgKey(*orgID)
}

// CipherKey returns the key that encrypts the cipher's fields: the per-cipher key (cipher.key,
// wrapped by the user/org key) when present, otherwise the user/org key itself.
func (k *Keys) CipherKey(c *Cipher) (*crypto.SymmetricKey, error) {
	owner, err := k.OwnerKey(c.OrganizationID)
	if err != nil {
		return nil, err
	}
	if c.Key == nil || *c.Key == "" {
		return owner, nil
	}
	return crypto.DecryptToKey(*c.Key, owner)
}

// wrapKey wraps a symmetric key like the SDK's wrap_symmetric_key.
func wrapKey(key, wrapping *crypto.SymmetricKey) (string, error) {
	return crypto.WrapKey(key, wrapping)
}
