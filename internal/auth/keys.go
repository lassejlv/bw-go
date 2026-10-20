package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// ErrKeyConnector is returned after a failed key connector request (handleKeyConnectorError).
var ErrKeyConnector = errors.New("Key Connector error")

// IsLegacyUserKey reports whether the master-key-wrapped user key needs the (no longer supported)
// encryption key migration: no user key at all, or a legacy AesCbc256_B64 (type 0) one.
func IsLegacyUserKey(encUserKey string) bool {
	if encUserKey == "" {
		return true
	}
	e, err := crypto.ParseEncString(encUserKey)
	return err == nil && e.Type == crypto.AesCbc256_B64
}

// MakeMasterKey derives the master key like LegacyCompatKeyService.makeMasterKey, which
// normalizes the email/salt before deriving.
func MakeMasterKey(password, email string, kdf crypto.KdfConfig) ([]byte, error) {
	return crypto.MakeMasterKey(password, NormalizeEmail(email), kdf)
}

// DecryptUserKeyWithMasterKey unwraps the user key with the (stretched) master key. Works for v1
// (AES) and v2 (COSE) user keys; the key bytes are interpreted by crypto.DecryptToKey.
func DecryptUserKeyWithMasterKey(masterKey []byte, encUserKey string) (*crypto.SymmetricKey, error) {
	if encUserKey == "" {
		return nil, errors.New("No master key encrypted user key found.")
	}
	return crypto.DecryptToKey(encUserKey, crypto.StretchKey(masterKey))
}

// UnlockWithMasterPassword derives the master key for acct and unwraps its user key. The master
// key is returned too (key connector migration needs it).
func UnlockWithMasterPassword(acct *state.Account, password string) (*crypto.SymmetricKey, []byte, error) {
	if password == "" {
		return nil, nil, errors.New("Master password is required")
	}
	if acct.EncUserKey == "" || !acct.HasMasterPassword && acct.UsesKeyConnector {
		return nil, nil, errors.New("Master password unlock data is required is null or undefined.")
	}
	salt := acct.KdfSalt
	if salt == "" {
		salt = acct.Email
	}
	mk, err := MakeMasterKey(password, salt, acct.Kdf)
	if err != nil {
		return nil, nil, err
	}
	uk, err := DecryptUserKeyWithMasterKey(mk, acct.EncUserKey)
	if err != nil {
		return nil, nil, errors.New("Invalid master password.")
	}
	if _, err := UnlockAccountKeys(ParseAccountKeys(GetAccountKeys(nil, acct)), acct.EncPrivateKey, uk); err != nil {
		return nil, nil, err
	}
	return uk, mk, nil
}

// UnlockAccountKeys validates the account cryptographic state against the user key, like the
// SDK's WrappedAccountCryptographicState::set_to_context: for v2 accounts the private and signing
// keys must decrypt and the signed public key and security state must verify; for v1 accounts the
// user key must be an AES-256-CBC-HMAC key. fallbackPrivateKey (the deprecated PrivateKey /
// EncPrivateKey) is used when keys carries no wrapped private key. Accounts without any private
// key (not yet initialized) are accepted as is. The user key must only be stored after this
// succeeds.
func UnlockAccountKeys(keys *AccountKeys, fallbackPrivateKey string, userKey *crypto.SymmetricKey) (*crypto.AccountKeys, error) {
	wrappedPrivateKey := keys.WrappedPrivateKey()
	if wrappedPrivateKey == "" {
		wrappedPrivateKey = fallbackPrivateKey
	}
	var wrappedSigningKey, signedPublicKey, signedSecurityState string
	if keys != nil {
		if keys.PublicKeyEncryptionKeyPair != nil {
			signedPublicKey = keys.PublicKeyEncryptionKeyPair.SignedPublicKey
		}
		if keys.SignatureKeyPair != nil {
			wrappedSigningKey = keys.SignatureKeyPair.WrappedSigningKey
		}
		if keys.SecurityState != nil {
			signedSecurityState = keys.SecurityState.SecurityState
		}
	}
	if wrappedPrivateKey == "" && wrappedSigningKey == "" && signedSecurityState == "" {
		return nil, nil
	}
	acc, err := crypto.UnlockAccountCryptographicState(userKey, wrappedPrivateKey, wrappedSigningKey, signedPublicKey, signedSecurityState)
	if err != nil {
		return nil, errors.New("Unable to unlock the account cryptographic state: " + err.Error())
	}
	return acc, nil
}

type keyConnectorUserKey struct {
	Key string `json:"key"`
}

// GetMasterKeyFromKeyConnector fetches the master key from `{keyConnectorUrl}/user-keys`.
func GetMasterKeyFromKeyConnector(c *api.Client, keyConnectorURL string) ([]byte, error) {
	var r keyConnectorUserKey
	if err := c.Send("GET", "/user-keys", nil, true, &r, &api.RequestOptions{BaseURL: trimSlash(keyConnectorURL)}); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(r.Key)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// PostUserKeyToKeyConnector posts the master key to `{keyConnectorUrl}/user-keys`.
func PostUserKeyToKeyConnector(c *api.Client, keyConnectorURL string, masterKey []byte) error {
	body := keyConnectorUserKey{Key: base64.StdEncoding.EncodeToString(masterKey)}
	return c.Send("POST", "/user-keys", body, true, nil, &api.RequestOptions{BaseURL: trimSlash(keyConnectorURL)})
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// UnlockWithKeyConnector fetches the key connector key and unwraps the user key with it
// (UnlockService.unlockWithKeyConnector). On a key connector failure the user is logged out.
// The account cryptographic state is validated with UnlockAccountKeys before the key is returned.
func UnlockWithKeyConnector(a *app.App, keyConnectorURL, encUserKey string, keys *AccountKeys, fallbackPrivateKey string) (*crypto.SymmetricKey, error) {
	mk, err := GetMasterKeyFromKeyConnector(a.API, keyConnectorURL)
	if err != nil {
		_ = a.Logout()
		return nil, ErrKeyConnector
	}
	uk, err := DecryptUserKeyWithMasterKey(mk, encUserKey)
	if err != nil {
		return nil, err
	}
	if _, err := UnlockAccountKeys(keys, fallbackPrivateKey, uk); err != nil {
		return nil, err
	}
	return uk, nil
}

// NewSsoUserKeyConnectorConversion mirrors NewSsoUserKeyConnectorConversion.
type NewSsoUserKeyConnectorConversion struct {
	KdfConfig       crypto.KdfConfig
	KeyConnectorURL string
	OrganizationID  string
}

type keysRequest struct {
	PublicKey           string `json:"publicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

type setKeyConnectorKeyRequest struct {
	Key            string      `json:"key"`
	Kdf            int         `json:"kdf"`
	KdfIterations  int         `json:"kdfIterations"`
	KdfMemory      *int        `json:"kdfMemory,omitempty"`
	KdfParallelism *int        `json:"kdfParallelism,omitempty"`
	OrgIdentifier  string      `json:"orgIdentifier"`
	Keys           keysRequest `json:"keys"`
}

// MakeKeyPair creates an RSA-2048 key pair and returns the base64 SPKI public key and the PKCS8
// private key encrypted with key.
func MakeKeyPair(key *crypto.SymmetricKey) (pub string, encPriv string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	enc, err := crypto.Encrypt(privDer, key)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pubDer), enc.String(), nil
}

// ConvertNewSsoUserToKeyConnector enrolls a freshly JIT-provisioned SSO user into key connector
// (KeyConnectorService.convertNewSsoUserToKeyConnectorV1) and unlocks the vault.
func ConvertNewSsoUserToKeyConnector(a *app.App, conv *NewSsoUserKeyConnectorConversion) error {
	acct := a.ActiveAccount()
	if acct == nil {
		return errors.New("Key Connector conversion not found")
	}
	password := crypto.GenerateKey().B64()
	mk, err := MakeMasterKey(password, acct.Email, conv.KdfConfig)
	if err != nil {
		return err
	}
	userKey := crypto.GenerateKey()
	encUserKey, err := crypto.Encrypt(userKey.Bytes(), crypto.StretchKey(mk))
	if err != nil {
		return err
	}
	pub, encPriv, err := MakeKeyPair(userKey)
	if err != nil {
		return err
	}
	if err := PostUserKeyToKeyConnector(a.API, conv.KeyConnectorURL, mk); err != nil {
		_ = a.Logout()
		return ErrKeyConnector
	}
	req := setKeyConnectorKeyRequest{
		Key:           encUserKey.String(),
		Kdf:           int(conv.KdfConfig.Type),
		KdfIterations: conv.KdfConfig.Iterations,
		OrgIdentifier: conv.OrganizationID,
		Keys:          keysRequest{PublicKey: pub, EncryptedPrivateKey: encPriv},
	}
	if conv.KdfConfig.Type == crypto.KdfArgon2id {
		req.KdfMemory, req.KdfParallelism = conv.KdfConfig.Memory, conv.KdfConfig.Parallelism
	}
	if err := a.API.Send("POST", "/accounts/set-key-connector-key", req, true, nil, nil); err != nil {
		return err
	}
	if err := a.UpdateAccount(func(acct *state.Account) error {
		acct.EncUserKey = encUserKey.String()
		acct.EncPrivateKey = encPriv
		acct.Kdf = conv.KdfConfig
		acct.UsesKeyConnector = true
		acct.KeyConnectorURL = conv.KeyConnectorURL
		acct.HasMasterPassword = false
		return nil
	}); err != nil {
		return err
	}
	return a.SetUserKey(userKey)
}

// MigrateUserToKeyConnector moves an existing master password user to key connector
// (KeyConnectorService.migrateUser): the master key is stored in key connector and the server
// account is converted.
func MigrateUserToKeyConnector(a *app.App, keyConnectorURL string, masterKey []byte) error {
	if err := PostUserKeyToKeyConnector(a.API, keyConnectorURL, masterKey); err != nil {
		_ = a.Logout()
		return ErrKeyConnector
	}
	if err := a.API.Send("POST", "/accounts/convert-to-key-connector", nil, true, nil, nil); err != nil {
		_ = a.Logout()
		return ErrKeyConnector
	}
	return a.UpdateAccount(func(acct *state.Account) error {
		acct.UsesKeyConnector = true
		acct.HasMasterPassword = false
		acct.KeyConnectorURL = keyConnectorURL
		return nil
	})
}

// Organization is the subset of a synced profile organization needed for key connector decisions.
type Organization struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Type                int    `json:"type"`
	KeyConnectorEnabled bool   `json:"keyConnectorEnabled"`
	KeyConnectorURL     string `json:"keyConnectorUrl"`
	IsProviderUser      bool   `json:"-"`
}

// Organization user types.
const (
	OrgUserOwner = 0
	OrgUserAdmin = 1
)

// ProfileOrganizations returns the organizations of the synced profile (organizationsNew ??
// organizations, merged with providerOrganizations like DefaultSyncService).
func ProfileOrganizations(acct *state.Account) []Organization {
	if acct == nil || len(acct.Vault.Profile) == 0 {
		return nil
	}
	var p struct {
		Organizations         []Organization  `json:"organizations"`
		OrganizationsNew      *[]Organization `json:"organizationsNew"`
		ProviderOrganizations []Organization  `json:"providerOrganizations"`
	}
	if err := json.Unmarshal(acct.Vault.Profile, &p); err != nil {
		return nil
	}
	src := p.Organizations
	if p.OrganizationsNew != nil {
		src = *p.OrganizationsNew
	}
	out := append([]Organization(nil), src...)
	for _, po := range p.ProviderOrganizations {
		found := false
		for i := range out {
			if out[i].ID == po.ID {
				out[i].IsProviderUser = true
				found = true
			}
		}
		if !found {
			po.IsProviderUser = true
			out = append(out, po)
		}
	}
	return out
}

// ManagingOrganization mirrors KeyConnectorService.findManagingOrganization.
func ManagingOrganization(acct *state.Account) *Organization {
	for _, o := range ProfileOrganizations(acct) {
		if o.KeyConnectorEnabled && o.Type != OrgUserAdmin && o.Type != OrgUserOwner && !o.IsProviderUser {
			o := o
			return &o
		}
	}
	return nil
}

// IsExternalLogin reports whether the access token was issued for an SSO login (amr contains
// "external"), like TokenService.getIsExternal.
func IsExternalLogin(accessToken string) bool {
	claims, err := api.DecodeJWT(accessToken)
	if err != nil {
		return false
	}
	amr, _ := claims["amr"].([]any)
	for _, v := range amr {
		if s, _ := v.(string); s == "external" {
			return true
		}
	}
	return false
}

// ConvertAccountRequired mirrors KeyConnectorService.convertAccountRequired$.
func ConvertAccountRequired(acct *state.Account) bool {
	if acct == nil || acct.AccessToken == "" || acct.UsesKeyConnector {
		return false
	}
	return IsExternalLogin(acct.AccessToken) && ManagingOrganization(acct) != nil
}
