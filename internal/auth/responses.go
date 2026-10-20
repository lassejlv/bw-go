package auth

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// NewDeviceVerificationRequiredMessage is ErrorModel.Message for device verification responses.
const NewDeviceVerificationRequiredMessage = "new device verification required"

// KdfConfigResponse mirrors KdfConfigResponse (KdfType/Iterations/Memory/Parallelism).
type KdfConfigResponse struct {
	KdfType     *int `json:"KdfType"`
	Iterations  *int `json:"Iterations"`
	Memory      *int `json:"Memory"`
	Parallelism *int `json:"Parallelism"`
}

// ToKdfConfig validates the response like the KdfConfigResponse constructor.
func (k *KdfConfigResponse) ToKdfConfig() (crypto.KdfConfig, error) {
	if k == nil || k.KdfType == nil {
		return crypto.KdfConfig{}, errors.New("KDF config response does not contain a valid KDF type")
	}
	if k.Iterations == nil {
		return crypto.KdfConfig{}, errors.New("KDF config response does not contain a valid number of iterations")
	}
	cfg := crypto.KdfConfig{Type: crypto.KdfType(*k.KdfType), Iterations: *k.Iterations}
	if cfg.Type == crypto.KdfArgon2id {
		if k.Memory == nil {
			return cfg, errors.New("KDF config response does not contain a valid memory size for Argon2id")
		}
		if k.Parallelism == nil {
			return cfg, errors.New("KDF config response does not contain a valid parallelism for Argon2id")
		}
		m, p := *k.Memory, *k.Parallelism
		cfg.Memory, cfg.Parallelism = &m, &p
	}
	return cfg, nil
}

// ValidateKdfConfigForPrelogin mirrors validateKdfConfigForPrelogin (downgrade protection).
func ValidateKdfConfigForPrelogin(cfg crypto.KdfConfig) error {
	switch cfg.Type {
	case crypto.KdfPBKDF2:
		if cfg.Iterations < 5000 {
			return errors.New("PBKDF2 iterations must be at least 5000, but was " + strconv.Itoa(cfg.Iterations) +
				"; possible pre-login downgrade attack detected.")
		}
	case crypto.KdfArgon2id:
		if cfg.Iterations < 2 {
			return errors.New("Argon2 iterations must be at least 2, but was " + strconv.Itoa(cfg.Iterations) +
				"; possible pre-login downgrade attack detected.")
		}
		if cfg.Memory == nil || *cfg.Memory < 16 {
			m := 0
			if cfg.Memory != nil {
				m = *cfg.Memory
			}
			return errors.New("Argon2 memory must be at least 16 MiB, but was " + strconv.Itoa(m) +
				" MiB; possible pre-login downgrade attack detected.")
		}
		if cfg.Parallelism == nil || *cfg.Parallelism < 1 {
			p := 0
			if cfg.Parallelism != nil {
				p = *cfg.Parallelism
			}
			return errors.New("Argon2 parallelism must be at least 1, but was " + strconv.Itoa(p) +
				"; possible pre-login downgrade attack detected.")
		}
	default:
		return errors.New("Unsupported KDF type")
	}
	return nil
}

// MasterPasswordPolicyResponse mirrors MasterPasswordPolicyResponse.
type MasterPasswordPolicyResponse struct {
	MinComplexity  int  `json:"MinComplexity"`
	MinLength      int  `json:"MinLength"`
	RequireUpper   bool `json:"RequireUpper"`
	RequireLower   bool `json:"RequireLower"`
	RequireNumbers bool `json:"RequireNumbers"`
	RequireSpecial bool `json:"RequireSpecial"`
	EnforceOnLogin bool `json:"EnforceOnLogin"`
}

// MasterPasswordUnlockResponse mirrors MasterPasswordUnlockResponse.
type MasterPasswordUnlockResponse struct {
	Salt                      string             `json:"Salt"`
	Kdf                       *KdfConfigResponse `json:"Kdf"`
	MasterKeyEncryptedUserKey string             `json:"MasterKeyEncryptedUserKey"`
}

// TrustedDeviceOption mirrors TrustedDeviceUserDecryptionOptionResponse.
type TrustedDeviceOption struct {
	HasAdminApproval                 bool   `json:"HasAdminApproval"`
	HasLoginApprovingDevice          bool   `json:"HasLoginApprovingDevice"`
	HasManageResetPasswordPermission bool   `json:"HasManageResetPasswordPermission"`
	IsTdeOffboarding                 bool   `json:"IsTdeOffboarding"`
	EncryptedPrivateKey              string `json:"EncryptedPrivateKey"`
	EncryptedUserKey                 string `json:"EncryptedUserKey"`
}

// KeyConnectorOption mirrors KeyConnectorUserDecryptionOptionResponse.
type KeyConnectorOption struct {
	KeyConnectorURL string `json:"KeyConnectorUrl"`
}

// UserDecryptionOptionsResponse mirrors UserDecryptionOptionsResponse.
type UserDecryptionOptionsResponse struct {
	HasMasterPassword    bool                          `json:"HasMasterPassword"`
	MasterPasswordUnlock *MasterPasswordUnlockResponse `json:"MasterPasswordUnlock"`
	TrustedDeviceOption  *TrustedDeviceOption          `json:"TrustedDeviceOption"`
	KeyConnectorOption   *KeyConnectorOption           `json:"KeyConnectorOption"`
	WebAuthnPrfOption    *json.RawMessage              `json:"WebAuthnPrfOption"`
}

// AccountKeys mirrors PrivateKeysResponseModel ("AccountKeys" / profile "accountKeys").
type AccountKeys struct {
	PublicKeyEncryptionKeyPair *struct {
		WrappedPrivateKey string `json:"wrappedPrivateKey"`
		PublicKey         string `json:"publicKey"`
		SignedPublicKey   string `json:"signedPublicKey"`
	} `json:"publicKeyEncryptionKeyPair"`
	SignatureKeyPair *struct {
		WrappedSigningKey string `json:"wrappedSigningKey"`
		VerifyingKey      string `json:"verifyingKey"`
	} `json:"signatureKeyPair"`
	SecurityState *struct {
		SecurityState   string `json:"securityState"`
		SecurityVersion int    `json:"securityVersion"`
	} `json:"securityState"`
}

// IsV2Encryption reports whether the account uses v2 (signing key + security state) encryption.
func (k *AccountKeys) IsV2Encryption() bool {
	return k != nil && k.SignatureKeyPair != nil && k.SecurityState != nil
}

// WrappedPrivateKey returns the user-key wrapped private key, or "".
func (k *AccountKeys) WrappedPrivateKey() string {
	if k == nil || k.PublicKeyEncryptionKeyPair == nil {
		return ""
	}
	return k.PublicKeyEncryptionKeyPair.WrappedPrivateKey
}

// TokenResponse mirrors IdentityTokenResponse.
type TokenResponse struct {
	AccessToken           string                         `json:"access_token"`
	ExpiresIn             *int                           `json:"expires_in"`
	RefreshToken          string                         `json:"refresh_token"`
	TokenType             string                         `json:"token_type"`
	PrivateKey            string                         `json:"PrivateKey"`
	AccountKeysRaw        json.RawMessage                `json:"AccountKeys"`
	Key                   string                         `json:"Key"`
	TwoFactorToken        string                         `json:"TwoFactorToken"`
	Kdf                   *int                           `json:"Kdf"`
	KdfIterations         *int                           `json:"KdfIterations"`
	KdfMemory             *int                           `json:"KdfMemory"`
	KdfParallelism        *int                           `json:"KdfParallelism"`
	ForcePasswordReset    bool                           `json:"ForcePasswordReset"`
	ApiUseKeyConnector    bool                           `json:"ApiUseKeyConnector"`
	MasterPasswordPolicy  *MasterPasswordPolicyResponse  `json:"MasterPasswordPolicy"`
	UserDecryptionOptions *UserDecryptionOptionsResponse `json:"UserDecryptionOptions"`

	AccountKeys *AccountKeys     `json:"-"`
	KdfConfig   crypto.KdfConfig `json:"-"`
}

// HasMasterKeyEncryptedUserKey mirrors hasMasterKeyEncryptedUserKey.
func (t *TokenResponse) HasMasterKeyEncryptedUserKey() bool { return t.Key != "" }

// MasterKeyWrappedUserKey returns userDecryptionOptions.masterPasswordUnlock.masterKeyWrappedUserKey,
// falling back to the deprecated Key property.
func (t *TokenResponse) MasterKeyWrappedUserKey() string {
	if o := t.UserDecryptionOptions; o != nil && o.MasterPasswordUnlock != nil && o.MasterPasswordUnlock.MasterKeyEncryptedUserKey != "" {
		return o.MasterPasswordUnlock.MasterKeyEncryptedUserKey
	}
	return t.Key
}

// CanUnlockWithKeyConnector mirrors canUnlockWithKeyConnector.
func (t *TokenResponse) CanUnlockWithKeyConnector() bool {
	o := t.UserDecryptionOptions
	return o != nil && o.KeyConnectorOption != nil && !o.HasMasterPassword && t.HasMasterKeyEncryptedUserKey()
}

// WrappedPrivateKey returns AccountKeys.publicKeyEncryptionKeyPair.wrappedPrivateKey, falling back
// to the deprecated PrivateKey property.
func (t *TokenResponse) WrappedPrivateKey() string {
	if k := t.AccountKeys.WrappedPrivateKey(); k != "" {
		return k
	}
	return t.PrivateKey
}

// TwoFactorResponse mirrors IdentityTwoFactorResponse.
type TwoFactorResponse struct {
	TwoFactorProviders      json.RawMessage               `json:"TwoFactorProviders"`
	TwoFactorProviders2     map[string]json.RawMessage    `json:"TwoFactorProviders2"`
	SsoEmail2faSessionToken string                        `json:"SsoEmail2faSessionToken"`
	Email                   string                        `json:"Email"`
	MasterPasswordPolicy    *MasterPasswordPolicyResponse `json:"MasterPasswordPolicy"`
}

// Providers returns the provider types present in TwoFactorProviders2, sorted.
func (t *TwoFactorResponse) Providers() []int {
	var out []int
	for k := range t.TwoFactorProviders2 {
		if n, err := strconv.Atoi(k); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// SsoRequiredResponse mirrors IdentitySsoRequiredResponse.
type SsoRequiredResponse struct {
	SsoOrganizationIdentifier string `json:"SsoOrganizationIdentifier"`
}

// IdentityResponse is the classified result of a /connect/token request: exactly one field is set.
type IdentityResponse struct {
	Token              *TokenResponse
	TwoFactor          *TwoFactorResponse
	DeviceVerification bool
	SsoRequired        *SsoRequiredResponse
}

// ParseIdentityResult classifies a raw identity response like ApiService.postIdentityToken and
// validates token responses like the IdentityTokenResponse constructor.
func ParseIdentityResult(res *api.IdentityResult) (*IdentityResponse, error) {
	if res.Body != nil {
		switch {
		case res.Status == 200:
			t, err := ParseTokenResponse(res.Raw)
			if err != nil {
				return nil, err
			}
			return &IdentityResponse{Token: t}, nil
		case res.Status == 400:
			if tf, ok := api.GetProp(res.Body, "TwoFactorProviders2").(map[string]any); ok && len(tf) > 0 {
				var r TwoFactorResponse
				if err := json.Unmarshal(res.Raw, &r); err != nil {
					return nil, err
				}
				return &IdentityResponse{TwoFactor: &r}, nil
			}
			if em, ok := api.GetProp(res.Body, "ErrorModel").(map[string]any); ok {
				if msg, _ := api.GetProp(em, "Message").(string); msg == NewDeviceVerificationRequiredMessage {
					return &IdentityResponse{DeviceVerification: true}, nil
				}
			}
			if s, ok := api.GetProp(res.Body, "SsoOrganizationIdentifier").(string); ok && s != "" {
				return &IdentityResponse{SsoRequired: &SsoRequiredResponse{SsoOrganizationIdentifier: s}}, nil
			}
		}
	}
	return nil, api.IdentityError(res)
}

// ParseTokenResponse parses and validates a successful identity token response.
func ParseTokenResponse(raw []byte) (*TokenResponse, error) {
	var t TokenResponse
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if t.AccessToken == "" {
		return nil, errors.New("Identity response does not contain a valid access token")
	}
	if t.TokenType == "" {
		return nil, errors.New("Identity response does not contain a valid token type")
	}
	if len(t.AccountKeysRaw) > 0 && string(t.AccountKeysRaw) != "null" {
		var k AccountKeys
		if err := json.Unmarshal(t.AccountKeysRaw, &k); err != nil {
			return nil, err
		}
		if k.PublicKeyEncryptionKeyPair == nil {
			return nil, errors.New("Response must contain a valid publicKeyEncryptionKeyPair")
		}
		if (k.SignatureKeyPair == nil) != (k.SecurityState == nil) {
			return nil, errors.New("Both signatureKeyPair and securityState must be present or absent together")
		}
		t.AccountKeys = &k
	} else {
		t.AccountKeysRaw = nil
	}
	if t.Kdf == nil {
		return nil, errors.New("kdf is required on IdentityTokenResponse")
	}
	iter := 0
	if t.KdfIterations != nil {
		iter = *t.KdfIterations
	}
	switch crypto.KdfType(*t.Kdf) {
	case crypto.KdfPBKDF2:
		t.KdfConfig = crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: iter}
	case crypto.KdfArgon2id:
		t.KdfConfig = crypto.KdfConfig{Type: crypto.KdfArgon2id, Iterations: iter, Memory: t.KdfMemory, Parallelism: t.KdfParallelism}
	default:
		return nil, errors.New("kdf is required on IdentityTokenResponse")
	}
	return &t, nil
}

// TwoFactorProviderDetails is a supported provider with its display name.
type TwoFactorProviderDetails struct {
	Type int
	Name string
}

// SupportedTwoFactorProviders mirrors TwoFactorService.getSupportedProviders for the CLI, which
// supports neither Duo nor WebAuthn.
func SupportedTwoFactorProviders(providers []int) []TwoFactorProviderDetails {
	has := map[int]bool{}
	for _, p := range providers {
		has[p] = true
	}
	var out []TwoFactorProviderDetails
	if has[TwoFactorAuthenticator] {
		out = append(out, TwoFactorProviderDetails{TwoFactorAuthenticator, "Authenticator App"})
	}
	if has[TwoFactorYubikey] {
		out = append(out, TwoFactorProviderDetails{TwoFactorYubikey, "Yubico OTP Security Key"})
	}
	if has[TwoFactorEmail] {
		out = append(out, TwoFactorProviderDetails{TwoFactorEmail, "Email"})
	}
	return out
}
