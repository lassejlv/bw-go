package auth

import (
	"errors"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// AuthResult mirrors AuthResult.
type AuthResult struct {
	UserID                         string
	TwoFactorProviders             []int // nil unless two-factor is required
	SsoEmail2FaSessionToken        string
	Email                          string
	RequiresEncryptionKeyMigration bool
	RequiresDeviceVerification     bool
	SsoOrganizationIdentifier      string
}

// RequiresTwoFactor reports whether a two-factor token is required.
func (r *AuthResult) RequiresTwoFactor() bool { return r.TwoFactorProviders != nil }

// RequiresSso reports whether the organization requires SSO.
func (r *AuthResult) RequiresSso() bool { return strings.TrimSpace(r.SsoOrganizationIdentifier) != "" }

// Kind of login strategy.
type Kind int

const (
	KindPassword Kind = iota
	KindUserAPIKey
	KindSso
)

// Strategy holds the state of a login in progress (LoginStrategy + LoginStrategyData).
type Strategy struct {
	a    *app.App
	Kind Kind
	req  *TokenRequest

	userEnteredEmail string
	masterPassword   string
	masterKey        []byte
	forceReason      int

	orgID         string
	ssoEmail      string
	ssoEmailToken string

	// conversion is set for brand-new SSO users who must enroll in key connector.
	conversion *NewSsoUserKeyConnectorConversion

	// Token is the last successful identity token response.
	Token *TokenResponse
}

func newStrategy(a *app.App, kind Kind, req *TokenRequest) (*Strategy, error) {
	d, err := a.Data()
	if err != nil {
		return nil, err
	}
	req.Device = NewDeviceRequest(d.AppID)
	if req.TwoFactor == nil {
		req.TwoFactor = &TwoFactorRequest{}
	}
	return &Strategy{a: a, Kind: kind, req: req}, nil
}

// LogInPassword starts a master password login (PasswordLoginStrategy.logIn).
func LogInPassword(a *app.App, email, masterPassword string, twoFactor *TwoFactorRequest) (*Strategy, *AuthResult, error) {
	prelogin, err := GetPreloginData(a.API, email)
	if err != nil {
		return nil, nil, err
	}
	mk, err := MakeMasterKey(masterPassword, email, prelogin.KdfConfig)
	if err != nil {
		return nil, nil, err
	}
	hash := crypto.HashMasterPassword(masterPassword, mk, crypto.HashServerAuthorization)
	s, err := newStrategy(a, KindPassword, &TokenRequest{
		GrantType: GrantPassword, Email: email, MasterPasswordHash: hash, TwoFactor: twoFactor,
	})
	if err != nil {
		return nil, nil, err
	}
	s.userEnteredEmail = email
	s.masterPassword = masterPassword
	s.masterKey = mk
	resp, result, err := s.startLogIn()
	if err != nil {
		return s, nil, err
	}
	if err := s.evaluateMasterPasswordIfRequired(resp, result); err != nil {
		return s, nil, err
	}
	return s, result, nil
}

// LogInUserAPIKey starts a personal API key login (UserApiLoginStrategy.logIn).
func LogInUserAPIKey(a *app.App, clientID, clientSecret string) (*Strategy, *AuthResult, error) {
	s, err := newStrategy(a, KindUserAPIKey, &TokenRequest{
		GrantType: GrantClientCredentials, ClientID: clientID, ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, nil, err
	}
	_, result, err := s.startLogIn()
	return s, result, err
}

// LogInSso starts an SSO login with an authorization code (SsoLoginStrategy.logIn).
func LogInSso(a *app.App, code, codeVerifier, redirectURI, orgID string, twoFactor *TwoFactorRequest) (*Strategy, *AuthResult, error) {
	s, err := newStrategy(a, KindSso, &TokenRequest{
		GrantType: GrantAuthorizationCode, Code: code, CodeVerifier: codeVerifier, RedirectURI: redirectURI,
		TwoFactor: twoFactor,
	})
	if err != nil {
		return nil, nil, err
	}
	s.orgID = orgID
	_, result, err := s.startLogIn()
	if err != nil {
		return s, nil, err
	}
	s.ssoEmail = result.Email
	s.ssoEmailToken = result.SsoEmail2FaSessionToken
	return s, result, nil
}

// LogInTwoFactor retries the login with a two-factor token.
func (s *Strategy) LogInTwoFactor(tf *TwoFactorRequest) (*AuthResult, error) {
	s.req.SetTwoFactor(tf)
	_, result, err := s.startLogIn()
	return result, err
}

// LogInNewDeviceVerification retries the login with a new device verification OTP.
func (s *Strategy) LogInNewDeviceVerification(otp string) (*AuthResult, error) {
	if s.Kind != KindPassword {
		return nil, errors.New("Current login strategy does not support device verification.")
	}
	s.req.NewDeviceOtp = otp
	_, result, err := s.startLogIn()
	return result, err
}

// Email returns the email of the login in progress (LoginStrategyService.getEmail).
func (s *Strategy) Email() string {
	switch s.Kind {
	case KindPassword:
		return s.req.Email
	case KindSso:
		return s.ssoEmail
	}
	return ""
}

// MasterPasswordHash returns the server master password hash (password logins only).
func (s *Strategy) MasterPasswordHash() string { return s.req.MasterPasswordHash }

// KeyConnectorConversion returns the pending new-SSO-user key connector enrollment, if any
// (KeyConnectorService.requiresDomainConfirmation$).
func (s *Strategy) KeyConnectorConversion() *NewSsoUserKeyConnectorConversion { return s.conversion }

// ClearKeyConnectorConversion forgets the pending enrollment.
func (s *Strategy) ClearKeyConnectorConversion() { s.conversion = nil }

func (s *Strategy) startLogIn() (*IdentityResponse, *AuthResult, error) {
	res, err := s.a.API.PostIdentityToken(s.req.Form(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := ParseIdentityResult(res)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case resp.TwoFactor != nil:
		providers := resp.TwoFactor.Providers()
		if providers == nil {
			providers = []int{}
		}
		return resp, &AuthResult{
			TwoFactorProviders:      providers,
			SsoEmail2FaSessionToken: resp.TwoFactor.SsoEmail2faSessionToken,
			Email:                   resp.TwoFactor.Email,
		}, nil
	case resp.Token != nil:
		r, err := s.processTokenResponse(resp.Token)
		return resp, r, err
	case resp.DeviceVerification:
		return resp, &AuthResult{RequiresDeviceVerification: true}, nil
	case resp.SsoRequired != nil:
		return resp, &AuthResult{SsoOrganizationIdentifier: resp.SsoRequired.SsoOrganizationIdentifier}, nil
	}
	return nil, nil, errors.New("Invalid response object.")
}

func (s *Strategy) processTokenResponse(t *TokenResponse) (*AuthResult, error) {
	result := &AuthResult{}
	s.Token = t
	// Encryption key migration of legacy users is not supported anymore (password logins only).
	if s.Kind == KindPassword && IsLegacyUserKey(t.MasterKeyWrappedUserKey()) {
		result.RequiresEncryptionKeyMigration = true
		return result, nil
	}
	userID, err := s.saveAccountInformation(t)
	if err != nil {
		return nil, err
	}
	result.UserID = userID
	if err := s.unlock(t); err != nil {
		return nil, err
	}
	if err := s.processForceSetPasswordReason(t); err != nil {
		return nil, err
	}
	return result, nil
}

// saveAccountInformation stores the account, tokens and decryption data and makes it active.
func (s *Strategy) saveAccountInformation(t *TokenResponse) (string, error) {
	claims, err := api.DecodeJWT(t.AccessToken)
	if err != nil {
		return "", err
	}
	userID, _ := claims["sub"].(string)
	if userID == "" {
		return "", errors.New("No user id found in access token.")
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	acct := &state.Account{
		UserID:        userID,
		Email:         email,
		Name:          name,
		AccessToken:   t.AccessToken,
		RefreshToken:  t.RefreshToken,
		Kdf:           t.KdfConfig,
		KdfSalt:       NormalizeEmail(email),
		EncUserKey:    t.Key,
		EncPrivateKey: t.WrappedPrivateKey(),
	}
	if s.Kind == KindUserAPIKey {
		acct.ApiClientID = s.req.ClientID
		acct.ApiClientSecret = s.req.ClientSecret
	}
	if o := t.UserDecryptionOptions; o != nil {
		acct.HasMasterPassword = o.HasMasterPassword
		if o.KeyConnectorOption != nil {
			acct.KeyConnectorURL = o.KeyConnectorOption.KeyConnectorURL
		}
		if mpu := o.MasterPasswordUnlock; mpu != nil {
			if cfg, err := mpu.Kdf.ToKdfConfig(); err == nil {
				acct.Kdf = cfg
			}
			if mpu.Salt != "" {
				acct.KdfSalt = mpu.Salt
			}
			if mpu.MasterKeyEncryptedUserKey != "" {
				acct.EncUserKey = mpu.MasterKeyEncryptedUserKey
			}
		}
	} else {
		// Servers without UserDecryptionOptions only know master password users.
		acct.HasMasterPassword = t.Key != ""
	}
	err = s.a.Store.Update(func(d *state.Data) error {
		if d.Accounts == nil {
			d.Accounts = map[string]*state.Account{}
		}
		d.Accounts[userID] = acct
		d.ActiveUserID = userID
		return nil
	})
	if err != nil {
		return "", err
	}
	if err := SetAccountKeys(s.a.Store, userID, t.AccountKeysRaw); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Strategy) setUserKey(userKey *crypto.SymmetricKey) error {
	return s.a.SetUserKey(userKey)
}

// unlock unlocks the vault with the method of the strategy.
func (s *Strategy) unlock(t *TokenResponse) error {
	switch s.Kind {
	case KindPassword:
		uk, err := DecryptUserKeyWithMasterKey(s.masterKey, t.MasterKeyWrappedUserKey())
		if err != nil {
			return err
		}
		if _, err := UnlockAccountKeys(t.AccountKeys, t.PrivateKey, uk); err != nil {
			return err
		}
		return s.setUserKey(uk)
	case KindUserAPIKey:
		if t.CanUnlockWithKeyConnector() {
			uk, err := UnlockWithKeyConnector(s.a, t.UserDecryptionOptions.KeyConnectorOption.KeyConnectorURL, t.Key, t.AccountKeys, t.PrivateKey)
			if err != nil {
				return err
			}
			return s.setUserKey(uk)
		}
	case KindSso:
		o := t.UserDecryptionOptions
		if o != nil && !o.HasMasterPassword && t.Key == "" && o.KeyConnectorOption != nil &&
			o.KeyConnectorOption.KeyConnectorURL != "" {
			s.conversion = &NewSsoUserKeyConnectorConversion{
				KdfConfig:       t.KdfConfig,
				KeyConnectorURL: o.KeyConnectorOption.KeyConnectorURL,
				OrganizationID:  s.orgID,
			}
		} else if t.CanUnlockWithKeyConnector() {
			uk, err := UnlockWithKeyConnector(s.a, o.KeyConnectorOption.KeyConnectorURL, t.Key, t.AccountKeys, t.PrivateKey)
			if err != nil {
				return err
			}
			return s.setUserKey(uk)
		}
		// Trusted device encryption needs a persisted device key, which the CLI does not have.
	}
	return nil
}

func (s *Strategy) setForceSetPasswordReason(reason int) error {
	return s.a.UpdateAccount(func(acct *state.Account) error {
		// AdminForcePasswordReset can only be replaced by None.
		if acct.ForceSetPasswordReason == ForceSetPasswordAdminForcePasswordReset && reason != ForceSetPasswordNone {
			return nil
		}
		acct.ForceSetPasswordReason = reason
		return nil
	})
}

func (s *Strategy) processForceSetPasswordReason(t *TokenResponse) error {
	if t.ForcePasswordReset {
		return s.setForceSetPasswordReason(ForceSetPasswordAdminForcePasswordReset)
	}
	switch s.Kind {
	case KindPassword:
		if s.forceReason != ForceSetPasswordNone {
			return s.setForceSetPasswordReason(s.forceReason)
		}
	case KindSso:
		o := t.UserDecryptionOptions
		if o == nil {
			return nil
		}
		hasKC := o.KeyConnectorOption != nil && o.KeyConnectorOption.KeyConnectorURL != ""
		switch {
		case o.TrustedDeviceOption != nil && o.TrustedDeviceOption.IsTdeOffboarding:
			return s.setForceSetPasswordReason(ForceSetPasswordTdeOffboarding)
		case o.TrustedDeviceOption == nil && !o.HasMasterPassword && !hasKC && t.WrappedPrivateKey() != "" && !s.a.IsUnlocked():
			return s.setForceSetPasswordReason(ForceSetPasswordTdeOffboardingUntrustedDevice)
		case !o.HasMasterPassword && o.TrustedDeviceOption != nil && o.TrustedDeviceOption.HasManageResetPasswordPermission:
			return s.setForceSetPasswordReason(ForceSetPasswordTdeUserWithoutPasswordHasPasswordResetPermission)
		case !o.HasMasterPassword && !hasKC && o.TrustedDeviceOption == nil:
			return s.setForceSetPasswordReason(ForceSetPasswordSsoNewJitProvisionedUser)
		}
	}
	return nil
}

// evaluateMasterPasswordIfRequired mirrors PasswordLoginStrategy.evaluateMasterPasswordIfRequired.
func (s *Strategy) evaluateMasterPasswordIfRequired(resp *IdentityResponse, result *AuthResult) error {
	if resp.DeviceVerification || resp.SsoRequired != nil {
		return nil
	}
	var policy *MasterPasswordPolicyResponse
	if resp.Token != nil {
		policy = resp.Token.MasterPasswordPolicy
	} else if resp.TwoFactor != nil {
		policy = resp.TwoFactor.MasterPasswordPolicy
	}
	if policy == nil || !policy.EnforceOnLogin {
		return nil
	}
	strength := PasswordStrength(s.masterPassword, s.userEnteredEmail)
	if EvaluateMasterPassword(strength, s.masterPassword, policy) {
		return nil
	}
	if resp.TwoFactor != nil {
		s.forceReason = ForceSetPasswordWeakMasterPassword
		return nil
	}
	if result == nil || result.UserID == "" {
		return nil
	}
	return s.setForceSetPasswordReason(ForceSetPasswordWeakMasterPassword)
}

var specialRe = regexp.MustCompile(`[!@#$%\^&*]`)
var digitRe = regexp.MustCompile(`[0-9]`)

// EvaluateMasterPassword mirrors PolicyService.evaluateMasterPassword. passwordStrength is the
// zxcvbn score (see PasswordStrength); nil (an empty password) never fails minComplexity, like
// comparing against undefined in JavaScript.
func EvaluateMasterPassword(passwordStrength *int, password string, p *MasterPasswordPolicyResponse) bool {
	if p == nil {
		return true
	}
	if p.MinComplexity > 0 && passwordStrength != nil && p.MinComplexity > *passwordStrength {
		return false
	}
	if p.MinLength > 0 && p.MinLength > utf16Len(password) {
		return false
	}
	if p.RequireUpper && strings.ToLower(password) == password {
		return false
	}
	if p.RequireLower && strings.ToUpper(password) == password {
		return false
	}
	if p.RequireNumbers && !digitRe.MatchString(password) {
		return false
	}
	if p.RequireSpecial && !specialRe.MatchString(password) {
		return false
	}
	return true
}

// utf16Len returns the JavaScript string length.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
