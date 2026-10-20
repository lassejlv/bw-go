// Package auth implements the login strategies of libs/auth (password, user api key and SSO),
// identity token request/response models, password prelogin and key connector helpers used by
// the `login`, `unlock` and related commands.
package auth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
)

// ClientID is the identity client id of the CLI (ClientType.Cli).
const ClientID = "cli"

// Two-factor provider types (TwoFactorProviderType).
const (
	TwoFactorAuthenticator   = 0
	TwoFactorEmail           = 1
	TwoFactorDuo             = 2
	TwoFactorYubikey         = 3
	TwoFactorRemember        = 5
	TwoFactorOrganizationDuo = 6
	TwoFactorWebAuthn        = 7
	TwoFactorRecoveryCode    = 8
)

// IsTwoFactorProviderType mirrors isTwoFactorProviderType.
func IsTwoFactorProviderType(v int) bool {
	switch v {
	case TwoFactorAuthenticator, TwoFactorEmail, TwoFactorDuo, TwoFactorYubikey, TwoFactorRemember,
		TwoFactorOrganizationDuo, TwoFactorWebAuthn, TwoFactorRecoveryCode:
		return true
	}
	return false
}

// ForceSetPasswordReason values (ForceSetPasswordReason enum).
const (
	ForceSetPasswordNone                                             = 0
	ForceSetPasswordSsoNewJitProvisionedUser                         = 1
	ForceSetPasswordTdeUserWithoutPasswordHasPasswordResetPermission = 2
	ForceSetPasswordTdeOffboarding                                   = 3
	ForceSetPasswordTdeOffboardingUntrustedDevice                    = 4
	ForceSetPasswordAdminForcePasswordReset                          = 5
	ForceSetPasswordWeakMasterPassword                               = 6
)

// TwoFactorRequest mirrors TokenTwoFactorRequest. Provider is nil when unknown.
type TwoFactorRequest struct {
	Provider *int
	Token    string
	Remember bool
}

// NewTwoFactorRequest builds a TwoFactorRequest for a known provider.
func NewTwoFactorRequest(provider int, token string) *TwoFactorRequest {
	return &TwoFactorRequest{Provider: &provider, Token: token}
}

// DeviceRequest mirrors DeviceRequest.
type DeviceRequest struct {
	Type       int
	Name       string
	Identifier string
}

// NewDeviceRequest builds the device request for this CLI installation.
func NewDeviceRequest(appID string) *DeviceRequest {
	return &DeviceRequest{Type: api.DeviceType(), Name: api.DeviceName(), Identifier: appID}
}

// Grant types.
const (
	GrantPassword          = "password"
	GrantClientCredentials = "client_credentials"
	GrantAuthorizationCode = "authorization_code"
)

// TokenRequest covers PasswordTokenRequest, UserApiTokenRequest and SsoTokenRequest.
type TokenRequest struct {
	GrantType string

	// password grant
	Email              string
	MasterPasswordHash string
	NewDeviceOtp       string

	// client_credentials grant
	ClientID     string
	ClientSecret string

	// authorization_code grant
	Code         string
	CodeVerifier string
	RedirectURI  string

	TwoFactor *TwoFactorRequest
	Device    *DeviceRequest
}

// SetTwoFactor replaces the two-factor data.
func (r *TokenRequest) SetTwoFactor(tf *TwoFactorRequest) { r.TwoFactor = tf }

// Form encodes the request like toIdentityToken (TokenRequest + subclasses).
func (r *TokenRequest) Form() url.Values {
	f := url.Values{}
	clientID := ClientID
	if r.GrantType == GrantClientCredentials {
		clientID = r.ClientID
	}
	f.Set("scope", "api offline_access")
	f.Set("client_id", clientID)
	if r.Device != nil {
		f.Set("deviceType", fmt.Sprint(r.Device.Type))
		f.Set("deviceIdentifier", r.Device.Identifier)
		f.Set("deviceName", r.Device.Name)
	}
	if r.TwoFactor != nil && r.TwoFactor.Token != "" && r.TwoFactor.Provider != nil {
		f.Set("twoFactorToken", r.TwoFactor.Token)
		f.Set("twoFactorProvider", fmt.Sprint(*r.TwoFactor.Provider))
		if r.TwoFactor.Remember {
			f.Set("twoFactorRemember", "1")
		} else {
			f.Set("twoFactorRemember", "0")
		}
	}
	switch r.GrantType {
	case GrantPassword:
		f.Set("grant_type", GrantPassword)
		f.Set("username", r.Email)
		f.Set("password", r.MasterPasswordHash)
		if r.NewDeviceOtp != "" {
			f.Set("newDeviceOtp", r.NewDeviceOtp)
		}
	case GrantClientCredentials:
		if strings.HasPrefix(r.ClientID, "organization") {
			f.Set("scope", "api.organization")
		} else {
			f.Set("scope", "api")
		}
		f.Set("grant_type", GrantClientCredentials)
		f.Set("client_secret", r.ClientSecret)
	case GrantAuthorizationCode:
		f.Set("grant_type", GrantAuthorizationCode)
		f.Set("code", r.Code)
		f.Set("code_verifier", r.CodeVerifier)
		f.Set("redirect_uri", r.RedirectURI)
	}
	return f
}
