package auth

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/syncer"
)

// LoginOptions are the options of `bw login`.
type LoginOptions struct {
	Method string
	Code   string
	// Sso is nil when --sso was not given; it points to "" when given without an identifier.
	Sso          *string
	APIKey       bool
	PasswordEnv  string
	PasswordFile string
}

const legacyEncryptionUnsupported = "Legacy encryption is no longer supported. Please contact support to recover your account."

func canInteract() bool { return os.Getenv("BW_NOINTERACTION") != "true" }

// Login implements LoginCommand.run.
func Login(a *app.App, email, password string, o LoginOptions) *cli.Response {
	interactive := canInteract()

	var ssoCodeVerifier, ssoCode, orgIdentifier, ssoRedirectURI string
	var clientID, clientSecret string
	isAPIKey := false

	if o.APIKey {
		isAPIKey = true
		var r *cli.Response
		clientID, clientSecret, r = apiIdentifiers(interactive)
		if r != nil {
			return r
		}
		if strings.TrimSpace(clientID) == "" {
			return cli.BadRequest("client_id is required.")
		}
		if clientSecret == "" {
			return cli.BadRequest("client_secret is required.")
		}
	} else if o.Sso != nil && interactive {
		data := bwauth.MakeSsoPromptData()
		ssoCodeVerifier = data.CodeVerifier
		res, err := bwauth.OpenSsoPrompt(a.Urls().WebVault, data, *o.Sso)
		if err != nil {
			return cli.BadRequest("Something went wrong. Try again.")
		}
		ssoCode, orgIdentifier, ssoRedirectURI = res.Code, res.OrgIdentifier, res.RedirectURI
	} else {
		if email == "" && interactive {
			v, err := cli.PromptInput("Email address:")
			if err != nil {
				return cli.Error(err)
			}
			email = v
		}
		if strings.TrimSpace(email) == "" {
			return cli.BadRequest("Email address is required.")
		}
		if !strings.Contains(email, "@") {
			return cli.BadRequest("Email address is invalid.")
		}
		if password == "" {
			if o.PasswordFile != "" {
				p, err := cli.ReadFirstLine(o.PasswordFile)
				if err != nil {
					return cli.Error(err)
				}
				password = p
			} else if o.PasswordEnv != "" && os.Getenv(o.PasswordEnv) != "" {
				password = os.Getenv(o.PasswordEnv)
			} else if interactive {
				p, err := cli.PromptPassword("Master password:")
				if err != nil {
					return cli.Error(err)
				}
				password = p
			}
		}
		if password == "" {
			return cli.BadRequest("Master password is required.")
		}
	}

	twoFactorToken := o.Code
	twoFactorTokenSet := o.Code != ""
	var twoFactorMethod *int
	if o.Method != "" {
		n, ok := parseInt(o.Method)
		if !ok || !bwauth.IsTwoFactorProviderType(n) {
			return cli.Error("Invalid two-step login method.")
		}
		twoFactorMethod = &n
	}
	var twoFactor *bwauth.TwoFactorRequest
	if twoFactorTokenSet {
		twoFactor = &bwauth.TwoFactorRequest{Provider: twoFactorMethod, Token: twoFactorToken}
	}

	r, err := func() (*cli.Response, error) {
		// validatedParams: a fresh session key for the login.
		app.NewSession()

		var s *bwauth.Strategy
		var res *bwauth.AuthResult
		var err error
		switch {
		case clientID != "" && clientSecret != "":
			if !strings.HasPrefix(clientID, "user") {
				return cli.Error("Invalid API Key; Organization API Key currently not supported"), nil
			}
			s, res, err = bwauth.LogInUserAPIKey(a, clientID, clientSecret)
			if err != nil {
				var apiErr *api.ErrorResponse
				if errors.As(err, &apiErr) {
					if e, ok := apiErr.Raw["error"].(string); ok && e == "invalid_client" {
						return cli.BadRequest("client_id or client_secret is incorrect. Try again."), nil
					}
				}
				return nil, err
			}
		case ssoCode != "" && ssoCodeVerifier != "":
			s, res, err = bwauth.LogInSso(a, ssoCode, ssoCodeVerifier, ssoRedirectURI, orgIdentifier, twoFactor)
		default:
			s, res, err = bwauth.LogInPassword(a, email, password, twoFactor)
		}
		if err != nil {
			return nil, err
		}

		if res.RequiresEncryptionKeyMigration {
			return cli.Error(legacyEncryptionUnsupported), nil
		}

		if res.RequiresSso() && interactive {
			data := bwauth.MakeSsoPromptData()
			ssoCodeVerifier = data.CodeVerifier
			sr, err := bwauth.OpenSsoPrompt(a.Urls().WebVault, data, res.SsoOrganizationIdentifier)
			if err != nil {
				return cli.BadRequest("Something went wrong. Try again."), nil
			}
			ssoCode, orgIdentifier, ssoRedirectURI = sr.Code, sr.OrgIdentifier, sr.RedirectURI
			if ssoCode != "" && ssoCodeVerifier != "" {
				s, res, err = bwauth.LogInSso(a, ssoCode, ssoCodeVerifier, ssoRedirectURI, orgIdentifier, twoFactor)
				if err != nil {
					return cli.BadRequest("Something went wrong. Try again."), nil
				}
			}
		}

		if res.RequiresTwoFactor() {
			providers := bwauth.SupportedTwoFactorProviders(res.TwoFactorProviders)
			if len(providers) == 0 {
				return cli.BadRequest("No providers available for this client."), nil
			}
			var selected *bwauth.TwoFactorProviderDetails
			if twoFactorMethod != nil {
				for i := range providers {
					if providers[i].Type == *twoFactorMethod {
						selected = &providers[i]
						break
					}
				}
			}
			if selected == nil {
				if len(providers) == 1 {
					selected = &providers[0]
				} else if interactive {
					names := make([]string, 0, len(providers)+1)
					for _, p := range providers {
						names = append(names, p.Name)
					}
					names = append(names, "Cancel")
					i, err := cli.PromptSelect("Two-step login method:", names)
					if err != nil {
						return nil, err
					}
					if i == len(names)-1 {
						return cli.Error("Login failed."), nil
					}
					selected = &providers[i]
				}
				if selected == nil {
					return cli.Error("Login failed. No provider selected."), nil
				}
			}

			if !twoFactorTokenSet && selected.Type == bwauth.TwoFactorEmail {
				body := map[string]any{"email": s.Email()}
				if res.SsoEmail2FaSessionToken != "" {
					body["ssoEmail2FaSessionToken"] = res.SsoEmail2FaSessionToken
				}
				if h := s.MasterPasswordHash(); h != "" {
					body["masterPasswordHash"] = h
				}
				if err := a.API.Send("POST", "/two-factor/send-email-login", body, false, nil, nil); err != nil {
					return nil, err
				}
			}

			if !twoFactorTokenSet {
				if interactive {
					v, err := cli.PromptInput("Two-step login code:")
					if err != nil {
						return nil, err
					}
					twoFactorToken = v
				}
				if twoFactorToken == "" {
					return cli.BadRequest("Code is required."), nil
				}
			}

			res, err = s.LogInTwoFactor(bwauth.NewTwoFactorRequest(selected.Type, twoFactorToken))
			if err != nil {
				return nil, err
			}
		}

		if res.RequiresDeviceVerification {
			otp := ""
			if interactive {
				v, err := cli.PromptInput("New device verification required. Enter OTP sent to login email:")
				if err != nil {
					return nil, err
				}
				otp = v
			}
			if otp == "" {
				return cli.BadRequest("Code is required."), nil
			}
			res, err = s.LogInNewDeviceVerification(otp)
			if err != nil {
				return nil, err
			}
		}

		if res.RequiresTwoFactor() {
			return cli.Error("Login failed."), nil
		}

		if ssoCode != "" && ssoCodeVerifier != "" && res.UserID != "" {
			if r := validateSsoUserHasCliSupportedDecryptionPath(a, s); r != nil {
				return r, nil
			}
		}

		if conv := s.KeyConnectorConversion(); conv != nil {
			if r := confirmKeyConnectorDomain(a, conv); !r.Success {
				return r, nil
			}
			s.ClearKeyConnectorConversion()
		}

		// Full sync before handling the success response (to get master password policies).
		_, _ = syncer.Sync(a, true, syncer.Options{SkipTokenRefresh: true})

		if !isAPIKey {
			acct := a.ActiveAccount()
			if acct != nil {
				switch acct.ForceSetPasswordReason {
				case bwauth.ForceSetPasswordAdminForcePasswordReset:
					Logout(a)
					return cli.Error("An organization administrator recently changed your master password. In order to access the vault, you must update your master password now via the web app. You have been logged out."), nil
				case bwauth.ForceSetPasswordWeakMasterPassword:
					Logout(a)
					return cli.Error("Your master password does not meet one or more of your organization policies. In order to access the vault, you must update your master password now via the web app. You have been logged out."), nil
				}
			}
		}

		if acct := a.ActiveAccount(); acct != nil {
			var masterPassword *string
			if password != "" {
				masterPassword = &password
			}
			if err := newMigrator(a).RunMigrations(acct.UserID, masterPassword); err != nil {
				return nil, err
			}
		}

		return loginSuccessResponse(a, o, interactive), nil
	}()
	if err != nil {
		var apiErr *api.ErrorResponse
		if errors.As(err, &apiErr) && apiErr.SingleMessage() == "Username or password is incorrect. Try again." {
			host := a.Urls().WebVault
			if u, perr := url.Parse(host); perr == nil && u.Host != "" {
				host = u.Host
			}
			return cli.Error("Invalid master password. Confirm your email is correct and your account was created on " + host + ".")
		}
		return cli.Error(err)
	}
	return r
}

func parseInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || end == 0 && (s[end] == '-' || s[end] == '+')) {
		end++
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}

func loginSuccessResponse(a *app.App, o LoginOptions, interactive bool) *cli.Response {
	usesKeyConnector := false
	if acct := a.ActiveAccount(); acct != nil {
		usesKeyConnector = acct.UsesKeyConnector
	}
	if (o.Sso != nil || o.APIKey) && interactive && !usesKeyConnector {
		return cli.Success(cli.NewMessage("You are logged in!",
			"\nTo unlock your vault, use the `unlock` command. ex:\n$ bwgo unlock"))
	}
	return cli.Success(sessionMessage("You are logged in!"))
}

// sessionMessage builds the BW_SESSION export instructions shared by login and unlock.
func sessionMessage(title string) *cli.MessageResponse {
	session := os.Getenv("BW_SESSION")
	msg := "\n" +
		"To unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n" +
		"$ export BW_SESSION=\"" + session + "\"\n" +
		"> $env:BW_SESSION=\"" + session + "\"\n\n" +
		"You can also pass the session key to any command with the `--session` option. ex:\n" +
		"$ bwgo list items --session " + session
	return cli.NewMessage(title, msg).SetRaw(session)
}

func apiIdentifiers(interactive bool) (string, string, *cli.Response) {
	clientID, ok := os.LookupEnv("BW_CLIENTID")
	if !ok {
		if interactive {
			v, err := cli.PromptInput("client_id:")
			if err != nil {
				return "", "", cli.Error(err)
			}
			clientID = v
		}
	}
	clientSecret, ok := os.LookupEnv("BW_CLIENTSECRET")
	if !ok {
		if interactive {
			v, err := cli.PromptInput("client_secret:")
			if err != nil {
				return "", "", cli.Error(err)
			}
			clientSecret = v
		}
	}
	return clientID, clientSecret, nil
}

// validateSsoUserHasCliSupportedDecryptionPath mirrors the LoginCommand method of the same name.
func validateSsoUserHasCliSupportedDecryptionPath(a *app.App, s *bwauth.Strategy) *cli.Response {
	if s.Token == nil {
		return nil
	}
	o := s.Token.UserDecryptionOptions
	if o == nil || o.HasMasterPassword || o.KeyConnectorOption != nil {
		return nil
	}
	Logout(a)
	if o.TrustedDeviceOption != nil {
		return cli.Error("The CLI does not support SSO login for accounts using trusted device encryption." +
			" Log in through the web vault, desktop app, or browser extension.")
	}
	if o.WebAuthnPrfOption != nil {
		return cli.Error("The CLI does not support SSO login for accounts using PRF passkey decryption." +
			" Log in through the web vault or browser extension.")
	}
	return cli.Error("In order to log in with SSO from the CLI, you must first log in" +
		" through the web vault, the desktop, or the extension to set your master password.")
}

// confirmKeyConnectorDomain mirrors ConfirmKeyConnectorDomainCommand.run.
func confirmKeyConnectorDomain(a *app.App, conv *bwauth.NewSsoUserKeyConnectorConversion) *cli.Response {
	if !canInteract() {
		Logout(a)
		return cli.Error(cli.NewMessageNull("An organization you are a member of is using Key Connector. In order to access the vault, you must confirm the Key Connector domain now via the web vault. You have been logged out."))
	}
	i, err := cli.PromptSelect("Please confirm the domain below with your organization administrator. Key Connector domain: "+conv.KeyConnectorURL,
		[]string{"Confirm", "Log out"})
	if err != nil {
		return cli.Error(err)
	}
	if i == 0 {
		if err := bwauth.ConvertNewSsoUserToKeyConnector(a, conv); err != nil {
			Logout(a)
			return cli.Error(err)
		}
		return cli.Success(nil)
	}
	Logout(a)
	return cli.Error("You have been logged out.")
}
