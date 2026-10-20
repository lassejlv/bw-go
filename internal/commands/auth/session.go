package auth

import (
	"os"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/syncer"
)

// Logout implements LogoutCommand.run (with the service container's logout callback): the active
// account and its data are removed and the session key is cleared.
func Logout(a *app.App) *cli.Response {
	if acct := a.ActiveAccount(); acct != nil {
		_ = bwauth.SetAccountKeys(a.Store, acct.UserID, nil)
	}
	if err := a.Logout(); err != nil {
		return cli.Error(err)
	}
	os.Unsetenv("BW_SESSION")
	return cli.Success(cli.NewMessageNull("You have logged out."))
}

// Lock implements LockCommand.run.
func Lock(a *app.App) *cli.Response {
	if err := a.Lock(); err != nil {
		return cli.Error(err)
	}
	os.Unsetenv("BW_SESSION")
	return cli.Success(cli.NewMessageNull("Your vault is locked."))
}

// UnlockOptions are the options of `bw unlock`.
type UnlockOptions struct {
	PasswordEnv  string
	PasswordFile string
}

// Unlock implements UnlockCommand.run.
func Unlock(a *app.App, password string, o UnlockOptions) *cli.Response {
	acct := a.ActiveAccount()
	if acct == nil {
		return cli.Error("No active account found")
	}
	conversionRequired := bwauth.ConvertAccountRequired(acct)

	password, r := cli.GetPassword(password, o.PasswordFile, o.PasswordEnv, "")
	if r != nil {
		return r
	}

	userKey, masterKey, err := bwauth.UnlockWithMasterPassword(acct, password)
	if err != nil {
		return cli.Error(err.Error())
	}
	// Only replace the session once the password is verified, so a failed unlock does not lock
	// an already unlocked vault (matters for long-running `bw serve`).
	app.NewSession()
	if err := a.SetUserKey(userKey); err != nil {
		return cli.Error(err.Error())
	}

	if conversionRequired {
		if r := convertToKeyConnector(a, masterKey); !r.Success {
			return r
		}
	}
	return cli.Success(sessionMessage("Your vault is now unlocked!"))
}

// convertToKeyConnector implements ConvertToKeyConnectorCommand.run.
func convertToKeyConnector(a *app.App, masterKey []byte) *cli.Response {
	if !canInteract() {
		Logout(a)
		return cli.Error(cli.NewMessageNull("An organization you are a member of is using Key Connector. In order to access the vault, you must opt-in to Key Connector now via the web vault. You have been logged out."))
	}
	org := bwauth.ManagingOrganization(a.ActiveAccount())
	if org == nil {
		return cli.Success(nil)
	}
	i, err := cli.PromptSelect("A master password is no longer required for members of the following organization. "+
		"Please confirm the domain below with your organization administrator. Organization name: "+org.Name+
		". Key Connector domain: "+org.KeyConnectorURL,
		[]string{"Remove master password and unlock", "Leave organization and unlock", "Log out"})
	if err != nil {
		return cli.Error(err)
	}
	switch i {
	case 0:
		if err := bwauth.MigrateUserToKeyConnector(a, org.KeyConnectorURL, masterKey); err != nil {
			return cli.Error(err)
		}
		// Update environment URL - required for api key login.
		err := a.Store.Update(func(d *state.Data) error {
			u := api.Resolve(d.Environment)
			d.Environment = state.Environment{
				Region:        regionSelfHosted,
				Base:          u.Base,
				WebVault:      u.WebVault,
				Api:           u.Api,
				Identity:      u.Identity,
				Icons:         u.Icons,
				Notifications: u.Notifications,
				Events:        u.Events,
				KeyConnector:  formatURL(org.KeyConnectorURL),
			}
			return nil
		})
		if err != nil {
			return cli.Error(err)
		}
		return cli.Success(nil)
	case 1:
		if err := a.API.Post("/organizations/"+org.ID+"/leave", nil, nil); err != nil {
			return cli.Error(err)
		}
		return cli.Success(nil)
	default:
		Logout(a)
		return cli.Error("You have been logged out.")
	}
}

// UnlockCheck implements `bw unlock --check`.
func UnlockCheck(a *app.App) *cli.Response {
	if a.IsUnlocked() {
		return cli.Success(cli.NewMessageNull("Vault is unlocked!"))
	}
	return cli.Error("Vault is locked.")
}

// LoginCheck implements `bw login --check`.
func LoginCheck(a *app.App) *cli.Response {
	if a.IsAuthed() {
		return cli.Success(cli.NewMessageNull("You are logged in!"))
	}
	return cli.Error("You are not logged in.")
}

// SyncOptions are the options of `bw sync`.
type SyncOptions struct {
	Force bool
	Last  bool
}

// Sync implements SyncCommand.run.
func Sync(a *app.App, o SyncOptions) *cli.Response {
	if o.Last {
		last := syncer.LastSync(a)
		if last == nil {
			return cli.Success(cli.NewNullString())
		}
		return cli.Success(cli.NewString(cli.FormatDate(*last)))
	}
	if err := syncer.FullSync(a, o.Force); err != nil {
		r := cli.Error(err)
		m := "Syncing failed: " + r.MessageText()
		r.Message = &m
		return r
	}
	return cli.Success(cli.NewMessageNull("Syncing complete."))
}

// StatusTemplate is the `bw status` output.
type StatusTemplate struct {
	ServerURL *string `json:"serverUrl"`
	LastSync  *string `json:"lastSync"`
	UserEmail *string `json:"userEmail,omitempty"`
	UserID    *string `json:"userId,omitempty"`
	Status    string  `json:"status"`
}

// Status implements StatusCommand.run.
func Status(a *app.App) *cli.Response {
	d, err := a.Data()
	if err != nil {
		return cli.Error(err)
	}
	t := &StatusTemplate{Status: "unauthenticated"}
	if api.HasBaseURL(d.Environment) {
		base := api.Resolve(d.Environment).Base
		t.ServerURL = &base
	}
	if acct := d.Active(); acct != nil {
		if acct.LastSync != nil {
			s := cli.FormatDate(*acct.LastSync)
			t.LastSync = &s
		}
		email, id := acct.Email, acct.UserID
		t.UserEmail, t.UserID = &email, &id
		if acct.AccessToken != "" {
			if a.IsUnlocked() {
				t.Status = "unlocked"
			} else {
				t.Status = "locked"
			}
		}
	}
	return cli.Success(cli.NewTemplate(t))
}

// ConfigOptions are the options of `bw config`.
type ConfigOptions struct {
	WebVault      string
	API           string
	Identity      string
	Icons         string
	Notifications string
	Events        string
	KeyConnector  string
}

const regionSelfHosted = "Self-hosted"

// formatURL mirrors formatUrl in DefaultEnvironmentService.
func formatURL(u string) string {
	if u == "" {
		return ""
	}
	u = strings.TrimRight(u, "/")
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	return strings.TrimSpace(u)
}

// Config implements ConfigCommand.run.
func Config(a *app.App, setting, value string, o ConfigOptions) *cli.Response {
	switch strings.ToLower(setting) {
	case "server":
		return configServer(a, value, o)
	default:
		return cli.BadRequest("Unknown setting.")
	}
}

func configServer(a *app.App, url string, o ConfigOptions) *cli.Response {
	d, err := a.Data()
	if err != nil {
		return cli.Error(err)
	}
	if strings.TrimSpace(url) == "" && o.WebVault == "" && o.API == "" && o.Identity == "" &&
		o.Icons == "" && o.Notifications == "" && o.Events == "" {
		if api.HasBaseURL(d.Environment) {
			return cli.Success(cli.NewString(api.Resolve(d.Environment).Base))
		}
		return cli.Success(cli.NewString("https://bitwarden.com"))
	}
	if d.Active() != nil {
		return cli.Error("Logout required before server config update.")
	}
	if url == "null" || url == "bitwarden.com" || url == "https://bitwarden.com" {
		url = ""
	}
	env := state.Environment{
		Region:        regionSelfHosted,
		Base:          formatURL(url),
		WebVault:      formatURL(o.WebVault),
		Api:           formatURL(o.API),
		Identity:      formatURL(o.Identity),
		Icons:         formatURL(o.Icons),
		Notifications: formatURL(o.Notifications),
		Events:        formatURL(o.Events),
		KeyConnector:  formatURL(o.KeyConnector),
	}
	// Self-hosted without urls falls back to the default region.
	if env.Base == "" && env.WebVault == "" && env.Api == "" && env.Identity == "" && env.Icons == "" &&
		env.Notifications == "" && env.Events == "" {
		env = state.Environment{Region: "US"}
	}
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment = env
		return nil
	})
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(cli.NewMessageNull("Saved setting `config`."))
}
