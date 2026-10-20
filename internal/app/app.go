// Package app wires state, the API client and key/session handling together and provides the
// authentication guards used by commands (BaseProgram.exitIfAuthed/exitIfNotAuthed/exitIfLocked).
package app

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/google/uuid"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// ErrLocked is returned when the vault is locked.
var ErrLocked = errors.New("Vault is locked.")

// App is the service container shared by all commands.
type App struct {
	Store *state.Store
	API   *api.Client
}

// New opens state and ensures a device identifier exists.
func New() (*App, error) {
	st, err := state.Open()
	if err != nil {
		return nil, err
	}
	a := &App{Store: st, API: api.New(st)}
	d, err := st.Load()
	if err != nil {
		return nil, err
	}
	if d.AppID == "" {
		_ = st.Update(func(d *state.Data) error {
			if d.AppID == "" {
				d.AppID = uuid.NewString()
			}
			return nil
		})
	}
	return a, nil
}

// Data loads the persisted state.
func (a *App) Data() (*state.Data, error) { return a.Store.Load() }

// Urls returns the resolved environment.
func (a *App) Urls() api.Urls { return a.API.Urls() }

// ActiveAccount returns the active account or nil.
func (a *App) ActiveAccount() *state.Account {
	d, err := a.Store.Load()
	if err != nil {
		return nil
	}
	return d.Active()
}

// UpdateAccount mutates the active account under the state lock.
func (a *App) UpdateAccount(fn func(acct *state.Account) error) error {
	return a.Store.Update(func(d *state.Data) error {
		acct := d.Active()
		if acct == nil {
			return errors.New("You are not logged in.")
		}
		return fn(acct)
	})
}

// SessionKey returns the key from BW_SESSION, or nil when absent/invalid.
func SessionKey() *crypto.SymmetricKey {
	s := os.Getenv("BW_SESSION")
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	k, err := crypto.NewSymmetricKey(b)
	if err != nil {
		return nil
	}
	return k
}

// NewSession generates a fresh session key and exports it to BW_SESSION for this process.
func NewSession() string {
	k := crypto.GenerateKey()
	s := k.B64()
	os.Setenv("BW_SESSION", s)
	return s
}

// SetUserKey stores the user key protected by the current session key (creating one if needed).
func (a *App) SetUserKey(userKey *crypto.SymmetricKey) error {
	sk := SessionKey()
	if sk == nil {
		NewSession()
		sk = SessionKey()
	}
	enc, err := crypto.EncryptBytes(userKey.Bytes(), sk)
	if err != nil {
		return err
	}
	return a.UpdateAccount(func(acct *state.Account) error {
		acct.ProtectedUserKey = base64.StdEncoding.EncodeToString(enc)
		return nil
	})
}

// UserKey returns the decrypted user key using BW_SESSION, or ErrLocked.
func (a *App) UserKey() (*crypto.SymmetricKey, error) {
	acct := a.ActiveAccount()
	if acct == nil {
		return nil, errors.New("You are not logged in.")
	}
	if acct.ProtectedUserKey == "" {
		return nil, ErrLocked
	}
	sk := SessionKey()
	if sk == nil {
		return nil, ErrLocked
	}
	buf, err := base64.StdEncoding.DecodeString(acct.ProtectedUserKey)
	if err != nil {
		return nil, ErrLocked
	}
	raw, err := crypto.DecryptBytes(buf, sk)
	if err != nil {
		return nil, ErrLocked
	}
	return crypto.NewSymmetricKey(raw)
}

// IsUnlocked reports whether the user key is available.
func (a *App) IsUnlocked() bool {
	_, err := a.UserKey()
	return err == nil
}

// Lock clears the protected user key.
func (a *App) Lock() error {
	return a.UpdateAccount(func(acct *state.Account) error {
		acct.ProtectedUserKey = ""
		return nil
	})
}

// Logout removes the active account and its data.
func (a *App) Logout() error {
	return a.Store.Update(func(d *state.Data) error {
		if d.ActiveUserID != "" {
			delete(d.Accounts, d.ActiveUserID)
		}
		d.ActiveUserID = ""
		return nil
	})
}

// IsAuthed reports whether there is an active account with an access token.
func (a *App) IsAuthed() bool {
	acct := a.ActiveAccount()
	return acct != nil && (acct.AccessToken != "")
}

// InteractiveUnlock is provided by the auth commands package to unlock when a command needs the vault.
var InteractiveUnlock func(a *App) *cli.Response

// ExitIfAuthed exits when a user is already logged in.
func (a *App) ExitIfAuthed() {
	if acct := a.ActiveAccount(); acct != nil && acct.AccessToken != "" {
		cli.Process(cli.Error("You are already logged in as "+acct.Email+"."), true)
	}
}

// ExitIfNotAuthed exits when no user is logged in and returns the active user id.
func (a *App) ExitIfNotAuthed() string {
	acct := a.ActiveAccount()
	if acct == nil || acct.AccessToken == "" {
		cli.Process(cli.Error("You are not logged in."), true)
		return ""
	}
	return acct.UserID
}

// ExitIfLocked exits when not logged in, or when locked and unlocking interactively fails.
func (a *App) ExitIfLocked() {
	a.ExitIfNotAuthed()
	if a.IsUnlocked() {
		return
	}
	if !cli.CanInteract() {
		cli.Process(cli.Error("Vault is locked."), true)
		return
	}
	acct := a.ActiveAccount()
	if acct.UsesKeyConnector {
		cli.Process(cli.Error("Your vault is locked. You must unlock your vault using your session key.\n"+
			"If you do not have your session key, you can get a new one by logging out and logging in again."), true)
		return
	}
	if InteractiveUnlock == nil {
		cli.Process(cli.Error("Vault is locked."), true)
		return
	}
	if r := InteractiveUnlock(a); r != nil && !r.Success {
		cli.Process(r, true)
	}
}
