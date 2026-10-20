// Package syncer implements the full vault sync (DefaultSyncService.fullSync): it downloads
// /sync and stores the encrypted vault, profile and key material in state.
package syncer

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// Options tweak a sync.
type Options struct {
	// SkipTokenRefresh skips the forced access token refresh before syncing (login uses it).
	SkipTokenRefresh bool
}

// FullSync runs a full sync for the active account, refreshing the access token first. Unless
// force is set, it only downloads the vault when the server revision date is newer than the
// last sync. It returns the error that made the sync fail (allowThrowOnError semantics);
// callers that should not fail on sync errors can ignore it.
func FullSync(a *app.App, force bool) error {
	_, err := Sync(a, force, Options{})
	return err
}

// LastSync returns the last sync date of the active account, or nil.
func LastSync(a *app.App) *time.Time {
	acct := a.ActiveAccount()
	if acct == nil {
		return nil
	}
	return acct.LastSync
}

// Sync is FullSync with options. It reports whether vault data was downloaded.
func Sync(a *app.App, force bool, opts Options) (bool, error) {
	acct := a.ActiveAccount()
	if acct == nil || acct.AccessToken == "" {
		return false, nil
	}
	userID := acct.UserID
	now := time.Now()

	needsSync, err := needsSyncing(a, acct, force)
	if err != nil {
		return false, err
	}
	if !needsSync {
		return false, setLastSync(a, userID, now)
	}

	if !opts.SkipTokenRefresh {
		if err := a.API.RefreshToken(); err != nil {
			return false, err
		}
	}

	var raw []byte
	if err := a.API.Get("/sync?excludeDomains=true", &raw); err != nil {
		return false, err
	}
	resp, err := ParseSyncResponse(raw)
	if err != nil {
		return false, err
	}
	if resp.ProfileID == "" {
		return false, errors.New("Sync response does not contain a profile.")
	}

	err = a.Store.Update(func(d *state.Data) error {
		acct := d.Accounts[userID]
		if acct == nil {
			return errors.New("You are not logged in.")
		}
		resp.Apply(acct)
		t := now.UTC()
		acct.LastSync = &t
		return nil
	})
	if err != nil {
		return false, err
	}
	if keys := resp.AccountKeys(); keys != nil {
		if err := auth.SetAccountKeys(a.Store, userID, keys); err != nil {
			return false, err
		}
	}
	return true, nil
}

func setLastSync(a *app.App, userID string, t time.Time) error {
	return a.Store.Update(func(d *state.Data) error {
		if acct := d.Accounts[userID]; acct != nil {
			u := t.UTC()
			acct.LastSync = &u
		}
		return nil
	})
}

func needsSyncing(a *app.App, acct *state.Account, force bool) (bool, error) {
	if force {
		return true, nil
	}
	if acct.LastSync == nil || acct.LastSync.IsZero() {
		return true, nil
	}
	var revision float64
	if err := a.API.Get("/accounts/revision-date", &revision); err != nil {
		return false, err
	}
	if revision < 0 {
		// Account was deleted, log out now.
		_ = a.Logout()
	}
	if !time.UnixMilli(int64(revision)).After(*acct.LastSync) {
		return false, nil
	}
	return true, nil
}

// Response is a parsed /sync response. Entities stay raw server JSON.
type Response struct {
	Profile     json.RawMessage
	ProfileID   string
	Folders     []json.RawMessage
	Collections []json.RawMessage
	Ciphers     []json.RawMessage
	Policies    []json.RawMessage
	Sends       []json.RawMessage
	Domains     json.RawMessage

	profile        profile
	userDecryption *userDecryption
}

type kdfResponse struct {
	KdfType     *int `json:"kdfType"`
	Iterations  *int `json:"iterations"`
	Memory      *int `json:"memory"`
	Parallelism *int `json:"parallelism"`
}

type userDecryption struct {
	MasterPasswordUnlock *struct {
		Salt                      string       `json:"salt"`
		Kdf                       *kdfResponse `json:"kdf"`
		MasterKeyEncryptedUserKey string       `json:"masterKeyEncryptedUserKey"`
	} `json:"masterPasswordUnlock"`
}

type profile struct {
	ID                 string          `json:"id"`
	Name               *string         `json:"name"`
	Email              string          `json:"email"`
	Key                string          `json:"key"`
	PrivateKey         string          `json:"privateKey"`
	AccountKeys        json.RawMessage `json:"accountKeys"`
	ForcePasswordReset bool            `json:"forcePasswordReset"`
	UsesKeyConnector   bool            `json:"usesKeyConnector"`
}

// ParseSyncResponse parses a /sync response body (PascalCase or camelCase).
func ParseSyncResponse(raw []byte) (*Response, error) {
	var r struct {
		Profile        json.RawMessage   `json:"profile"`
		Folders        []json.RawMessage `json:"folders"`
		Collections    []json.RawMessage `json:"collections"`
		Ciphers        []json.RawMessage `json:"ciphers"`
		Policies       []json.RawMessage `json:"policies"`
		Sends          []json.RawMessage `json:"sends"`
		Domains        json.RawMessage   `json:"domains"`
		UserDecryption *userDecryption   `json:"userDecryption"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	out := &Response{
		Folders: r.Folders, Collections: r.Collections, Ciphers: r.Ciphers,
		Policies: r.Policies, Sends: r.Sends, userDecryption: r.UserDecryption,
	}
	if isPresent(r.Profile) {
		out.Profile = r.Profile
		if err := json.Unmarshal(r.Profile, &out.profile); err != nil {
			return nil, err
		}
		out.ProfileID = out.profile.ID
	}
	if isPresent(r.Domains) {
		out.Domains = r.Domains
	}
	return out, nil
}

func isPresent(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }

// idsOf returns the ids of items in server order.
func idsOf(items []json.RawMessage) []string {
	ids := make([]string, 0, len(items))
	for _, it := range items {
		var x struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(it, &x) == nil && x.ID != "" {
			ids = append(ids, x.ID)
		}
	}
	return ids
}

func byID(items []json.RawMessage) map[string]json.RawMessage {
	m := make(map[string]json.RawMessage, len(items))
	for _, it := range items {
		var x struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(it, &x) == nil && x.ID != "" {
			m[x.ID] = it
		}
	}
	return m
}

// AccountKeys returns the profile's raw accountKeys, or nil.
func (r *Response) AccountKeys() json.RawMessage {
	if isPresent(r.profile.AccountKeys) {
		return r.profile.AccountKeys
	}
	return nil
}

// Apply stores the sync response into acct (vault data, profile info and key material).
func (r *Response) Apply(acct *state.Account) {
	p := r.profile
	acct.Vault = state.VaultData{
		Profile:     r.Profile,
		Ciphers:     byID(r.Ciphers),
		Folders:     byID(r.Folders),
		Collections: byID(r.Collections),
		Policies:    r.Policies,
		Sends:       byID(r.Sends),
		Domains:     r.Domains,

		CipherOrder:     idsOf(r.Ciphers),
		FolderOrder:     idsOf(r.Folders),
		CollectionOrder: idsOf(r.Collections),
		SendOrder:       idsOf(r.Sends),
	}
	if p.Name != nil {
		acct.Name = *p.Name
	}
	if p.Email != "" {
		acct.Email = p.Email
	}
	acct.UsesKeyConnector = p.UsesKeyConnector
	if p.ForcePasswordReset {
		acct.ForceSetPasswordReason = 5 // AdminForcePasswordReset
	}

	// Crypto sync handler: master password unlock data and account cryptographic state.
	if r.userDecryption != nil && r.userDecryption.MasterPasswordUnlock != nil {
		mpu := r.userDecryption.MasterPasswordUnlock
		if mpu.MasterKeyEncryptedUserKey != "" {
			acct.EncUserKey = mpu.MasterKeyEncryptedUserKey
		}
		if mpu.Salt != "" {
			acct.KdfSalt = mpu.Salt
		}
		if k := mpu.Kdf; k != nil && k.KdfType != nil && k.Iterations != nil {
			cfg := crypto.KdfConfig{Type: crypto.KdfType(*k.KdfType), Iterations: *k.Iterations}
			if cfg.Type == crypto.KdfArgon2id {
				cfg.Memory, cfg.Parallelism = k.Memory, k.Parallelism
			}
			acct.Kdf = cfg
		}
		acct.HasMasterPassword = true
	} else if p.Key != "" {
		acct.EncUserKey = p.Key
	}
	if isPresent(p.AccountKeys) {
		var k struct {
			PublicKeyEncryptionKeyPair *struct {
				WrappedPrivateKey string `json:"wrappedPrivateKey"`
			} `json:"publicKeyEncryptionKeyPair"`
		}
		if json.Unmarshal(p.AccountKeys, &k) == nil && k.PublicKeyEncryptionKeyPair != nil &&
			k.PublicKeyEncryptionKeyPair.WrappedPrivateKey != "" {
			acct.EncPrivateKey = k.PublicKeyEncryptionKeyPair.WrappedPrivateKey
		}
	} else if p.PrivateKey != "" {
		acct.EncPrivateKey = p.PrivateKey
	}
}
