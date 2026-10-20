package migrations

import (
	"errors"
	"fmt"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/state"
)

// Port of migrations/user-key-id-backfill-migration.ts and the SDK's
// UserCryptoManagementClient::user_key_id_needs_backfill / user_key_id_backfill
// (bitwarden-user-crypto-management/src/key_id_backfill.rs).
//
// Reviewed before porting: the migration only records the id of the user's current user key with
// the server (POST /accounts/key-management/user-key-id). No key material leaves the client and no
// key, KDF or encrypted data changes, so other clients keep reading the account unchanged.

// cooldown is COOLDOWN_HOURS.
const cooldown = 24 * time.Hour

// KeyIDBackfillError is the SDK KeyIdBackfillError (a flat error: name "KeyIdBackfillError").
type KeyIDBackfillError struct {
	Variant string
}

// KeyIdBackfillError variants.
const (
	BackfillUserKeyNotAvailable = "UserKeyNotAvailable"
	BackfillNoKeyID             = "NoKeyId"
	BackfillAPI                 = "Api"
)

func (e *KeyIDBackfillError) Error() string {
	msg := e.Variant
	switch e.Variant {
	case BackfillUserKeyNotAvailable:
		msg = "User key is not available in key store"
	case BackfillNoKeyID:
		msg = "The current user key has no key id to backfill"
	case BackfillAPI:
		msg = "API call failed during user key id backfill"
	}
	// String(error) of the SDK's JS error.
	return "KeyIdBackfillError: " + msg
}

// UserKeyIDBackfillMigration records the id of the user's current user key with the server.
// It requires the account to be unlocked, but never the master password.
type UserKeyIDBackfillMigration struct {
	app      *app.App
	fullSync func(force bool) error
	log      Logger
	now      func() time.Time
}

// NewUserKeyIDBackfillMigration creates the migration.
func NewUserKeyIDBackfillMigration(a *app.App, fullSync func(bool) error, log Logger) *UserKeyIDBackfillMigration {
	return &UserKeyIDBackfillMigration{app: a, fullSync: fullSync, log: log, now: time.Now}
}

// RunMigrations posts the key id and stores it as the id the server knows.
func (m *UserKeyIDBackfillMigration) RunMigrations(userID string, _ *string) error {
	if userID == "" {
		return errors.New("userId is null or undefined.")
	}
	m.log.Info("[UserKeyIdBackfillMigration] Recording the user key id for " + userID)

	keyID, err := m.currentUserKeyID(userID)
	if err != nil {
		return err
	}
	if keyID == "" {
		return &KeyIDBackfillError{Variant: BackfillNoKeyID}
	}
	body := struct {
		UserKeyID string `json:"userKeyId"`
	}{keyID}
	if err := m.app.API.Send("POST", "/accounts/key-management/user-key-id", body, true, nil, nil); err != nil {
		// Only server-side failures back off: the server may not support the endpoint at all.
		m.startCooldown(userID)
		return &KeyIDBackfillError{Variant: BackfillAPI}
	}
	// Written only after the server accepted it, so state never claims an id the server lacks.
	return m.app.Store.Update(func(d *state.Data) error {
		if acct := d.Accounts[userID]; acct != nil {
			acct.UserKeyID = keyID
		}
		return nil
	})
}

// NeedsMigration reports whether the server is missing the id of the current user key.
func (m *UserKeyIDBackfillMigration) NeedsMigration(userID string) Requirement {
	if userID == "" {
		return NoMigrationNeeded
	}
	// Checked before anything else: a failing migration would otherwise loop through the sync.
	if m.isInCooldown(userID) {
		m.log.Info(fmt.Sprintf("[UserKeyIdBackfillMigration] Skipping migration for user %s; a previous attempt failed less than %d hours ago",
			userID, int(cooldown/time.Hour)))
		return NoMigrationNeeded
	}

	needs, err := m.needsBackfill(userID)
	if err == nil && needs {
		// If another device has performed the backfill, but the local device has not synced
		// recently, sync first so the backfill is not done twice.
		_ = m.fullSync(false)
		needs, err = m.needsBackfill(userID)
		if err == nil && !needs {
			m.log.Info(fmt.Sprintf("[UserKeyIdBackfillMigration] After syncing, user %s does not need migration anymore. This means the migration was likely already performed on another client!", userID))
			return NoMigrationNeeded
		}
	}
	if err != nil {
		m.log.Warning(fmt.Sprintf("[UserKeyIdBackfillMigration] Could not determine whether user %s needs migration: %v", userID, err))
		return NoMigrationNeeded
	}
	if !needs {
		return NoMigrationNeeded
	}
	return NeedsMigration
}

// needsBackfill is user_key_id_needs_backfill: false when the server already knows a key id,
// otherwise whether the current user key has one.
func (m *UserKeyIDBackfillMigration) needsBackfill(userID string) (bool, error) {
	d, err := m.app.Data()
	if err != nil {
		return false, err
	}
	if acct := d.Accounts[userID]; acct != nil && acct.UserKeyID != "" {
		return false, nil
	}
	keyID, err := m.currentUserKeyID(userID)
	if err != nil {
		return false, err
	}
	return keyID != "", nil
}

// currentUserKeyID reads the key id of the unlocked user key ("" when it has none).
func (m *UserKeyIDBackfillMigration) currentUserKeyID(userID string) (string, error) {
	acct := m.app.ActiveAccount()
	if acct == nil || acct.UserID != userID {
		return "", &KeyIDBackfillError{Variant: BackfillUserKeyNotAvailable}
	}
	userKey, err := m.app.UserKey()
	if err != nil {
		return "", &KeyIDBackfillError{Variant: BackfillUserKeyNotAvailable}
	}
	id, _ := bwauth.SymmetricKeyID(userKey)
	return id, nil
}

func (m *UserKeyIDBackfillMigration) isInCooldown(userID string) bool {
	d, err := m.app.Data()
	if err != nil {
		return false
	}
	acct := d.Accounts[userID]
	if acct == nil || acct.UserKeyIDBackfillCooldown == nil {
		return false
	}
	return m.now().Sub(*acct.UserKeyIDBackfillCooldown) < cooldown
}

func (m *UserKeyIDBackfillMigration) startCooldown(userID string) {
	t := m.now().UTC()
	_ = m.app.Store.Update(func(d *state.Data) error {
		if acct := d.Accounts[userID]; acct != nil {
			acct.UserKeyIDBackfillCooldown = &t
		}
		return nil
	})
}
