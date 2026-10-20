package migrations

import (
	"errors"
	"fmt"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// Port of migrations/biometric-persistent-encryption-migration.ts.
//
// Reviewed before porting: it only re-enrolls the locally stored, biometric-protected copy of the
// user key when the user key changed since the last enrollment. Nothing changes on the server and
// no account key changes. Upstream registers it for the desktop client only, and on the CLI the
// biometrics service never has a persistent key (CliBiometricsService.hasPersistentKey), so it
// never runs in bwgo; it is registered only for ClientDesktop, like upstream.

// BiometricsService is the part of BiometricsService the migration uses.
type BiometricsService interface {
	HasPersistentKey(userID string) bool
	EnrollPersistent(userID string, userKey *crypto.SymmetricKey) error
	SetBiometricProtectedUnlockKeyForUser(userID string, userKey *crypto.SymmetricKey) error
	DeleteBiometricUnlockKeyForUser(userID string) error
}

// BiometricStateService is the part of BiometricStateService the migration uses.
type BiometricStateService interface {
	BiometricUnlockEnabled(userID string) bool
	// BiometricEnrolledKeyID returns the hex key id of the enrolled key, or nil.
	BiometricEnrolledKeyID(userID string) *string
}

// Toaster shows the platform toast (PlatformUtilsService.showToast); nil on the CLI.
type Toaster func(kind, title, text string)

// BiometricPersistentMigration re-enrolls biometric stored keys when the user key has changed
// since the last biometric enrollment, detected by comparing key ids (a key id appearing or
// disappearing counts as a change).
type BiometricPersistentMigration struct {
	app   *app.App
	bio   BiometricsService
	state BiometricStateService
	log   Logger
	toast Toaster
}

// NewBiometricPersistentMigration creates the migration. toast may be nil (the CLI has none).
func NewBiometricPersistentMigration(a *app.App, bio BiometricsService, st BiometricStateService, log Logger, toast Toaster) *BiometricPersistentMigration {
	return &BiometricPersistentMigration{app: a, bio: bio, state: st, log: log, toast: toast}
}

func (m *BiometricPersistentMigration) userKey(userID string) *crypto.SymmetricKey {
	acct := m.app.ActiveAccount()
	if acct == nil || acct.UserID != userID {
		return nil
	}
	k, err := m.app.UserKey()
	if err != nil {
		return nil
	}
	return k
}

// NeedsMigration compares the enrolled key id with the current user key's.
func (m *BiometricPersistentMigration) NeedsMigration(userID string) Requirement {
	if m.bio == nil || m.state == nil || !m.state.BiometricUnlockEnabled(userID) {
		return NoMigrationNeeded
	}
	if !m.bio.HasPersistentKey(userID) {
		return NoMigrationNeeded
	}
	userKey := m.userKey(userID)
	if userKey == nil {
		return NoMigrationNeeded
	}
	var current *string
	if id, ok := bwauth.SymmetricKeyID(userKey); ok {
		current = &id
	}
	enrolled := m.state.BiometricEnrolledKeyID(userID)
	if current == nil && enrolled == nil || current != nil && enrolled != nil && *current == *enrolled {
		return NoMigrationNeeded
	}
	return NeedsMigration
}

// RunMigrations re-enrolls the persistent biometric key; on failure it turns off biometric
// unlock on restart instead.
func (m *BiometricPersistentMigration) RunMigrations(userID string, _ *string) error {
	userKey := m.userKey(userID)
	if userKey == nil {
		return errors.New("User key is not available")
	}
	m.log.Info("[BiometricPersistentMigration] Re-enrolling biometric keys for user " + userID)
	if err := m.bio.EnrollPersistent(userID, userKey); err != nil {
		m.log.Error(fmt.Sprintf("[BiometricPersistentMigration] Re-enrollment failed %v", err))
		return m.disablePersistent(userID, userKey)
	}
	return m.bio.SetBiometricProtectedUnlockKeyForUser(userID, userKey)
}

// disablePersistent turns off biometric unlock on app restart after a failed re-enrollment; the
// session biometric unlock keeps working.
func (m *BiometricPersistentMigration) disablePersistent(userID string, userKey *crypto.SymmetricKey) error {
	if err := m.bio.DeleteBiometricUnlockKeyForUser(userID); err != nil {
		return err
	}
	if err := m.bio.SetBiometricProtectedUnlockKeyForUser(userID, userKey); err != nil {
		return err
	}
	if m.toast != nil {
		m.toast("warning", "Unlock with biometrics", "Biometric unlock on app restart was turned off. Turn it on again in settings.")
	}
	return nil
}
