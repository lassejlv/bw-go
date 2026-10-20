// Package migrations ports the encrypted-data migrations the CLI runs after login and unlock
// (libs/common/src/key-management/encrypted-migrator): DefaultEncryptedMigrator with the
// UserKeyIdBackfillMigration and the BiometricPersistentMigration.
package migrations

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/syncer"
)

// Requirement is MigrationRequirement.
type Requirement string

// MigrationRequirement values.
const (
	NeedsMigration                   Requirement = "needsMigration"
	NeedsMigrationWithMasterPassword Requirement = "needsMigrationWithMasterPassword"
	NoMigrationNeeded                Requirement = "noMigrationNeeded"
)

// Migration is EncryptedMigration: an online migration of the user's persistent state, run at
// most once per user (or device for local migrations), safe to fail but never leaving the user in
// a broken state.
type Migration interface {
	// RunMigrations runs the migration.
	RunMigrations(userID string, masterPassword *string) error
	// NeedsMigration reports whether the migration needs to run, and whether it needs the
	// master password.
	NeedsMigration(userID string) Requirement
}

// ClientType is the client the migrator runs in (ClientType enum values).
type ClientType string

// Client types.
const (
	ClientCli     ClientType = "cli"
	ClientDesktop ClientType = "desktop"
)

// Logger is the subset of the CLI's ConsoleLogService the migrations use.
type Logger struct {
	// Info is filtered out unless BITWARDENCLI_DEBUG is "true" (stdout, stderr with BW_RESPONSE).
	Info func(string)
	// Warning and Error always go to stderr.
	Warning func(string)
	Error   func(string)
}

// ConsoleLogger mirrors the CLI's ConsoleLogService configuration.
func ConsoleLogger() Logger {
	return Logger{
		Info: func(msg string) {
			if os.Getenv("BITWARDENCLI_DEBUG") != "true" {
				return
			}
			w := os.Stdout
			if os.Getenv("BW_RESPONSE") == "true" {
				w = os.Stderr
			}
			fmt.Fprintln(w, msg)
		},
		Warning: func(msg string) { fmt.Fprintln(os.Stderr, msg) },
		Error:   func(msg string) { fmt.Fprintln(os.Stderr, msg) },
	}
}

type namedMigration struct {
	name      string
	migration Migration
}

// Migrator is DefaultEncryptedMigrator.
type Migrator struct {
	log        Logger
	fullSync   func(force bool) error
	migrations []namedMigration

	mu      sync.Mutex
	running bool
}

// Deps are the services the migrations need.
type Deps struct {
	App        *app.App
	ClientType ClientType
	Log        Logger
	// FullSync is SyncService.fullSync (defaults to syncer.FullSync on App). Its errors are
	// ignored, like fullSync without allowThrowOnError.
	FullSync func(force bool) error
	// Biometrics and BiometricState are needed by the BiometricPersistentMigration, which is
	// only registered for the desktop client.
	Biometrics     BiometricsService
	BiometricState BiometricStateService
	Toast          Toaster
}

// New creates the migrator with its migrations registered in upstream order.
func New(d Deps) *Migrator {
	if d.FullSync == nil {
		a := d.App
		d.FullSync = func(force bool) error { return syncer.FullSync(a, force) }
	}
	if d.Log.Info == nil {
		d.Log = ConsoleLogger()
	}
	m := &Migrator{log: d.Log, fullSync: d.FullSync}

	// Register migrations here

	m.migrations = append(m.migrations, namedMigration{
		name:      "User Key Id Backfill Migration",
		migration: NewUserKeyIDBackfillMigration(d.App, d.FullSync, d.Log),
	})

	// "Minimum PBKDF2 Iteration Count Migration" (MinimumKdfMigration) is registered here
	// upstream. It is deliberately not ported: it changes the account's KDF on the server
	// (re-deriving the master key and re-wrapping the user key), which bwgo must not do.

	// Biometric persistent encryption is only relevant on desktop
	if d.ClientType == ClientDesktop {
		m.migrations = append(m.migrations, namedMigration{
			name:      "Biometric V2 Encryption Migration",
			migration: NewBiometricPersistentMigration(d.App, d.Biometrics, d.BiometricState, d.Log, d.Toast),
		})
	}

	// "V2 User Key Rotation Migration" (V2KeyRotationMigration) is registered here upstream for
	// every client except the CLI. It is deliberately not ported: it rotates the user key and
	// re-encrypts the vault on the server.

	return m
}

// RunMigrations runs the migrations the user needs, sequentially in registration order, then
// forces a full sync if any ran. It needs the decrypted user key to be set already. When a
// migration needs the master password and masterPassword is nil, nothing runs. Errors of a
// migration are returned.
func (m *Migrator) RunMigrations(userID string, masterPassword *string) error {
	if userID == "" {
		return errors.New("userId is null or undefined.")
	}

	switch m.NeedsMigrations(userID) {
	case NoMigrationNeeded:
		return nil
	case NeedsMigrationWithMasterPassword:
		if masterPassword == nil {
			return nil
		}
	}

	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	m.log.Info("[Encrypted Migrator] Starting migrations for user: " + userID)
	ranMigration := false
	for _, nm := range m.migrations {
		if nm.migration.NeedsMigration(userID) != NoMigrationNeeded {
			m.log.Info("[Encrypted Migrator] Running migration: " + nm.name)
			if err := nm.migration.RunMigrations(userID, masterPassword); err != nil {
				m.log.Error(fmt.Sprintf("[Encrypted Migrator] Error running migrations for user: %s %v", userID, err))
				return err
			}
			ranMigration = true
		}
	}
	m.log.Info("[Encrypted Migrator] Completed migrations for user: " + userID)
	if ranMigration {
		// fullSync does not throw (allowThrowOnError is false).
		_ = m.fullSync(true)
	}
	return nil
}

// NeedsMigrations reports the strongest requirement of all migrations.
func (m *Migrator) NeedsMigrations(userID string) Requirement {
	reqs := make([]Requirement, len(m.migrations))
	for i, nm := range m.migrations {
		reqs[i] = nm.migration.NeedsMigration(userID)
	}
	out := NoMigrationNeeded
	for _, r := range reqs {
		if r == NeedsMigrationWithMasterPassword {
			return r
		}
		if r == NeedsMigration {
			out = r
		}
	}
	return out
}

// IsRunningMigrations reports whether migrations are running.
func (m *Migrator) IsRunningMigrations() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}
