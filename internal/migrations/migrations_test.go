package migrations

import (
	"errors"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

const userID = "11111111-2222-3333-4444-555555555555"

func quietLog(t *testing.T, buf *strings.Builder) Logger {
	w := func(prefix string) func(string) {
		return func(m string) { buf.WriteString(prefix + m + "\n") }
	}
	return Logger{Info: w("info: "), Warning: w("warn: "), Error: w("error: ")}
}

type fakeMigration struct {
	name    string
	req     Requirement
	err     error
	ran     *[]string
	gotPass **string
}

func (f *fakeMigration) NeedsMigration(string) Requirement { return f.req }
func (f *fakeMigration) RunMigrations(_ string, mp *string) error {
	*f.ran = append(*f.ran, f.name)
	if f.gotPass != nil {
		*f.gotPass = mp
	}
	return f.err
}

func newTestMigrator(t *testing.T, syncs *[]bool, ms ...*fakeMigration) *Migrator {
	var buf strings.Builder
	m := &Migrator{log: quietLog(t, &buf), fullSync: func(force bool) error { *syncs = append(*syncs, force); return nil }}
	for _, f := range ms {
		m.migrations = append(m.migrations, namedMigration{name: f.name, migration: f})
	}
	return m
}

func TestMigratorRunsNeededMigrationsInOrder(t *testing.T) {
	var ran []string
	var syncs []bool
	var gotPass *string
	m := newTestMigrator(t, &syncs,
		&fakeMigration{name: "a", req: NeedsMigration, ran: &ran, gotPass: &gotPass},
		&fakeMigration{name: "b", req: NoMigrationNeeded, ran: &ran},
		&fakeMigration{name: "c", req: NeedsMigration, ran: &ran},
	)
	pw := "pw"
	if err := m.RunMigrations(userID, &pw); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, ",") != "a,c" || len(syncs) != 1 || !syncs[0] || gotPass == nil || *gotPass != "pw" {
		t.Errorf("ran %v, syncs %v", ran, syncs)
	}
	if m.IsRunningMigrations() {
		t.Error("still running")
	}

	// Nothing needed: no run, no sync.
	ran, syncs = nil, nil
	m = newTestMigrator(t, &syncs, &fakeMigration{name: "a", req: NoMigrationNeeded, ran: &ran})
	if err := m.RunMigrations(userID, nil); err != nil || len(ran) != 0 || len(syncs) != 0 {
		t.Errorf("ran %v syncs %v err %v", ran, syncs, err)
	}

	if err := m.RunMigrations("", nil); err == nil || err.Error() != "userId is null or undefined." {
		t.Errorf("empty user id: %v", err)
	}
}

func TestMigratorMasterPasswordGate(t *testing.T) {
	var ran []string
	var syncs []bool
	m := newTestMigrator(t, &syncs,
		&fakeMigration{name: "a", req: NeedsMigration, ran: &ran},
		&fakeMigration{name: "b", req: NeedsMigrationWithMasterPassword, ran: &ran},
	)
	if m.NeedsMigrations(userID) != NeedsMigrationWithMasterPassword {
		t.Error("aggregate requirement")
	}
	// No password (e.g. biometric unlock or API key login): everything is skipped.
	if err := m.RunMigrations(userID, nil); err != nil || len(ran) != 0 {
		t.Errorf("ran without password: %v %v", ran, err)
	}
	pw := ""
	if err := m.RunMigrations(userID, &pw); err != nil || strings.Join(ran, ",") != "a,b" {
		t.Errorf("ran with password: %v %v", ran, err)
	}
}

func TestMigratorStopsOnError(t *testing.T) {
	var ran []string
	var syncs []bool
	boom := errors.New("boom")
	m := newTestMigrator(t, &syncs,
		&fakeMigration{name: "a", req: NeedsMigration, ran: &ran, err: boom},
		&fakeMigration{name: "b", req: NeedsMigration, ran: &ran},
	)
	if err := m.RunMigrations(userID, nil); !errors.Is(err, boom) || strings.Join(ran, ",") != "a" || len(syncs) != 0 {
		t.Errorf("err %v ran %v syncs %v", err, ran, syncs)
	}
	if m.IsRunningMigrations() {
		t.Error("lock not released after an error")
	}
	// A run already in progress makes another call return immediately.
	m.running = true
	ran = nil
	if err := m.RunMigrations(userID, nil); err != nil || len(ran) != 0 {
		t.Errorf("concurrent run: %v %v", ran, err)
	}
}

func unlockedApp(t *testing.T) (*app.App, *crypto.SymmetricKey) {
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Store.Update(func(d *state.Data) error {
		d.ActiveUserID = userID
		d.Accounts = map[string]*state.Account{userID: {UserID: userID, Email: "u@example.com", AccessToken: "x"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	k := crypto.GenerateKey()
	if err := a.SetUserKey(k); err != nil {
		t.Fatal(err)
	}
	return a, k
}

func TestRegisteredMigrations(t *testing.T) {
	a, _ := unlockedApp(t)
	var names []string
	for _, nm := range New(Deps{App: a, ClientType: ClientCli}).migrations {
		names = append(names, nm.name)
	}
	if strings.Join(names, ",") != "User Key Id Backfill Migration" {
		t.Errorf("cli migrations = %v", names)
	}
	names = nil
	for _, nm := range New(Deps{App: a, ClientType: ClientDesktop}).migrations {
		names = append(names, nm.name)
	}
	if strings.Join(names, ",") != "User Key Id Backfill Migration,Biometric V2 Encryption Migration" {
		t.Errorf("desktop migrations = %v", names)
	}
}

type fakeBio struct {
	persistent bool
	enrollErr  error
	calls      []string
}

func (f *fakeBio) HasPersistentKey(string) bool { return f.persistent }
func (f *fakeBio) EnrollPersistent(string, *crypto.SymmetricKey) error {
	f.calls = append(f.calls, "enroll")
	return f.enrollErr
}
func (f *fakeBio) SetBiometricProtectedUnlockKeyForUser(string, *crypto.SymmetricKey) error {
	f.calls = append(f.calls, "setProtected")
	return nil
}
func (f *fakeBio) DeleteBiometricUnlockKeyForUser(string) error {
	f.calls = append(f.calls, "delete")
	return nil
}

type fakeBioState struct {
	enabled  bool
	enrolled *string
}

func (f *fakeBioState) BiometricUnlockEnabled(string) bool    { return f.enabled }
func (f *fakeBioState) BiometricEnrolledKeyID(string) *string { return f.enrolled }

func TestBiometricPersistentMigration(t *testing.T) {
	a, key := unlockedApp(t)
	id, _ := bwauth.SymmetricKeyID(key)
	other := "00000000000000000000000000000000"
	var buf strings.Builder
	var toasts []string
	toast := func(kind, title, text string) { toasts = append(toasts, kind+"|"+title+"|"+text) }

	cases := []struct {
		name  string
		bio   *fakeBio
		state *fakeBioState
		want  Requirement
	}{
		{"biometrics disabled", &fakeBio{persistent: true}, &fakeBioState{enabled: false, enrolled: &other}, NoMigrationNeeded},
		{"no persistent key", &fakeBio{}, &fakeBioState{enabled: true, enrolled: &other}, NoMigrationNeeded},
		{"same key", &fakeBio{persistent: true}, &fakeBioState{enabled: true, enrolled: &id}, NoMigrationNeeded},
		{"rotated key", &fakeBio{persistent: true}, &fakeBioState{enabled: true, enrolled: &other}, NeedsMigration},
		{"key id appeared", &fakeBio{persistent: true}, &fakeBioState{enabled: true}, NeedsMigration},
	}
	for _, c := range cases {
		m := NewBiometricPersistentMigration(a, c.bio, c.state, quietLog(t, &buf), toast)
		if got := m.NeedsMigration(userID); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	bio := &fakeBio{persistent: true}
	m := NewBiometricPersistentMigration(a, bio, &fakeBioState{enabled: true, enrolled: &other}, quietLog(t, &buf), toast)
	if err := m.RunMigrations(userID, nil); err != nil || strings.Join(bio.calls, ",") != "enroll,setProtected" {
		t.Errorf("re-enroll: %v %v", bio.calls, err)
	}

	bio = &fakeBio{persistent: true, enrollErr: errors.New("cancelled")}
	m = NewBiometricPersistentMigration(a, bio, &fakeBioState{enabled: true, enrolled: &other}, quietLog(t, &buf), toast)
	if err := m.RunMigrations(userID, nil); err != nil || strings.Join(bio.calls, ",") != "enroll,delete,setProtected" {
		t.Errorf("failed re-enroll: %v %v", bio.calls, err)
	}
	if len(toasts) != 1 || toasts[0] != "warning|Unlock with biometrics|Biometric unlock on app restart was turned off. Turn it on again in settings." {
		t.Errorf("toasts = %q", toasts)
	}

	// Locked: nothing to compare, and running fails.
	_ = a.Lock()
	if got := m.NeedsMigration(userID); got != NoMigrationNeeded {
		t.Errorf("locked: %s", got)
	}
	if err := m.RunMigrations(userID, nil); err == nil || err.Error() != "User key is not available" {
		t.Errorf("locked run: %v", err)
	}
}

func TestUserKeyIDBackfillNeedsMigration(t *testing.T) {
	a, key := unlockedApp(t)
	id, _ := bwauth.SymmetricKeyID(key)
	var buf strings.Builder
	syncs := 0
	m := NewUserKeyIDBackfillMigration(a, func(bool) error { syncs++; return nil }, quietLog(t, &buf))
	if got := m.NeedsMigration(userID); got != NeedsMigration || syncs != 1 {
		t.Errorf("unknown id: %s (syncs %d)", got, syncs)
	}
	_ = a.UpdateAccount(func(acct *state.Account) error { acct.UserKeyID = id; return nil })
	if got := m.NeedsMigration(userID); got != NoMigrationNeeded || syncs != 1 {
		t.Errorf("known id: %s (syncs %d)", got, syncs)
	}

	// A legacy AES-256-CBC user key has no id: nothing to backfill, and running fails.
	_ = a.UpdateAccount(func(acct *state.Account) error { acct.UserKeyID = ""; return nil })
	legacy, _ := crypto.NewSymmetricKey(make([]byte, 32))
	_ = a.SetUserKey(legacy)
	if got := m.NeedsMigration(userID); got != NoMigrationNeeded {
		t.Errorf("legacy key: %s", got)
	}
	if err := m.RunMigrations(userID, nil); err == nil || err.Error() != "KeyIdBackfillError: The current user key has no key id to backfill" {
		t.Errorf("legacy run: %v", err)
	}
}
