package auth

import (
	"os"
	"strings"
	"testing"
	"time"

	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// The server does not know the user key id yet: login records it, then forces a full sync.
func TestLoginBackfillsUserKeyID(t *testing.T) {
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	wantID, _ := bwauth.SymmetricKeyID(userKey)
	fs.userKeyID = ""
	a := newTestApp(t, fs.URL)

	r := Login(a, testEmail, testPassword, LoginOptions{})
	if !r.Success {
		t.Fatalf("login: %s", r.MessageText())
	}
	if len(fs.keyIDPosts) != 1 || fs.keyIDPosts[0] != wantID {
		t.Fatalf("posted key ids = %q, want %s", fs.keyIDPosts, wantID)
	}
	// Login sync, then the migrator's forced sync (the server now reports the id).
	if fs.syncCalls != 2 {
		t.Errorf("sync calls = %d", fs.syncCalls)
	}
	if acct := a.ActiveAccount(); acct.UserKeyID != wantID || acct.UserKeyIDBackfillCooldown != nil {
		t.Errorf("account key id = %q cooldown %v", acct.UserKeyID, acct.UserKeyIDBackfillCooldown)
	}

	// Unlock: the server knows the id, nothing is posted.
	Lock(a)
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success {
		t.Fatalf("unlock: %s", r.MessageText())
	}
	if len(fs.keyIDPosts) != 1 {
		t.Errorf("posted again: %q", fs.keyIDPosts)
	}
}

// A server without the endpoint fails the backfill: the error is returned like upstream (the
// login command reports it) and the migration backs off for 24 hours.
func TestUserKeyIDBackfillCooldown(t *testing.T) {
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	fs.userKeyID = ""
	fs.keyIDStatus = 404
	a := newTestApp(t, fs.URL)

	var r *cli.Response
	stderr := captureStderr(t, func() { r = Login(a, testEmail, testPassword, LoginOptions{}) })
	if r.Success || r.MessageText() != "KeyIdBackfillError: API call failed during user key id backfill" {
		t.Fatalf("login with failing backfill: %v %s", r.Success, r.MessageText())
	}
	if !strings.HasPrefix(stderr, "[Encrypted Migrator] Error running migrations for user: "+testUserID+" KeyIdBackfillError: API call failed") {
		t.Errorf("stderr = %q", stderr)
	}
	acct := a.ActiveAccount()
	if acct == nil || acct.UserKeyIDBackfillCooldown == nil || acct.UserKeyID != "" || len(fs.keyIDPosts) != 1 {
		t.Fatalf("after failed backfill: %+v posts %q", acct, fs.keyIDPosts)
	}

	// Within the cooldown nothing is attempted and unlock succeeds.
	Lock(a)
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success || len(fs.keyIDPosts) != 1 {
		t.Fatalf("unlock in cooldown: %s (posts %d)", r.MessageText(), len(fs.keyIDPosts))
	}

	// After the cooldown the backfill is retried and succeeds.
	old := time.Now().Add(-25 * time.Hour)
	if err := a.UpdateAccount(func(acct *state.Account) error { acct.UserKeyIDBackfillCooldown = &old; return nil }); err != nil {
		t.Fatal(err)
	}
	fs.keyIDStatus = 0
	Lock(a)
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success || len(fs.keyIDPosts) != 2 {
		t.Fatalf("unlock after cooldown: %s (posts %d)", r.MessageText(), len(fs.keyIDPosts))
	}
	if acct := a.ActiveAccount(); acct.UserKeyID == "" {
		t.Error("key id not stored after the retry")
	}
}

// Another client did the backfill: the sync before migrating reveals it and nothing is posted.
func TestUserKeyIDBackfillDoneElsewhere(t *testing.T) {
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	id, _ := bwauth.SymmetricKeyID(userKey)
	a := newTestApp(t, fs.URL)
	if r := Login(a, testEmail, testPassword, LoginOptions{}); !r.Success {
		t.Fatal(r.MessageText())
	}
	// Local state lost the id (e.g. synced by an older client); the server knows it.
	if err := a.UpdateAccount(func(acct *state.Account) error { acct.UserKeyID = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	fs.userKeyID = id
	fs.revision = time.Now().Add(time.Hour).UnixMilli()
	Lock(a)
	before := fs.syncCalls
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success {
		t.Fatal(r.MessageText())
	}
	if len(fs.keyIDPosts) != 0 || fs.syncCalls != before+1 || a.ActiveAccount().UserKeyID != id {
		t.Errorf("posts %q, syncs %d, id %q", fs.keyIDPosts, fs.syncCalls-before, a.ActiveAccount().UserKeyID)
	}
}

// Logging in with an API key leaves the vault locked: the migration cannot read the user key and
// is skipped with a warning.
func TestAPIKeyLoginSkipsBackfill(t *testing.T) {
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	fs.userKeyID = ""
	a := newTestApp(t, fs.URL)
	t.Setenv("BW_CLIENTID", "user.abc")
	t.Setenv("BW_CLIENTSECRET", "secret")
	var r *cli.Response
	stderr := captureStderr(t, func() { r = Login(a, "", "", LoginOptions{APIKey: true}) })
	if !r.Success {
		t.Fatalf("api key login: %s", r.MessageText())
	}
	if len(fs.keyIDPosts) != 0 {
		t.Errorf("posted %q", fs.keyIDPosts)
	}
	want := "[UserKeyIdBackfillMigration] Could not determine whether user " + testUserID +
		" needs migration: KeyIdBackfillError: User key is not available in key store\n"
	if stderr != want {
		t.Errorf("stderr = %q", stderr)
	}
	os.Unsetenv("BW_SESSION")
}
