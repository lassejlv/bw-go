package auth

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/biometrics"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/ipc"
	"github.com/lassejlv/bw-go/internal/ipc/ipctest"
)

const flagEnv = "BW_FEATURE_" + biometrics.BiometricsSDKIPC

// loggedInLocked logs in against a fake server and locks the vault.
func loggedInLocked(t *testing.T) (*app.App, *fakeServer, *crypto.SymmetricKey) {
	t.Helper()
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	a := newTestApp(t, fs.URL)
	if r := Login(a, testEmail, testPassword, LoginOptions{}); !r.Success {
		t.Fatalf("login: %s", r.MessageText())
	}
	Lock(a)
	os.Unsetenv("BW_SESSION")
	return a, fs, userKey
}

// withDesktop routes the biometrics IPC to a fake desktop app and enables interaction.
func withDesktop(t *testing.T, flag string) *ipctest.FakeDesktop {
	t.Helper()
	d := ipctest.NewFakeDesktop(t)
	prev := biometrics.NewTransport
	biometrics.NewTransport = func(log ipc.Logger) ipc.Transport {
		return ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, log)
	}
	t.Cleanup(func() { biometrics.NewTransport = prev })
	t.Setenv(flagEnv, flag)
	t.Setenv("BW_NOINTERACTION", "")
	t.Setenv("BW_QUIET", "")
	t.Setenv("BW_RESPONSE", "")
	return d
}

// captureStderr runs fn and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	defer func() { os.Stderr = orig }()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

func TestUnlockWithBiometrics(t *testing.T) {
	a, _, userKey := loggedInLocked(t)
	d := withDesktop(t, "true")
	k := userKey.B64()
	d.Set(func(d *ipctest.FakeDesktop) { d.UserKey = &k })

	var r *cli.Response
	stderr := captureStderr(t, func() { r = Unlock(a, "", UnlockOptions{}) })
	if !r.Success || *r.Data.(*cli.MessageResponse).Title != "Your vault is now unlocked!" {
		t.Fatalf("biometric unlock: %s", r.MessageText())
	}
	if stderr != "Unlocking with biometrics...\n" {
		t.Errorf("stderr = %q", stderr)
	}
	session := *r.Data.(*cli.MessageResponse).Raw
	if session == "" || os.Getenv("BW_SESSION") != session {
		t.Errorf("session not exported: %q", session)
	}
	if got, err := a.UserKey(); err != nil || got.B64() != userKey.B64() {
		t.Fatalf("user key after biometric unlock: %v", err)
	}
	if got := strings.Join(d.RequestTypes(), ","); got != "DiscoverRequest,GetBiometricsStatus,UnlockBiometrics" {
		t.Errorf("requests = %s", got)
	}
	for _, req := range d.Requests()[1:] {
		if string(req.Request) != `{"user_id":"`+testUserID+`"}` {
			t.Errorf("%s request = %s", req.Type, req.Request)
		}
	}
	if got := d.Announcements(); len(got) != 1 || got[0] != `{"clientType":"cli"}` {
		t.Errorf("announcements = %q", got)
	}

	// --quiet / --response suppress the progress line.
	Lock(a)
	t.Setenv("BW_RESPONSE", "true")
	stderr = captureStderr(t, func() { r = Unlock(a, "", UnlockOptions{}) })
	if !r.Success || stderr != "" {
		t.Errorf("unlock with --response: %v %q", r.Success, stderr)
	}
}

func TestBiometricUnlockFallsBack(t *testing.T) {
	a, _, userKey := loggedInLocked(t)
	good := userKey.B64()
	wrong := crypto.GenerateKey().B64()

	cases := []struct {
		name  string
		flag  string
		setup func(d *ipctest.FakeDesktop)
		want  string // request types
	}{
		{"flag off", "false", func(*ipctest.FakeDesktop) {}, ""},
		{"not enabled in desktop", "true", func(d *ipctest.FakeDesktop) { d.Status = "NotEnabled"; d.UserKey = &good }, "DiscoverRequest,GetBiometricsStatus"},
		{"unlock needed", "true", func(d *ipctest.FakeDesktop) { d.Status = "UnlockNeeded"; d.UserKey = &good }, "DiscoverRequest,GetBiometricsStatus"},
		{"unknown status", "true", func(d *ipctest.FakeDesktop) { d.Status = "Whatever"; d.UserKey = &good }, "DiscoverRequest,GetBiometricsStatus"},
		{"prompt cancelled", "true", func(d *ipctest.FakeDesktop) { d.UserKey = nil }, "DiscoverRequest,GetBiometricsStatus,UnlockBiometrics"},
		{"invalid user key", "true", func(d *ipctest.FakeDesktop) { d.UserKey = &wrong }, "DiscoverRequest,GetBiometricsStatus,UnlockBiometrics"},
		{"no handler", "true", func(d *ipctest.FakeDesktop) {
			d.Unregistered = map[string]bool{"GetBiometricsStatus": true}
		}, "DiscoverRequest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := withDesktop(t, c.flag)
			d.Set(c.setup)
			var ok bool
			stderr := captureStderr(t, func() { ok = tryUnlockWithDesktop(a, testUserID) })
			if ok || a.IsUnlocked() {
				t.Fatal("biometric unlock succeeded")
			}
			if got := strings.Join(d.RequestTypes(), ","); got != c.want {
				t.Errorf("requests = %q, want %q", got, c.want)
			}
			wantStderr := ""
			if strings.Contains(c.want, "UnlockBiometrics") {
				wantStderr = "Unlocking with biometrics...\n"
			}
			if stderr != wantStderr {
				t.Errorf("stderr = %q", stderr)
			}
			if c.flag == "false" && len(d.Announcements()) != 0 {
				t.Error("connected to the desktop with the flag off")
			}
		})
	}
}

func TestBiometricUnlockSkipped(t *testing.T) {
	a, _, userKey := loggedInLocked(t)
	d := withDesktop(t, "true")
	k := userKey.B64()
	d.Set(func(d *ipctest.FakeDesktop) { d.UserKey = &k })

	// A given password skips biometrics.
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success {
		t.Fatalf("unlock with password: %s", r.MessageText())
	}
	Lock(a)
	t.Setenv("BW_PASSWORD", testPassword)
	if r := Unlock(a, "", UnlockOptions{PasswordEnv: "BW_PASSWORD"}); !r.Success {
		t.Fatalf("unlock with --passwordenv: %s", r.MessageText())
	}
	Lock(a)
	// --nointeraction skips biometrics.
	t.Setenv("BW_NOINTERACTION", "true")
	if r := Unlock(a, "", UnlockOptions{}); r.Success || r.MessageText() != "Master password is required. Try again in interactive mode or provide a password file or environment variable." {
		t.Errorf("unlock without interaction: %v %s", r.Success, r.MessageText())
	}
	if n := len(d.Announcements()); n != 0 {
		t.Errorf("desktop contacted %d times", n)
	}
}

// A desktop that does not answer SDK IPC (older versions) makes the status check fail after the
// handshake timeouts, so unlock falls back to the master password.
func TestBiometricUnlockSilentDesktop(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for handshake timeouts")
	}
	a, _, _ := loggedInLocked(t)
	d := withDesktop(t, "true")
	d.Set(func(d *ipctest.FakeDesktop) { d.Silent = true })
	start := time.Now()
	if tryUnlockWithDesktop(a, testUserID) {
		t.Fatal("unlocked through a silent desktop")
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Errorf("took %v", el)
	}
}

func TestBiometricsServiceStatusMapping(t *testing.T) {
	a, _, _ := loggedInLocked(t)
	d := withDesktop(t, "true")
	svc := biometrics.NewService(a)
	defer svc.Close()
	for status, want := range map[string]biometrics.Status{
		"Available":           biometrics.Available,
		"UnlockNeeded":        biometrics.UnlockNeeded,
		"HardwareUnavailable": biometrics.HardwareUnavailable,
		"NotEnabled":          biometrics.NotEnabledInConnectedDesktopApp,
	} {
		d.Set(func(d *ipctest.FakeDesktop) { d.Status = status })
		if got := svc.GetBiometricsStatusForUser(testUserID); got != want {
			t.Errorf("status %s = %d, want %d", status, got, want)
		}
	}
	d.Set(func(d *ipctest.FakeDesktop) { d.Status = "NotEnabled" })
	if got := svc.GetBiometricsStatus(); got != biometrics.NotEnabledInConnectedDesktopApp {
		t.Errorf("active account status = %d", got)
	}
	d.Set(func(d *ipctest.FakeDesktop) { d.AuthResult = true })
	if !svc.AuthenticateWithBiometrics() {
		t.Error("authenticate failed")
	}
	reqs := d.Requests()
	if last := reqs[len(reqs)-1]; last.Type != "AuthenticateBiometrics" || string(last.Request) != "null" {
		t.Errorf("authenticate request = %+v", last)
	}

	t.Setenv(flagEnv, "false")
	if got := svc.GetBiometricsStatusForUser(testUserID); got != biometrics.PlatformUnsupported {
		t.Errorf("flag off status = %d", got)
	}
	if svc.AuthenticateWithBiometrics() || svc.UnlockWithBiometricsForUser(testUserID) != nil {
		t.Error("flag off still talks to the desktop")
	}
	if svc.HasPersistentKey(testUserID) || svc.GetShouldAutopromptNow() {
		t.Error("CLI has no persistent biometric key")
	}
}
