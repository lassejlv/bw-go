package ipc_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/ipc"
	"github.com/lassejlv/bw-go/internal/ipc/ipctest"
)

func TestMain(m *testing.M) {
	// Re-executed as a fake desktop_proxy by TestProxyTransport.
	if sock := os.Getenv(ipctest.FakeProxyEnv); sock != "" {
		os.Exit(ipctest.RunFakeProxy(sock, os.Args[1:], os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}

func socketClient(t *testing.T, d *ipctest.FakeDesktop) *ipc.Client {
	t.Helper()
	tr := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, nil)
	c := ipc.NewClient(tr, nil)
	t.Cleanup(c.Close)
	return c
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestClientRPCOverSocket(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	c := socketClient(t, d)

	r, err := c.Discover(ctxT(t, 5*time.Second), ipc.DesktopRenderer)
	if err != nil || r.Version != "2026.9.0" {
		t.Fatalf("discover = %+v, %v", r, err)
	}
	var status string
	if err := c.Request(ctxT(t, 5*time.Second), ipc.DesktopRenderer, "GetBiometricsStatus", map[string]string{"user_id": "u1"}, &status); err != nil || status != "Available" {
		t.Fatalf("status = %q, %v", status, err)
	}
	if got := d.Announcements(); len(got) != 1 || got[0] != `{"clientType":"cli"}` {
		t.Errorf("announcements = %q", got)
	}
	reqs := d.Requests()
	if len(reqs) != 2 || reqs[0].Type != "DiscoverRequest" || string(reqs[1].Request) != `{"user_id":"u1"}` {
		t.Errorf("requests = %+v", reqs)
	}

	// Unknown request types are answered with RpcError::NoHandlerFound.
	err = c.Request(ctxT(t, 5*time.Second), ipc.DesktopRenderer, "Nope", nil, nil)
	var rpcErr *ipc.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Variant != "NoHandlerFound" ||
		err.Error() != "Request could not be completed because no handler has been registered for" {
		t.Errorf("unknown request = %v", err)
	}

	// Handler errors surface as RpcError::RequestDeserialization.
	err = c.Request(ctxT(t, 5*time.Second), ipc.DesktopRenderer, "GetBiometricsStatus", map[string]string{}, &status)
	if err == nil || err.Error() != "Failed to read request: missing field `user_id`" {
		t.Errorf("bad request = %v", err)
	}

	// Only desktop destinations are reachable through the desktop service.
	svc := ipc.NewDesktopService(func() ipc.Transport {
		return ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, nil)
	}, nil)
	defer svc.Disconnect()
	err = svc.Client().Request(ctxT(t, 5*time.Second), ipc.Endpoint{Kind: ipc.KindBrowserBackground, Host: ipc.HostID{Own: true}}, "DiscoverRequest", nil, nil)
	if err == nil || err.Error() != "CLI IPC only supports Bitwarden Desktop destinations" {
		t.Errorf("non-desktop destination = %v", err)
	}
}

func TestVerifyDesktopConnection(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	newSvc := func() *ipc.DesktopService {
		svc := ipc.NewDesktopService(func() ipc.Transport {
			return ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, nil)
		}, nil)
		t.Cleanup(svc.Disconnect)
		return svc
	}
	svc := newSvc()
	v, err := svc.VerifyDesktopConnection(context.Background())
	if err != nil || v != "2026.9.0" {
		t.Fatalf("verify = %q, %v", v, err)
	}
	// Cached: no second discover.
	if _, err := svc.VerifyDesktopConnection(context.Background()); err != nil || len(d.Requests()) != 1 {
		t.Errorf("verification not cached: %v %d", err, len(d.Requests()))
	}

	d.Set(func(d *ipctest.FakeDesktop) { d.Version = "2026.8.0" })
	_, err = newSvc().VerifyDesktopConnection(context.Background())
	want := "Could not establish SDK IPC with Bitwarden Desktop. Biometric unlock requires Bitwarden Desktop 2026.9.0 or newer. Bitwarden Desktop 2026.8.0 is unsupported."
	if err == nil || err.Error() != want {
		t.Errorf("old desktop = %v", err)
	}
}

func TestHandshakeTimeoutWithSilentDesktop(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	d.Set(func(d *ipctest.FakeDesktop) { d.Silent = true })
	c := socketClient(t, d)
	start := time.Now()
	_, err := c.Discover(ctxT(t, 5*time.Second), ipc.DesktopRenderer)
	if !errors.Is(err, ipc.ErrHandshakeTimeout) {
		t.Fatalf("silent desktop = %v", err)
	}
	if el := time.Since(start); el < 2*time.Second || el > 4*time.Second {
		t.Errorf("handshake timeout after %v, want ~2s", el)
	}
}

func TestRequestCancelledByContext(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	d.Set(func(d *ipctest.FakeDesktop) { d.UnlockDelay = 2 * time.Second })
	c := socketClient(t, d)
	var resp json.RawMessage
	err := c.Request(ctxT(t, 300*time.Millisecond), ipc.DesktopRenderer, "UnlockBiometrics", map[string]string{"user_id": "u"}, &resp)
	if !errors.Is(err, ipc.ErrCancelled) {
		t.Errorf("timed out request = %v", err)
	}
}

// After the desktop app restarts (losing its Noise session), the CLI's next frame is answered with
// CryptoInvalidated and a later request re-handshakes on the new connection.
func TestReconnectAfterDesktopRestart(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	tr := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, nil)
	c := ipc.NewClient(tr, nil)
	defer c.Close()
	if _, err := c.Discover(ctxT(t, 5*time.Second), ipc.DesktopRenderer); err != nil {
		t.Fatal(err)
	}
	tr.Close() // drop the connection; the client keeps its session
	tr2 := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.SocketStream(d.SocketPath) }, nil)
	c2 := ipc.NewClient(tr2, nil)
	defer c2.Close()
	if _, err := c2.Discover(ctxT(t, 5*time.Second), ipc.DesktopRenderer); err != nil {
		t.Fatalf("new connection: %v", err)
	}
	if n := len(d.Announcements()); n != 2 {
		t.Errorf("connections = %d", n)
	}
}

func TestProxyTransport(t *testing.T) {
	d := ipctest.NewFakeDesktop(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(ipctest.FakeProxyEnv, d.SocketPath)
	tr := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.ProxyStream(exe) }, nil)
	c := ipc.NewClient(tr, nil)
	defer c.Close()
	r, err := c.Discover(ctxT(t, 10*time.Second), ipc.DesktopRenderer)
	if err != nil || r.Version != "2026.9.0" {
		t.Fatalf("discover through proxy = %+v, %v", r, err)
	}
	var key struct {
		UserKey *string `json:"user_key"`
	}
	k := "a2V5"
	d.Set(func(d *ipctest.FakeDesktop) { d.UserKey = &k })
	if err := c.Request(ctxT(t, 10*time.Second), ipc.DesktopRenderer, "UnlockBiometrics", map[string]string{"user_id": "u"}, &key); err != nil || key.UserKey == nil || *key.UserKey != k {
		t.Fatalf("unlock through proxy = %+v, %v", key, err)
	}
	if got := d.Announcements(); len(got) != 1 || got[0] != `{"clientType":"cli"}` {
		t.Errorf("announcements = %q", got)
	}
}

func TestProxyTransportFailures(t *testing.T) {
	// A proxy that exits before connecting.
	exe, _ := os.Executable()
	t.Setenv(ipctest.FakeProxyEnv, filepath.Join(t.TempDir(), "missing.sock"))
	tr := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.ProxyStream(exe) }, nil)
	defer tr.Close()
	err := tr.Send(context.Background(), ipc.OutgoingMessage{Destination: ipc.DesktopRenderer})
	if err == nil || err.Error() != "Bitwarden Desktop proxy exited with code 1" {
		t.Errorf("exiting proxy = %v", err)
	}

	// A proxy that never reports {"command":"connected"}.
	if testing.Short() || runtime.GOOS == "windows" {
		return
	}
	dir := t.TempDir()
	hang := filepath.Join(dir, "hang.sh")
	if err := os.WriteFile(hang, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tr2 := ipc.NewStreamTransport(func() (*ipc.Stream, error) { return ipc.ProxyStream(hang) }, nil)
	defer tr2.Close()
	start := time.Now()
	err = tr2.Send(context.Background(), ipc.OutgoingMessage{Destination: ipc.DesktopRenderer})
	if err == nil || err.Error() != "Connection to Bitwarden Desktop via "+hang+" timed out" {
		t.Errorf("hanging proxy = %v", err)
	}
	if el := time.Since(start); el < 5*time.Second || el > 8*time.Second {
		t.Errorf("connection timeout after %v", el)
	}
}

func TestDesktopProxyPaths(t *testing.T) {
	env := map[string]string{"LOCALAPPDATA": `C:\Users\me\AppData\Local`, "ProgramFiles": `C:\Program Files`}
	got := ipc.DesktopProxyPaths("windows", `C:\Users\me`, func(k string) string { return env[k] })
	want := []string{`C:\Users\me\AppData\Local\Programs\Bitwarden\desktop_proxy.exe`, `C:\Program Files\Bitwarden\desktop_proxy.exe`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("windows paths = %q", got)
	}
	got = ipc.DesktopProxyPaths("darwin", "/Users/me", func(string) string { return "" })
	if strings.Join(got, "|") != "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy|/Users/me/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy" {
		t.Errorf("mac paths = %q", got)
	}
	if got = ipc.DesktopProxyPaths("linux", "/home/me", nil); len(got) != 5 || got[0] != "/opt/Bitwarden/desktop_proxy" || got[4] != "/snap/bitwarden/current/desktop_proxy" {
		t.Errorf("linux paths = %q", got)
	}

	exists := func(p string) bool { return p == "/b" || p == "/override" }
	if p, err := ipc.ResolveDesktopProxyPath([]string{"/a", "/b"}, "", exists); err != nil || p != "/b" {
		t.Errorf("resolve = %q, %v", p, err)
	}
	if p, err := ipc.ResolveDesktopProxyPath([]string{"/b"}, "/override", exists); err != nil || p != "/override" {
		t.Errorf("override = %q, %v", p, err)
	}
	if _, err := ipc.ResolveDesktopProxyPath(nil, "/nope", exists); err == nil ||
		err.Error() != "BITWARDEN_DESKTOP_PROXY_PATH points to a file that does not exist: /nope" {
		t.Errorf("missing override = %v", err)
	}
	if _, err := ipc.ResolveDesktopProxyPath([]string{"/a"}, "", exists); err == nil ||
		err.Error() != "Could not find the Bitwarden Desktop proxy. Set BITWARDEN_DESKTOP_PROXY_PATH to its path." {
		t.Errorf("not found = %v", err)
	}
}

func TestSocketPaths(t *testing.T) {
	home := t.TempDir()
	mac := ipc.SocketEnv{GOOS: "darwin", HomeDir: home, CacheDir: filepath.Join(home, "Library/Caches")}
	// Unpackaged (no app group): the cache directory with the stable name.
	if got := ipc.SocketPath(mac, "bw"); got != filepath.Join(home, "Library/Caches/com.bitwarden.desktop/s.bw") {
		t.Errorf("mac unpackaged = %s", got)
	}
	// Packaged, but the group container does not exist: cache dir named after the bundle.
	mac.MacAppGroupID, mac.MacBundleID = "LTZ2PFU5D6.com.bitwarden.beta.desktop", "com.bitwarden.beta.desktop"
	if got := ipc.SocketPath(mac, "bw"); got != filepath.Join(home, "Library/Caches/com.bitwarden.beta.desktop/s.bw") {
		t.Errorf("mac without container = %s", got)
	}
	// Packaged with the App Group container (the sandbox container shared with the app).
	container := filepath.Join(home, "Library/Group Containers/LTZ2PFU5D6.com.bitwarden.beta.desktop")
	if err := os.MkdirAll(container, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := ipc.AllSocketPaths(mac, "bw"); len(got) != 1 || got[0] != filepath.Join(container, "s.bw") {
		t.Errorf("mac container = %q", got)
	}

	linux := ipc.SocketEnv{GOOS: "linux", HomeDir: "/home/me", CacheDir: "/home/me/.cache", HostHomeDir: "/host/me"}
	got := ipc.AllSocketPaths(linux, "bw")
	if len(got) != 9 || got[0] != "/home/me/.cache/com.bitwarden.desktop/s.bw" ||
		got[1] != "/home/me/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/.app.bw.socket" ||
		got[8] != "/host/me/.mozilla/native-messaging-hosts/.app.bw.socket" {
		t.Errorf("linux = %q", got)
	}

	// \\.\pipe\<base64url(sha256(home))>.s.bw
	win := ipc.SocketEnv{GOOS: "windows", HomeDir: `C:\Users\me`}
	if got := ipc.SocketPath(win, "bw"); got != `\\.\pipe\`+"Zq6YBP3-vekgryo6YGe1f2q8hoUuMIjHIB8BOUpZS58"+".s.bw" {
		t.Errorf("windows = %s", got)
	}
}

func TestParseInfoPlist(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BitwardenAppGroupIdentifier</key>
	<string>LTZ2PFU5D6.com.bitwarden.desktop</string>
	<key>CFBundleLocalizations</key>
	<array><string>en</string><string>CFBundleIdentifier</string></array>
	<key>ITSAppUsesNonExemptEncryption</key>
	<false/>
	<key>CFBundleIdentifier</key>
	<string>com.bitwarden.desktop</string>
</dict>
</plist>`
	group, id := ipc.ParseInfoPlist(strings.NewReader(plist))
	if group != "LTZ2PFU5D6.com.bitwarden.desktop" || id != "com.bitwarden.desktop" {
		t.Errorf("plist = %q %q", group, id)
	}
}
