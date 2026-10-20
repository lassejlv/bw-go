package ipc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Port of the desktop IPC socket location (apps/desktop/desktop_native/core/src/ipc/mod.rs,
// path/all_paths) and of the client side of desktop_proxy (core/src/ipc/client.rs): the proxy
// connects to the desktop app's socket, announces the client it was launched for and then relays
// length-delimited frames. bwgo spawns the installed desktop_proxy exactly like the official CLI
// (transport.go); talking to the socket directly is only a fallback for when no proxy binary can
// be found.

// SocketName is the IPC endpoint name the desktop app listens on ("bw").
const SocketName = "bw"

// The client announcement desktop_proxy sends for `--client=cli` (ClientAnnouncement).
const cliAnnouncement = `{"clientType":"cli"}`

// Linux native-messaging host directories (FLATPAK_PATHS, UNSANDBOXED_PATHS).
var (
	flatpakPaths = []string{
		"org.mozilla.firefox/.mozilla/native-messaging-hosts",
		"com.google.Chrome/config/google-chrome/NativeMessagingHosts",
		"org.chromium.Chromium/config/chromium/NativeMessagingHosts",
		"com.microsoft.Edge/config/microsoft-edge/NativeMessagingHosts",
	}
	unsandboxedPaths = []string{
		".config/chromium/NativeMessagingHosts",
		".config/google-chrome/NativeMessagingHosts",
		".config/microsoft-edge/NativeMessagingHosts",
		".mozilla/native-messaging-hosts",
	}
)

// SocketEnv is what the socket path depends on, injectable for tests.
type SocketEnv struct {
	GOOS     string
	HomeDir  string
	CacheDir string // dirs::cache_dir (macOS ~/Library/Caches, Linux $XDG_CACHE_HOME or ~/.cache)
	// MacAppGroupID and MacBundleID are read from the desktop app's Info.plist
	// (BitwardenAppGroupIdentifier, CFBundleIdentifier); empty for unpackaged builds.
	MacAppGroupID string
	MacBundleID   string
	// HostHomeDir is the passwd home of $USER (Linux, for snap sandboxes); empty if unknown.
	HostHomeDir string
}

// DefaultSocketEnv describes the current machine.
func DefaultSocketEnv() SocketEnv {
	home, _ := os.UserHomeDir()
	env := SocketEnv{GOOS: runtime.GOOS, HomeDir: home}
	switch runtime.GOOS {
	case "darwin":
		env.CacheDir = filepath.Join(home, "Library/Caches")
		for _, bundle := range macAppBundles(home) {
			if group, id := readAppInfoPlist(filepath.Join(bundle, "Contents/Info.plist")); group != "" {
				env.MacAppGroupID, env.MacBundleID = group, id
				break
			}
		}
	case "windows":
	default:
		if x := os.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(x) {
			env.CacheDir = x
		} else {
			env.CacheDir = filepath.Join(home, ".cache")
		}
		name := os.Getenv("USER")
		if name == "" {
			name = "unknown"
		}
		if u, err := user.Lookup(name); err == nil {
			env.HostHomeDir = u.HomeDir
		}
	}
	return env
}

// macAppGroupContainer is NSFileManager containerURLForSecurityApplicationGroupIdentifier.
func macAppGroupContainer(env SocketEnv) string {
	if env.MacAppGroupID == "" {
		return ""
	}
	return filepath.Join(env.HomeDir, "Library/Group Containers", env.MacAppGroupID)
}

// cacheDirName is the directory under the cache directory holding the sockets: the bundle
// identifier of a packaged app, com.bitwarden.desktop otherwise.
func cacheDirName(env SocketEnv) string {
	if env.GOOS == "darwin" && env.MacAppGroupID != "" && env.MacBundleID != "" {
		return env.MacBundleID
	}
	return "com.bitwarden.desktop"
}

// windowsPipePath builds `\\.\pipe\<hash>.s.<name>` from the user's home directory.
func windowsPipePath(scope, name string) string {
	sum := sha256.Sum256([]byte(scope))
	return `\\.\pipe\` + base64.RawURLEncoding.EncodeToString(sum[:]) + ".s." + name
}

// SocketPath is the main path of the desktop IPC socket (ipc::path).
func SocketPath(env SocketEnv, name string) string {
	switch env.GOOS {
	case "windows":
		return windowsPipePath(env.HomeDir, name)
	case "darwin":
		// Every socket lives in the shared App Group container (the macOS sandbox container
		// shared by the app, the proxy and the autofill extension) when there is one.
		if c := macAppGroupContainer(env); c != "" && dirExists(c) {
			return filepath.Join(c, "s."+name)
		}
	}
	return filepath.Join(env.CacheDir, cacheDirName(env), "s."+name)
}

// AllSocketPaths are the socket paths including the Linux flatpak and unsandboxed alternatives
// (ipc::all_paths); the proxy uses the first that exists.
func AllSocketPaths(env SocketEnv, name string) []string {
	paths := []string{SocketPath(env, name)}
	if env.GOOS != "linux" {
		return paths
	}
	for _, p := range flatpakPaths {
		paths = append(paths, filepath.Join(env.HomeDir, ".var/app", p, ".app."+name+".socket"))
	}
	if env.HostHomeDir != "" {
		for _, p := range unsandboxedPaths {
			paths = append(paths, filepath.Join(env.HostHomeDir, p, ".app."+name+".socket"))
		}
	}
	return paths
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// readAppInfoPlist reads BitwardenAppGroupIdentifier and CFBundleIdentifier from an XML
// Info.plist (binary plists are not supported and yield empty values).
func readAppInfoPlist(p string) (groupID, bundleID string) {
	f, err := os.Open(p)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	return ParseInfoPlist(f)
}

func ParseInfoPlist(r io.Reader) (groupID, bundleID string) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	depth, dictDepth := 0, -1
	var lastKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch t.Name.Local {
			case "dict":
				if dictDepth < 0 {
					dictDepth = depth
				}
			case "key", "string":
				if depth != dictDepth+1 {
					continue
				}
				var s string
				if dec.DecodeElement(&s, &t) != nil {
					return
				}
				depth--
				if t.Name.Local == "key" {
					lastKey = s
					continue
				}
				switch lastKey {
				case "BitwardenAppGroupIdentifier":
					groupID = strings.TrimSpace(s)
				case "CFBundleIdentifier":
					bundleID = strings.TrimSpace(s)
				}
				lastKey = ""
			default:
				if depth == dictDepth+1 {
					lastKey = ""
				}
			}
		case xml.EndElement:
			depth--
		}
	}
}

// DialSocket connects to a desktop IPC socket and announces the client like desktop_proxy does
// for `--client=cli`. The returned connection carries native-endian length-delimited frames.
func DialSocket(p string) (net.Conn, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("connecting to the desktop named pipe directly is not supported")
	}
	conn, err := net.Dial("unix", p)
	if err != nil {
		return nil, err
	}
	if err := WriteFrame(conn, []byte(cliAnnouncement)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// findSocket returns the first existing socket path.
func findSocket(env SocketEnv) (string, bool) {
	for _, p := range AllSocketPaths(env, SocketName) {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}
