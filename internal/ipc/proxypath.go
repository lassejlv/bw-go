package ipc

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Port of apps/cli/src/platform/services/cli-desktop-proxy-path.ts.

// DesktopProxyPathEnv overrides the location of the desktop_proxy binary.
const DesktopProxyPathEnv = "BITWARDEN_DESKTOP_PROXY_PATH"

// DesktopProxyPaths returns the well-known locations of the desktop native-messaging proxy.
func DesktopProxyPaths(goos, homeDir string, getenv func(string) string) []string {
	switch goos {
	case "windows":
		var out []string
		if v := getenv("LOCALAPPDATA"); v != "" {
			out = append(out, winJoin(v, "Programs", "Bitwarden", "desktop_proxy.exe"))
		}
		if v := getenv("ProgramFiles"); v != "" {
			out = append(out, winJoin(v, "Bitwarden", "desktop_proxy.exe"))
		}
		if v := getenv("ProgramFiles(x86)"); v != "" {
			out = append(out, winJoin(v, "Bitwarden", "desktop_proxy.exe"))
		}
		return out
	case "darwin":
		return []string{
			"/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy",
			path.Join(homeDir, "Applications/Bitwarden.app/Contents/MacOS/desktop_proxy"),
		}
	default:
		return []string{
			"/opt/Bitwarden/desktop_proxy",
			"/app/Bitwarden/desktop_proxy",
			"/usr/lib/bitwarden/desktop_proxy",
			"/usr/lib/bitwarden-desktop/desktop_proxy",
			"/snap/bitwarden/current/desktop_proxy",
		}
	}
}

// winJoin is path.win32.join for the simple case of joining onto an absolute directory.
func winJoin(elem ...string) string {
	parts := make([]string, 0, len(elem))
	for i, e := range elem {
		e = strings.ReplaceAll(e, "/", `\`)
		if i > 0 {
			e = strings.Trim(e, `\`)
		} else {
			e = strings.TrimRight(e, `\`)
		}
		if e != "" {
			parts = append(parts, e)
		}
	}
	return strings.Join(parts, `\`)
}

// errProxyNotFound is returned when no installed desktop proxy exists and no override is set.
var errProxyNotFound = errors.New("Could not find the Bitwarden Desktop proxy. Set " + DesktopProxyPathEnv + " to its path.")

// ResolveDesktopProxyPath resolves the explicit override or the first installed desktop proxy.
func ResolveDesktopProxyPath(proxyPaths []string, override string, exists func(string) bool) (string, error) {
	if override != "" {
		if !exists(override) {
			return "", errors.New(DesktopProxyPathEnv + " points to a file that does not exist: " + override)
		}
		return override, nil
	}
	for _, p := range proxyPaths {
		if exists(p) {
			return p, nil
		}
	}
	return "", errProxyNotFound
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func defaultProxyPath() (string, error) {
	home, _ := os.UserHomeDir()
	return ResolveDesktopProxyPath(DesktopProxyPaths(runtime.GOOS, home, os.Getenv), os.Getenv(DesktopProxyPathEnv), fileExists)
}

// macAppBundles are the desktop app bundles the proxy paths above live in.
func macAppBundles(homeDir string) []string {
	return []string{"/Applications/Bitwarden.app", filepath.Join(homeDir, "Applications/Bitwarden.app")}
}
