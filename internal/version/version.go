// Package version holds the application version reported to the server and by `bw --version`.
package version

// Version tracks the upstream Node CLI release this port targets. Override at build time with
// -ldflags "-X github.com/lassejlv/bw-go/internal/version.Version=...".
var Version = "2026.10.1"
