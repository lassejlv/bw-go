package ipc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port of apps/cli/src/platform/services/cli-ipc.service.ts.

// MinimumBiometricDesktopVersion is MINIMUM_BIOMETRIC_DESKTOP_VERSION.
const MinimumBiometricDesktopVersion = "2026.9.0"

// DesktopDiscoverTimeout is DESKTOP_DISCOVER_TIMEOUT_MS.
const DesktopDiscoverTimeout = 5 * time.Second

// DesktopService is the CLI's SDK IPC service backed by the Bitwarden Desktop proxy.
type DesktopService struct {
	newTransport func() Transport
	log          Logger

	mu       sync.Mutex
	client   *Client
	verified *string
}

// NewDesktopService creates the service; newTransport is called once, on first use.
func NewDesktopService(newTransport func() Transport, log Logger) *DesktopService {
	if log == nil {
		log = func(string) {}
	}
	return &DesktopService{newTransport: newTransport, log: log}
}

// desktopOnly is the communication backend of CliIpcService: it only sends to the desktop.
type desktopOnly struct{ Transport }

func (d desktopOnly) Send(ctx context.Context, msg OutgoingMessage) error {
	if msg.Destination.Kind != KindDesktopMain && msg.Destination.Kind != KindDesktopRenderer {
		return errors.New("CLI IPC only supports Bitwarden Desktop destinations")
	}
	return d.Transport.Send(ctx, msg)
}

// Client returns the IPC client, creating it on first use (init()).
func (s *DesktopService) Client() *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		s.client = NewClient(desktopOnly{s.newTransport()}, s.log)
	}
	return s.client
}

// Disconnect closes the connection to the desktop app.
func (s *DesktopService) Disconnect() {
	s.mu.Lock()
	c := s.client
	s.client, s.verified = nil, nil
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// VerifyDesktopConnection checks that the connected desktop understands the SDK IPC protocol
// (DiscoverRequest to DesktopRenderer) and is recent enough, returning its version.
func (s *DesktopService) VerifyDesktopConnection(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.verified != nil {
		v := *s.verified
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()

	version, err := s.discoverDesktop(ctx)
	if err != nil {
		s.Disconnect()
		return "", fmt.Errorf("Could not establish SDK IPC with Bitwarden Desktop. Biometric unlock requires Bitwarden Desktop %s or newer. %w",
			MinimumBiometricDesktopVersion, err)
	}
	s.mu.Lock()
	s.verified = &version
	s.mu.Unlock()
	return version, nil
}

func (s *DesktopService) discoverDesktop(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DesktopDiscoverTimeout)
	defer cancel()
	resp, err := s.Client().Discover(ctx, DesktopRenderer)
	if err != nil {
		return "", err
	}
	older, err := SemverLess(resp.Version, MinimumBiometricDesktopVersion)
	if err != nil {
		return "", err
	}
	if older {
		return "", fmt.Errorf("Bitwarden Desktop %s is unsupported.", resp.Version)
	}
	return resp.Version, nil
}

type semver struct {
	nums [3]int64
	pre  []string
}

func parseSemver(v string) (semver, error) {
	invalid := errors.New("Invalid Version: " + v)
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "="), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var out semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if i == len(s)-1 {
			return out, invalid
		}
		out.pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, invalid
	}
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return out, invalid
		}
		out.nums[i] = n
	}
	return out, nil
}

// SemverLess is semver.lt(a, b).
func SemverLess(a, b string) (bool, error) {
	va, err := parseSemver(a)
	if err != nil {
		return false, err
	}
	vb, err := parseSemver(b)
	if err != nil {
		return false, err
	}
	for i := range 3 {
		if va.nums[i] != vb.nums[i] {
			return va.nums[i] < vb.nums[i], nil
		}
	}
	// A pre-release sorts before the release.
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return false, nil
	case len(va.pre) == 0:
		return false, nil
	case len(vb.pre) == 0:
		return true, nil
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		x, y := va.pre[i], vb.pre[i]
		if x == y {
			continue
		}
		xn, xerr := strconv.ParseInt(x, 10, 64)
		yn, yerr := strconv.ParseInt(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			return xn < yn, nil
		case xerr == nil:
			return true, nil
		case yerr == nil:
			return false, nil
		default:
			return x < y, nil
		}
	}
	return len(va.pre) < len(vb.pre), nil
}
