package sendcore

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/state"
)

// ToURLB64 encodes bytes as unpadded url-safe base64 (Utils.fromBufferToUrlB64).
func ToURLB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// FromURLB64 decodes url-safe base64 with or without padding (Utils.fromUrlB64ToArray).
func FromURLB64(s string) ([]byte, error) {
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	switch len(s) % 4 {
	case 0:
	case 2:
		s += "=="
	case 3:
		s += "="
	default:
		return nil, errors.New("Illegal base64url string!")
	}
	return base64.StdEncoding.DecodeString(s)
}

// AccessURL builds the link of a Send: sendURL + accessId + "/" + urlB64(seed).
func AccessURL(sendURL, accessID string, seed []byte) string {
	if sendURL == "" {
		sendURL = "https://send.bitwarden.com/#"
	}
	return sendURL + accessID + "/" + ToURLB64(seed)
}

// ParseURL parses a URL like the WHATWG URL constructor would accept it (an absolute URL with
// a scheme). It returns an error for anything `new URL(url)` would reject.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, errors.New("invalid url")
	}
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return nil, errors.New("invalid url")
	}
	return u, nil
}

// Origin returns the serialized origin of u (scheme://host[:port]), or "null" for opaque
// origins, like URL.origin.
func Origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" && scheme != "ftp" {
		return "null"
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") ||
		(scheme == "ws" && port == "80") || (scheme == "wss" && port == "443") || (scheme == "ftp" && port == "21") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// OriginOf parses s and returns its origin, or "" when s is not a URL.
func OriginOf(s string) string {
	u, err := ParseURL(s)
	if err != nil {
		return ""
	}
	return Origin(u)
}

// IDAndKey extracts the access id and url-b64 key from the fragment of a Send link: the last two
// "/"-separated segments of the hash (receive.command.ts getIdAndKey).
func IDAndKey(u *url.URL) (id, key string) {
	frag := u.EscapedFragment()
	parts := strings.Split(frag, "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	if len(parts) > 0 {
		id = parts[0]
	}
	if len(parts) > 1 {
		key = parts[1]
	}
	return id, key
}

// ---------- regions and server resolution ----------

// Region is a production Bitwarden region (PRODUCTION_REGIONS).
type Region struct {
	Key      string
	API      string
	Identity string
	WebVault string
	Send     string
}

// ProductionRegions mirrors PRODUCTION_REGIONS in default-environment.service.ts.
var ProductionRegions = []Region{
	{Key: "US", API: "https://api.bitwarden.com", Identity: "https://identity.bitwarden.com",
		WebVault: "https://vault.bitwarden.com", Send: "https://send.bitwarden.com"},
	{Key: "EU", API: "https://api.bitwarden.eu", Identity: "https://identity.bitwarden.eu",
		WebVault: "https://vault.bitwarden.eu", Send: "https://vault.bitwarden.eu"},
	{Key: "Gov", API: "https://api.bitwarden-gov.com", Identity: "https://identity.bitwarden-gov.com",
		WebVault: "https://vault.bitwarden-gov.com", Send: "https://send.bitwarden-gov.com"},
}

// IsDev mirrors CliPlatformUtilsService.isDev.
func IsDev() bool { return os.Getenv("BWCLI_ENV") == "development" }

func formatURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	u = strings.TrimRight(u, "/")
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	return u
}

// ConfiguredRegion returns the region key of the configured environment ("US", "EU" or
// "Self-hosted").
func ConfiguredRegion(e state.Environment) string {
	custom := e.Base != "" || e.Api != "" || e.Identity != "" || e.WebVault != "" ||
		e.Icons != "" || e.Notifications != "" || e.Events != "" || e.KeyConnector != ""
	if custom || e.Region == "Self-hosted" {
		return "Self-hosted"
	}
	if e.Region == "" {
		return "US"
	}
	return e.Region
}

// Server is the server that owns a Send, resolved from its url.
type Server struct {
	APIURL      string
	IdentityURL string
	// Trusted is true for a known Bitwarden region or the configured server (no prompt needed).
	Trusted bool
	// IsConfiguredServer is true when the Send lives on the configured server.
	IsConfiguredServer bool
}

// ResolveServer mirrors SendReceiveCommand.resolveSendServer.
func ResolveServer(u *url.URL, env state.Environment, urls api.Urls) Server {
	origin := Origin(u)
	region := ConfiguredRegion(env)
	for _, r := range ProductionRegions {
		if (r.Send != "" && r.Send == origin) || (r.WebVault != "" && r.WebVault == origin) {
			return Server{APIURL: r.API, IdentityURL: r.Identity, Trusted: true, IsConfiguredServer: r.Key == region}
		}
	}
	// env.getUrls() only holds explicitly configured urls.
	rawAPI := formatURL(env.Api)
	rawWebVault := formatURL(env.WebVault)
	switch {
	case rawAPI != "" && origin == rawAPI:
		return Server{APIURL: origin, IdentityURL: urls.Identity, Trusted: true, IsConfiguredServer: true}
	case IsDev() && rawWebVault != "" && origin == rawWebVault:
		apiURL := rawAPI
		if apiURL == "" {
			apiURL = urls.Api
		}
		return Server{APIURL: apiURL, IdentityURL: urls.Identity, Trusted: true, IsConfiguredServer: true}
	case origin == urls.WebVault:
		return Server{APIURL: urls.Api, IdentityURL: urls.Identity, Trusted: true, IsConfiguredServer: true}
	default:
		return Server{APIURL: origin + "/api", IdentityURL: origin + "/identity"}
	}
}

// IsInsecureURL reports a non-https url outside development mode.
func IsInsecureURL(u string) bool { return !strings.HasPrefix(u, "https://") && !IsDev() }

// ---------- url safety (libs/common/src/tools/url-safety.ts) ----------

// UnsafeURLReason describes why a url is unsafe to fetch.
type UnsafeURLReason struct {
	Code   string // "invalid", "scheme" or "host"
	Detail string
}

var ipv4Re = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)

func isPrivateIPv4(host string) bool {
	m := ipv4Re.FindStringSubmatch(host)
	if m == nil {
		return false
	}
	var o [4]int
	for i := 0; i < 4; i++ {
		o[i], _ = strconv.Atoi(m[i+1])
		if o[i] > 255 {
			return false
		}
	}
	a, b := o[0], o[1]
	return a == 0 || a == 127 || a == 10 || (a == 172 && b >= 16 && b <= 31) ||
		(a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254)
}

func isPrivateIPv6(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if !strings.Contains(h, ":") {
		return false
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return isPrivateIPv4(v4.String())
	}
	// IPv4-compatible (::a.b.c.d).
	if strings.HasPrefix(h, "::") && !strings.HasPrefix(h, "::ffff:") {
		if allZero(ip[:12]) {
			return isPrivateIPv4(net.IP(ip[12:16]).String())
		}
	}
	return ip.IsLinkLocalUnicast() || (ip[0]&0xfe) == 0xfc
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// UnsafeURL returns why raw is unsafe to fetch, or nil. A url on trustedOrigin is exempt.
func UnsafeURL(raw, trustedOrigin string) *UnsafeURLReason {
	u, err := ParseURL(raw)
	if err != nil {
		return &UnsafeURLReason{Code: "invalid"}
	}
	origin := Origin(u)
	if trustedOrigin != "" && origin != "null" && origin == OriginOf(trustedOrigin) {
		return nil
	}
	if strings.ToLower(u.Scheme) != "https" {
		return &UnsafeURLReason{Code: "scheme", Detail: strings.ToLower(u.Scheme) + ":"}
	}
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || isPrivateIPv4(host) || isPrivateIPv6(host) {
		return &UnsafeURLReason{Code: "host", Detail: host}
	}
	return nil
}
