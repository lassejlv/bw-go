package keepasskdbx

import (
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// sanitizeURI is bitwarden_exporters::sanitize_uri (Login::sanitize_uris). Its URL checks rely on
// the Rust `url` crate (a WHATWG URL parser); parseHost below approximates the parts that matter:
// whether a URL parses and has a host, and whether that host is an IPv4 address.
func sanitizeURI(uri string) string {
	if ok, hasHost, _ := parseURLHost(uri); ok && hasHost {
		return uri
	}
	withHTTP := "http://" + uri
	if ok, hasHost, ipv4 := parseURLHost(withHTTP); ok && hasHost && ipv4 {
		return withHTTP
	}
	// Upstream's `!starts_with("http://") || !starts_with("https://")` is always true.
	return "https://" + uri
}

func isSpecialScheme(s string) bool {
	switch s {
	case "http", "https", "ws", "wss", "ftp":
		return true
	}
	return false
}

func isASCIIAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseURLHost runs the subset of the WHATWG basic URL parser (no base URL) needed to answer:
// does the input parse, does the result have a host, and is the host IPv4.
func parseURLHost(input string) (ok, hasHost, ipv4 bool) {
	// Strip leading/trailing C0 controls and spaces, remove ASCII tab and newlines.
	input = strings.TrimFunc(input, func(r rune) bool { return r <= 0x20 })
	input = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, input)

	// Scheme.
	if input == "" || !isASCIIAlpha(input[0]) {
		return false, false, false
	}
	i := 1
	for i < len(input) {
		c := input[i]
		if isASCIIAlpha(c) || isASCIIDigit(c) || c == '+' || c == '-' || c == '.' {
			i++
			continue
		}
		break
	}
	if i >= len(input) || input[i] != ':' {
		return false, false, false // relative URL without a base
	}
	scheme := strings.ToLower(input[:i])
	rest := input[i+1:]

	special := isSpecialScheme(scheme)
	switch {
	case scheme == "file":
		if !(strings.HasPrefix(rest, "//") || strings.HasPrefix(rest, `\\`) || strings.HasPrefix(rest, `/\`) || strings.HasPrefix(rest, `\/`)) {
			return true, false, false
		}
		auth := rest[2:]
		if j := strings.IndexAny(auth, `/\?#`); j >= 0 {
			auth = auth[:j]
		}
		// A Windows drive letter is a path, not a host.
		if len(auth) == 2 && isASCIIAlpha(auth[0]) && (auth[1] == ':' || auth[1] == '|') {
			return true, false, false
		}
		if auth == "" {
			return true, false, false
		}
		host, ok4, err := parseSpecialHost(auth)
		if err {
			return false, false, false
		}
		if host == "localhost" {
			return true, false, false
		}
		return true, true, ok4
	case special:
		rest = strings.TrimLeft(rest, `/\`)
		end := len(rest)
		if j := strings.IndexAny(rest, `/\?#`); j >= 0 {
			end = j
		}
		hostPort := splitAuthority(rest[:end])
		if hostPort == "" {
			return false, false, false
		}
		host, port := splitPort(hostPort)
		if !validPort(port) {
			return false, false, false
		}
		if host == "" {
			return false, false, false
		}
		_, ok4, err := parseSpecialHost(host)
		if err {
			return false, false, false
		}
		return true, true, ok4
	default:
		if !strings.HasPrefix(rest, "//") {
			return true, false, false
		}
		rest = rest[2:]
		end := len(rest)
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			end = j
		}
		hostPort := splitAuthority(rest[:end])
		host, port := splitPort(hostPort)
		if !validPort(port) {
			return false, false, false
		}
		if strings.HasPrefix(host, "[") {
			if !validIPv6(host) {
				return false, false, false
			}
			return true, true, false
		}
		for _, r := range host {
			if r != '%' && isForbiddenHostCodePoint(r) {
				return false, false, false
			}
		}
		return true, true, false
	}
}

// splitAuthority drops the userinfo part (up to the last '@').
func splitAuthority(auth string) string {
	if j := strings.LastIndex(auth, "@"); j >= 0 {
		return auth[j+1:]
	}
	return auth
}

// splitPort separates host and port (a ':' inside [...] belongs to the host).
func splitPort(hostPort string) (host, port string) {
	inBrackets := false
	for i := 0; i < len(hostPort); i++ {
		switch hostPort[i] {
		case '[':
			inBrackets = true
		case ']':
			inBrackets = false
		case ':':
			if !inBrackets {
				return hostPort[:i], hostPort[i+1:]
			}
		}
	}
	return hostPort, ""
}

func validPort(port string) bool {
	if port == "" {
		return true
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if !isASCIIDigit(port[i]) {
			return false
		}
		n = n*10 + int(port[i]-'0')
		if n > 65535 {
			return false
		}
	}
	return true
}

func validIPv6(host string) bool {
	if !strings.HasSuffix(host, "]") {
		return false
	}
	ip := net.ParseIP(host[1 : len(host)-1])
	return ip != nil && strings.Contains(host, ":")
}

func isForbiddenHostCodePoint(r rune) bool {
	switch r {
	case 0, '\t', '\n', '\r', ' ', '#', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '|':
		return true
	}
	return false
}

func isForbiddenDomainCodePoint(r rune) bool {
	return isForbiddenHostCodePoint(r) || r <= 0x1F || r == '%' || r == 0x7F
}

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
	idna.ValidateLabels(false),
	idna.CheckHyphens(false),
	idna.CheckJoiners(true),
	idna.BidiRule(),
)

// parseSpecialHost is the WHATWG host parser for special schemes: IPv6 literal, or percent-decoded
// domain → domain-to-ASCII → forbidden code points → IPv4 when it ends in a number.
func parseSpecialHost(input string) (host string, ipv4 bool, failed bool) {
	if strings.HasPrefix(input, "[") {
		if !validIPv6(input) {
			return "", false, true
		}
		return input, false, false
	}
	decoded, ok := percentDecode(input)
	if !ok || !utf8.ValidString(decoded) {
		return "", false, true
	}
	ascii := strings.ToLower(decoded)
	if !isASCII(decoded) {
		var err error
		ascii, err = idnaProfile.ToASCII(decoded)
		if err != nil || ascii == "" {
			return "", false, true
		}
	}
	for _, r := range ascii {
		if isForbiddenDomainCodePoint(r) {
			return "", false, true
		}
	}
	if endsInANumber(ascii) {
		if !validIPv4(ascii) {
			return "", false, true
		}
		return ascii, true, false
	}
	return ascii, false, false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func percentDecode(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String(), true
}

func isHex(c byte) bool {
	return isASCIIDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case isASCIIDigit(c):
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func ipv4Parts(s string) []string {
	parts := strings.Split(s, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// endsInANumber is the WHATWG "ends in a number checker".
func endsInANumber(s string) bool {
	parts := strings.Split(s, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" {
		allDigits := true
		for i := 0; i < len(last); i++ {
			if !isASCIIDigit(last[i]) {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	_, ok := parseIPv4Number(last)
	return ok
}

func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		var d uint64
		c := s[i]
		switch {
		case isASCIIDigit(c):
			d = uint64(c - '0')
		case base == 16 && isHex(c):
			d = uint64(unhex(c))
		default:
			return 0, false
		}
		if int(d) >= base {
			return 0, false
		}
		n = n*uint64(base) + d
		if n > 1<<40 {
			n = 1 << 40 // saturate: anything this large is out of range anyway
		}
	}
	return n, true
}

func validIPv4(s string) bool {
	parts := ipv4Parts(s)
	if len(parts) > 4 {
		return false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Number(p)
		if !ok {
			return false
		}
		nums[i] = n
	}
	for i, n := range nums {
		if i < len(nums)-1 && n > 255 {
			return false
		}
	}
	limit := uint64(1) << (8 * uint(5-len(nums)))
	return nums[len(nums)-1] < limit
}
