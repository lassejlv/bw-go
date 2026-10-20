package vault

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// URI helpers mirroring Utils.getHostname / getHost / getDomain (tldts with validHosts
// ["localhost"] and private domains allowed) and LoginUriView.matchesUri.

var validHosts = []string{"localhost"}

// domainMatchBlacklist mirrors Utils.DomainMatchBlacklist.
var domainMatchBlacklist = map[string]map[string]bool{
	"google.com": {"script.google.com": true},
}

// extractHostname mirrors tldts' extractHostname; ok is false when no hostname can be extracted.
func extractHostname(s string) (string, bool) {
	start, end := 0, len(s)
	for start < end && s[start] <= 32 {
		start++
	}
	for end > start+1 && s[end-1] <= 32 {
		end--
	}
	if start >= end {
		return "", false
	}
	if strings.HasPrefix(s[start:end], "data:") {
		return "", false
	}
	if end-start >= 2 && s[start] == '/' && s[start+1] == '/' {
		start += 2
	} else if i := strings.Index(s[start:end], ":/"); i != -1 {
		scheme := s[start : start+i]
		for _, c := range scheme {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
				return "", false
			}
		}
		start += i + 2
		for start < end && s[start] == '/' {
			start++
		}
	}
	identifier, closingBracket, port := -1, -1, -1
	for i := start; i < end; i++ {
		c := s[i]
		if c == '#' || c == '/' || c == '?' {
			end = i
			break
		} else if c == '@' {
			identifier = i
		} else if c == ']' {
			closingBracket = i
		} else if c == ':' {
			port = i
		}
	}
	if identifier != -1 && identifier > start && identifier < end {
		start = identifier + 1
	}
	if start < end && s[start] == '[' {
		if closingBracket != -1 && closingBracket > start {
			return strings.ToLower(s[start+1 : closingBracket]), true
		}
		return "", false
	} else if port != -1 && port > start && port < end {
		end = port
	}
	for end > start+1 && s[end-1] == '.' {
		end--
	}
	h := strings.ToLower(s[start:end])
	if h == "" {
		return "", false
	}
	return h, true
}

// isValidHostname mirrors tldts' isValidHostname (rough equivalent).
func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	first, _ := utf8.DecodeRuneInString(h)
	if !(first >= 'a' && first <= 'z' || first >= '0' && first <= '9' || first == '_' || first > 127) {
		return false
	}
	labelStart := 0
	prev := rune(0)
	for i, c := range h {
		if c == '.' {
			if i-labelStart > 63 || i == labelStart || prev == '-' {
				return false
			}
			labelStart = i + 1
		} else if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c > 127) {
			return false
		}
		prev = c
	}
	return len(h)-labelStart <= 63 && prev != '-'
}

func isIP(h string) bool { return net.ParseIP(strings.Trim(h, "[]")) != nil }

// GetHostname mirrors Utils.getHostname (nil when unavailable).
func GetHostname(uri string) *string {
	s := strings.TrimSpace(uri)
	if s == "" || strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "about:") || strings.HasPrefix(s, "file:") {
		return nil
	}
	h, ok := extractHostname(s)
	if !ok {
		return nil
	}
	if !isIP(h) && !isValidHostname(h) {
		return nil
	}
	return &h
}

// GetDomain mirrors Utils.getDomain: the registrable domain (public suffix + 1, private domains
// included), the hostname for localhost and IP addresses, nil otherwise.
func GetDomain(uri string) *string {
	s := strings.TrimSpace(uri)
	if s == "" || strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "about:") {
		return nil
	}
	h, ok := extractHostname(s)
	if !ok {
		return nil
	}
	if isIP(h) {
		return &h
	}
	if !isValidHostname(h) {
		return nil
	}
	if h == "localhost" {
		return &h
	}
	for _, vh := range validHosts {
		if h == vh || strings.HasSuffix(h, "."+vh) {
			d := vh
			return &d
		}
	}
	ascii, err := idna.ToASCII(h)
	if err != nil {
		ascii = h
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || d == "" {
		return nil
	}
	if ascii != h {
		if u, err := idna.ToUnicode(d); err == nil {
			d = u
		}
	}
	return &d
}

var defaultPorts = map[string]string{"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}

// GetHost mirrors Utils.getHost (hostname[:port] from the URL, http:// assumed when the string has
// no protocol but contains a dot).
func GetHost(uri string) *string {
	s := strings.TrimSpace(uri)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		if !strings.Contains(s, ".") {
			return nil
		}
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && defaultPorts[strings.ToLower(u.Scheme)] != p {
		host += ":" + p
	}
	return &host
}

func punycodeToUnicode(s string) string {
	u, err := idna.ToUnicode(s)
	if err != nil {
		return s
	}
	return u
}

// MatchesURI mirrors LoginUriView.matchesUri. equivalentDomains may be nil; defaultMatch nil means
// Domain. overrideNever upgrades a Never strategy to Domain.
func (u *LoginURIView) MatchesURI(targetURI string, equivalentDomains []string, defaultMatch *UriMatch, overrideNever bool) bool {
	if u.URI == nil || *u.URI == "" || targetURI == "" {
		return false
	}
	matchType := UriMatchDomain
	if u.Match != nil {
		matchType = *u.Match
	} else if defaultMatch != nil {
		matchType = *defaultMatch
	}
	if overrideNever && matchType == UriMatchNever {
		matchType = UriMatchDomain
	}
	switch matchType {
	case UriMatchDomain:
		domains := map[string]bool{}
		for _, d := range equivalentDomains {
			domains[d] = true
		}
		if td := GetDomain(targetURI); td != nil {
			domains[*td] = true
		}
		return u.matchesDomain(targetURI, domains)
	case UriMatchHost:
		urlHost := GetHost(targetURI)
		own := GetHost(*u.URI)
		return urlHost != nil && own != nil && *urlHost == *own
	case UriMatchExact:
		return targetURI == *u.URI
	case UriMatchStartsWith:
		return strings.HasPrefix(targetURI, *u.URI)
	case UriMatchRegularExpression:
		re, err := regexp.Compile("(?i)" + *u.URI)
		if err != nil {
			return false
		}
		return re.MatchString(targetURI)
	}
	return false
}

func (u *LoginURIView) matchesDomain(targetURI string, matchDomains map[string]bool) bool {
	d := GetDomain(*u.URI)
	if d == nil || *d == "" {
		return false
	}
	domain := *d
	if !matchDomains[domain] {
		normalized := punycodeToUnicode(domain)
		found := false
		for md := range matchDomains {
			if punycodeToUnicode(md) == normalized {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if bl, ok := domainMatchBlacklist[domain]; ok {
		h := GetHost(targetURI)
		return h == nil || !bl[*h]
	}
	return true
}

// MatchesURI mirrors LoginView.matchesUri.
func (l *LoginView) MatchesURI(targetURI string, equivalentDomains []string, defaultMatch *UriMatch, overrideNever bool) bool {
	for i := range l.URIs {
		if l.URIs[i].MatchesURI(targetURI, equivalentDomains, defaultMatch, overrideNever) {
			return true
		}
	}
	return false
}

// EquivalentDomainsFor mirrors DomainSettingsService.getUrlEquivalentDomains: all domains of every
// equivalent-domain set that contains the URL's domain.
func EquivalentDomainsFor(targetURL string, sets [][]string) []string {
	d := GetDomain(targetURL)
	if d == nil {
		return nil
	}
	var out []string
	for _, set := range sets {
		for _, s := range set {
			if s == *d {
				out = append(out, set...)
				break
			}
		}
	}
	return out
}

// FilterCiphersForURL mirrors CipherService.filterCiphersForUrl for the CLI (no extra types):
// non-deleted, non-archived logins whose URIs match.
func FilterCiphersForURL(ciphers []*CipherView, targetURL string, sets [][]string, defaultMatch *UriMatch) []*CipherView {
	eq := EquivalentDomainsFor(targetURL, sets)
	out := []*CipherView{}
	for _, c := range ciphers {
		if c.IsDeleted() || c.IsArchived() || c.Type != CipherTypeLogin || c.Login == nil {
			continue
		}
		if c.Login.MatchesURI(targetURL, eq, defaultMatch, false) {
			out = append(out, c)
		}
	}
	return out
}
