package send

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
)

var emailRe = regexp.MustCompile(`^([\w._+-]+?)@([\w._+-]+?)$`)

func isEmail(s string) bool { return s != "" && emailRe.MatchString(s) }

func parseList(value, sep string) ([]string, error) {
	var parts []string
	for _, p := range strings.Split(value, sep) {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	for _, p := range parts {
		if !isEmail(p) {
			return nil, errors.New("Invalid email address: " + p)
		}
	}
	return parts, nil
}

// ParseEmail parses email addresses (single address, JSON array, comma- or space-separated list)
// and appends them to previous (apps/cli/src/tools/send/util.ts parseEmail).
func ParseEmail(input string, previous []string) ([]string, error) {
	result := previous
	switch {
	case isEmail(input):
		result = append(result, input)
	case strings.HasPrefix(input, "["):
		var arr any
		if err := json.Unmarshal([]byte(input), &arr); err != nil {
			return nil, errors.New("Invalid JSON format for email list")
		}
		list, ok := arr.([]any)
		if !ok {
			return nil, errors.New("invalid JSON")
		}
		for _, v := range list {
			if s, ok := v.(string); ok {
				result = append(result, s)
			} else {
				result = append(result, cli.MarshalJSON(v, false))
			}
		}
	case strings.Contains(input, ","):
		l, err := parseList(input, ",")
		if err != nil {
			return nil, err
		}
		result = append(result, l...)
	case strings.Contains(input, " "):
		l, err := parseList(input, " ")
		if err != nil {
			return nil, err
		}
		result = append(result, l...)
	default:
		return nil, errors.New("`input` must be a single address, a comma-separated list, or a JSON array")
	}
	return result, nil
}

// emailsFlag is a repeatable --emails option parsed with ParseEmail (commander argParser).
type emailsFlag struct {
	emails []string
	set    bool
}

func (f *emailsFlag) String() string { return strings.Join(f.emails, ",") }
func (f *emailsFlag) Type() string   { return "emails" }
func (f *emailsFlag) Set(s string) error {
	r, err := ParseEmail(s, f.emails)
	if err != nil {
		return err
	}
	f.emails, f.set = r, true
	return nil
}

// decodeB64Lenient decodes base64 like Node's Buffer.from(s, "base64"): url-safe characters are
// accepted, invalid characters ignored and padding optional.
func decodeB64Lenient(s string) []byte {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			b.WriteRune(c)
		case c == '-':
			b.WriteByte('+')
		case c == '_':
			b.WriteByte('/')
		case c == '=':
			goto done
		}
	}
done:
	clean := b.String()
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out, _ := base64.RawStdEncoding.DecodeString(clean)
	return out
}

// jsDate interprets a JSON value like `new Date(value)`. present is false for null/absent;
// valid is false for an Invalid Date.
func jsDate(raw json.RawMessage) (t *time.Time, present, valid bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, false, true
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil, true, false
	}
	switch x := v.(type) {
	case float64:
		if math.Abs(x) > 8.64e15 {
			return nil, true, false
		}
		tm := time.UnixMilli(int64(x))
		return &tm, true, true
	case bool:
		ms := int64(0)
		if x {
			ms = 1
		}
		tm := time.UnixMilli(ms)
		return &tm, true, true
	case string:
		if tm, ok := parseJSDateString(x); ok {
			return &tm, true, true
		}
	}
	return nil, true, false
}

func parseJSDateString(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := cli.ParseDate(s); err == nil {
		return t, true
	}
	layouts := []string{
		http.TimeFormat, time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC, time.UnixDate,
		"2006-01-02T15:04", "2006-01-02T15:04Z07:00", "2006-01-02 15:04:05", "2006/01/02",
		"2006/01/02 15:04:05", "Jan 2, 2006", "Jan 2 2006", "January 2, 2006", "2 Jan 2006",
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseIntJS mirrors parseInt(value, 10); nil means NaN.
func parseIntJS(v string) *int {
	v = strings.TrimSpace(v)
	end := 0
	for end < len(v) && (v[end] >= '0' && v[end] <= '9' || (end == 0 && (v[end] == '-' || v[end] == '+'))) {
		end++
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return nil
	}
	return &n
}

// jsNumber mirrors Number(value) for option strings (NaN on failure, "" is 0).
func jsNumber(v string) float64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return float64(n)
		}
		return math.NaN()
	}
	return f
}

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

// IsGUID mirrors isGuid from @bitwarden/guid.
func IsGUID(s string) bool { return guidRe.MatchString(s) }

func isServe() bool { return getenv("BW_SERVE") == "true" }
