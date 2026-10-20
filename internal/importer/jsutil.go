package importer

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/lassejlv/bw-go/internal/importer/papa"
)

// JavaScript-compatible string helpers. The TypeScript importers rely on JS semantics (trim()
// stripping U+FEFF and Unicode spaces, string lengths in UTF-16 code units, parseInt, Date
// parsing); use these instead of the nearest Go function when porting.

// IsJSSpace reports whether r is whitespace for JavaScript's String.prototype.trim and /\s/.
func IsJSSpace(r rune) bool { return papa.IsJSSpace(r) }

// JSTrim is String.prototype.trim.
func JSTrim(s string) string { return strings.TrimFunc(s, IsJSSpace) }

// JSTrimStart is String.prototype.trimStart.
func JSTrimStart(s string) string { return strings.TrimLeftFunc(s, IsJSSpace) }

// JSTrimEnd is String.prototype.trimEnd.
func JSTrimEnd(s string) string { return strings.TrimRightFunc(s, IsJSSpace) }

// RemoveJSWhitespace is s.replace(/\s/g, "").
func RemoveJSWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if IsJSSpace(r) {
			return -1
		}
		return r
	}, s)
}

// IsNullOrWhitespace is Utils.isNullOrWhitespace for a string ("" stands for null/undefined).
func IsNullOrWhitespace(s string) bool { return JSTrim(s) == "" }

// Len16 returns the JavaScript length of s (UTF-16 code units).
func Len16(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// Substring16 is s.substring(start, end) with UTF-16 code unit indexes (end < 0 means "to the
// end"). A surrogate pair split by the bounds becomes U+FFFD.
func Substring16(s string, start, end int) string {
	u := utf16.Encode([]rune(s))
	if end < 0 || end > len(u) {
		end = len(u)
	}
	if start < 0 {
		start = 0
	}
	if start > len(u) {
		start = len(u) // JS clamps out-of-range indexes
	}
	if start > end {
		start, end = end, start
	}
	return string(utf16.Decode(u[start:end]))
}

var newLineRegex = regexp.MustCompile(`\r\n|\r|\n`)

// SplitNewLine is BaseImporter.splitNewLine: str.split(/(?:\r\n|\r|\n)/).
func SplitNewLine(s string) []string { return newLineRegex.Split(s, -1) }

// ContainsNewLine is `str.search(/(?:\r\n|\r|\n)/) > -1`.
func ContainsNewLine(s string) bool { return strings.ContainsAny(s, "\r\n") }

// ParseInt is parseInt(s, 10): leading JS whitespace, optional sign, then as many decimal digits
// as possible. ok is false where JavaScript returns NaN.
func ParseInt(s string) (n int, ok bool) {
	s = JSTrimStart(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

// ToValidUTF8 decodes bytes like Node's Buffer.toString("utf8"): every invalid byte becomes
// U+FFFD. A leading BOM is kept (Node keeps it too).
func ToValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			sb.WriteRune(utf8.RuneError)
			b = b[1:]
			continue
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// NormalizeExpiryYearFormat is normalizeExpiryYearFormat from libs/common/src/autofill/utils:
// two-digit (and other non-4-digit) years get the current century. Returns "" for null.
func NormalizeExpiryYearFormat(yearInput string) string {
	if yearInput == "" {
		return ""
	}
	if regexp.MustCompile(`^[1-9]{1}\d{3}$`).MatchString(yearInput) {
		return yearInput
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, yearInput)
	// remove leading zero padding, leaving the last zero if it ends the string
	for len(digits) > 1 && digits[0] == '0' {
		digits = digits[1:]
	}
	if digits == "" {
		return ""
	}
	if len(digits) != 4 {
		padded := "00" + digits
		padded = padded[len(padded)-2:]
		century := strconv.Itoa(timeNow().Year())[:2]
		digits = century + padded
	}
	return digits
}

var timeNow = time.Now

// FormatDateString is BaseImporter.formatDateString: YYYY-MM-DD from the UTC components.
func FormatDateString(t time.Time) string {
	u := t.UTC()
	return strconv.Itoa(u.Year()) + "-" + pad2(int(u.Month())) + "-" + pad2(u.Day())
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
