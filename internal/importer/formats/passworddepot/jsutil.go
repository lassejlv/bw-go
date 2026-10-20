package passworddepot

import (
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
)

var (
	jsDecimalLiteral = regexp.MustCompile(`^[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$`)
	jsNonDecimal     = regexp.MustCompile(`^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// isNaNNumber is the global isNaN(s) for a string: true when Number(s) is NaN.
func isNaNNumber(s string) bool {
	s = importer.JSTrim(s)
	if s == "" {
		return false
	}
	return !jsDecimalLiteral.MatchString(s) && !jsNonDecimal.MatchString(s)
}

// jsParseInt is parseInt(s) without a radix (hex "0x" prefix allowed); NaN for no digits.
func jsParseInt(s string) float64 {
	s = importer.JSTrimStart(s)
	sign := 1.0
	if s != "" && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' {
			sign = -1
		}
		s = s[1:]
	}
	radix := 10.0
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		radix = 16
		s = s[2:]
	}
	n, digits := 0.0, 0
digitLoop:
	for ; digits < len(s); digits++ {
		c := s[digits]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case radix == 16 && c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case radix == 16 && c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			d = -1
		}
		if d < 0 {
			break digitLoop
		}
		n = n*radix + float64(d)
	}
	if digits == 0 {
		return math.NaN()
	}
	return sign * n
}

// excelDateToLocaleDateString is
// `new Date((parseInt(value) - (25567 + 2)) * 86400 * 1000).toLocaleDateString()` with Node's
// default en-US locale ("M/D/YYYY" in local time, "Invalid Date" for an invalid date). A null value
// is parseInt("null"), i.e. NaN.
func excelDateToLocaleDateString(value string, hasValue bool) string {
	numericValue := math.NaN()
	if hasValue {
		numericValue = jsParseInt(value)
	}
	const secondsInDay = 86400
	const missingLeapYearDays = secondsInDay * 1000
	ms := (numericValue - (25567 + 2)) * missingLeapYearDays
	if math.IsNaN(ms) || math.Abs(ms) > 8.64e15 {
		return "Invalid Date"
	}
	t := time.UnixMilli(int64(ms)).In(time.Local)
	return strconv.Itoa(int(t.Month())) + "/" + strconv.Itoa(t.Day()) + "/" + strconv.Itoa(t.Year())
}

// atob is the browser/Node atob (forgiving-base64 decode) returning a binary (Latin-1) string.
func atob(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\f', '\r', ' ':
			return -1
		}
		return r
	}, s)
	if len(s)%4 == 0 {
		if strings.HasSuffix(s, "==") {
			s = s[:len(s)-2]
		} else if strings.HasSuffix(s, "=") {
			s = s[:len(s)-1]
		}
	}
	errInvalid := errors.New("The string to be decoded is not correctly encoded.")
	if len(s)%4 == 1 || strings.ContainsAny(s, "=") {
		return "", errInvalid
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return "", errInvalid
	}
	runes := make([]rune, len(b))
	for i, c := range b {
		runes[i] = rune(c)
	}
	return string(runes), nil
}
