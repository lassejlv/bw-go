package onepassword

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
)

// The 1pif and 1pux importers work on JSON.parse output with untyped (`any`) property access.
// This file is a tiny JavaScript value model so the ports keep those semantics: objects keep
// their key order (Object.keys), missing properties are `undefined` (distinct from null), and
// reading a property of null/undefined throws a TypeError.

// jsUndefined is the JavaScript `undefined` value; JSON null decodes to Go nil.
type jsUndefined struct{}

var undefined any = jsUndefined{}

// jsObject is a JSON object with its keys in insertion order.
type jsObject struct {
	keys []string
	vals map[string]any
}

func (o *jsObject) get(k string) any {
	if v, ok := o.vals[k]; ok {
		return v
	}
	return undefined
}

func (o *jsObject) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// typeError is a thrown JavaScript TypeError.
type typeError struct{ msg string }

func (e *typeError) Error() string { return e.msg }

func throwTypeError(format string, args ...any) {
	panic(&typeError{msg: fmt.Sprintf(format, args...)})
}

// catch converts a thrown TypeError (or a Go runtime panic, the equivalent of an unexpected
// JavaScript exception) into an error.
func catch(err *error) {
	if r := recover(); r != nil {
		switch e := r.(type) {
		case *typeError:
			*err = e
		case error:
			*err = e
		default:
			*err = fmt.Errorf("%v", r)
		}
	}
}

func isNullish(v any) bool {
	if v == nil {
		return true
	}
	_, u := v.(jsUndefined)
	return u
}

func nullishName(v any) string {
	if v == nil {
		return "null"
	}
	return "undefined"
}

// get is `v[key]` / `v.key`.
func get(v any, key string) any {
	switch t := v.(type) {
	case nil, jsUndefined:
		throwTypeError("Cannot read properties of %s (reading '%s')", nullishName(v), key)
	case *jsObject:
		return t.get(key)
	case []any:
		if key == "length" {
			return float64(len(t))
		}
		if i, err := strconv.Atoi(key); err == nil && i >= 0 && strconv.Itoa(i) == key && i < len(t) {
			return t[i]
		}
	case string:
		if key == "length" {
			return float64(importer.Len16(t))
		}
		if i, err := strconv.Atoi(key); err == nil && i >= 0 && strconv.Itoa(i) == key && i < importer.Len16(t) {
			return importer.Substring16(t, i, i+1)
		}
	}
	return undefined
}

// objectKeys is Object.keys(v) (throws for null/undefined).
func objectKeys(v any) []string {
	switch t := v.(type) {
	case nil, jsUndefined:
		throwTypeError("Cannot convert undefined or null to object")
	case *jsObject:
		return t.keys
	case []any:
		keys := make([]string, len(t))
		for i := range t {
			keys[i] = strconv.Itoa(i)
		}
		return keys
	case string:
		keys := make([]string, importer.Len16(t))
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		return keys
	}
	return nil
}

// substringJS is String.prototype.substring(start, end) on UTF-16 code units.
func substringJS(s string, start, end int) string {
	n := importer.Len16(s)
	start, end = max(0, min(start, n)), max(0, min(end, n))
	if start > end {
		start, end = end, start
	}
	return importer.Substring16(s, start, end)
}

// path is a chain of property reads (`v.a.b.c`).
func path(v any, keys ...string) any {
	for _, k := range keys {
		v = get(v, k)
	}
	return v
}

// optPath is optional chaining (`v?.a?.b`).
func optPath(v any, keys ...string) any {
	for _, k := range keys {
		if isNullish(v) {
			return undefined
		}
		v = get(v, k)
	}
	return v
}

// array returns v as an array for forEach/for-of; anything else throws.
func array(v any, what string) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	if isNullish(v) {
		throwTypeError("Cannot read properties of %s (reading 'forEach')", nullishName(v))
	}
	throwTypeError("%s.forEach is not a function", what)
	return nil
}

// truthy is JavaScript ToBoolean.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil, jsUndefined:
		return false
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	case string:
		return t != ""
	}
	return true
}

// isNOW is Utils.isNullOrWhitespace(any): true for non-strings.
func isNOW(v any) bool {
	s, ok := v.(string)
	return !ok || importer.IsNullOrWhitespace(s)
}

// valueOrDefault is BaseImporter.getValueOrDefault for an untyped value.
func valueOrDefault(v any, def ...string) string {
	if isNOW(v) {
		if len(def) > 0 {
			return def[0]
		}
		return ""
	}
	return v.(string)
}

// jsString is String(v) / v.toString().
func jsString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case jsUndefined:
		return "undefined"
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return importer.FormatJSNumber(t)
	case *jsObject:
		return "[object Object]"
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			if !isNullish(e) {
				parts[i] = jsString(e)
			}
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(v)
}

// toStr converts a value assigned to a (string) view property: strings as is, null/undefined as
// "" (the model's null), anything else String(v).
func toStr(v any) string {
	if isNullish(v) {
		return ""
	}
	return jsString(v)
}

// toNumber is JavaScript ToNumber.
func toNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case jsUndefined:
		return math.NaN()
	case bool:
		if t {
			return 1
		}
		return 0
	case float64:
		return t
	case string:
		s := importer.JSTrim(t)
		if s == "" {
			return 0
		}
		switch s {
		case "Infinity", "+Infinity":
			return math.Inf(1)
		case "-Infinity":
			return math.Inf(-1)
		}
		if len(s) > 2 && s[0] == '0' && (s[1]|0x20 == 'x' || s[1]|0x20 == 'o' || s[1]|0x20 == 'b') {
			base := map[byte]int{'x': 16, 'o': 8, 'b': 2}[s[1]|0x20]
			if n, err := strconv.ParseUint(s[2:], base, 64); err == nil {
				return float64(n)
			}
			return math.NaN()
		}
		for _, c := range s {
			if !(c >= '0' && c <= '9' || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
				return math.NaN()
			}
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return f
			}
			return math.NaN()
		}
		return f
	case []any:
		return toNumber(jsString(t))
	}
	return math.NaN()
}

// jsDate is a JavaScript Date (valid=false is an Invalid Date).
type jsDate struct {
	t     time.Time
	valid bool
}

// dateFromMs is `new Date(ms)` (TimeClip).
func dateFromMs(ms float64) jsDate {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > 8.64e15 {
		return jsDate{}
	}
	return jsDate{t: time.UnixMilli(int64(math.Trunc(ms))).UTC(), valid: true}
}

// newDate is `new Date(v)` for a number or a string.
func newDate(v any) jsDate {
	if s, ok := v.(string); ok {
		t, ok := importer.ParseJSDate(s)
		if !ok {
			return jsDate{}
		}
		return jsDate{t: t, valid: true}
	}
	return dateFromMs(toNumber(v))
}

// toUTCString is Date.prototype.toUTCString.
func (d jsDate) toUTCString() string {
	if !d.valid {
		return "Invalid Date"
	}
	u := d.t.UTC()
	year := u.Year()
	ys := fmt.Sprintf("%04d", year)
	if year < 0 {
		ys = fmt.Sprintf("-%06d", -year)
	}
	return fmt.Sprintf("%s, %02d %s %s %02d:%02d:%02d GMT", u.Format("Mon"), u.Day(), u.Format("Jan"), ys, u.Hour(), u.Minute(), u.Second())
}

// formatDateString is BaseImporter.formatDateString ("" for an invalid date).
func (d jsDate) formatDateString() string {
	if !d.valid {
		return ""
	}
	return importer.FormatDateString(d.t)
}

// dateUTC is Date.UTC(year, month, day) (years 0..99 map to 1900+year).
func dateUTC(year, month, day float64) float64 {
	if math.IsNaN(year) || math.IsNaN(month) || math.IsNaN(day) || math.IsInf(year, 0) || math.IsInf(month, 0) {
		return math.NaN()
	}
	y := math.Trunc(year)
	if y >= 0 && y <= 99 {
		y += 1900
	}
	m := math.Trunc(month)
	ym := y + math.Floor(m/12)
	mn := math.Mod(m, 12)
	if mn < 0 {
		mn += 12
	}
	if math.Abs(ym) > 400000 {
		return math.NaN()
	}
	t := time.Date(int(ym), time.Month(int(mn)+1), 1, 0, 0, 0, 0, time.UTC)
	ms := float64(t.UnixMilli()) + (math.Trunc(day)-1)*86400000
	if math.Abs(ms) > 8.64e15 {
		return math.NaN()
	}
	return ms
}

// parseJSON is JSON.parse with ordered objects; syntax errors are importer SyntaxErrors.
func parseJSON(data string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, importer.NewSyntaxError(fmt.Errorf("Unexpected non-whitespace character after JSON"))
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Unexpected end of JSON input")
		}
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &jsObject{vals: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				o.set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return a, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
				return nil, err
			}
		}
		return f, nil
	case string, bool:
		return t, nil
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected token")
}
