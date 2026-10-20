// Package jsvalue is a minimal model of the JavaScript values JSON.parse produces, for porting
// importers that walk untyped JSON (`any`) the way TypeScript does: object keys keep JavaScript
// order, non-string values are "null or whitespace" for BaseImporter helpers, and reading a property
// of null/undefined (or calling forEach on a non-array) throws a TypeError, which an importer's
// Parse turns into an error via CatchTypeError. It is shared by the importer packages that need it.
package jsvalue

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Kind is the JavaScript type of a Value.
type Kind uint8

const (
	Undefined Kind = iota
	Null
	Bool
	Number
	String
	Array
	Object
)

// Value is one JSON.parse value.
type Value struct {
	kind  Kind
	b     bool
	n     float64
	s     string
	arr   []*Value
	keys  []string // object keys in insertion order
	props map[string]*Value
}

var undef = &Value{kind: Undefined}

// NewString returns the string value s.
func NewString(s string) *Value { return &Value{kind: String, s: s} }

// TypeError is a thrown JavaScript TypeError.
type TypeError struct{ msg string }

func (e *TypeError) Error() string { return e.msg }

// ThrowTypeError throws (panics with) a *TypeError; recover it with CatchTypeError.
func ThrowTypeError(format string, args ...any) {
	panic(&TypeError{msg: fmt.Sprintf(format, args...)})
}

// CatchTypeError recovers a thrown TypeError into *err (use as `defer jsvalue.CatchTypeError(&err)`).
func CatchTypeError(err *error) {
	if r := recover(); r != nil {
		if te, ok := r.(*TypeError); ok {
			*err = te
			return
		}
		panic(r)
	}
}

// Parse is JSON.parse(data); syntax errors are wrapped with importer.NewSyntaxError.
func Parse(data string) (*Value, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	v, err := decodeJS(dec)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("unexpected non-whitespace character after JSON")
		}
		return nil, importer.NewSyntaxError(err)
	}
	return v, nil
}

func decodeJS(dec *json.Decoder) (*Value, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '[':
			v := &Value{kind: Array, arr: []*Value{}}
			for dec.More() {
				e, err := decodeJS(dec)
				if err != nil {
					return nil, err
				}
				v.arr = append(v.arr, e)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		case '{':
			v := &Value{kind: Object, props: map[string]*Value{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				e, err := decodeJS(dec)
				if err != nil {
					return nil, err
				}
				if _, ok := v.props[k]; !ok {
					v.keys = append(v.keys, k)
				}
				v.props[k] = e
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		}
		return nil, fmt.Errorf("unexpected token %v", t)
	case string:
		return &Value{kind: String, s: t}, nil
	case json.Number:
		f, _ := strconv.ParseFloat(string(t), 64) // out of range: ±Inf, like JavaScript
		return &Value{kind: Number, n: f}, nil
	case bool:
		return &Value{kind: Bool, b: t}, nil
	case nil:
		return &Value{kind: Null}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

// Kind is the type of v (Undefined for a nil v).
func (v *Value) Kind() Kind {
	if v == nil {
		return Undefined
	}
	return v.kind
}

// Bool is the payload of a Bool value (false for every other kind).
func (v *Value) Bool() bool { return v.b }

// Num is the payload of a Number value (0 for every other kind).
func (v *Value) Num() float64 { return v.n }

// Elems is the elements of an Array value (nil for every other kind).
func (v *Value) Elems() []*Value { return v.arr }

// Set is the assignment v[key] = val on an object (v must be an Object).
func (v *Value) Set(key string, val *Value) {
	if _, ok := v.props[key]; !ok {
		v.keys = append(v.keys, key)
	}
	v.props[key] = val
}

// Nullish is `v == null`.
func (v *Value) Nullish() bool { return v == nil || v.kind == Undefined || v.kind == Null }

// IsString reports whether v is a string.
func (v *Value) IsString() bool { return v != nil && v.kind == String }

// IsArray is Array.isArray(v).
func (v *Value) IsArray() bool { return v != nil && v.kind == Array }

func (v *Value) nullishName() string {
	if v == nil || v.kind == Undefined {
		return "undefined"
	}
	return "null"
}

// Get is the property access v[key] (v.key); it throws for null/undefined like JavaScript.
func (v *Value) Get(key string) *Value {
	if v.Nullish() {
		ThrowTypeError("Cannot read properties of %s (reading '%s')", v.nullishName(), key)
	}
	switch v.kind {
	case Object:
		if p, ok := v.props[key]; ok {
			return p
		}
	case Array:
		if key == "length" {
			return &Value{kind: Number, n: float64(len(v.arr))}
		}
		if isArrayIndex(key) {
			if i, _ := strconv.Atoi(key); i < len(v.arr) {
				return v.arr[i]
			}
		}
	case String:
		if key == "length" {
			return &Value{kind: Number, n: float64(importer.Len16(v.s))}
		}
		if isArrayIndex(key) {
			if i, _ := strconv.Atoi(key); i < importer.Len16(v.s) {
				return &Value{kind: String, s: importer.Substring16(v.s, i, i+1)}
			}
		}
	}
	return undef
}

// Index is v[i].
func (v *Value) Index(i int) *Value { return v.Get(strconv.Itoa(i)) }

// Str is the value when it is a string and "" otherwise: BaseImporter's isNullOrWhitespace (and so
// getValueOrDefault, processKvp, processFolder) treats every non-string as null.
func (v *Value) Str() string {
	if v.IsString() {
		return v.s
	}
	return ""
}

// IsNullOrWhitespace is Utils.isNullOrWhitespace(v).
func (v *Value) IsNullOrWhitespace() bool { return !v.IsString() || importer.IsNullOrWhitespace(v.s) }

// LengthIs reports whether v.length is the number n (v must not be nullish).
func (v *Value) LengthIs(n float64) bool {
	l := v.Get("length")
	return l.kind == Number && l.n == n
}

// LengthGreaterThan is `v.length > n` (v must not be nullish).
func (v *Value) LengthGreaterThan(n float64) bool {
	l := v.Get("length")
	return l.kind == Number && l.n > n
}

// JSString is String(v) (and `v + ""`).
func (v *Value) JSString() string {
	if v == nil {
		return "undefined"
	}
	switch v.kind {
	case Undefined:
		return "undefined"
	case Null:
		return "null"
	case Bool:
		return strconv.FormatBool(v.b)
	case Number:
		return importer.FormatJSNumber(v.n)
	case String:
		return v.s
	case Array:
		return v.Join(",")
	}
	return "[object Object]"
}

// ToString is v.toString() (throws for null/undefined).
func (v *Value) ToString() string {
	if v.Nullish() {
		ThrowTypeError("Cannot read properties of %s (reading 'toString')", v.nullishName())
	}
	return v.JSString()
}

// Join is Array.prototype.join(sep): null/undefined elements become "".
func (v *Value) Join(sep string) string {
	parts := make([]string, len(v.arr))
	for i, e := range v.arr {
		if !e.Nullish() {
			parts[i] = e.JSString()
		}
	}
	return strings.Join(parts, sep)
}

// ForEach is v.forEach(fn); expr names v in the TypeError thrown for non-arrays.
func (v *Value) ForEach(expr string, fn func(*Value)) {
	if v.Nullish() {
		ThrowTypeError("Cannot read properties of %s (reading 'forEach')", v.nullishName())
	}
	if v.kind != Array {
		ThrowTypeError("%s.forEach is not a function", expr)
	}
	for _, e := range v.arr {
		fn(e)
	}
}

// OwnKeys is Object.keys(v) (also the order of `for (const k in v)` on JSON values).
func (v *Value) OwnKeys() []string {
	if v.Nullish() {
		ThrowTypeError("Cannot convert undefined or null to object")
	}
	switch v.kind {
	case Array:
		keys := make([]string, len(v.arr))
		for i := range v.arr {
			keys[i] = strconv.Itoa(i)
		}
		return keys
	case String:
		n := importer.Len16(v.s)
		keys := make([]string, n)
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		return keys
	case Object:
		var ints, strs []string
		for _, k := range v.keys {
			if isArrayIndex(k) {
				ints = append(ints, k)
			} else {
				strs = append(strs, k)
			}
		}
		sort.SliceStable(ints, func(i, j int) bool {
			a, _ := strconv.ParseUint(ints[i], 10, 64)
			b, _ := strconv.ParseUint(ints[j], 10, 64)
			return a < b
		})
		return append(ints, strs...)
	}
	return nil
}

func isArrayIndex(k string) bool {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 4294967295
}

// MakeUriArray is BaseImporter.makeUriArray(v) for an untyped JSON value.
func MakeUriArray(b *importer.Base, v *Value) []*model.LoginUriView {
	if v.Nullish() {
		return nil
	}
	if v.kind == String {
		return b.MakeUriArray(v.s)
	}
	if !v.LengthGreaterThan(0) {
		return nil
	}
	if v.kind != Array {
		ThrowTypeError("uri.forEach is not a function")
	}
	var uris []string
	for _, u := range v.arr {
		if u.Nullish() {
			continue // fixUri(null) is null
		}
		if u.kind != String {
			ThrowTypeError("uri.trim is not a function")
		}
		uris = append(uris, u.s)
	}
	return b.MakeUriArray(uris...)
}
