package keeper

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/lassejlv/bw-go/internal/importer"
)

// The Keeper JSON importer works on JSON.parse output directly (custom fields are free-form and
// their key order matters), so the export is decoded into a small JavaScript value model instead
// of Go structs.

type jsKind int

const (
	jsNull jsKind = iota
	jsBool
	jsNumber
	jsString
	jsArray
	jsObject
)

// jsValue is a JSON.parse result. A nil *jsValue is `undefined`.
type jsValue struct {
	kind jsKind
	b    bool
	n    float64
	s    string
	arr  []*jsValue
	obj  *jsObj
}

// jsObj is a plain object with JavaScript property order (integer-like keys ascending first, then
// string keys in insertion order).
type jsObj struct {
	keys []string
	m    map[string]*jsValue
}

func newJSObj() *jsObj { return &jsObj{m: map[string]*jsValue{}} }

func (o *jsObj) set(k string, v *jsValue) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

func (o *jsObj) del(k string) {
	if _, ok := o.m[k]; !ok {
		return
	}
	delete(o.m, k)
	for i, kk := range o.keys {
		if kk == k {
			o.keys = append(o.keys[:i:i], o.keys[i+1:]...)
			break
		}
	}
}

// isArrayIndex reports whether k is a canonical array index (ordered first by Object.keys).
func isArrayIndex(k string) (uint64, bool) {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 4294967295 {
		return 0, false
	}
	return n, true
}

// orderedKeys is Object.keys(o).
func (o *jsObj) orderedKeys() []string {
	var idx []string
	var rest []string
	for _, k := range o.keys {
		if _, ok := isArrayIndex(k); ok {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, _ := isArrayIndex(idx[a])
		y, _ := isArrayIndex(idx[b])
		return x < y
	})
	return append(idx, rest...)
}

// parseJS is JSON.parse. Syntax errors are wrapped as importer.SyntaxError.
func parseJS(data string) (*jsValue, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	v, err := decodeJS(dec)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, importer.NewSyntaxError(fmt.Errorf("Unexpected non-whitespace character after JSON"))
	}
	return v, nil
}

func decodeJS(dec *json.Decoder) (*jsValue, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	switch t := tok.(type) {
	case nil:
		return &jsValue{kind: jsNull}, nil
	case bool:
		return &jsValue{kind: jsBool, b: t}, nil
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			// Out of range numbers become ±Infinity in JavaScript.
			if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
				return nil, err
			}
		}
		return &jsValue{kind: jsNumber, n: f}, nil
	case string:
		return &jsValue{kind: jsString, s: t}, nil
	case json.Delim:
		switch t {
		case '[':
			v := &jsValue{kind: jsArray, arr: []*jsValue{}}
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
			v := &jsValue{kind: jsObject, obj: newJSObj()}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				e, err := decodeJS(dec)
				if err != nil {
					return nil, err
				}
				v.obj.set(k, e)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		}
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

// isNullish is `v == null`.
func (v *jsValue) isNullish() bool { return v == nil || v.kind == jsNull }

// truthy is JavaScript truthiness.
func (v *jsValue) truthy() bool {
	if v == nil {
		return false
	}
	switch v.kind {
	case jsNull:
		return false
	case jsBool:
		return v.b
	case jsNumber:
		return v.n != 0 && v.n == v.n
	case jsString:
		return v.s != ""
	}
	return true
}

// get is property access `v[k]` (undefined for anything that has no such own property). Only
// objects, arrays and string indices are supported.
func (v *jsValue) get(k string) *jsValue {
	if v == nil {
		return nil
	}
	switch v.kind {
	case jsObject:
		return v.obj.m[k]
	case jsArray:
		if i, ok := isArrayIndex(k); ok && i < uint64(len(v.arr)) {
			return v.arr[i]
		}
	case jsString:
		if i, ok := isArrayIndex(k); ok {
			u := utf16Units(v.s)
			if i < uint64(len(u)) {
				return &jsValue{kind: jsString, s: string(rune(u[i]))}
			}
		}
	}
	return nil
}

// keys is Object.keys(v) (for non-nullish v).
func (v *jsValue) keys() []string {
	if v == nil {
		return nil
	}
	switch v.kind {
	case jsObject:
		return v.obj.orderedKeys()
	case jsArray:
		out := make([]string, len(v.arr))
		for i := range v.arr {
			out[i] = strconv.Itoa(i)
		}
		return out
	case jsString:
		n := importer.Len16(v.s)
		out := make([]string, n)
		for i := 0; i < n; i++ {
			out[i] = strconv.Itoa(i)
		}
		return out
	}
	return nil
}

func utf16Units(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// str returns the value when v is a string, else "" (how BaseImporter's isNullOrWhitespace treats
// non-strings).
func (v *jsValue) str() string {
	if v != nil && v.kind == jsString {
		return v.s
	}
	return ""
}

// toString is String(v) / `${v}` / v.toString().
func (v *jsValue) toString() string {
	if v == nil {
		return "undefined"
	}
	switch v.kind {
	case jsNull:
		return "null"
	case jsBool:
		if v.b {
			return "true"
		}
		return "false"
	case jsNumber:
		return importer.FormatJSNumber(v.n)
	case jsString:
		return v.s
	case jsArray:
		parts := make([]string, len(v.arr))
		for i, e := range v.arr {
			if !e.isNullish() {
				parts[i] = e.toString()
			}
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// stringify is JSON.stringify(v) for a defined value.
func (v *jsValue) stringify() string {
	var b strings.Builder
	v.writeJSON(&b)
	return b.String()
}

func (v *jsValue) writeJSON(b *strings.Builder) {
	if v == nil {
		b.WriteString("null")
		return
	}
	switch v.kind {
	case jsNull:
		b.WriteString("null")
	case jsBool, jsNumber:
		if v.kind == jsNumber && (v.n != v.n || v.n > 1.7976931348623157e308 || v.n < -1.7976931348623157e308) {
			b.WriteString("null")
			return
		}
		b.WriteString(v.toString())
	case jsString:
		writeJSONString(b, v.s)
	case jsArray:
		b.WriteByte('[')
		for i, e := range v.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			e.writeJSON(b)
		}
		b.WriteByte(']')
	case jsObject:
		b.WriteByte('{')
		for i, k := range v.obj.orderedKeys() {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, k)
			b.WriteByte(':')
			v.obj.m[k].writeJSON(b)
		}
		b.WriteByte('}')
	}
}

func writeJSONString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xF])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// makeArray is KeeperJsonImporter.makeArray.
func makeArray(v *jsValue) []*jsValue {
	if v != nil && v.kind == jsArray {
		return v.arr
	}
	if !v.isNullish() {
		return []*jsValue{v}
	}
	return nil
}

// typeError is a JavaScript TypeError thrown by the upstream code (not a SyntaxError, so the import
// service reports its message as is).
type typeError struct{ msg string }

func (e *typeError) Error() string { return e.msg }

func newTypeError(format string, args ...any) error {
	return &typeError{msg: fmt.Sprintf(format, args...)}
}
