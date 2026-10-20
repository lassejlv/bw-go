package protonpass

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
)

// JSON helpers that keep JavaScript semantics the importer depends on: Object.keys/entries
// order, typeof checks and "x is not iterable" TypeErrors.

// jsStr decodes a JSON string; any other JSON value decodes to "". The importer only ever uses
// these values through getValueOrDefault/processKvp/isNullOrWhitespace, which treat non-strings
// like null (Utils.isNullOrWhitespace checks typeof === "string").
type jsStr string

func (s *jsStr) UnmarshalJSON(b []byte) error {
	var v string
	if json.Unmarshal(b, &v) == nil {
		*s = jsStr(v)
	} else {
		*s = ""
	}
	return nil
}

// kv is one own enumerable property of a parsed JSON object.
type kv struct {
	Key   string
	Value json.RawMessage
}

// isNullish reports whether raw is absent (undefined) or JSON null.
func isNullish(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

func firstByte(raw json.RawMessage) byte {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return 0
	}
	return t[0]
}

// isArrayIndex reports whether k is a canonical array index (JS orders those first).
func isArrayIndex(k string) (uint64, bool) {
	if k == "" || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return n, true
}

// objectEntries is Object.entries(JSON.parse(raw)) for an object value: integer-like keys
// first in ascending order, then the rest in insertion order; a duplicate key keeps its first
// position and its last value. ok is false when raw is not an object.
func objectEntries(raw json.RawMessage) (entries []kv, ok bool) {
	if firstByte(raw) != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil, false
	}
	index := map[string]int{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		if i, dup := index[key]; dup {
			entries[i].Value = v
			continue
		}
		index[key] = len(entries)
		entries = append(entries, kv{Key: key, Value: v})
	}
	sort.SliceStable(entries, func(a, b int) bool {
		na, ia := isArrayIndex(entries[a].Key)
		nb, ib := isArrayIndex(entries[b].Key)
		if ia && ib {
			return na < nb
		}
		return ia && !ib
	})
	return entries, true
}

// entries is Object.entries(value) for any non-nullish JSON value: objects as above, arrays by
// index, strings by character, other primitives none.
func entries(raw json.RawMessage) []kv {
	switch firstByte(raw) {
	case '{':
		e, _ := objectEntries(raw)
		return e
	case '[':
		var arr []json.RawMessage
		_ = json.Unmarshal(raw, &arr)
		out := make([]kv, len(arr))
		for i, v := range arr {
			out[i] = kv{Key: strconv.Itoa(i), Value: v}
		}
		return out
	case '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		var out []kv
		i := 0
		for _, r := range s {
			b, _ := json.Marshal(string(r))
			out = append(out, kv{Key: strconv.Itoa(i), Value: b})
			i++
		}
		return out
	}
	return nil
}

// forOf is `for (const x of value)` over a JSON value: arrays yield their elements, strings
// their characters, anything else throws a TypeError.
func forOf(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	switch firstByte(raw) {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	case '"':
		var out []json.RawMessage
		for _, e := range entries(raw) {
			out = append(out, e.Value)
		}
		return out, nil
	}
	return nil, errors.New(name + " is not iterable")
}

// forEach is `value.forEach(...)`: only arrays have it; anything else throws a TypeError.
func forEach(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	if firstByte(raw) != '[' {
		if isNullish(raw) {
			return nil, errors.New("Cannot read properties of null (reading 'forEach')")
		}
		return nil, errors.New(name + ".forEach is not a function")
	}
	return forOf(raw, name)
}

// obj is a parsed JSON value used for property reads (`value.key`): the own properties of an
// object, or none for primitives and arrays (whose reads yield undefined for the keys we use).
type obj []kv

// get is `o[key]` with exact (case-sensitive) key matching; nil means undefined.
func (o obj) get(key string) json.RawMessage {
	for _, p := range o {
		if p.Key == key {
			return p.Value
		}
	}
	return nil
}

// has is `key in o` / Object.prototype.hasOwnProperty.
func (o obj) has(key string) bool { return o.get(key) != nil }

// toObj prepares raw for property reads, throwing like JavaScript when it is null/undefined
// (`Cannot read properties of null (reading 'key')`).
func toObj(raw json.RawMessage, key string) (obj, error) {
	if isNullish(raw) {
		what := "undefined"
		if len(bytes.TrimSpace(raw)) > 0 {
			what = "null"
		}
		return nil, errors.New("Cannot read properties of " + what + " (reading '" + key + "')")
	}
	e, _ := objectEntries(raw)
	return obj(e), nil
}

// str is `value` used where a string is expected: the string, or "" for any non-string.
func str(raw json.RawMessage) string {
	var s jsStr
	_ = s.UnmarshalJSON(raw)
	return string(s)
}

// isTruthy is JavaScript truthiness (`if (value)`).
func isTruthy(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return false
	}
	switch t[0] {
	case 'n', 'f':
		return false
	case '"':
		return len(t) > 2
	case 't', '{', '[':
		return true
	}
	f, err := strconv.ParseFloat(string(t), 64)
	return err == nil && f != 0
}

// isNumber reports whether raw is a JSON number (typeof value === "number") and returns it.
func isNumber(raw json.RawMessage) (float64, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return 0, false
	}
	switch t[0] {
	case '"', 'n', 't', 'f', '{', '[':
		return 0, false
	}
	f, err := strconv.ParseFloat(string(t), 64)
	return f, err == nil
}

// looseEqualsNumber is `value == n` for a JSON value (numbers and numeric strings).
func looseEqualsNumber(raw json.RawMessage, n float64) bool {
	if f, ok := isNumber(raw); ok {
		return f == n
	}
	if firstByte(raw) == '"' {
		s := importer.JSTrim(str(raw))
		if s == "" {
			return n == 0
		}
		f, err := strconv.ParseFloat(s, 64)
		return err == nil && f == n
	}
	return false
}

// templateString is `${value}` for a JSON value (`${x ?? ""}` callers map nullish to "").
func templateString(raw json.RawMessage) string {
	switch firstByte(raw) {
	case 0, 'n':
		return "null"
	case '"':
		return str(raw)
	case 't':
		return "true"
	case 'f':
		return "false"
	case '{':
		return "[object Object]"
	case '[':
		var arr []json.RawMessage
		_ = json.Unmarshal(raw, &arr)
		parts := make([]string, len(arr))
		for i, v := range arr {
			if !isNullish(v) {
				parts[i] = templateString(v)
			}
		}
		return strings.Join(parts, ",")
	}
	f, _ := isNumber(raw)
	return importer.FormatJSNumber(f)
}
