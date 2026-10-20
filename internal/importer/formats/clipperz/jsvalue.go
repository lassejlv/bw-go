package clipperz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/lassejlv/bw-go/internal/importer"
)

// object is a parsed JSON object that keeps JavaScript's property order.
type object struct {
	keys []string
	m    map[string]any
}

// get returns the property (nil for missing, or when o is nil, i.e. a non-object value).
func (o *object) get(k string) any {
	if o == nil {
		return nil
	}
	return o.m[k]
}

func typeError(format string, a ...any) error {
	return fmt.Errorf("TypeError: "+format, a...)
}

// parseJSON is JSON.parse: objects become *object, arrays []any, numbers json.Number. Syntax
// errors are returned as *importer.SyntaxError.
func parseJSON(s string) (any, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, importer.NewSyntaxError(errors.New("Unexpected non-whitespace character after JSON"))
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		case '{':
			o := &object{m: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, dup := o.m[k]; !dup {
					o.keys = append(o.keys, k)
				}
				o.m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil
	}
}

// arrayIndex reports whether k is a canonical array index (JS orders those first, ascending).
func arrayIndex(k string) (uint64, bool) {
	n, err := strconv.ParseUint(k, 10, 32)
	if err != nil || n == 1<<32-1 || strconv.FormatUint(n, 10) != k {
		return 0, false
	}
	return n, true
}

// forInKeys returns the keys `for (const p in v)` visits for a JSON value: object own properties
// in JS order (integer keys ascending, then insertion order), array/string indices, nothing for
// other values.
func forInKeys(v any) []string {
	switch t := v.(type) {
	case *object:
		var ints, rest []string
		for _, k := range t.keys {
			if _, ok := arrayIndex(k); ok {
				ints = append(ints, k)
			} else {
				rest = append(rest, k)
			}
		}
		sort.Slice(ints, func(a, b int) bool {
			x, _ := arrayIndex(ints[a])
			y, _ := arrayIndex(ints[b])
			return x < y
		})
		return append(ints, rest...)
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

// forInValue is v[property] for a key returned by forInKeys. String characters are returned as
// non-object values (they carry no field properties).
func forInValue(v any, property string) any {
	switch t := v.(type) {
	case *object:
		return t.m[property]
	case []any:
		n, _ := strconv.Atoi(property)
		return t[n]
	case string:
		return "" // a one-character string: no actionType/label/value properties
	}
	return nil
}
