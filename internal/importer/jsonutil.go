package importer

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
)

// Lenient JSON scalar types for porting JSON importers. JSON.parse never fails on a "wrong" type,
// so decoding export files into strict Go types would reject files upstream accepts. Use these in
// the structs you decode into.

// JSONString decodes a JSON string, or the JavaScript String() of a number/boolean. null, objects
// and arrays decode to "". Use *JSONString when null must be distinguished from "".
type JSONString string

// UnmarshalJSON implements json.Unmarshaler.
func (s *JSONString) UnmarshalJSON(b []byte) error {
	*s = JSONString(jsonScalarString(b))
	return nil
}

// String returns the value.
func (s JSONString) String() string { return string(s) }

// Str returns the value of a possibly nil *JSONString ("" for nil).
func Str(s *JSONString) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func jsonScalarString(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			return s
		}
		return ""
	case 't', 'f':
		return string(b)
	case 'n', '{', '[':
		return ""
	default:
		f, err := strconv.ParseFloat(string(b), 64)
		if err != nil {
			return string(b)
		}
		return FormatJSNumber(f)
	}
}

// FormatJSNumber formats f like JavaScript's String(number) for the common cases (integers and
// plain decimals).
func FormatJSNumber(f float64) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 0) {
		if f > 0 {
			return "Infinity"
		}
		return "-Infinity"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// JSONNumber decodes a JSON number (or a numeric string, like JavaScript's loose comparisons);
// Valid is false for null, missing, non-numeric strings and non-scalars.
type JSONNumber struct {
	Value float64
	Valid bool
	// IsNumber is true only when the JSON value was a number (typeof x === "number").
	IsNumber bool
}

// UnmarshalJSON implements json.Unmarshaler.
func (n *JSONNumber) UnmarshalJSON(b []byte) error {
	*n = JSONNumber{}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '"':
		var s string
		if json.Unmarshal(b, &s) == nil {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				n.Value, n.Valid = f, true
			}
		}
	case 'n', '{', '[', 't', 'f':
	default:
		if f, err := strconv.ParseFloat(string(b), 64); err == nil {
			n.Value, n.Valid, n.IsNumber = f, true, true
		}
	}
	return nil
}

// Int returns the value truncated to an int (0 when invalid).
func (n JSONNumber) Int() int {
	if !n.Valid {
		return 0
	}
	return int(n.Value)
}

// IsInteger is Number.isInteger(x) (only for real JSON numbers).
func (n JSONNumber) IsInteger() bool {
	return n.IsNumber && n.Value == math.Trunc(n.Value) && !math.IsInf(n.Value, 0)
}

// JSONBool decodes true/false; any other value decodes as JavaScript truthiness (non-empty
// strings and non-zero numbers are true).
type JSONBool bool

// UnmarshalJSON implements json.Unmarshaler.
func (v *JSONBool) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0:
		*v = false
	case b[0] == 't':
		*v = true
	case b[0] == 'f' || b[0] == 'n':
		*v = false
	case b[0] == '"':
		*v = len(b) > 2
	case b[0] == '{' || b[0] == '[':
		*v = true
	default:
		f, err := strconv.ParseFloat(string(b), 64)
		*v = JSONBool(err == nil && f != 0 && !math.IsNaN(f))
	}
	return nil
}

// UnmarshalJSONLenient decodes data like JSON.parse would accept it: syntax errors (and structural
// mismatches such as an object where an array is expected) are reported as *SyntaxError, which the
// import service turns into the "Data is not formatted correctly" message.
func UnmarshalJSONLenient(data string, v any) error {
	if err := json.Unmarshal([]byte(data), v); err != nil {
		return NewSyntaxError(err)
	}
	return nil
}
