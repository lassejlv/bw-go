package vault

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Opt models a JavaScript property that can be undefined (omitted from JSON), null, or a value.
// Use it with the `omitzero` struct tag: an undefined Opt is omitted, a defined Opt with a nil
// value marshals as null. When unmarshalling, a present key (even `null`) marks the Opt defined.
type Opt[T any] struct {
	Val     *T
	Defined bool
}

// Some returns a defined Opt holding v.
func Some[T any](v T) Opt[T] { return Opt[T]{Val: &v, Defined: true} }

// Null returns a defined Opt holding null.
func Null[T any]() Opt[T] { return Opt[T]{Defined: true} }

// FromPtr returns undefined for nil, otherwise a defined value (JS: `x ?? undefined`).
func FromPtr[T any](p *T) Opt[T] {
	if p == nil {
		return Opt[T]{}
	}
	v := *p
	return Opt[T]{Val: &v, Defined: true}
}

// NullFromPtr returns null for nil, otherwise the value (JS: `x ?? null`).
func NullFromPtr[T any](p *T) Opt[T] {
	if p == nil {
		return Null[T]()
	}
	return Some(*p)
}

// IsZero reports whether the value is undefined (used by `omitzero`).
func (o Opt[T]) IsZero() bool { return !o.Defined }

// IsNull reports whether the value is undefined or null (JS `== null`).
func (o Opt[T]) IsNull() bool { return o.Val == nil }

// Get returns the value or the zero value.
func (o Opt[T]) Get() T {
	if o.Val == nil {
		var z T
		return z
	}
	return *o.Val
}

// Ptr returns a copy of the value as pointer, nil when null/undefined.
func (o Opt[T]) Ptr() *T {
	if o.Val == nil {
		return nil
	}
	v := *o.Val
	return &v
}

// MarshalJSON implements json.Marshaler.
func (o Opt[T]) MarshalJSON() ([]byte, error) {
	if o.Val == nil {
		return []byte("null"), nil
	}
	return marshalNoEscape(*o.Val)
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *Opt[T]) UnmarshalJSON(b []byte) error {
	o.Defined = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Val = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.Val = &v
	return nil
}

// marshalNoEscape marshals like JSON.stringify (no HTML escaping).
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func strPtr(s string) *string { return &s }

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// isNullOrWhitespace mirrors Utils.isNullOrWhitespace.
func isNullOrWhitespace(p *string) bool { return p == nil || strings.TrimSpace(*p) == "" }

// isNullOrEmpty mirrors Utils.isNullOrEmpty.
func isNullOrEmpty(p *string) bool { return p == nil || *p == "" }

// clonePtr copies a string pointer.
func clonePtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
