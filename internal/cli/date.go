package cli

import (
	"encoding/json"
	"strings"
	"time"
)

// JSDateLayout matches JavaScript's Date.prototype.toISOString().
const JSDateLayout = "2006-01-02T15:04:05.000Z"

// FormatDate formats t like Date.toISOString().
func FormatDate(t time.Time) string { return t.UTC().Format(JSDateLayout) }

// Date is a timestamp that marshals like a JavaScript Date (millisecond precision, UTC) and
// unmarshals any RFC 3339 variant the server sends. Use *Date for nullable fields.
type Date struct{ time.Time }

// NewDate wraps t.
func NewDate(t time.Time) *Date { return &Date{t} }

// MarshalJSON implements json.Marshaler.
func (d Date) MarshalJSON() ([]byte, error) { return json.Marshal(FormatDate(d.Time)) }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s == "" {
		return nil
	}
	t, err := ParseDate(s)
	if err != nil {
		return err
	}
	d.Time = t
	return nil
}

// ParseDate parses server/ISO dates, with or without zone and fractional seconds.
func ParseDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if len(s) >= 6 && !strings.ContainsAny(s[len(s)-6:], "Z+") {
		if t, err := time.Parse("2006-01-02T15:04:05.999999999", s); err == nil {
			return t, nil
		}
	}
	return time.Parse("2006-01-02", s)
}
