package exporter

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func newGUID() string { return uuid.NewString() }

// csvArray is a JS array value; it is rendered with Array.prototype.toString (elements joined by
// ",", null/undefined elements empty).
type csvArray []*string

// csvRow is one exported object: values in property insertion order. nil is null/undefined.
type csvRow []any

// jsToString renders a cell value like papaparse's `str.toString()`.
func jsToString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, true
	case *string:
		if x == nil {
			return "", false
		}
		return *x, true
	case int:
		return strconv.Itoa(x), true
	case csvArray:
		parts := make([]string, len(x))
		for i, p := range x {
			if p != nil {
				parts[i] = *p
			}
		}
		return strings.Join(parts, ","), true
	}
	return "", false
}

// csvSafe mirrors papaparse 5.5.3 unparse `safe()` with the default config (delimiter ",",
// quoteChar '"', escapeChar '"', quotes false, escapeFormulae false).
func csvSafe(v any) string {
	s, ok := jsToString(v)
	if !ok {
		return ""
	}
	escaped := strings.ReplaceAll(s, `"`, `""`)
	needsQuote := strings.ContainsAny(escaped, "\r\n\"\uFEFF") ||
		strings.Contains(escaped, ",") ||
		strings.HasPrefix(escaped, " ") ||
		strings.HasSuffix(escaped, " ")
	if needsQuote {
		return `"` + escaped + `"`
	}
	return escaped
}

// Unparse mirrors papa.unparse(arrayOfObjects) for objects that all share the property order of
// fields: a header row and one row per object, separated by "\r\n" without a trailing newline.
// An empty input yields "".
func Unparse(fields []string, rows []csvRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(csvSafe(f))
	}
	b.WriteString("\r\n")
	for r, row := range rows {
		for c := range fields {
			if c > 0 {
				b.WriteByte(',')
			}
			var v any
			if c < len(row) {
				v = row[c]
			}
			b.WriteString(csvSafe(v))
		}
		if r < len(rows)-1 {
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// commonCSVFields are the properties set by BaseVaultExportService.buildCommonCipher, in order.
var commonCSVFields = []string{"type", "name", "notes", "fields", "reprompt", "archivedDate",
	"login_uri", "login_username", "login_password", "login_totp"}

// IndividualCSVFields is the header of an individual vault CSV export.
var IndividualCSVFields = append([]string{"folder", "favorite"}, commonCSVFields...)

// OrganizationCSVFields is the header of an organization vault CSV export.
var OrganizationCSVFields = append([]string{"collections"}, commonCSVFields...)

// buildCommonCipher mirrors BaseVaultExportService.buildCommonCipher for logins and secure notes.
func buildCommonCipher(c *vault.CipherView) csvRow {
	var typ, uris, username, password, totp any
	var fields any
	if c.Fields != nil {
		s := ""
		for i, f := range c.Fields {
			if i > 0 {
				s += "\n"
			}
			name := ""
			if f.Name != nil {
				name = *f.Name
			}
			value := "undefined" // SDK FieldView: absent value is undefined
			if f.Value != nil {
				value = *f.Value
			}
			s += name + ": " + value
		}
		if len(c.Fields) > 0 {
			fields = s
		}
	}
	var archived any
	if c.ArchivedDate != nil {
		archived = cli.FormatDate(*c.ArchivedDate)
	}
	switch c.Type {
	case vault.CipherTypeLogin:
		typ = "login"
		if l := c.Login; l != nil {
			username, password, totp = l.Username, l.Password, l.Totp
			if l.URIs != nil {
				arr := csvArray{}
				for _, u := range l.URIs {
					arr = append(arr, u.URI)
				}
				uris = arr
			}
		}
	case vault.CipherTypeSecureNote:
		typ = "note"
	}
	var notes any
	if c.Notes != nil {
		notes = *c.Notes
	}
	return csvRow{typ, c.Name, notes, fields, int(c.Reprompt), archived, uris, username, password, totp}
}
