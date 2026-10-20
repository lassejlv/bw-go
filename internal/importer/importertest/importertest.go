// Package importertest holds test helpers shared by the importer ports (the Go side of
// spec-data/importer-test-utils.ts and the common `importer.parse` + expectations pattern).
package importertest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Options returns importer options that swallow CSV warnings (so tests stay quiet).
func Options() importer.Options {
	return importer.Options{Warn: func(string) {}}
}

// OrgOptions is Options with an organization id.
func OrgOptions(orgID string) importer.Options {
	o := Options()
	o.OrganizationID = orgID
	return o
}

// Parse runs imp.Parse and fails the test on an error.
func Parse(t testing.TB, imp importer.Importer, data string) *model.ImportResult {
	t.Helper()
	r, err := imp.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r == nil {
		t.Fatal("Parse returned a nil result")
	}
	return r
}

// ReadFile reads testdata/<name> relative to the test's package directory.
func ReadFile(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Field is an expected custom field: name, value and (optionally) type.
type Field struct {
	Name  string
	Value string
	Type  *model.FieldType
}

// F builds a Field; pass a type to also check it.
func F(name, value string, typ ...model.FieldType) Field {
	f := Field{Name: name, Value: value}
	if len(typ) > 0 {
		f.Type = &typ[0]
	}
	return f
}

// AssertCustomFieldsExist is importer-test-utils.ts assertCustomFieldsExist: every expected field
// is present (first match by name).
func AssertCustomFieldsExist(t testing.TB, fields []*model.FieldView, expected ...Field) {
	t.Helper()
	for _, e := range expected {
		var found *model.FieldView
		for _, f := range fields {
			if f.Name == e.Name {
				found = f
				break
			}
		}
		if found == nil {
			t.Errorf("custom field %q not found", e.Name)
			continue
		}
		if found.Value != e.Value {
			t.Errorf("custom field %q: value %q, want %q", e.Name, found.Value, e.Value)
		}
		if e.Type != nil && found.Type != *e.Type {
			t.Errorf("custom field %q: type %d, want %d", e.Name, found.Type, *e.Type)
		}
	}
}

// AssertCustomFieldsStructure is importer-test-utils.ts assertCustomFieldsStructure: the fields
// match exactly, in order.
func AssertCustomFieldsStructure(t testing.TB, fields []*model.FieldView, expected ...Field) {
	t.Helper()
	if len(fields) != len(expected) {
		t.Errorf("got %d custom fields, want %d: %s", len(fields), len(expected), Dump(fields))
		return
	}
	for i, e := range expected {
		f := fields[i]
		if f.Name != e.Name {
			t.Errorf("Expected custom field name %s, received %s", e.Name, f.Name)
		}
		if f.Value != e.Value {
			t.Errorf("Expected custom field value %s, received %s", e.Value, f.Value)
		}
		if e.Type != nil && f.Type != *e.Type {
			t.Errorf("Expected custom field type %d, received %d", *e.Type, f.Type)
		}
	}
}

// Dump renders v as indented JSON for failure messages.
func Dump(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// AssertEqualJSON compares got and want by their JSON rendering (handy for whole CipherViews).
func AssertEqualJSON(t testing.TB, got, want any) {
	t.Helper()
	g, w := Dump(got), Dump(want)
	if g != w {
		t.Errorf("mismatch\n got: %s\nwant: %s", g, w)
	}
}

// URIs returns the URI strings of a login (nil-safe).
func URIs(c *model.CipherView) []string {
	if c == nil || c.Login == nil {
		return nil
	}
	var out []string
	for _, u := range c.Login.Uris {
		out = append(out, u.Uri)
	}
	return out
}
