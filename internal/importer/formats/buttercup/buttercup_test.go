package buttercup

import (
	"reflect"
	"slices"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/buttercup-csv-importer.spec.ts
// (spec-data/buttercup-csv/testdata.csv.ts).

func parse(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, name+".txt"))
	if !r.Success {
		t.Fatalf("success = false")
	}
	return r
}

func TestButtercupBasicLogin(t *testing.T) {
	r := parse(t, "buttercupCsvTestData")
	if len(r.Ciphers) != 2 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "Test Entry" || c.Login.Username != "testuser" || c.Login.Password != "testpass123" ||
		!reflect.DeepEqual(importertest.URIs(c), []string{"https://example.com"}) {
		t.Fatal(importertest.Dump(c))
	}
}

func TestButtercupFolders(t *testing.T) {
	r := parse(t, "buttercupCsvTestData")
	if len(r.Folders) != 1 || r.Folders[0].Name != "General" || len(r.FolderRelationships) != 2 {
		t.Fatal(importertest.Dump(r))
	}
}

func TestButtercupLowercaseUrl(t *testing.T) {
	r := parse(t, "buttercupCsvWithUrlFieldTestData")
	if got := importertest.URIs(r.Ciphers[0]); !reflect.DeepEqual(got, []string{"https://lowercase-url.com"}) {
		t.Fatal(got)
	}
}

func TestButtercupNote(t *testing.T) {
	r := parse(t, "buttercupCsvWithNoteTestData")
	if r.Ciphers[0].Notes != "This is a note" {
		t.Fatal(r.Ciphers[0].Notes)
	}
}

func TestButtercupCustomFields(t *testing.T) {
	r := parse(t, "buttercupCsvWithCustomFieldsTestData")
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[0].Fields,
		importertest.F("custom_field", "custom value"),
		importertest.F("another_field", "another value"))
}

func TestButtercupSubfolders(t *testing.T) {
	r := parse(t, "buttercupCsvWithSubfoldersTestData")
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	for _, want := range []string{"Work/Projects", "Work", "Personal/Finance", "Personal"} {
		if !slices.Contains(names, want) {
			t.Errorf("missing folder %q in %v", want, names)
		}
	}
}
