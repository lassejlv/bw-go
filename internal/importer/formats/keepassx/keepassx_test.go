package keepassx

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Ported from libs/importer/src/importers/keepassx-csv-importer.spec.ts
// (spec-data/keepassx-csv/testdata.csv.ts).

func TestKeePassXCsvImporter(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, "keepassxTestData.txt"))
	if len(r.Ciphers) != 2 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}

	t.Run("should parse login data when provided valid CSV", func(t *testing.T) {
		c := r.Ciphers[0]
		if c.Name != "Example Entry" || c.Login.Username != "testuser" || c.Login.Password != "password123" ||
			!reflect.DeepEqual(importertest.URIs(c), []string{"https://example.com"}) || c.Notes != "Some notes" {
			t.Fatal(importertest.Dump(c))
		}
	})

	t.Run("should import TOTP when present in the CSV", func(t *testing.T) {
		c := r.Ciphers[len(r.Ciphers)-1]
		if c.Name != "Another Entry" || c.Login.Username != "anotheruser" || c.Login.Password != "anotherpassword" ||
			!reflect.DeepEqual(importertest.URIs(c), []string{"https://another.com"}) || c.Notes != "Another set of notes" ||
			c.Login.Totp != "otpauth://totp/Another?secret=ABCD1234EFGH5678" {
			t.Fatal(importertest.Dump(c))
		}
	})
}

func TestKeePassXGroups(t *testing.T) {
	csv := "Group,Title,Username,Password,URL,Notes\nRoot/Work/Sub,A,u,p,,\nRoot,B,u,p,,\n,,u,p,,"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if len(r.Ciphers) != 2 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	if !reflect.DeepEqual(names, []string{"Work/Sub", "Work", "Root"}) {
		t.Fatal(names)
	}
}
