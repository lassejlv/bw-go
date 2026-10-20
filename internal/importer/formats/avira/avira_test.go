package avira

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// No upstream spec; expectations follow avira-csv-importer.ts.

func TestAviraCsvImporter(t *testing.T) {
	csv := "name,website,username,secondary_username,password\n" +
		",https://www.example.com/login,,alt,pw1\n" +
		"Named,example.org,user,alt,pw2"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a, b := r.Ciphers[0], r.Ciphers[1]
	if a.Name != "example.com" || a.Login.Username != "alt" || a.Notes != "" || a.Login.Password != "pw1" ||
		!reflect.DeepEqual(importertest.URIs(a), []string{"https://www.example.com/login"}) {
		t.Fatal(importertest.Dump(a))
	}
	if b.Name != "Named" || b.Login.Username != "user" || b.Notes != "alt" ||
		!reflect.DeepEqual(importertest.URIs(b), []string{"http://example.org"}) {
		t.Fatal(importertest.Dump(b))
	}
}
