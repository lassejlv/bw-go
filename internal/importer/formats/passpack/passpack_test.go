package passpack

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow passpack-csv-importer.ts.

const csv = `Entry Name,User ID,Password,URL,Tags,Notes,Shared Notes,Extra Fields
Site,u,p,example.com,"{""tags"":[""{\""tag\"":\""Work\""}"",""bad json"",""{\""tag\"":\""Home\""}""]}",n,shared,"{""extraFields"":[""{\""name\"":\""PIN\"",\""data\"":\""1234\""}"",""nope""]}",extra1,,extra2
Plain,u2,p2,,,,,`

func TestPasspackCsvImporter(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a := r.Ciphers[0]
	if a.Name != "Site" || a.Login.Username != "u" || a.Login.Password != "p" || a.Login.Uris[0].Uri != "http://example.com" ||
		a.Notes != "n\n\nshared\n\nextra1\nextra2" {
		t.Fatalf("%q %s", a.Notes, importertest.Dump(a))
	}
	importertest.AssertCustomFieldsStructure(t, a.Fields, importertest.F("PIN", "1234"))
	if len(r.Folders) != 1 || r.Folders[0].Name != "Work" {
		t.Fatal(importertest.Dump(r.Folders))
	}
	if b := r.Ciphers[1]; b.Notes != "" { // "\n\n\n" is whitespace, cleanupCipher clears it
		t.Fatalf("%q", b.Notes)
	}

	org := importertest.Parse(t, New(importertest.OrgOptions("org")), csv)
	if len(org.Collections) != 2 || org.Collections[0].Name != "Work" || org.Collections[1].Name != "Home" ||
		!reflect.DeepEqual(org.CollectionRelationships, []model.Relationship{{0, 0}, {0, 1}}) {
		t.Fatal(importertest.Dump(org))
	}
}

func TestPasspackMalformedTagsThrow(t *testing.T) {
	_, err := New(importertest.Options()).Parse("Entry Name,Tags\nx,{bad")
	if !importer.IsSyntaxError(err) {
		t.Fatalf("err = %v", err)
	}
}
