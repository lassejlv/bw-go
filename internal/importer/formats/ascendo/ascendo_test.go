package ascendo

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow ascendo-csv-importer.ts.

func TestAscendoCsvImporter(t *testing.T) {
	csv := "Site,Login,me,Password,secret,URL,example.com,PIN,1234,the notes\n" +
		"Note only,,the note\n" +
		"x"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "Site" || c.Notes != "the notes" || c.Login.Username != "me" ||
		c.Login.Password != "secret" || !reflect.DeepEqual(importertest.URIs(c), []string{"http://example.com"}) {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("PIN", "1234"))

	n := r.Ciphers[1]
	if n.Type != model.CipherTypeSecureNote || n.Name != "Note only" || n.Notes != "the note" {
		t.Fatal(importertest.Dump(n))
	}
}
