package gnome

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for gnome-json-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	data := `{"Login": [
	    {"display_name":"https://www.example.com/a/very/long/path/that/is/cut","secret":"pw",
	     "attributes":{"username_value":"user","xdg:schema":"x","b":"2","1":"one","a":"1"}},
	    {"display_name":"not a url","secret":"skip"}
	  ],
	  "Empty": [],
	  "": [{"display_name":"http://skipped.com"}]}`
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "www.example.com/a/very/long/pa" || c.Login.Password != "pw" || c.Login.Username != "user" ||
		c.Login.Uris[0].Uri != "https://www.example.com/a/very/long/path/that/is/cut" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	// Object key order: integer-like keys first.
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("1", "one"), importertest.F("b", "2"), importertest.F("a", "1"))
	if len(r.Folders) != 1 || r.Folders[0].Name != "Login" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}

	r = importertest.Parse(t, New(importertest.OrgOptions("org")), data)
	if len(r.Collections) != 1 || len(r.Folders) != 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestEmptyAndErrors(t *testing.T) {
	for _, data := range []string{`{}`, `null`, `5`} {
		if r := importertest.Parse(t, New(importertest.Options()), data); r.Success {
			t.Errorf("%s: expected failure", data)
		}
	}
	if _, err := New(importertest.Options()).Parse(`{"k":null}`); err == nil {
		t.Fatal("expected a TypeError")
	}
	if !importer.IsImplemented("gnomejson") {
		t.Fatal("not registered")
	}
}
