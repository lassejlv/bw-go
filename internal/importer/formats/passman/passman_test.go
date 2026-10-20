package passman

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for passman-json-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	data := `[
	  {"label":"Site","username":"user","email":"me@x.com","password":"pw","url":"example.com",
	   "description":"desc","otp":{"secret":"TOTP"},"tags":[{"text":"Work"}],
	   "custom_fields":[{"label":"f1","value":"v1","field_type":"text"},{"label":"f2","value":"v2","field_type":"file"},
	     {"label":"f3","value":"v3","field_type":"password"}]},
	  {"label":"EmailOnly","email":"e@x.com","tags":[]},
	  {"label":"Note","description":"just text"}
	]`
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pw" || c.Notes != "Email: me@x.com\ndesc" ||
		c.Login.Totp != "TOTP" || c.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("f1", "v1"), importertest.F("f3", "v3"))
	if e := r.Ciphers[1]; e.Login.Username != "e@x.com" || e.Notes != "" {
		t.Fatalf("%s", importertest.Dump(e))
	}
	if n := r.Ciphers[2]; n.Type != model.CipherTypeSecureNote || n.Notes != "just text" {
		t.Fatalf("%s", importertest.Dump(n))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != "Work" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestEmptyAndErrors(t *testing.T) {
	for _, data := range []string{`[]`, `null`} {
		if r := importertest.Parse(t, New(importertest.Options()), data); r.Success {
			t.Errorf("%s: expected failure", data)
		}
	}
	for _, data := range []string{`{}`, `[null]`, `[{"custom_fields":{}}]`} {
		if _, err := New(importertest.Options()).Parse(data); err == nil {
			t.Errorf("%s: expected a TypeError", data)
		}
	}
	if !importer.IsImplemented("passmanjson") {
		t.Fatal("not registered")
	}
}
