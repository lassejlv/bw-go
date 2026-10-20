package passkeep

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// No upstream spec; expectations follow passkeep-csv-importer.ts (PassKeep headers have a leading
// space after each comma).

func TestPassKeepCsvImporter(t *testing.T) {
	csv := "category, title, username, password, site, password2, description\n" +
		"Web,Site,u,p,example.com,p2,desc"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatal(importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "u" || c.Login.Password != "p" || c.Notes != "desc" ||
		c.Login.Uris[0].Uri != "http://example.com" {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("Password 2", "p2"))
	if len(r.Folders) != 1 || r.Folders[0].Name != "Web" {
		t.Fatal(importertest.Dump(r.Folders))
	}
}
