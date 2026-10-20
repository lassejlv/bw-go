package padlock

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow padlock-csv-importer.ts.

const csv = "name,tags,User Name,Password,URL,Other\n" +
	"Site,\"work, home\",u,p,example.com,custom\n" +
	"Bad,row\n" +
	"Site2,home,u2,p2,,"

func TestPadlockCsvImporter(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a := r.Ciphers[0]
	if a.Name != "Site" || a.Login.Username != "u" || a.Login.Password != "p" ||
		!reflect.DeepEqual(importertest.URIs(a), []string{"http://example.com"}) {
		t.Fatal(importertest.Dump(a))
	}
	importertest.AssertCustomFieldsStructure(t, a.Fields, importertest.F("Other", "custom"))
	if len(r.Folders) != 2 || r.Folders[0].Name != "work" || r.Folders[1].Name != "home" ||
		!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {1, 1}}) {
		t.Fatal(importertest.Dump(r))
	}

	org := importertest.Parse(t, New(importertest.OrgOptions("org")), csv)
	if len(org.Collections) != 2 || org.Collections[0].Name != "work" || org.Collections[1].Name != "home" ||
		!reflect.DeepEqual(org.CollectionRelationships, []model.Relationship{{0, 0}, {0, 1}, {1, 1}}) {
		t.Fatal(importertest.Dump(org))
	}
}
