package delineacsv

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/delinea-csv-importer.spec.ts (spec-data/delinea).

func parse(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, name))
}

func TestParseCsvData(t *testing.T) {
	r := parse(t, "DelineaCsvTestData.txt")
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestEmpty(t *testing.T) {
	r := parse(t, "DelineaCsvTestDataEmpty.txt")
	if r.Success || len(r.Ciphers) != 0 || len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestFolders(t *testing.T) {
	r := parse(t, "DelineaCsvTestData.txt")
	if !r.Success || len(r.Folders) != 1 || r.Folders[0].Name != "Finance" ||
		!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestSecureNoteWithoutURL(t *testing.T) {
	r := parse(t, "DelineaCsvTestData.txt")
	c := r.Ciphers[1]
	if c.Type != model.CipherTypeSecureNote || c.Notes != "Level 1 = 1024" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Username", "myUser"),
		importertest.F("Password", "SoftBatchCookies123!", model.FieldTypeHidden),
		importertest.F("Date Created", "9/24/2020 9:02"),
		importertest.F("Expires", "9/24/2020 9:00"),
	)
}

func TestLoginWithURL(t *testing.T) {
	r := parse(t, "DelineaCsvTestData.txt")
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Login.Username != "myUser" || c.Login.Password != "SoftBatchCookies123!" ||
		!reflect.DeepEqual(importertest.URIs(c), []string{"https://bitwarden.com"}) || c.Notes != "Level 1 = 1024" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Date Created", "3/9/2020 9:29"),
		importertest.F("Expires", "3/9/2020 8:52"),
	)
}

func TestOrganizationMovesFoldersToCollections(t *testing.T) {
	r := importertest.Parse(t, New(importertest.OrgOptions("org")), importertest.ReadFile(t, "DelineaCsvTestData.txt"))
	if len(r.Folders) != 0 || len(r.Collections) != 1 || r.Collections[0].Name != "Finance" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}
