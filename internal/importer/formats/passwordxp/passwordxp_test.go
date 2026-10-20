package passwordxp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/passsordxp/passwordxp-csv-importer.spec.ts
// (spec-data/passwordxp-csv).

func parse(t *testing.T, data string, org ...string) *model.ImportResult {
	t.Helper()
	o := importertest.Options()
	if len(org) > 0 {
		o = importertest.OrgOptions(org[0])
	}
	return importertest.Parse(t, New(o), data)
}

func importLoginWithCustomFields(t *testing.T, csvData string) {
	t.Helper()
	r := parse(t, csvData)
	if !r.Success {
		t.Fatal("not successful")
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "Title2" || c.Notes != "Test Notes" ||
		c.Login.Username != "Username2" || c.Login.Password != "12345678" || c.Login.Uris[0].Uri != "http://URL2.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Account", "Account2"),
		importertest.F("Modified", "27-3-2024 08:11:21"),
		importertest.F("Created", "27-3-2024 08:11:21"),
		importertest.F("Expire on", "27-5-2024 08:11:21"),
		importertest.F("Modified by", "someone"),
	)
}

func TestEmpty(t *testing.T) {
	if parse(t, "").Success {
		t.Fatal("expected failure")
	}
}

func TestUntranslatedHeaders(t *testing.T) {
	data := strings.Replace(importertest.ReadFile(t, "germanHeaders.txt"), "Titel;", "UnknownTitle;", 1)
	if parse(t, data).Success {
		t.Fatal("expected failure")
	}
}

func TestSkipRows(t *testing.T) {
	r := parse(t, importertest.ReadFile(t, "noFolder.txt"))
	if !r.Success || len(r.Ciphers) != 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestWithoutFolders(t *testing.T) {
	r := parse(t, importertest.ReadFile(t, "withoutFolders.txt"))
	if !r.Success || len(r.Ciphers) != 4 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	type want struct {
		typ                          model.CipherType
		name, notes, user, pass, uri string
	}
	for i, w := range []want{
		{model.CipherTypeLogin, "Title2", "Test Notes", "Username2", "12345678", "http://URL2.com"},
		{model.CipherTypeLogin, "Title Test 1", "Test Notes 2", "Username1", "Password1", "http://URL1.com"},
		{model.CipherTypeSecureNote, "Certificate 1", "Test Notes Certicate 1", "", "", ""},
		{model.CipherTypeLogin, "test", "Test Notes 3", "testtest", "test", "http://test"},
	} {
		c := r.Ciphers[i]
		if c.Type != w.typ || c.Name != w.name || c.Notes != w.notes {
			t.Fatalf("%d: %s", i, importertest.Dump(c))
		}
		if w.typ == model.CipherTypeLogin && (c.Login.Username != w.user || c.Login.Password != w.pass || c.Login.Uris[0].Uri != w.uri) {
			t.Fatalf("%d: %s", i, importertest.Dump(c))
		}
	}
}

func TestEnglishHeaders(t *testing.T) {
	importLoginWithCustomFields(t, importertest.ReadFile(t, "withoutFolders.txt"))
}
func TestGermanHeaders(t *testing.T) {
	importLoginWithCustomFields(t, importertest.ReadFile(t, "germanHeaders.txt"))
}
func TestDutchHeaders(t *testing.T) {
	importLoginWithCustomFields(t, importertest.ReadFile(t, "dutchHeaders.txt"))
}

func TestWithFolders(t *testing.T) {
	r := parse(t, importertest.ReadFile(t, "withFolders.txt"))
	if !r.Success || len(r.Ciphers) != 5 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	if !reflect.DeepEqual(names, []string{"Test Folder", "Cert folder", "Cert folder/Nested folder"}) {
		t.Fatal(names)
	}
	if !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 0}, {2, 1}, {3, 1}, {4, 2}}) {
		t.Fatal(r.FolderRelationships)
	}
}

func TestWithFoldersOrganization(t *testing.T) {
	r := parse(t, importertest.ReadFile(t, "withFolders.txt"), "someOrg")
	if !r.Success || len(r.Ciphers) != 5 || len(r.Collections) != 3 ||
		r.Collections[0].Name != "Test Folder" || r.Collections[1].Name != "Cert folder" ||
		r.Collections[2].Name != "Cert folder/Nested folder" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{1, 0}, {2, 1}, {3, 1}, {4, 2}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestMultipleFoldersOrganization(t *testing.T) {
	r := parse(t, importertest.ReadFile(t, "withMultipleFolders.txt"), "someOrg")
	if !r.Success || len(r.Ciphers) != 5 || len(r.Collections) != 3 ||
		r.Collections[0].Name != "Test Folder" || r.Collections[1].Name != "Test Folder/Level 2 Folder" ||
		r.Collections[2].Name != "Test Folder/Level 2 Folder/Level 3 Folder" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{1, 0}, {2, 1}, {3, 1}, {4, 2}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}
