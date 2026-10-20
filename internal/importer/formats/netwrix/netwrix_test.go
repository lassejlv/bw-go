package netwrix

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/netwrix/netwrix-passwordsecure-csv-importer.spec.ts.
// testdata/*.txt were extracted from spec-data/netwrix-csv/login-export.csv.ts.

func parse(t *testing.T, file string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, file))
}

func parseOrg(t *testing.T, file string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.OrgOptions(importer.NewGuid())), importertest.ReadFile(t, file))
}

func checkLogin(t *testing.T, c *model.CipherView, name, user, pass, totp, uri, notes string) {
	t.Helper()
	if c.Name != name || c.Login.Username != user || c.Login.Password != pass || c.Login.Totp != totp || c.Notes != notes {
		t.Errorf("cipher mismatch: %s", importertest.Dump(c))
	}
	if u := importertest.URIs(c); len(u) != 1 || u[0] != uri {
		t.Errorf("uris %v, want [%s]", u, uri)
	}
}

func TestInvalidData(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "")
	if r.Success {
		t.Fatal("expected failure")
	}
}

func TestParseLoginRecords(t *testing.T) {
	r := parse(t, "credentialsData.txt")
	checkLogin(t, r.Ciphers[0], "Test Entry 1", "someUser", "somePassword", "someTOTPSeed", "https://www.example.com", "some note for example.com")
	checkLogin(t, r.Ciphers[1], "Test Entry 2", "jdoe", "})9+Kg2fz_O#W1§H1-<ox>0Zio", "anotherTOTP", "http://www.123.com", "Description123")
	checkLogin(t, r.Ciphers[2], "Test Entry 3", "username", "password", "", "http://www.internetsite.com", "Information")
}

func TestAlternateUriHeaders(t *testing.T) {
	r := parse(t, "credentialsDataAlternateUriHeaders.txt")
	if !r.Success {
		t.Fatal("expected success")
	}
	expected := map[string]string{
		"Internetadresse Entry": "https://www.internetadresse.com",
		"Webseite Entry":        "https://www.webseite.com",
		"Website Entry":         "https://www.website.com",
		"Webmail Entry":         "https://www.webmail.com",
		"Web page Entry":        "https://www.webpage.com",
		"URL Entry":             "https://www.url.com",
	}
	if len(r.Ciphers) != len(expected) {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	for _, c := range r.Ciphers {
		if u := importertest.URIs(c); len(u) != 1 || u[0] != expected[c.Name] {
			t.Errorf("%s: uris %v", c.Name, u)
		}
		if len(c.Fields) != 0 {
			t.Errorf("%s: fields %s", c.Name, importertest.Dump(c.Fields))
		}
	}
}

func TestUnmappedFields(t *testing.T) {
	r := parse(t, "credentialsData.txt")
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[0].Fields, importertest.F("DataTags", "tag1, tag2, tag3"))
}

func fieldValue(c *model.CipherView, name string) (string, bool) {
	for _, f := range c.Fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func TestEnclosedInQuotes(t *testing.T) {
	r := parse(t, "credentialsDataEnclosedInQuotes.txt")
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	var folders []string
	for _, f := range r.Folders {
		folders = append(folders, f.Name)
	}
	if !reflect.DeepEqual(folders, []string{"folderOrCollection1", "folderOrCollection2"}) {
		t.Errorf("folders %v", folders)
	}
	if !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {1, 1}}) {
		t.Errorf("relationships %v", r.FolderRelationships)
	}

	first := r.Ciphers[0]
	if first.Name != "Test Entry 1" || first.Login.Username != "someUser" || first.Login.Password != "somePassword" || first.Notes != "some note for example.com" {
		t.Errorf("%s", importertest.Dump(first))
	}
	if u := importertest.URIs(first); !reflect.DeepEqual(u, []string{"https://www.example.com", "https://webseite.example.com", "https://webseite1.example.com"}) {
		t.Errorf("uris %v", u)
	}
	if _, ok := fieldValue(first, "DataTags"); !ok {
		t.Error("DataTags missing")
	}
	if v, _ := fieldValue(first, "EMail-Adresse"); v != "user@example.com" {
		t.Errorf("EMail-Adresse %q", v)
	}

	second := r.Ciphers[1]
	if second.Name != "Test Entry 2" || second.Login.Username != "jdoe" || second.Login.Password != "secret" || second.Notes != "Description123" {
		t.Errorf("%s", importertest.Dump(second))
	}
	if u := importertest.URIs(second); !reflect.DeepEqual(u, []string{"http://www.123.com"}) {
		t.Errorf("uris %v", u)
	}
	if _, ok := fieldValue(second, "DataTags"); ok {
		t.Error("DataTags should be absent")
	}
	if v, _ := fieldValue(second, "EMail-Adresse"); v != "jdoe@123.com" {
		t.Errorf("EMail-Adresse %q", v)
	}
}

func TestEnclosedInQuotesEmptyRow(t *testing.T) {
	r := parse(t, "credentialsDataEnclosedInQuotesEmptyRow.txt")
	if !r.Success {
		t.Fatal("expected success")
	}
}

func TestEnglishOrgUnit(t *testing.T) {
	r := parse(t, "credentialsDataEnclosedInQuotesEnglishOrgUnit.txt")
	if !r.Success || len(r.Folders) != 1 || r.Folders[0].Name != "Bohn, Markus" || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "TESTING" || c.Login.Username != "myUser" || c.Login.Password != "test" {
		t.Errorf("%s", importertest.Dump(c))
	}
}

func TestCreateFolder(t *testing.T) {
	r := parse(t, "credentialsData.txt")
	if !r.Success || len(r.Folders) != 2 || r.Folders[0].Name != "folderOrCollection1" || r.Folders[1].Name != "folderOrCollection2" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
	if !reflect.DeepEqual(r.FolderRelationships[:3], []model.Relationship{{0, 0}, {1, 1}, {2, 0}}) {
		t.Errorf("%v", r.FolderRelationships)
	}
}

func TestCreateCollection(t *testing.T) {
	r := parseOrg(t, "credentialsData.txt")
	if !r.Success || len(r.Collections) != 2 || r.Collections[0].Name != "folderOrCollection1" || r.Collections[1].Name != "folderOrCollection2" {
		t.Fatalf("%s", importertest.Dump(r.Collections))
	}
	if !reflect.DeepEqual(r.CollectionRelationships[:3], []model.Relationship{{0, 0}, {1, 1}, {2, 0}}) {
		t.Errorf("%v", r.CollectionRelationships)
	}
}

func TestMultipleCollections(t *testing.T) {
	r := parseOrg(t, "credentialsDataWithFolders.txt")
	var names []string
	for _, c := range r.Collections {
		names = append(names, c.Name)
	}
	if !r.Success || !reflect.DeepEqual(names, []string{"folder1/folder2/folder3", "folder1/folder2", "folder1"}) {
		t.Fatalf("%v", names)
	}
	if !reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}}) {
		t.Errorf("%v", r.CollectionRelationships)
	}
}
