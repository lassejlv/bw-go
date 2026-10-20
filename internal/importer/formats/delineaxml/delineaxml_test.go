package delineaxml

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/delinea-xml-importer.spec.ts. testdata/*.txt were
// extracted from spec-data/delinea/delinea-xml-importer-testdata.ts.

func parse(t *testing.T, file string) *model.ImportResult {
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, file))
}

func TestParseXML(t *testing.T) {
	if r := parse(t, "DelineaXmlTestDataNote.txt"); !r.Success {
		t.Fatal("should parse XML data")
	}
}

func TestMissingRoot(t *testing.T) {
	r := parse(t, "DelineaXmlTestDataMissingRoot.txt")
	if r.Success || r.ErrorMessage != "Missing `ImportFile` node." {
		t.Fatalf("%v %q", r.Success, r.ErrorMessage)
	}
}

func TestUnparsable(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "<ImportFile>")
	if r.Success || r.ErrorMessage != "Unable to parse XML file." {
		t.Fatalf("%v %q", r.Success, r.ErrorMessage)
	}
}

func TestFolders(t *testing.T) {
	r := parse(t, "DelineaXmlTestDataLogin.txt")
	if !r.Success || len(r.Folders) != 1 || r.Folders[0].Name != "Finance" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
	if len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%v", r.FolderRelationships)
	}
}

func TestSecureNote(t *testing.T) {
	r := parse(t, "DelineaXmlTestDataNote.txt")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Notes != "Level 1 = 1024" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("username", "myUser"),
		importertest.F("password", "SoftBatchCookies123!", model.FieldTypeHidden),
		importertest.F("expires", "2020-03-09 08:52:49 AM"),
	)
	if len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
		t.Fatal("unexpected folders")
	}
}

func TestLogin(t *testing.T) {
	r := parse(t, "DelineaXmlTestDataLogin.txt")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Login.Username != "myUser" || c.Login.Password != "SoftBatchCookies123!" || c.Notes != "Level 1 = 1024" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if u := importertest.URIs(c); len(u) != 1 || u[0] != "https://bitwarden.com" {
		t.Fatalf("%v", u)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("date-created", "2020-03-09 09:29:08 AM"),
		importertest.F("expires", "2020-03-09 08:52:49 AM"),
	)
	if len(r.Folders) != 1 || len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatal("folders")
	}
}

func TestEmptySlugValue(t *testing.T) {
	r := parse(t, "DelineaXmlTestDataEmptySlugValue.txt")
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatal("parse")
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Notes != "" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("username", "myUser"),
		importertest.F("password", "SoftBatchCookies123!"),
	)
	if len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
		t.Fatal("unexpected folders")
	}
}

func TestOrganization(t *testing.T) {
	r := importertest.Parse(t, New(importertest.OrgOptions("org")), importertest.ReadFile(t, "DelineaXmlTestDataLogin.txt"))
	if len(r.Folders) != 0 || len(r.Collections) != 1 || r.Collections[0].Name != "Finance" || len(r.CollectionRelationships) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}
