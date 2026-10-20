package keepass2

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/keepass2-xml-importer.spec.ts. testdata/*.txt were
// extracted from spec-data/keepass2-xml/keepass2-xml-importer-testdata.ts.

func parse(t *testing.T, file string) *model.ImportResult {
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, file))
}

func TestKeePass2XmlImporter(t *testing.T) {
	r := parse(t, "TestData.txt")
	if !r.Success {
		t.Fatal("should parse XML data")
	}
	if r.Folders[0].Name != "Folder2" {
		t.Fatalf("folders %s", importertest.Dump(r.Folders))
	}
	c := r.Ciphers[0]
	if c.Login.Uri() == "" || c.Login.Username == "" || c.Login.Password == "" {
		t.Fatalf("login details %s", importertest.Dump(c))
	}

	if r := parse(t, "TestData1.txt"); r.ErrorMessage != "Missing `KeePassFile > Root` node." {
		t.Fatalf("missing root: %q", r.ErrorMessage)
	}
	if r := parse(t, "TestData2.txt"); r.Success {
		t.Fatal("missing KeePassFile should fail")
	}
}

func TestKeePass2FolderStructure(t *testing.T) {
	r := parse(t, "TestData.txt")
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	if len(r.Ciphers) == 0 || len(r.FolderRelationships) != len(r.Ciphers) {
		t.Fatalf("%v %v", names, r.FolderRelationships)
	}
	// Organization imports turn the folders into collections.
	org := importertest.Parse(t, New(importertest.OrgOptions("org")), importertest.ReadFile(t, "TestData.txt"))
	if len(org.Folders) != 0 || len(org.Collections) != len(r.Folders) || len(org.CollectionRelationships) != len(r.FolderRelationships) {
		t.Fatalf("%s", importertest.Dump(org))
	}
}

func TestProtectedFields(t *testing.T) {
	r := parse(t, "TestDataWithProtectedFields.txt")
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Test Entry" || c.Login.Username != "testuser" || c.Login.Password != "testpass" || !strings.Contains(c.Notes, "Regular notes") {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsExist(t, c.Fields,
		importertest.F("SAFE UN-LOCKING instructions", "Secret instructions here", model.FieldTypeHidden),
		importertest.F("CustomField", "Custom value", model.FieldTypeText),
	)
	var long, multi *model.FieldView
	for _, f := range c.Fields {
		switch f.Name {
		case "LongProtectedField":
			long = f
		case "MultilineProtectedField":
			multi = f
		}
	}
	if long == nil || long.Type != model.FieldTypeHidden || !strings.Contains(long.Value, "This is a very long protected field") {
		t.Fatal("long protected field")
	}
	if multi == nil || multi.Type != model.FieldTypeHidden || !strings.Contains(multi.Value, "Line 1") {
		t.Fatal("multiline protected field")
	}
	for _, s := range []string{"LongProtectedField", "MultilineProtectedField", "SAFE UN-LOCKING instructions", "Secret instructions here"} {
		if strings.Contains(c.Notes, s) {
			t.Fatalf("notes contain %q", s)
		}
	}
}
