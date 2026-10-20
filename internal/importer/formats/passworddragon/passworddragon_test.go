package passworddragon

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for passworddragon-xml-importer.ts; this fixture follows the structure the
// importer reads.
const data = `<?xml version="1.0" encoding="UTF-8"?>
<PasswordManager>
  <record>
    <Account-Name>Example</Account-Name>
    <User-Id>jdoe</User-Id>
    <Password>secret</Password>
    <URL>example.com</URL>
    <Notes>some notes</Notes>
    <Category>Work</Category>
    <Attribute-1>PIN 1234</Attribute-1>
    <Attribute-2>null</Attribute-2>
    <Attribute-3>  </Attribute-3>
    <Attribute-10>last</Attribute-10>
    <Attribute-11>ignored</Attribute-11>
  </record>
  <record>
    <Category>Unfiled</Category>
    <Account-Name> </Account-Name>
  </record>
</PasswordManager>`

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Example" || c.Login.Username != "jdoe" || c.Login.Password != "secret" || c.Notes != "some notes" ||
		importertest.URIs(c)[0] != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Attribute-1", "PIN 1234", model.FieldTypeText),
		importertest.F("Attribute-10", "last", model.FieldTypeText),
	)
	if len(r.Folders) != 1 || r.Folders[0].Name != "Work" || len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s %v", importertest.Dump(r.Folders), r.FolderRelationships)
	}
	if r.Ciphers[1].Name != "--" {
		t.Fatal("default name")
	}

	if r := importertest.Parse(t, New(importertest.Options()), "<PasswordManager>"); r.Success {
		t.Fatal("invalid xml should fail")
	}
	org := importertest.Parse(t, New(importertest.OrgOptions("o")), data)
	if len(org.Collections) != 1 || len(org.Folders) != 0 {
		t.Fatal("collections")
	}
}
