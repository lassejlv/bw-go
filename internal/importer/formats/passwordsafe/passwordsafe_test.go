package passwordsafe

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for passwordsafe-xml-importer.ts; this fixture follows the pwsafe.org XML
// export format.
const data = `<?xml version="1.0" encoding="UTF-8"?>
<passwordsafe delimiter="»" Database_Format="0x030d">
  <entry id="1">
    <group>Banking.Online</group>
    <title>Bank</title>
    <username>jdoe</username>
    <password>secret</password>
    <url>bank.example.com</url>
    <email>jdoe@example.com</email>
    <notes>line one»line two</notes>
  </entry>
  <entry id="2">
    <title>Mail only</title>
    <email>me@example.com</email>
  </entry>
  <entry id="3">
    <username>u</username>
    <email>e@example.com</email>
  </entry>
</passwordsafe>`

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Bank" || c.Login.Username != "jdoe" || c.Login.Password != "secret" ||
		importertest.URIs(c)[0] != "http://bank.example.com" || c.Notes != "line one\nline two\nEmail: jdoe@example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Folders) != 2 || r.Folders[0].Name != "Banking/Online" || r.Folders[1].Name != "Banking" ||
		len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s %v", importertest.Dump(r.Folders), r.FolderRelationships)
	}
	if c := r.Ciphers[1]; c.Login.Username != "me@example.com" || c.Notes != "" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if c := r.Ciphers[2]; c.Name != "--" || c.Notes != "Email: e@example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestMissingDelimiterSplitsOnNull(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), `<passwordsafe><entry><notes>anullb</notes></entry></passwordsafe>`)
	if r.Ciphers[0].Notes != "a\nb" {
		t.Fatalf("%q", r.Ciphers[0].Notes)
	}
}

func TestMissingRoot(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), `<other/>`)
	if r.Success || r.ErrorMessage != "Missing `passwordsafe` node." {
		t.Fatalf("%v %q", r.Success, r.ErrorMessage)
	}
}
