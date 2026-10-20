package stickypassword

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for stickypassword-xml-importer.ts; this fixture follows the Sticky
// Password XML export structure the importer reads.
const data = `<?xml version="1.0" encoding="UTF-8"?>
<root>
  <Database>
    <Groups>
      <Group ID="1" Name="Personal" ParentID="0"/>
      <Group ID="2" Name="Email" ParentID="1"/>
    </Groups>
    <Accounts>
      <Account ID="10" Name="Gmail" Link="mail.google.com" ParentID="2" Comments="line1/nline2">
        <LoginLinks>
          <Login SourceLoginID="100"/>
        </LoginLinks>
      </Account>
    </Accounts>
    <Logins>
      <Login ID="100" Name="jdoe" Password="secret"/>
      <Login ID="101" Name="orphan" Password="pw"/>
      <Login Name="no id"/>
    </Logins>
  </Database>
</root>`

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Gmail" || c.Login.Username != "jdoe" || c.Login.Password != "secret" || c.Notes != "line1\nline2" ||
		importertest.URIs(c)[0] != "http://mail.google.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Folders) != 2 || r.Folders[0].Name != "Personal/Email" || r.Folders[1].Name != "Personal" ||
		len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s %v", importertest.Dump(r.Folders), r.FolderRelationships)
	}
	if c := r.Ciphers[1]; c.Name != "--" || c.Login.Username != "orphan" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestGroupCycle(t *testing.T) {
	_, err := New(importertest.Options()).Parse(`<root><Database><Groups><Group ID="1" Name="A" ParentID="1"/></Groups>
<Accounts><Account Name="x" ParentID="1"><LoginLinks><Login SourceLoginID="5"/></LoginLinks></Account></Accounts>
<Logins><Login ID="5"/></Logins></Database></root>`)
	if err == nil {
		t.Fatal("cyclic groups should fail like upstream's stack overflow")
	}
}
