package passwordagent

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for passwordagent-csv-importer.ts; these tests follow its logic.

func TestOldVersion(t *testing.T) {
	r := importertest.Parse(t, New(importertest.OrgOptions("org")), "Site,user,pass,example.com,a note\n")
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pass" || c.Notes != "a note" ||
		!reflect.DeepEqual(importertest.URIs(c), []string{"http://example.com"}) {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Collections) != 0 { // old version: folders are not moved
		t.Fatal(r.Collections)
	}
}

func TestNewVersionFolders(t *testing.T) {
	data := "Site,user,pass,notes,https://a.com,x,y,z,Group > Sub\n" +
		"0,Alt,u2,p2,x,notes2,https://b.com,y,z,(None)\n" +
		"short,row\n" +
		",,,,,,,,\n"
	r := importertest.Parse(t, New(importertest.Options()), data)
	if len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	if r.Folders[0].Name != "Group / Sub" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	alt := r.Ciphers[1]
	// altFormat: name/user/pass from 1..3, notes from 5, but uris still from value[4].
	if alt.Name != "Alt" || alt.Login.Username != "u2" || alt.Login.Password != "p2" || alt.Notes != "notes2" ||
		!reflect.DeepEqual(importertest.URIs(alt), []string{"x"}) {
		t.Fatalf("%s", importertest.Dump(alt))
	}
	if r.Ciphers[2].Type != model.CipherTypeSecureNote || r.Ciphers[2].Name != "--" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers[2]))
	}

	r = importertest.Parse(t, New(importertest.OrgOptions("org")), data)
	// "Group / Sub" also creates its parent "Group ".
	if len(r.Folders) != 0 || len(r.Collections) != 2 || r.Collections[1].Name != "Group " {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestRegistered(t *testing.T) {
	if !importer.IsImplemented("passwordagentcsv") {
		t.Fatal("not registered")
	}
}
