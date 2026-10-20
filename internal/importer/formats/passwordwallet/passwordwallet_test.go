package passwordwallet

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for passwordwallet-txt-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "Site,example.com,user,pass,line1¬line2,Folder\\Sub\nOnly\n")
	if len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pass" || c.Notes != "line1\nline2" ||
		!reflect.DeepEqual(importertest.URIs(c), []string{"http://example.com"}) {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Folders) != 2 || r.Folders[0].Name != "Folder/Sub" || r.Folders[1].Name != "Folder" ||
		!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if o := r.Ciphers[1]; o.Name != "Only" || o.Type != model.CipherTypeLogin {
		t.Fatalf("%s", importertest.Dump(o))
	}
	if !importer.IsImplemented("passwordwallettxt") {
		t.Fatal("not registered")
	}
}
