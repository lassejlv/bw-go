package splashid

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for splashid-csv-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	data := "Web Logins,Site,user,pass,example.com,extra1,,f7,f8,Notes here,Folder1\n" +
		"Credit Cards,Visa,4111,12/30,123,x,y,z,Card notes,Cards\n" +
		"a,b\n"
	r := importertest.Parse(t, New(importertest.Options()), data)
	if len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	l := r.Ciphers[0]
	// fields 5..len-4 go to the notes, the last 3 columns are not parsed.
	if l.Type != model.CipherTypeLogin || l.Name != "Site" || l.Login.Username != "user" || l.Login.Password != "pass" ||
		!reflect.DeepEqual(importertest.URIs(l), []string{"http://example.com"}) || l.Notes != "Notes hereextra1\nf7\n" {
		t.Fatalf("%s", importertest.Dump(l))
	}
	n := r.Ciphers[1]
	if n.Type != model.CipherTypeSecureNote || n.Name != "Visa" || n.Notes != "Card notes4111\n12/30\n123\nx\ny\n" {
		t.Fatalf("%s", importertest.Dump(n))
	}
	if len(r.Folders) != 2 || r.Folders[1].Name != "Cards" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
	if !importer.IsImplemented("splashidcsv") {
		t.Fatal("not registered")
	}
}
