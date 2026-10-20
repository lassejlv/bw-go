package blackberry

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow blackberry-csv-importer.ts.

func TestBlackBerryCsvImporter(t *testing.T) {
	csv := "url,username,password,extra,name,grouping,fav\n" +
		"https://a.com,u,p,notes,Site,,1\n" +
		",,,secret text,My Note,note,0\n" +
		",,,,List,list,0"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a, b := r.Ciphers[0], r.Ciphers[1]
	if a.Type != model.CipherTypeLogin || !a.Favorite || a.Name != "Site" || a.Notes != "notes" ||
		a.Login.Username != "u" || a.Login.Password != "p" {
		t.Fatal(importertest.Dump(a))
	}
	if b.Type != model.CipherTypeSecureNote || b.Favorite || b.Name != "My Note" || b.Notes != "secret text" {
		t.Fatal(importertest.Dump(b))
	}
}
