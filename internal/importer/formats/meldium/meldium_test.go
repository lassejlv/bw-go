package meldium

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// No upstream spec; expectations follow meldium-csv-importer.ts.

func TestMeldiumCsvImporter(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "DisplayName,Notes,UserName,Password,Url\nSite,n,u,p,https://a.com\n,,,,")
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a := r.Ciphers[0]
	if a.Name != "Site" || a.Notes != "n" || a.Login.Username != "u" || a.Login.Password != "p" || a.Login.Uris[0].Uri != "https://a.com" {
		t.Fatal(importertest.Dump(a))
	}
	if r.Ciphers[1].Name != "--" {
		t.Fatal(importertest.Dump(r.Ciphers[1]))
	}
}
