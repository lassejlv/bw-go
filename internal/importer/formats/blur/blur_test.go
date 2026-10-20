package blur

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// No upstream spec; expectations follow blur-csv-importer.ts.

func TestBlurCsvImporter(t *testing.T) {
	csv := "domain,email,username,password,label\n" +
		"www.example.com,,user,pw,null\n" +
		"example.org,me@x.com,user2,pw2,Label"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 2 {
		t.Fatal(importertest.Dump(r))
	}
	a, b := r.Ciphers[0], r.Ciphers[1]
	if a.Name != "example.com" || a.Login.Username != "user" || a.Notes != "" || a.Login.Uris[0].Uri != "http://www.example.com" {
		t.Fatal(importertest.Dump(a))
	}
	if b.Name != "Label" || b.Login.Username != "me@x.com" || b.Notes != "user2" || b.Login.Password != "pw2" {
		t.Fatal(importertest.Dump(b))
	}
}
