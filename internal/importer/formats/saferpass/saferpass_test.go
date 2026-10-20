package saferpass

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Upstream has no spec for saferpass-csv-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "url,username,password,notes\nhttps://www.example.com/login,u,p,n\n,u2,p2,\n")
	c := r.Ciphers[0]
	if c.Name != "example.com" || c.Login.Username != "u" || c.Login.Password != "p" || c.Notes != "n" ||
		c.Login.Uris[0].Uri != "https://www.example.com/login" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if c := r.Ciphers[1]; c.Name != "--" || c.Login.Uris != nil {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if !importer.IsImplemented("saferpasscsv") {
		t.Fatal("not registered")
	}
}
