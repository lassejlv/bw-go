package upm

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Upstream has no spec for upm-csv-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "Site,user,pass,example.com,notes\nbad,row\n")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pass" || c.Notes != "notes" ||
		c.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if !importer.IsImplemented("upmcsv") {
		t.Fatal("not registered")
	}
}
