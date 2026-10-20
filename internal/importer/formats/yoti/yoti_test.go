package yoti

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Upstream has no spec for yoti-csv-importer.ts; these tests follow its logic.

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "Name,URL,User name,Password\nSite,https://a.com,user,pass\n")
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pass" || c.Login.Uris[0].Uri != "https://a.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if !importer.IsImplemented("yoticsv") {
		t.Fatal("not registered")
	}
}
