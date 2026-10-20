package securesafe

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Ported from libs/importer/src/importers/securesafe-csv-importer.spec.ts (spec-data/securesafe-csv).

func TestSecureSafeCsvImporter(t *testing.T) {
	cases := []struct{ title, file string }{
		{"should parse upper case url", "data_upperUrl.txt"},
		{"should parse lower case url", "data_lowerUrl.txt"},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, c.file))
			if len(r.Ciphers) == 0 {
				t.Fatal("no ciphers")
			}
			cipher := r.Ciphers[0]
			if cipher.Name != "Gmail" || cipher.Login.Username != "test@gmail.com" || cipher.Login.Password != "test" ||
				len(cipher.Login.Uris) != 1 || cipher.Login.Uris[0].Uri != "https://gmail.com" {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
		})
	}
}
