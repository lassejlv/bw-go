package safari

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/safari-csv-importer.spec.ts (spec-data/safari-csv).

func TestSafariCsvImporter(t *testing.T) {
	cases := []struct {
		title, file, notes, totp string
	}{
		{"should parse URLs in new CSV format", "simple-password-data/data.txt", "Example note\nMore notes on new line", "otpauth://totp/test?secret=examplesecret"},
		{"should parse URLs in old CSV format", "old-simple-password-data/data.txt", "", ""},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, c.file))
			if len(r.Ciphers) == 0 {
				t.Fatal("no ciphers")
			}
			cipher := r.Ciphers[0]
			if cipher.Type != model.CipherTypeLogin || cipher.Name != "example.com (example_user)" ||
				cipher.Login.Username != "example_user" || cipher.Login.Password != "example_p@ssword" ||
				len(cipher.Login.Uris) != 1 || cipher.Login.Uris[0].Uri != "https://example.com" ||
				cipher.Login.Totp != c.totp || cipher.Notes != c.notes {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
		})
	}
}

func TestUrlColumnPrecedence(t *testing.T) {
	// value.Url ?? value.URL: an empty Url column still wins over URL.
	r := importertest.Parse(t, New(importertest.Options()), "Title,Url,URL\nx,,https://a.com\n")
	if r.Ciphers[0].Login.Uris != nil {
		t.Fatalf("%s", importertest.Dump(r.Ciphers[0]))
	}
}
