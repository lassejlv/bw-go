package arc

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/arc-csv-importer.spec.ts (spec-data/arc-csv).

func TestArcCsvImporter(t *testing.T) {
	cases := []struct {
		title, csv, name, user, pass, notes string
		uris                                []string
	}{
		{"should parse password", "name,url,username,password,note\nexample.com,https://example.com/,user@example.com,password123,",
			"example.com", "user@example.com", "password123", "", []string{"https://example.com/"}},
		{"should parse password with note", "name,url,username,password,note\nexample.com,https://example.com/,user@example.com,password123,This is a test note",
			"example.com", "user@example.com", "password123", "This is a test note", []string{"https://example.com/"}},
		{"should strip www. prefix from name", "name,url,username,password,note\nwww.example.com,https://www.example.com/,user@example.com,password123,",
			"example.com", "user@example.com", "password123", "", []string{"https://www.example.com/"}},
		{"should extract name from URL when name is missing", "name,url,username,password,note\n,https://example.com/login,user@example.com,password123,",
			"example.com", "user@example.com", "password123", "", []string{"https://example.com/login"}},
		{"should use -- as name when both name and URL are missing", "name,url,username,password,note\n,,,password123,",
			"--", "", "password123", "", nil},
		{"should preserve subdomain in name", "name,url,username,password,note\nlogin.example.com,https://login.example.com/auth,user@example.com,password123,",
			"login.example.com", "user@example.com", "password123", "", []string{"https://login.example.com/auth"}},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), c.csv)
			if !r.Success || len(r.Ciphers) == 0 {
				t.Fatalf("%+v", r)
			}
			cipher := r.Ciphers[0]
			if cipher.Type != model.CipherTypeLogin || cipher.Name != c.name || cipher.Notes != c.notes ||
				cipher.Login.Username != c.user || cipher.Login.Password != c.pass ||
				!reflect.DeepEqual(importertest.URIs(cipher), c.uris) {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
		})
	}
}
