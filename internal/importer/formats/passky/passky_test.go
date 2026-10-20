package passky

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Ported from libs/importer/src/importers/passky/passky-json-importer.spec.ts (spec-data/passky-json).

func TestEncrypted(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, "passky-encrypted/testData.json"))
	if r.Success || r.ErrorMessage != "Unable to import an encrypted passky backup." {
		t.Fatalf("%+v", r)
	}
}

func TestLoginData(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, "passky-unencrypted/testData.json"))
	c := r.Ciphers[0]
	if c.Name != "https://bitwarden.com/" || c.Login.Username != "testUser" || c.Login.Password != "testPassword" ||
		len(c.Login.Uris) != 1 || c.Login.Uris[0].Uri != "https://bitwarden.com/" || c.Notes != "my notes" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestLooseEncryptedFlagAndErrors(t *testing.T) {
	for _, enc := range []string{`1`, `"1"`, `" 1.0 "`, `[1]`, `"0x1"`} {
		r := importertest.Parse(t, New(importertest.Options()), `{"encrypted":`+enc+`,"passwords":[{}]}`)
		if r.Success {
			t.Errorf("%s: expected encrypted", enc)
		}
	}
	for _, enc := range []string{`"true"`, `2`, `{}`, `null`, `"0x1p0"`} {
		r := importertest.Parse(t, New(importertest.Options()), `{"encrypted":`+enc+`,"passwords":[{"website":"a.com"}]}`)
		if !r.Success {
			t.Errorf("%s: expected success", enc)
		}
	}
	if _, err := New(importertest.Options()).Parse(`{"passwords":[null]}`); err == nil ||
		!strings.Contains(err.Error(), "Cannot read properties of null") {
		t.Fatal(err)
	}
	if _, err := New(importertest.Options()).Parse(`{`); !importer.IsSyntaxError(err) {
		t.Fatal(err)
	}
	r := importertest.Parse(t, New(importertest.Options()), `{"passwords":[]}`)
	if r.Success {
		t.Fatal("empty passwords must fail")
	}
}
