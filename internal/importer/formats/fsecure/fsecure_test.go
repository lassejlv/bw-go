package fsecure

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/fsecure/fsecure-fsk-importer.spec.ts. testdata/*.json
// were extracted from fsecure/fsk-test-data.ts.

func parse(t *testing.T, file string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, file))
}

func TestLogin(t *testing.T) {
	r := parse(t, "LoginTestEntry.json")
	c := r.Ciphers[0]
	if c.Name != "example.com" || !c.Favorite || c.Notes != "some note for example.com" || c.Type != model.CipherTypeLogin ||
		c.Login.Username != "jdoe" || c.Login.Password != "somePassword" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if u := importertest.URIs(c); len(u) != 1 || u[0] != "https://www.example.com" {
		t.Fatalf("uris %v", u)
	}
}

func TestCreditCard(t *testing.T) {
	r := parse(t, "CreditCardTestEntry.json")
	c := r.Ciphers[0]
	if c.Name != "My credit card" || c.Favorite || c.Notes != "some notes to my card" || c.Type != model.CipherTypeCard ||
		c.Card.CardholderName != "John Doe" || c.Card.Number != "4242424242424242" || c.Card.Code != "123" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Expiration", "22.10.2026"),
		importertest.F("PIN", "1234"),
	)
}

func TestInvalid(t *testing.T) {
	for _, in := range []string{"null", "{}", `{"data":null}`, "[]"} {
		if r := importertest.Parse(t, New(importertest.Options()), in); r.Success {
			t.Errorf("%s: expected failure", in)
		}
	}
	if _, err := New(importertest.Options()).Parse("{"); err == nil {
		t.Error("expected syntax error")
	}
}

func TestObjectOrder(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), `{"data":{"b":{"type":1,"service":"B","username":"u"},"2":{"type":1,"service":"Two","username":"u"},"a":{"type":3}}}`)
	if len(r.Ciphers) != 2 || r.Ciphers[0].Name != "Two" || r.Ciphers[1].Name != "B" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
}
