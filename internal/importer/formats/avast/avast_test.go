package avast

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no specs for the Avast importers; these tests follow their logic.

func TestCsv(t *testing.T) {
	r := importertest.Parse(t, NewCsv(importertest.Options()), "name,web,login,password\nSite,example.com,user,pass\n")
	c := r.Ciphers[0]
	if c.Name != "Site" || c.Login.Username != "user" || c.Login.Password != "pass" || c.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestJson(t *testing.T) {
	data := `{"logins":[{"custName":"Site","note":"n","url":"example.com","pwd":"p","loginName":"u"},
	  {"custName":5,"pwd":12345}],
	  "notes":[{"label":"Note","text":"body"}],
	  "cards":[{"custName":"Card","holderName":"Jane","cardNumber":"4111111111111111","cvv":"123",
	    "expirationDate":{"month":3,"year":"2030"}}]}`
	r := importertest.Parse(t, NewJson(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 4 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	l := r.Ciphers[0]
	if l.Name != "Site" || l.Notes != "n" || l.Login.Username != "u" || l.Login.Password != "p" || l.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(l))
	}
	// Non-string values are "null or whitespace" for getValueOrDefault.
	if l2 := r.Ciphers[1]; l2.Name != "--" || l2.Login.Password != "" {
		t.Fatalf("%s", importertest.Dump(l2))
	}
	if n := r.Ciphers[2]; n.Type != model.CipherTypeSecureNote || n.Name != "Note" || n.Notes != "body" || n.Login != nil {
		t.Fatalf("%s", importertest.Dump(n))
	}
	c := r.Ciphers[3]
	if c.Type != model.CipherTypeCard || c.Card.CardholderName != "Jane" || c.Card.Brand != "Visa" || c.Card.Code != "123" ||
		c.Card.ExpMonth != "3" || c.Card.ExpYear != "2030" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestJsonErrors(t *testing.T) {
	if r := importertest.Parse(t, NewJson(importertest.Options()), "null"); r.Success {
		t.Fatal("null must fail")
	}
	if _, err := NewJson(importertest.Options()).Parse("{"); !importer.IsSyntaxError(err) {
		t.Fatal(err)
	}
	if _, err := NewJson(importertest.Options()).Parse(`{"logins":{}}`); err == nil || !strings.Contains(err.Error(), "forEach") {
		t.Fatal(err)
	}
	if _, err := NewJson(importertest.Options()).Parse(`{"logins":[null]}`); err == nil {
		t.Fatal("expected a TypeError")
	}
}

func TestRegistered(t *testing.T) {
	for _, id := range []string{"avastcsv", "avastjson"} {
		if !importer.IsImplemented(id) {
			t.Errorf("%s not registered", id)
		}
	}
}
