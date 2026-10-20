package encryptr

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow encryptr-csv-importer.ts.

func TestEncryptrCsvImporter(t *testing.T) {
	csv := "Entry Type,Label,Notes,Text,Username,Password,Site URL,Name on card,Card Number,CVV,Expiry\n" +
		"Password,Site,n,extra,u,p,example.com,,,,\n" +
		"Credit Card,Card,,,,,,Joe,4111111111111111,123,08/25\n" +
		"Credit Card,Card2,,,,,,Joe,4111111111111111,123,0x0A/ab\n" +
		"General,Note,,hello,,,,,,,"
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 4 {
		t.Fatal(importertest.Dump(r))
	}
	a := r.Ciphers[0]
	if a.Type != model.CipherTypeLogin || a.Notes != "n\n\nextra" || a.Login.Username != "u" || a.Login.Uris[0].Uri != "http://example.com" {
		t.Fatal(importertest.Dump(a))
	}
	b := r.Ciphers[1]
	if b.Type != model.CipherTypeCard || b.Card.CardholderName != "Joe" || b.Card.Brand != "Visa" || b.Card.Code != "123" ||
		b.Card.ExpMonth != "8" || b.Card.ExpYear != "2025" {
		t.Fatal(importertest.Dump(b))
	}
	c := r.Ciphers[2]
	if c.Card.ExpMonth != "10" || c.Card.ExpYear != "NaN" {
		t.Fatal(importertest.Dump(c))
	}
	d := r.Ciphers[3]
	if d.Type != model.CipherTypeSecureNote || d.Notes != "hello" {
		t.Fatal(importertest.Dump(d))
	}
}
