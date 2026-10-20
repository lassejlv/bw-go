package msecure

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/msecure-csv-importer.spec.ts.

// expiration is CardView.expiration.
func expiration(c *model.CardView) string {
	year := ""
	if c.ExpYear != "" {
		year = importer.NormalizeExpiryYearFormat(c.ExpYear)
	}
	if c.ExpMonth == "" && year == "" {
		return ""
	}
	exp := "__"
	if c.ExpMonth != "" {
		m := "0" + c.ExpMonth
		exp = m[len(m)-2:]
	}
	if year == "" {
		year = "____"
	}
	return exp + " / " + year
}

func parse(t *testing.T, csv string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, New(importertest.Options()), strings.TrimSpace(csv))
	if !r.Success {
		t.Fatal("success = false")
	}
	return r
}

func TestLegacyCard(t *testing.T) {
	r := parse(t, `aWeirdOldStyleCard|1032,Credit Card,,Security code 1234,Card Number|12|5555 4444 3333 2222,Expiration Date|11|04/0029,Name on Card|9|Obi Wan Kenobi,Security Code|9|444,`)
	if len(r.Ciphers) != 1 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "aWeirdOldStyleCard" || c.Type != model.CipherTypeCard || c.Card.Number != "5555 4444 3333 2222" ||
		expiration(c.Card) != "04 / 2029" || c.Card.Code != "444" || c.Card.CardholderName != "Obi Wan Kenobi" ||
		c.Notes != "Security code 1234" || c.Card.Brand != "" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestCard(t *testing.T) {
	r := parse(t, `myCreditCard|155089404,Credit Card,,,Card Number|12|41111111111111111,Expiration Date|11|05/2026,Security Code|9|123,Name on Card|0|John Doe,PIN|9|1234,Issuing Bank|0|Visa,Phone Number|4|,Billing Address|0|,`)
	if len(r.Ciphers) != 1 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "myCreditCard" || c.Type != model.CipherTypeCard || c.Card.Number != "41111111111111111" ||
		expiration(c.Card) != "05 / 2026" || c.Card.Code != "123" || c.Card.CardholderName != "John Doe" ||
		c.Card.Brand != "Visa" {
		t.Fatal(importertest.Dump(c))
	}
	if c.Notes != "PIN: 1234\nPhone Number: \nBilling Address: " {
		t.Fatalf("notes = %q", c.Notes)
	}
}

func TestLogin(t *testing.T) {
	r := parse(t, `
        Bitwarden|810974637,Login,,,Website|2|bitwarden.com,Username|7|bitwarden user,Password|8|bitpassword,
    `)
	c := r.Ciphers[0]
	if len(r.Ciphers) != 1 || c.Name != "Bitwarden" || c.Type != model.CipherTypeLogin ||
		c.Login.Username != "bitwarden user" || c.Login.Password != "bitpassword" ||
		!strings.Contains(c.Login.Uris[0].Uri, "bitwarden.com") {
		t.Fatal(importertest.Dump(c))
	}
}

func TestLoginWithNotes(t *testing.T) {
	r := parse(t, `Example|188987444,Login,,This is a note |,Website|2|example2.com,Username|7|username || lol,Password|8|this is a password,`)
	c := r.Ciphers[0]
	if len(r.Ciphers) != 1 || c.Name != "Example" || c.Type != model.CipherTypeLogin ||
		c.Login.Username != "username || lol" || c.Login.Password != "this is a password" ||
		!strings.Contains(c.Login.Uris[0].Uri, "example2.com") || c.Notes != "This is a note |" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestLoginWithTag(t *testing.T) {
	r := parse(t, `
        Website with a tag|1401978655,Login,tag holding it,,Website|2|johndoe.com,Username|7|JohnDoeWebsite,Password|8|JohnDoePassword,
    `)
	c := r.Ciphers[0]
	if len(r.Ciphers) != 1 || c.Name != "Website with a tag" || c.Type != model.CipherTypeLogin ||
		c.Login.Username != "JohnDoeWebsite" || c.Login.Password != "JohnDoePassword" ||
		!strings.Contains(c.Login.Uris[0].Uri, "johndoe.com") || c.Notes != "" ||
		!strings.Contains(r.Folders[0].Name, "tag holding it") {
		t.Fatal(importertest.Dump(r))
	}
}

func TestMultipleEntries(t *testing.T) {
	r := parse(t, `myCreditCard|155089404,Credit Card,,,Card Number|12|41111111111111111,Expiration Date|11|05/2026,Security Code|9|123,Name on Card|0|John Doe,PIN|9|1234,Issuing Bank|0|Visa,Phone Number|4|,Billing Address|0|,
Bitwarden|810974637,Login,,,Website|2|bitwarden.com,Username|7|bitwarden user,Password|8|bitpassword,
Example|188987444,Login,,This is a note |,Website|2|example2.com,Username|7|username || lol,Password|8|this is a password,
Website with a tag|1401978655,Login,tag holding it,,Website|2|johndoe.com,Username|7|JohnDoeWebsite,Password|8|JohnDoePassword,`)
	want := []struct {
		name string
		typ  model.CipherType
	}{
		{"myCreditCard", model.CipherTypeCard},
		{"Bitwarden", model.CipherTypeLogin},
		{"Example", model.CipherTypeLogin},
		{"Website with a tag", model.CipherTypeLogin},
	}
	if len(r.Ciphers) != len(want) {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	for k, w := range want {
		if r.Ciphers[k].Name != w.name || r.Ciphers[k].Type != w.typ {
			t.Errorf("cipher %d: %s", k, importertest.Dump(r.Ciphers[k]))
		}
	}
}

func TestSecureNote(t *testing.T) {
	r := parse(t, `Wifi|1,Note,Home,line one,,line two`)
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Name != "Note: Wifi" || c.Notes != "line one\nline two\n" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestCardWithoutExpirationThrows(t *testing.T) {
	if _, err := New(importertest.Options()).Parse(`card|1,Credit Card,,`); err == nil {
		t.Fatal("expected an error (upstream throws on null.split)")
	}
}
