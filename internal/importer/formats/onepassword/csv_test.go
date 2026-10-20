package onepassword

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from onepassword-mac-csv-importer.spec.ts and onepassword-win-csv-importer.spec.ts.
// testdata/onepassword-csv/* were extracted from spec-data/onepassword-csv/*.csv.ts.

func readCsv(t *testing.T, name string) string {
	return importertest.ReadFile(t, "onepassword-csv/"+name)
}

func expectIdentityCommon(t *testing.T, c *model.CipherView) {
	t.Helper()
	if c.Type != model.CipherTypeIdentity {
		t.Fatalf("type %d, want identity: %s", c.Type, importertest.Dump(c))
	}
	id := c.Identity
	want := model.IdentityView{
		FirstName: "first name", MiddleName: "mi", LastName: "last name", Username: "userNam3",
		Company: "bitwarden", Phone: "8005555555", Email: "email@bitwarden.com",
	}
	got := model.IdentityView{
		FirstName: id.FirstName, MiddleName: id.MiddleName, LastName: id.LastName, Username: id.Username,
		Company: id.Company, Phone: id.Phone, Email: id.Email,
	}
	if got != want {
		t.Errorf("identity %+v, want %+v", got, want)
	}
}

func expectCard(t *testing.T, c *model.CipherView, expYear string) {
	t.Helper()
	if c.Type != model.CipherTypeCard {
		t.Fatalf("type %d, want card: %s", c.Type, importertest.Dump(c))
	}
	card := c.Card
	if card.Number != "4111111111111111" || card.Code != "111" || card.CardholderName != "test" ||
		card.ExpMonth != "1" || card.ExpYear != expYear {
		t.Errorf("card %+v", *card)
	}
}

func expectMacIdentity(t *testing.T, c *model.CipherView) {
	t.Helper()
	expectIdentityCommon(t, c)
	if !strings.Contains(c.Notes, "address\ncity state zip\nUnited States") {
		t.Errorf("notes %q", c.Notes)
	}
}

func expectWinIdentity(t *testing.T, c *model.CipherView) {
	t.Helper()
	expectIdentityCommon(t, c)
	found := false
	for _, f := range c.Fields {
		if f.Type == model.FieldTypeText && f.Name == "address" && f.Value == "address city state zip us" {
			found = true
		}
	}
	if !found {
		t.Errorf("address field missing: %s", importertest.Dump(c.Fields))
	}
}

func parseCsvWith(t *testing.T, ctor importer.Constructor, file string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, ctor(importertest.Options()), readCsv(t, file))
	if !r.Success {
		t.Fatalf("%s: not successful", file)
	}
	return r
}

func TestMacCsvIdentity(t *testing.T) {
	r := parseCsvWith(t, NewMacCsv, "identity.mac.csv")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectMacIdentity(t, r.Ciphers[0])
}

func TestMacCsvCreditCard(t *testing.T) {
	r := parseCsvWith(t, NewMacCsv, "credit-card.mac.csv")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectCard(t, r.Ciphers[0], "2030")
}

func TestMacCsvMultipleRecordTypes(t *testing.T) {
	r := parseCsvWith(t, NewMacCsv, "multiple-items.mac.csv")
	if len(r.Ciphers) != 4 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectMacIdentity(t, r.Ciphers[1])
	expectCard(t, r.Ciphers[2], "2030")
}

func TestWinCsvIdentity(t *testing.T) {
	r := parseCsvWith(t, NewWinCsv, "identity.windows.csv")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectWinIdentity(t, r.Ciphers[0])
}

func TestWinCsvCreditCard(t *testing.T) {
	r := parseCsvWith(t, NewWinCsv, "credit-card.windows.csv")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectCard(t, r.Ciphers[0], "1970")
}

func TestWinCsvMultipleRecordTypes(t *testing.T) {
	r := parseCsvWith(t, NewWinCsv, "multiple-items.windows.csv")
	if len(r.Ciphers) != 4 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	expectWinIdentity(t, r.Ciphers[1])
	expectCard(t, r.Ciphers[2], "1970")
}

func TestCsvRegistered(t *testing.T) {
	for _, id := range []string{"1passwordwincsv", "1passwordmaccsv", "1password1pif", "1password1pux"} {
		if !importer.IsImplemented(id) {
			t.Errorf("%s is not registered", id)
		}
	}
}

func TestCsvCreatedDate(t *testing.T) {
	data := "title,created date,modified date\nItem,1458090000,abc\n"
	r := importertest.Parse(t, NewMacCsv(importertest.Options()), data)
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[0].Fields,
		importertest.F("1Password created date", "Wed, 16 Mar 2016 01:00:00 GMT"),
		importertest.F("1Password modified date", "Invalid Date"),
	)
}

func TestWinCsvMalformedExpiryThrows(t *testing.T) {
	data := "title,1: number,2: expiry date\nCard,4111111111111111,01/2030\n"
	if _, err := NewWinCsv(importertest.Options()).Parse(data); err == nil {
		t.Fatal("expected a TypeError like upstream (expSplit[2] is undefined)")
	}
}
