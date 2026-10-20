package enpass

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/enpass/enpass-csv-importer.spec.ts.

func parseCsvFixture(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, NewCsv(importertest.Options()), importertest.ReadFile(t, name))
	if !r.Success {
		t.Fatalf("success = false: %s", importertest.Dump(r))
	}
	return r
}

func wantCiphers(t *testing.T, r *model.ImportResult, n int) {
	t.Helper()
	if len(r.Ciphers) != n {
		t.Fatalf("got %d ciphers, want %d: %s", len(r.Ciphers), n, importertest.Dump(r.Ciphers))
	}
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestCsvRealExportLabels(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login.csv")
	wantCiphers(t, r, 2)
	booking, consumer := r.Ciphers[0], r.Ciphers[1]

	eq(t, "type", booking.Type, model.CipherTypeLogin)
	eq(t, "name", booking.Name, "Booking")
	eq(t, "username", booking.Login.Username, "rwilsoncloud@gmail.com")
	eq(t, "password", booking.Login.Password, "MyPassWordHere")
	if u := importertest.URIs(booking); len(u) != 2 || u[0] != "https://account.booking.com" || u[1] != "https://account.booking.com/sign-in" {
		t.Errorf("uris = %v", u)
	}
	eq(t, "notes", booking.Notes, "")

	eq(t, "type", consumer.Type, model.CipherTypeLogin)
	eq(t, "name", consumer.Name, "Consumerreports")
	eq(t, "username", consumer.Login.Username, "rwilsoncloud@gmail.com")
	eq(t, "password", consumer.Login.Password, "MyPassWordHere2")
	if u := importertest.URIs(consumer); len(u) != 2 || u[0] != "https://secure.consumerreports.org" ||
		u[1] != "https://secure.consumerreports.org/ec/account/change-password" {
		t.Errorf("uris = %v", u)
	}
	importertest.AssertCustomFieldsExist(t, consumer.Fields, importertest.F("E-mail", "rwilsoncloud@gmail.com", model.FieldTypeText))
}

func TestCsvMultipleQuotedRows(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-quoted.csv")
	wantCiphers(t, r, 4)
	want := []struct{ name, user, pass, uri string }{
		{"Amazon", "Food", "Adasceafazxc", "https://www.amazon.com"},
		{"Google", "Test", "Testingas", "https://accounts.google.com/"},
		{"LinkedIn", "aksldkl", "amlkzmcklmxklzmclkzmxklcmzlkxmclkm", "https://www.linkedin.com/"},
		{"Wikipedia", "aslmdlkads", "amc,.zxla;skd;lkpokpokwpoqkeopkalsd", "https://en.wikipedia.org/w/index.php?title=Special:UserLogin&returnto=Main+Page"},
	}
	for i, w := range want {
		c := r.Ciphers[i]
		eq(t, "name", c.Name, w.name)
		eq(t, "username", c.Login.Username, w.user)
		eq(t, "password", c.Login.Password, w.pass)
		eq(t, "uri", c.Login.Uri(), w.uri)
	}
}

func TestCsvNoteOnlyRow(t *testing.T) {
	r := parseCsvFixture(t, "enpass.secure-note.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeSecureNote)
	eq(t, "name", c.Name, "MyNote")
	eq(t, "notes", c.Notes, "Some note text")
}

func TestCsvTrailingNote(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-trailing-note.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "name", c.Name, "SomeSite")
	eq(t, "username", c.Login.Username, "someuser")
	eq(t, "password", c.Login.Password, "somepass")
	eq(t, "notes", c.Notes, "Some trailing note text")
}

func TestCsvLoginWithoutUsername(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-no-username.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "name", c.Name, "Router")
	eq(t, "password", c.Login.Password, "secret")
	eq(t, "uri", c.Login.Uri(), "https://router.local")
}

func TestCsvLoginStarredPasswordOnly(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-starred-only.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "name", c.Name, "Router")
	eq(t, "password", c.Login.Password, "secret")
}

func TestCsvCard(t *testing.T) {
	r := parseCsvFixture(t, "enpass.card.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeCard)
	eq(t, "name", c.Name, "Visa")
	eq(t, "card", *c.Card, model.CardView{
		CardholderName: "John Doe", Number: "4111111111111111", Brand: "Visa", Code: "123", ExpMonth: "1", ExpYear: "2030",
	})
}

func TestCsvSensitiveCustomField(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-sensitive-custom-field.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	importertest.AssertCustomFieldsExist(t, c.Fields, importertest.F("Security answer", "42", model.FieldTypeHidden))
}

func TestCsvOneTimeCode(t *testing.T) {
	r := parseCsvFixture(t, "enpass.login-one-time-code.csv")
	wantCiphers(t, r, 1)
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "totp", c.Login.Totp, "TOTP_SEED_VALUE")
}
