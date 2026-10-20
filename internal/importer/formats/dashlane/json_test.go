package dashlane

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for dashlane-json-importer.ts; these are sanity checks of the port.

const dashlaneJSON = `{
  "ADDRESS": [{"addressName": "Home", "addressFull": "1 Main St", "city": "Town", "state": "ST",
               "zipcode": "12345", "country": "us"}],
  "AUTHENTIFIANT": [
    {"title": "Example", "login": "jdoe", "email": "j@example.com", "password": "pw",
     "domain": "example.com", "note": "a note"},
    {"title": "OnlyEmail", "email": "e@example.com", "password": "pw2"},
    {"title": "Empty"}
  ],
  "BANKSTATEMENT": [{"BankAccountName": "Checking", "BankAccountBIC": "BIC1", "Number": 42}],
  "IDCARD": [{"Fullname": "John Doe", "Number": "ID1"}],
  "PAYMENTMEANS_CREDITCARD": [{"bank": "MyBank", "cardNumber": "4111111111111111", "owner": "John Doe"}],
  "IDENTITY": [{"fullName": "John Q Doe", "pseudo": "jqd"}],
  "EMAIL": [{"x": "ignored"}],
  "OTHER": [{"a": "b", "flag": true, "list": [1, null, "x"]}]
}`

func TestJsonSanity(t *testing.T) {
	r := importertest.Parse(t, NewJson(importertest.Options()), dashlaneJSON)
	if !r.Success {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if len(r.Ciphers) != 9 {
		t.Fatalf("got %d ciphers: %s", len(r.Ciphers), importertest.Dump(r.Ciphers))
	}

	addr := r.Ciphers[0]
	eq(t, "addr type", addr.Type, model.CipherTypeIdentity)
	eq(t, "addr name", addr.Name, "Home")
	eq(t, "addr country", addr.Identity.Country, "US")
	eq(t, "addr postal", addr.Identity.PostalCode, "12345")

	login := r.Ciphers[1]
	eq(t, "login name", login.Name, "Example")
	eq(t, "login username", login.Login.Username, "jdoe")
	eq(t, "login notes", login.Notes, "Email: j@example.com\na note")
	eq(t, "login uri", login.Login.Uri(), "http://example.com")

	eq(t, "email username", r.Ciphers[2].Login.Username, "e@example.com")
	eq(t, "empty type", r.Ciphers[3].Type, model.CipherTypeSecureNote)

	bank := r.Ciphers[4]
	eq(t, "bank name", bank.Name, "Checking")
	importertest.AssertCustomFieldsStructure(t, bank.Fields, fields("BankAccountBIC", "BIC1", "Number", "42")...)

	eq(t, "idcard name", r.Ciphers[5].Name, "John Doe")

	card := r.Ciphers[6]
	eq(t, "card name", card.Name, "MyBank - Visa")
	eq(t, "card holder", card.Card.CardholderName, "John Doe")

	id := r.Ciphers[7]
	eq(t, "identity first", id.Identity.FirstName, "John")
	eq(t, "identity middle", id.Identity.MiddleName, "Q")
	eq(t, "identity last", id.Identity.LastName, "Doe")
	eq(t, "identity username", id.Identity.Username, "jqd")

	other := r.Ciphers[8]
	eq(t, "other name", other.Name, "Generic Note")
	importertest.AssertCustomFieldsStructure(t, other.Fields, fields("a", "b", "flag", "true", "list", "1,,x")...)
}

func TestJsonEmptyAndInvalid(t *testing.T) {
	r := importertest.Parse(t, NewJson(importertest.Options()), "[]")
	if r.Success {
		t.Error("empty array should fail")
	}
	r = importertest.Parse(t, NewJson(importertest.Options()), "null")
	if r.Success {
		t.Error("null should fail")
	}
	if _, err := NewJson(importertest.Options()).Parse("{"); !importer.IsSyntaxError(err) {
		t.Errorf("want syntax error, got %v", err)
	}
	if _, err := NewJson(importertest.Options()).Parse(`{"AUTHENTIFIANT": {}}`); err == nil {
		t.Error("want a TypeError for a non-array section")
	}
}
