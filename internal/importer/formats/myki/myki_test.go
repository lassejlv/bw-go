package myki

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/myki-csv-importer.spec.ts (spec-data/myki-csv).

// fullName is IdentityView.fullName.
func fullName(id *model.IdentityView) string {
	name := ""
	for _, p := range []string{id.Title, id.FirstName, id.MiddleName} {
		if !importer.IsNullOrWhitespace(p) {
			name += p + " "
		}
	}
	if !importer.IsNullOrWhitespace(id.LastName) {
		name += id.LastName
	}
	return importer.JSTrim(name)
}

func parse(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, name+".txt"))
	if !r.Success {
		t.Fatal("success = false")
	}
	return r
}

func TestUserAccount(t *testing.T) {
	c := parse(t, "userAccountData").Ciphers[0]
	if c.Name != "PasswordNickname" || c.Login.Username != "user.name@email.com" || c.Login.Password != "abc123" ||
		c.Login.Totp != "someTOTPSeed" || !reflect.DeepEqual(importertest.URIs(c), []string{"http://www.google.com"}) ||
		c.Notes != "This is the additional information text." {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("status", "active"), importertest.F("tags", "someTag"))
}

func TestUserTwoFa(t *testing.T) {
	c := parse(t, "userTwoFaData").Ciphers[0]
	if c.Name != "2FA nickname" || c.Login.Username != "" || c.Login.Password != "" || c.Login.Totp != "someTOTPSeed" ||
		c.Notes != "Additional information field content." {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("status", "active"), importertest.F("tags", "someTag"))
}

func TestCreditCard(t *testing.T) {
	r := parse(t, "userCreditCardData")
	if len(r.Ciphers) != 1 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeCard || c.Name != "Visa test card" || c.Card.Brand != "Visa" ||
		c.Card.CardholderName != "Joe User" || c.Card.Number != "4111111111111111" || c.Card.Code != "222" ||
		c.Card.ExpMonth != "04" || c.Card.ExpYear != "24" || c.Notes != "This is the additional information field" {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("status", "active"), importertest.F("tags", "someTag"))
}

func TestIdentity(t *testing.T) {
	c := parse(t, "userIdentityData").Ciphers[0]
	id := c.Identity
	if c.Type != model.CipherTypeIdentity || c.Name != "Joe User's nickname" || fullName(id) != "Mr Joe M User" ||
		id.Title != "Mr" || id.FirstName != "Joe" || id.MiddleName != "M" || id.LastName != "User" ||
		id.Email != "joe.user@email.com" || id.Address1 != "1 Example House" || id.Address2 != "Suite 300" ||
		id.City != "Portland" || id.PostalCode != "04101" || id.Country != "United States" {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("status", "active"), importertest.F("tags", "someTag"),
		importertest.F("gender", "Male"), importertest.F("number", "2223334444"))
}

func TestSecureNote(t *testing.T) {
	r := parse(t, "userNoteData")
	if len(r.Ciphers) != 1 {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Name != "The title of a secure note" ||
		c.Notes != "The content of a secure note. Lorem ipsum, etc." {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("status", "active"))
}

func TestIdCards(t *testing.T) {
	r := parse(t, "userIdCardData")
	type exp struct {
		name, notes, field, number, idType, issued, expires string
	}
	want := []exp{
		{"Joe User's nickname", "Additional information", "license", "123456", "Driver's License", "02/02/2022", "02/02/2024"},
		{"Passport ID card", "Additional information field", "passport", "1234567", "Passport", "03/07/2022", "03/07/2028"},
		{"Social Security ID card", "Additional information field text", "ssn", "123455678", "Social Security", "03/07/2022", "03/07/2028"},
		{"ID card type ID card", "Additional Information field text", "license", "1234566", "ID Card", "03/07/2022", "03/07/2028"},
		{"Tax number ID card", "Additional information text field", "license", "12345678", "Tax Number", "03/07/2022", "03/07/2028"},
		{"Bank account ID card", "Additional text information here", "license", "12344556677", "Bank Account", "03/07/2022", "03/07/2028"},
		{"Insurance card ID card", "Additional information text goes here", "license", "123456677", "Insurance Card", "03/07/2022", "03/07/2022"},
		{"Health card Id card", "More info", "license", "1234670", "Health Card", "03/07/2022", "03/07/2028"},
		{"Membership ID card", "Add'l info", "license", "12345709", "Membership", "03/07/2022", "03/07/2028"},
		{"Database ID card", "Addin't info", "license", "12345089u", "Database", "03/07/2022", "03/07/2028"},
		{"Outdoor license ID card", "Additional info", "license", "123890090", "Outdoor License", "03/07/2022", "03/07/2028"},
		{"Reward program Id card", "1234890", "license", "12345890b", "Reward Program", "03/07/2022", "03/07/2028"},
		{"Software license ID card", "It seems like the fields don't change, which makes it pretty useless that they have so many ID card types.", "license", "1234567c", "Software License", "03/07/2022", "03/07/2028"},
		{"Tour visa ID card", "Additional Information text", "license", "123456lkhj", "Tour Visa", "03/07/2022", "03/07/2028"},
	}
	if len(r.Ciphers) != len(want) {
		t.Fatalf("ciphers = %d", len(r.Ciphers))
	}
	for k, w := range want {
		c := r.Ciphers[k]
		id := c.Identity
		var number string
		switch w.field {
		case "passport":
			number = id.PassportNumber
		case "ssn":
			number = id.Ssn
		default:
			number = id.LicenseNumber
		}
		if c.Type != model.CipherTypeIdentity || c.Name != w.name || c.Notes != w.notes ||
			fullName(id) != "Joe M User" || id.FirstName != "Joe" || id.MiddleName != "M" || id.LastName != "User" ||
			number != w.number || id.Country != "United States" {
			t.Errorf("%s: %s", w.name, importertest.Dump(c))
		}
		importertest.AssertCustomFieldsStructure(t, c.Fields,
			importertest.F("status", "active"), importertest.F("tags", "someTag"),
			importertest.F("idType", w.idType), importertest.F("idIssuanceDate", w.issued),
			importertest.F("idExpirationDate", w.expires))
	}
}
