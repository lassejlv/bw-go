package onepassword

import (
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from onepassword-1pif-importer.spec.ts. testdata/onepassword-1pif/*.txt were extracted
// from spec-data/onepassword-1pif/{testdata,bankaccount,passport,driverslicense}.ts.

func pifOptions(newItemTypes bool) importer.Options {
	o := importertest.Options()
	o.Features.NewItemTypes = newItemTypes
	return o
}

func parsePif(t *testing.T, file string, newItemTypes bool) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, New1Pif(pifOptions(newItemTypes)), importertest.ReadFile(t, "onepassword-1pif/"+file))
	if len(r.Ciphers) != 1 {
		t.Fatalf("%s: %d ciphers", file, len(r.Ciphers))
	}
	return r
}

func iso(d time.Time) string { return d.UTC().Format("2006-01-02T15:04:05.000Z") }

func TestPifParseData(t *testing.T) {
	c := parsePif(t, "TestData.txt", false).Ciphers[0]
	if c.Login.Username != "user@test.net" || c.Login.Password != "myservicepassword" {
		t.Errorf("login %+v", *c.Login)
	}
	if len(c.Login.Uris) != 1 || c.Login.Uris[0].Uri != "https://www.google.com" {
		t.Errorf("uris %s", importertest.Dump(c.Login.Uris))
	}
}

func TestPifConcealedFieldIsHidden(t *testing.T) {
	c := parsePif(t, "TestData.txt", false).Ciphers[0]
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("console password", "console-password-123", model.FieldTypeHidden))
}

func TestPifIdentity(t *testing.T) {
	c := parsePif(t, "IdentityTestData.txt", false).Ciphers[0]
	if c.Name != "Test Identity" {
		t.Errorf("name %q", c.Name)
	}
	id := c.Identity
	want := model.IdentityView{
		FirstName: "Frank", MiddleName: "MD", LastName: "Fritzenberger", Company: "Web Inc.",
		Address1: "Mainstreet 1", Country: "DE", City: "Berlin", PostalCode: "223344",
		Phone: "+49 001 222 333 44", Email: "test@web.de",
	}
	if *id != want {
		t.Errorf("identity %+v\nwant %+v", *id, want)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("sex", "male"),
		importertest.F("birth date", "Mon, 11 Mar 2019 12:01:00 GMT"),
		importertest.F("occupation", "Engineer"),
		importertest.F("department", "IT"),
		importertest.F("job title", "Developer"),
		importertest.F("home", "+49 333 222 111"),
	)
}

func TestPifPasswordHistory(t *testing.T) {
	c := parsePif(t, "TestData.txt", false).Ciphers[0]
	if len(c.PasswordHistory) != 1 {
		t.Fatalf("history %s", importertest.Dump(c.PasswordHistory))
	}
	ph := c.PasswordHistory[0]
	if ph.Password != "old-password" || iso(ph.LastUsedDate) != "2015-11-17T20:17:01.000Z" {
		t.Errorf("%s %s", ph.Password, iso(ph.LastUsedDate))
	}
}

func TestPifPasswordHistoryWindowsOpVault(t *testing.T) {
	c := parsePif(t, "WindowsOpVaultTestData.txt", false).Ciphers[0]
	want := []struct{ pw, date string }{
		{"oldpass6", "2019-03-24T02:27:41.000Z"},
		{"oldpass5", "2019-03-24T02:27:40.000Z"},
		{"oldpass4", "2019-03-24T02:27:39.000Z"},
		{"oldpass3", "2019-03-24T02:27:38.000Z"},
		{"oldpass2", "2019-03-24T02:27:37.000Z"},
	}
	if len(c.PasswordHistory) != len(want) {
		t.Fatalf("history %s", importertest.Dump(c.PasswordHistory))
	}
	for k, w := range want {
		ph := c.PasswordHistory[k]
		if ph.Password != w.pw || iso(ph.LastUsedDate) != w.date {
			t.Errorf("%d: %s %s, want %+v", k, ph.Password, iso(ph.LastUsedDate), w)
		}
	}
}

func TestPifBankAccountFlagOff(t *testing.T) {
	c := parsePif(t, "BankAccountTestData.txt", false).Ciphers[0]
	if c.Name != "Test Bank Account" || c.Type != model.CipherTypeSecureNote || c.Login != nil {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("bank name", "Bank of the Shire"),
		importertest.F("owner", "Bilbo Baggins"),
		importertest.F("account type", "Checking"),
		importertest.F("routing number", "12345"),
		importertest.F("account number", "1234567890"),
		importertest.F("SWIFT", "123"),
		importertest.F("IBAN", "1234"),
		importertest.F("Telephone PIN", "1111"),
		importertest.F("phone", "1112223333"),
		importertest.F("address", "1 Main Street, Bree, Bree-hill, Eriador"),
	)
}

func TestPifBankAccountFlagOn(t *testing.T) {
	c := parsePif(t, "BankAccountTestData.txt", true).Ciphers[0]
	if c.Name != "Test Bank Account" || c.Type != model.CipherTypeBankAccount {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.BankAccountView{
		BankName: "Bank of the Shire", NameOnAccount: "Bilbo Baggins", AccountType: model.BankAccountTypeChecking,
		RoutingNumber: "12345", AccountNumber: "1234567890", SwiftCode: "123", Iban: "1234", Pin: "1111",
		BankContactPhone: "1112223333",
	}
	if *c.BankAccount != want {
		t.Errorf("bank account %+v\nwant %+v", *c.BankAccount, want)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("address", "1 Main Street, Bree, Bree-hill, Eriador"))
}

func TestPifPassportFlagOff(t *testing.T) {
	c := parsePif(t, "PassportTestData.txt", false).Ciphers[0]
	if c.Name != "Test Passport" || c.Type != model.CipherTypeSecureNote {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("type", "Shire Passport"),
		importertest.F("issuing country", "The Shire"),
		importertest.F("number", "1234567890"),
		importertest.F("full name", "Bilbo Baggins"),
		importertest.F("gender", "Male"),
		importertest.F("nationality", "Shire-folk"),
		importertest.F("issuing authority", "The Shire"),
		importertest.F("date of birth", "Fri, 22 Sep 2890 00:00:00 GMT"),
		importertest.F("place of birth", "Bag End, The Shire"),
		importertest.F("issued on", "Mon, 19 Jun 2941 00:00:00 GMT"),
		importertest.F("expiry date", "Sat, 19 Jun 2951 00:00:00 GMT"),
	)
}

func TestPifPassportFlagOn(t *testing.T) {
	c := parsePif(t, "PassportTestData.txt", true).Ciphers[0]
	if c.Name != "Test Passport" || c.Type != model.CipherTypePassport {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.PassportView{
		PassportType: "Shire Passport", IssuingCountry: "The Shire", PassportNumber: "1234567890",
		GivenName: "Bilbo", Surname: "Baggins", Nationality: "Shire-folk", IssuingAuthority: "The Shire",
		DateOfBirth: "2890-09-22", BirthPlace: "Bag End, The Shire", IssueDate: "2941-06-19",
		ExpirationDate: "2951-06-19",
	}
	if *c.Passport != want {
		t.Errorf("passport %+v\nwant %+v", *c.Passport, want)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("gender", "Male"))
}

func TestPifDriversLicenseFlagOff(t *testing.T) {
	c := parsePif(t, "DriversLicenseTestData.txt", false).Ciphers[0]
	if c.Name != "Test Driver's License" || c.Type != model.CipherTypeSecureNote {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("full name", "Bilbo Baggins"),
		importertest.F("address", "Bag End, Bagshot Row, Under-Hill, Hobbiton, Westfarthing, The Shire"),
		importertest.F("date of birth", "Fri, 22 Sep 2890 00:00:00 GMT"),
		importertest.F("gender", "Male"),
		importertest.F("height", "4'0\""),
		importertest.F("number", "1234567890"),
		importertest.F("license class", "D"),
		importertest.F("state", "Westfarthing"),
		importertest.F("country", "The Shire"),
		importertest.F("expiry date", "295106"),
	)
}

func TestPifDriversLicenseFlagOn(t *testing.T) {
	c := parsePif(t, "DriversLicenseTestData.txt", true).Ciphers[0]
	if c.Name != "Test Driver's License" || c.Type != model.CipherTypeDriversLicense {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.DriversLicenseView{
		FirstName: "Bilbo", LastName: "Baggins", DateOfBirth: "2890-09-22", LicenseNumber: "1234567890",
		LicenseClass: "D", IssuingState: "Westfarthing", IssuingCountry: "The Shire", ExpirationDate: "2951-06-30",
	}
	if *c.DriversLicense != want {
		t.Errorf("drivers license %+v\nwant %+v", *c.DriversLicense, want)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("address", "Bag End, Bagshot Row, Under-Hill, Hobbiton, Westfarthing, The Shire"),
		importertest.F("gender", "Male"),
		importertest.F("height", "4'0\""),
	)
}

func TestPifInvalidJSONLine(t *testing.T) {
	_, err := New1Pif(pifOptions(false)).Parse("{not json}\n")
	if !importer.IsSyntaxError(err) {
		t.Fatalf("got %v, want a syntax error", err)
	}
}

func TestPifTrashedAndSeparatorLines(t *testing.T) {
	data := "***5642bee8-a5ff-11dc-8314-0800200c9a66***\n" +
		`{"title":"gone","trashed":true,"typeName":"webforms.WebForm"}` + "\n" +
		`{"title":"note","typeName":"securenotes.SecureNote","secureContents":{"notesPlain":"a\r\nb"}}` + "\n"
	r := importertest.Parse(t, New1Pif(pifOptions(false)), data)
	if len(r.Ciphers) != 1 || r.Ciphers[0].Notes != "a\nb\n" || r.Ciphers[0].Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
}
