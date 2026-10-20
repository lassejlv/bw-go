package onepassword

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
	"github.com/lassejlv/bw-go/internal/sshkey"
)

// Ported from onepassword-1pux-importer.spec.ts. testdata/onepassword-1pux/*.json were
// extracted from spec-data/onepassword-1pux/*.ts.

func puxData(t *testing.T, name string) string {
	return importertest.ReadFile(t, "onepassword-1pux/"+name+".json")
}

func puxOptions(newItemTypes bool) importer.Options {
	o := importertest.Options()
	o.Features.NewItemTypes = newItemTypes
	return o
}

func parsePux(t *testing.T, data string, newItemTypes bool) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New1Pux(puxOptions(newItemTypes)), data)
}

func onlyCipher(t *testing.T, r *model.ImportResult) *model.CipherView {
	t.Helper()
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers: %s", len(r.Ciphers), importertest.Dump(r.Ciphers))
	}
	return r.Ciphers[0]
}

var f = importertest.F

// mutateJSON decodes data, applies fn and re-encodes it (like the spec's
// JSON.parse(JSON.stringify(...)) clones).
func mutateJSON(t *testing.T, data string, fn func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func firstItems(m map[string]any) []any {
	vault := m["accounts"].([]any)[0].(map[string]any)["vaults"].([]any)[0].(map[string]any)
	return vault["items"].([]any)
}

func setFirstItems(m map[string]any, items []any) {
	vault := m["accounts"].([]any)[0].(map[string]any)["vaults"].([]any)[0].(map[string]any)
	vault["items"] = items
}

func withSSHHook(t *testing.T, fn func(key, pw string) (*model.SshKeyView, error)) {
	saved := importer.ImportSSHKey
	importer.ImportSSHKey = fn
	t.Cleanup(func() { importer.ImportSSHKey = saved })
}

func TestPuxArchivedItems(t *testing.T) {
	data := mutateJSON(t, puxData(t, "LoginData"), func(m map[string]any) {
		firstItems(m)[0].(map[string]any)["state"] = "archived"
	})
	c := onlyCipher(t, parsePux(t, data, false))
	if c.ArchivedDate == nil {
		t.Fatal("archived item should have an archivedDate")
	}
}

func TestPuxActiveItemsUnarchived(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "LoginData"), false))
	if c.ArchivedDate != nil {
		t.Fatal("active item should not be archived")
	}
}

func TestPuxLoginData(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "LoginData"), false))
	if c.Type != model.CipherTypeLogin || c.Name != "eToro" {
		t.Errorf("%d %q", c.Type, c.Name)
	}
	l := c.Login
	if l.Username != "username123123123@gmail.com" || l.Password != "password!" || len(l.Uris) != 1 ||
		l.Uri() != "https://www.fakesite.com" || l.Totp != "otpseed777" {
		t.Errorf("login %s", importertest.Dump(l))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("terms", "false"), f("policies", "true"), f("Create an account", "username123123"))
}

func TestPuxNotes(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "OnePuxExampleFile"), false))
	if c.Notes != "This is a note. *bold*! _italic_!" {
		t.Errorf("notes %q", c.Notes)
	}
}

func TestPuxFavorite(t *testing.T) {
	if c := onlyCipher(t, parsePux(t, puxData(t, "OnePuxExampleFile"), false)); !c.Favorite {
		t.Error("favIndex 1 should set favorite")
	}
}

func TestPuxCustomBooleanFields(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "LoginData"), false))
	importertest.AssertCustomFieldsExist(t, c.Fields,
		f("terms", "false", model.FieldTypeBoolean), f("policies", "true", model.FieldTypeBoolean))
	if c.Fields[0].Name != "terms" || c.Fields[1].Name != "policies" {
		t.Errorf("%s", importertest.Dump(c.Fields))
	}
}

func TestPuxEmailFieldsAsCustomFields(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "EmailFieldData"), false))
	if len(c.Fields) < 2 {
		t.Fatalf("%s", importertest.Dump(c.Fields))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields[:2],
		f("registered email", "kriddler@nullvalue.test", model.FieldTypeText),
		f("provider", "myEmailProvider", model.FieldTypeText))
}

func TestPuxConcealedFieldIsHidden(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "OnePuxExampleFile"), false))
	importertest.AssertCustomFieldsStructure(t, c.Fields, f("PIN", "12345", model.FieldTypeHidden))
}

func TestPuxPasswordHistory(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "OnePuxExampleFile"), false))
	if len(c.PasswordHistory) != 1 {
		t.Fatalf("%s", importertest.Dump(c.PasswordHistory))
	}
	ph := c.PasswordHistory[0]
	if ph.Password != "12345password" || iso(ph.LastUsedDate) != "2016-03-18T17:32:35.000Z" {
		t.Errorf("%s %s", ph.Password, iso(ph.LastUsedDate))
	}
}

func TestPuxCreditCard(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "CreditCardData"), false))
	if c.Name != "Parent's Credit Card" || c.Notes != "My parents' credit card." {
		t.Errorf("%q %q", c.Name, c.Notes)
	}
	want := model.CardView{CardholderName: "Fred Engels", Number: "6011111111111117", Code: "1312",
		Brand: "Discover", ExpMonth: "12", ExpYear: "2099"}
	if *c.Card != want {
		t.Errorf("card %+v", *c.Card)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("valid from", "200101"),
		f("", "card"),
		// Section "Contact Information"
		f("issuing bank", "Some bank"),
		f("phone (local)", "123456"),
		f("phone (toll free)", "0800123456"),
		f("phone (intl)", "+49123456"),
		f("website", "somebank.com"),
		// Section "Additional Details"
		f("PIN", "1234"),
		f("credit limit", "$1312"),
		f("cash withdrawal limit", "$500"),
		f("interest rate", "1%"),
		f("issue number", "123456"),
	)
}

func TestPuxIdentity(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "IdentityData"), false))
	if c.Name != "George Engels" {
		t.Errorf("name %q", c.Name)
	}
	want := model.IdentityView{FirstName: "George", MiddleName: "S", LastName: "Engels", Company: "Acme Inc.",
		Address1: "1312 Main St.", Country: "US", State: "California", City: "Atlantis", PostalCode: "90210",
		Phone: "4565555555", Email: "gengels@nullvalue.test", Username: "gengels"}
	if *c.Identity != want {
		t.Errorf("identity %+v\nwant %+v", *c.Identity, want)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("sex", "male"),
		f("birth date", "Thu, 01 Jan 1981 12:01:00 GMT"),
		f("occupation", "Steel Worker"),
		f("department", "QA"),
		f("job title", "Quality Assurance Manager"),
		f("home", "4575555555"),
		f("cell", "4585555555"),
		f("business", "4595555555"),
		f("reminder question", "Who's a super cool guy?"),
		f("reminder answer", "Me, buddy."),
		f("website", "cv.gengels.nullvalue.test"),
		f("ICQ", "12345678"),
		f("skype", "skypeisbad1619"),
		f("AOL/AIM", "aollol@lololol.aol.com"),
		f("Yahoo", "sk8rboi13@yah00.com"),
		f("MSN", "msnothankyou@msn&m&m.com"),
		f("forum signature", "super cool guy"),
	)
}

func TestPuxEmailFieldOnIdentity(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "EmailFieldOnIdentityData"), false))
	if c.Identity.Email != "gengels@nullvalue.test" {
		t.Errorf("email %q", c.Identity.Email)
	}
	importertest.AssertCustomFieldsExist(t, c.Fields[:1], f("provider", "myEmailProvider", model.FieldTypeText))
}

func TestPuxEmailFieldOnIdentityPrefilled(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "EmailFieldOnIdentityPrefilledData"), false))
	if c.Identity.Email != "gengels@nullvalue.test" {
		t.Errorf("email %q", c.Identity.Email)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields[:2],
		f("2nd email", "kriddler@nullvalue.test", model.FieldTypeText),
		f("provider", "myEmailProvider", model.FieldTypeText))
}

func TestPuxCategory005Password(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "PasswordData"), false))
	if c.Type != model.CipherTypeLogin || c.Name != "SuperSecret Password" || c.Notes != "SuperSecret Password Notes" {
		t.Errorf("%s", importertest.Dump(c))
	}
	if c.Login.Password != "GBq[AGb]4*Si3tjwuab^" || c.Login.Uri() != "https://n0t.y0ur.n0rm4l.w3bs1t3" {
		t.Errorf("%s", importertest.Dump(c.Login))
	}
}

func TestPuxCategory100SoftwareLicense(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "SoftwareLicenseData"), false))
	if c.Type != model.CipherTypeSecureNote || c.Name != "Limux Product Key" || c.Notes != "My Software License" {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("version", "5.10.1000"),
		f("license key", "265453-13457355-847327"),
		f("licensed to", "Kay Riddler"),
		f("registered email", "kriddler@nullvalue.test"),
		f("company", "Riddles and Jigsaw Puzzles GmbH"),
		f("download page", "https://limuxcompany.nullvalue.test/5.10.1000/isos"),
		f("publisher", "Limux Software and Hardware"),
		f("website", "https://limuxcompany.nullvalue.test/"),
		f("retail price", "$999"),
		f("support email", "support@nullvalue.test"),
		f("purchase date", "Thu, 01 Apr 2021 12:01:00 GMT"),
		f("order number", "594839"),
		f("order total", "$1086.59"),
	)
}

func TestPuxCategory101BankAccountFlagOff(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "BankAccountData"), false))
	if c.Type != model.CipherTypeCard || c.Name != "Bank Account" || c.Notes != "My Bank Account" {
		t.Errorf("%s", importertest.Dump(c))
	}
	if c.Card.CardholderName != "Cool Guy" {
		t.Errorf("cardholder %q", c.Card.CardholderName)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("bank name", "Super Credit Union"),
		f("type", "checking"),
		f("routing number", "111000999"),
		f("account number", "192837465918273645"),
		f("SWIFT", "123456"),
		f("IBAN", "DE12 123456"),
		f("PIN", "5555"),
		f("phone", "9399399933"),
		f("address", "1 Fifth Avenue"),
	)
}

func TestPuxCategory101BankAccountFlagOn(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "BankAccountData"), true))
	if c.Type != model.CipherTypeBankAccount || c.Name != "Bank Account" || c.Notes != "My Bank Account" {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.BankAccountView{NameOnAccount: "Cool Guy", BankName: "Super Credit Union",
		AccountType: model.BankAccountTypeChecking, RoutingNumber: "111000999", AccountNumber: "192837465918273645",
		SwiftCode: "123456", Iban: "DE12 123456", Pin: "5555", BankContactPhone: "9399399933"}
	if *c.BankAccount != want {
		t.Errorf("bank account %+v", *c.BankAccount)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, f("address", "1 Fifth Avenue"))
}

func TestPuxCategory102Database(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "DatabaseData"), false))
	if c.Type != model.CipherTypeLogin || c.Name != "Database" || c.Notes != "My Database" {
		t.Errorf("%s", importertest.Dump(c))
	}
	if c.Login.Username != "cooldbuser" || c.Login.Password != "^+kTjhLaN7wVPAhGU)*J" {
		t.Errorf("%s", importertest.Dump(c.Login))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("type", "postgresql"),
		f("server", "my.secret.db.server"),
		f("port", "1337"),
		f("database", "user_database"),
		f("SID", "ASDIUFU-283234"),
		f("alias", "cdbu"),
		f("connection options", "ssh"),
	)
}

func TestPuxCategory103DriversLicenseFlagOff(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "DriversLicenseData"), false))
	if c.Name != "Michael Scarn" || c.Type != model.CipherTypeIdentity || c.Notes != "My Driver's License" {
		t.Errorf("%s", importertest.Dump(c))
	}
	id := c.Identity
	if id.FirstName != "Michael" || id.MiddleName != "" || id.LastName != "Scarn" || id.Address1 != "2120 Mifflin Rd." ||
		id.State != "Pennsylvania" || id.Country != "United States" || id.LicenseNumber != "12345678901" {
		t.Errorf("identity %+v", *id)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("date of birth", "Sun, 01 Jan 1978 12:01:00 GMT"),
		f("sex", "male"),
		f("height", "5'11\""),
		f("license class", "C"),
		f("conditions / restrictions", "B"),
		f("expiry date", "203012"),
	)
}

func TestPuxCategory103DriversLicenseFlagOn(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "DriversLicenseData"), true))
	if c.Name != "Michael Scarn" || c.Type != model.CipherTypeDriversLicense || c.Notes != "My Driver's License" {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.DriversLicenseView{FirstName: "Michael", LastName: "Scarn", IssuingState: "Pennsylvania",
		IssuingCountry: "United States", LicenseNumber: "12345678901", DateOfBirth: "1978-01-01",
		LicenseClass: "C", ExpirationDate: "2030-12-31"}
	if *c.DriversLicense != want {
		t.Errorf("drivers license %+v", *c.DriversLicense)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("address", "2120 Mifflin Rd."),
		f("sex", "male"),
		f("height", "5'11\""),
		f("conditions / restrictions", "B"),
	)
}

func TestPuxCategory104OutdoorLicense(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "OutdoorLicenseData"), false))
	if c.Type != model.CipherTypeIdentity || c.Name != "Harvest License" || c.Notes != "My Outdoor License" {
		t.Errorf("%s", importertest.Dump(c))
	}
	id := c.Identity
	if id.FirstName != "Cash" || id.MiddleName != "" || id.LastName != "Bandit" || id.State != "Washington" ||
		id.Country != "United States of America" {
		t.Errorf("identity %+v", *id)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("valid from", "Thu, 01 Apr 2021 12:01:00 GMT"),
		f("expires", "Fri, 01 Apr 2044 12:01:00 GMT"),
		f("approved wildlife", "Bananas,blueberries,corn"),
		f("maximum quota", "100/each"),
	)
}

func TestPuxCategory105Membership(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "MembershipData"), false))
	if c.Type != model.CipherTypeIdentity || c.Name != "Library Card" {
		t.Errorf("%s", importertest.Dump(c))
	}
	id := c.Identity
	if id.FirstName != "George" || id.MiddleName != "" || id.LastName != "Engels" ||
		id.Company != "National Public Library" || id.Phone != "9995555555" {
		t.Errorf("identity %+v", *id)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("website", "https://npl.nullvalue.gov.test"),
		f("member since", "199901"),
		f("expiry date", "203412"),
		f("member ID", "64783862"),
		f("PIN", "19191"),
	)
}

func TestPuxCategory106PassportFlagOff(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "PassportData"), false))
	if c.Type != model.CipherTypeIdentity || c.Name != "Mr. Globewide" {
		t.Errorf("%s", importertest.Dump(c))
	}
	id := c.Identity
	if id.FirstName != "David" || id.MiddleName != "" || id.LastName != "Global" || id.PassportNumber != "76436847" {
		t.Errorf("identity %+v", *id)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("type", "US Passport"),
		f("sex", "female"),
		f("nationality", "International"),
		f("issuing authority", "Department of State"),
		f("date of birth", "Fri, 01 Apr 1983 12:01:00 GMT"),
		f("place of birth", "A cave somewhere in Maine"),
		f("issued on", "Wed, 01 Jan 2020 12:01:00 GMT"),
		f("expiry date", "Sat, 01 Jan 2050 12:01:00 GMT"),
	)
}

func TestPuxCategory106PassportFlagOn(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "PassportData"), true))
	if c.Type != model.CipherTypePassport || c.Name != "Mr. Globewide" {
		t.Errorf("%s", importertest.Dump(c))
	}
	want := model.PassportView{GivenName: "David", Surname: "Global", IssuingCountry: "United States of America",
		PassportNumber: "76436847", PassportType: "US Passport", Nationality: "International",
		IssuingAuthority: "Department of State", DateOfBirth: "1983-04-01", BirthPlace: "A cave somewhere in Maine",
		IssueDate: "2020-01-01", ExpirationDate: "2050-01-01"}
	if *c.Passport != want {
		t.Errorf("passport %+v", *c.Passport)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, f("sex", "female"))
}

func TestPuxCategory107RewardsProgram(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "RewardsProgramData"), false))
	if c.Type != model.CipherTypeIdentity || c.Name != "Retail Reward Thing" {
		t.Errorf("%s", importertest.Dump(c))
	}
	id := c.Identity
	if id.FirstName != "Chef" || id.MiddleName != "" || id.LastName != "Coldroom" || id.Company != "Super Cool Store Co." {
		t.Errorf("identity %+v", *id)
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("member ID", "member-29813569"),
		f("PIN", "99913"),
		f("member ID (additional)", "additional member id"),
		f("member since", "202101"),
		f("customer service phone", "123456"),
		f("phone for reservations", "123456"),
		f("website", "supercoolstore.com"),
	)
}

func TestPuxCategory108SSN(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "SSNData"), false))
	id := c.Identity
	if c.Name != "SSN" || id.FirstName != "Jack" || id.MiddleName != "" || id.LastName != "Judd" || id.Ssn != "131-216-1900" {
		t.Errorf("%s", importertest.Dump(c))
	}
}

func TestPuxCategory109WirelessRouter(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "WirelessRouterData"), false))
	if c.Type != model.CipherTypeSecureNote || c.Name != "Wireless Router" || c.Notes != "My Wifi Router Config" {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("base station name", "pixel 2Xl"),
		f("base station password", "BqatGTVQ9TCN72tLbjrsHqkb"),
		f("server / ip address", "127.0.0.1"),
		f("airport id", "some airportId"),
		f("network name", "some network name"),
		f("wireless security", "WPA"),
		f("wireless network password", "wifipassword"),
		f("attached storage password", "diskpassword"),
	)
}

func TestPuxCategory110Server(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "ServerData"), false))
	if c.Type != model.CipherTypeLogin || c.Name != "Super Cool Server" || c.Notes != "My Server" {
		t.Errorf("%s", importertest.Dump(c))
	}
	if c.Login.Username != "frankly-notsure" || c.Login.Password != "*&YHJI87yjy78u" ||
		c.Login.Uri() != "https://coolserver.nullvalue.test" {
		t.Errorf("%s", importertest.Dump(c.Login))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("admin console URL", "https://coolserver.nullvalue.test/admin"),
		f("admin console username", "frankly-idontknowwhatimdoing"),
		f("console password", "^%RY&^YUiju8iUYHJI(U"),
		f("name", "Private Hosting Provider Inc."),
		f("website", "https://phpi.nullvalue.test"),
		f("support URL", "https://phpi.nullvalue.test/support"),
		f("support phone", "8882569382"),
	)
}

func TestPuxCategory111EmailAccount(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "EmailAccountData"), false))
	if c.Type != model.CipherTypeSecureNote || c.Name != "Email Config" || c.Notes != "My Email Config" {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("type", "either"),
		f("username", "someuser@nullvalue.test"),
		f("server", "mailserver.nullvalue.test"),
		f("port number", "587"),
		f("password", "u1jsf<UI*&YU&^T"),
		f("security", "TLS"),
		f("auth method", "kerberos_v5"),
		// Section "SMTP"
		f("SMTP server", "mailserver.nullvalue.test"),
		f("port number", "589"),
		f("username", "someuser@nullvalue.test"),
		f("password", "(*1674%^UIUJ*UI(IUI8u98uyy"),
		f("security", "TLS"),
		f("auth method", "password"),
		// Section "Contact Information"
		f("provider", "Telum"),
		f("provider's website", "https://telum.nullvalue.test"),
		f("phone (local)", "2346666666"),
		f("phone (toll free)", "18005557777"),
	)
}

func TestPuxCategory112APICredentials(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "APICredentialsData"), false))
	if c.Type != model.CipherTypeLogin || c.Name != "API Credential" || c.Notes != "My API Credential" {
		t.Errorf("%s", importertest.Dump(c))
	}
	if c.Login.Username != "apiuser@nullvalue.test" || c.Login.Password != "apiapiapiapiapiapiappy" ||
		c.Login.Uri() != "http://not.your.everyday.hostname" {
		t.Errorf("%s", importertest.Dump(c.Login))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("type", "jwt"),
		f("filename", "filename.jwt"),
		f("valid from", "Mon, 04 Apr 2011 12:01:00 GMT"),
		f("expires", "Tue, 01 Apr 2031 12:01:00 GMT"),
	)
}

func TestPuxSecureNote(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "SecureNoteData"), false))
	if c.Name != "Secure Note #1" || c.SecureNote.Type != model.SecureNoteTypeGeneric ||
		c.Notes != "This is my secure note. \n\nLorem ipsum expecto patronum. \nThe quick brown fox jumped over the lazy dog." {
		t.Errorf("%s", importertest.Dump(c))
	}
}

func TestPuxCategory113MedicalRecord(t *testing.T) {
	c := onlyCipher(t, parsePux(t, puxData(t, "MedicalRecordData"), false))
	if c.Type != model.CipherTypeSecureNote || c.Name != "Some Health Record" ||
		c.Notes != "Some notes about my medical history" || c.SecureNote.Type != model.SecureNoteTypeGeneric {
		t.Errorf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		f("date", "Sat, 01 Jan 2022 12:01:00 GMT"),
		f("location", "some hospital/clinic"),
		f("healthcare professional", "Some Doctor"),
		f("patient", "Me"),
		f("reason for visit", "unwell"),
		f("medication", "Insuline"),
		f("dosage", "1"),
		f("medication notes", "multiple times a day"),
	)
}

const onePuxSSHKeyPKCS8 = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIDn1BgTbZ/5UUeGLIfVV+qLBOvEsS3XMK6Twzw2Dkukq\ngSEAlrKdxRVVQrBndt4bHEZAz3xsymfM9Vf2QfZ823QxUbM=\n-----END PRIVATE KEY-----\n"

func TestPuxCategory114SSHKey(t *testing.T) {
	mock := &model.SshKeyView{
		PrivateKey:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCWsp3FFVVCMGZ23hscRkDPfGzKZ8z1V/ZB9nzbdDFRswAAAJh8F3bYfBd2\n2AAAAAtzc2gtZWQyNTUxOQAAACCWsp3FFVVCMGZ23hscRkDPfGzKZ8z1V/ZB9nzbdDFRsw\nAAAEA59QYE22f+VFHhiyH1Vfqiwz7xLEt1zCuk8M8Ng5LpKpayncUVVUKwZ3beGxxGQM98\nbMpnzPVX9kH2fNt0MVGzAAAAE3Rlc3RAZXhhbXBsZS5jb20BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n",
		PublicKey:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJayncUVVUKwZ3beGxxGQM98bMpnzPVX9kH2fNt0MVGz",
		KeyFingerprint: "SHA256:/9qSxXuic8kaVBhwv3c8PuetiEpaOgIp7xHNCbcSuN8",
	}
	var calledWith []string
	withSSHHook(t, func(key, pw string) (*model.SshKeyView, error) {
		calledWith = []string{key, pw}
		v := *mock
		return &v, nil
	})
	c := onlyCipher(t, parsePux(t, puxData(t, "SSH_KeyData"), false))
	if c.Type != model.CipherTypeSshKey || c.Name != "Some SSH Key" || c.Notes != "SSH Key Note" {
		t.Errorf("%s", importertest.Dump(c))
	}
	// import_ssh_key is called with the PKCS#8 key from 1Password and no password.
	if len(calledWith) != 2 || calledWith[0] != onePuxSSHKeyPKCS8 || calledWith[1] != "" {
		t.Errorf("import_ssh_key called with %q", calledWith)
	}
	if *c.SshKey != *mock {
		t.Errorf("ssh key %+v", *c.SshKey)
	}
}

// With the real SDK port (internal/sshkey) the converted key matches 1Password's metadata.
func TestPuxCategory114SSHKeyRealImport(t *testing.T) {
	withSSHHook(t, func(key, pw string) (*model.SshKeyView, error) {
		var p *string
		if pw != "" {
			p = &pw
		}
		d, err := sshkey.ImportKey(key, p)
		if err != nil {
			return nil, err
		}
		return &model.SshKeyView{PrivateKey: d.PrivateKey, PublicKey: d.PublicKey, KeyFingerprint: d.Fingerprint}, nil
	})
	c := onlyCipher(t, parsePux(t, puxData(t, "SSH_KeyData"), false))
	if c.SshKey.PublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJayncUVVUKwZ3beGxxGQM98bMpnzPVX9kH2fNt0MVGz" ||
		c.SshKey.KeyFingerprint != "SHA256:/9qSxXuic8kaVBhwv3c8PuetiEpaOgIp7xHNCbcSuN8" {
		t.Errorf("%+v", *c.SshKey)
	}
	if _, err := sshkey.ImportKey(c.SshKey.PrivateKey, nil); err != nil {
		t.Errorf("converted key does not re-import: %v", err)
	}
}

func TestPuxSkipsUnparseableSSHKey(t *testing.T) {
	withSSHHook(t, func(string, string) (*model.SshKeyView, error) { return nil, sshkey.ErrParsing })
	r, err := New1Pux(puxOptions(false)).Parse(puxData(t, "SSH_KeyData"))
	if err != nil || !r.Success {
		t.Fatalf("%v", err)
	}
	for _, c := range r.Ciphers {
		if c.Type == model.CipherTypeSshKey {
			t.Error("unparseable SSH key should be skipped")
		}
	}
	if len(r.Errors) != 1 || r.Errors[0].ID != "kf7wevmfiqmbgyao42plvgrasy" ||
		r.Errors[0].Reason != model.ImportRecordErrorReasonSshKeyParseFailed {
		t.Errorf("errors %+v", r.Errors)
	}
}

func TestPuxSSHKeyErrorReasons(t *testing.T) {
	for err, want := range map[error]model.ImportRecordErrorReason{
		sshkey.ErrUnsupportedKeyType:          model.ImportRecordErrorReasonUnsupportedType,
		sshkey.ErrParsing:                     model.ImportRecordErrorReasonSshKeyParseFailed,
		sshkey.ErrWrongPassword:               model.ImportRecordErrorReasonError,
		importer.ErrSSHKeyImportUnsupported:   model.ImportRecordErrorReasonError,
		errors.New("something else entirely"): model.ImportRecordErrorReasonError,
	} {
		if got := importErrorReason(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

func TestPuxSkipsAnyFailingItem(t *testing.T) {
	data := `{"accounts":[{"vaults":[{"items":[
		{"uuid":"broken-login-uuid","categoryUuid":"001","favIndex":0,"state":"active","overview":{"title":"Broken Login"}},
		{"categoryUuid":"001","favIndex":0,"state":"active","overview":{"title":"Good Login"},
		 "details":{"loginFields":[{"designation":"username","value":"bob"}],"passwordHistory":[],"sections":[]}}
	]}]}]}`
	var warnings []string
	o := puxOptions(false)
	o.Warn = func(s string) { warnings = append(warnings, s) }
	r, err := New1Pux(o).Parse(data)
	if err != nil || !r.Success {
		t.Fatal(err)
	}
	if len(r.Ciphers) != 1 || r.Ciphers[0].Name != "Good Login" {
		t.Errorf("%s", importertest.Dump(r.Ciphers))
	}
	if len(r.Errors) != 1 || r.Errors[0].ID != "broken-login-uuid" || r.Errors[0].Reason != model.ImportRecordErrorReasonError {
		t.Errorf("errors %+v", r.Errors)
	}
	if len(warnings) != 1 || warnings[0] != "1Password import skipped an item (uuid: broken-login-uuid, reason: error)" {
		t.Errorf("warnings %q", warnings)
	}
}

func TestPuxSkippedSSHKeyFolderNotMisattributed(t *testing.T) {
	withSSHHook(t, func(string, string) (*model.SshKeyView, error) { return nil, sshkey.ErrParsing })
	data := mutateJSON(t, puxData(t, "SSH_KeyData"), func(m map[string]any) {
		items := firstItems(m)
		items[0].(map[string]any)["overview"].(map[string]any)["tags"] = []any{"Work"}
		items = append(items, map[string]any{
			"uuid": "loginitem", "favIndex": 0, "createdAt": 1724868152, "updatedAt": 1724868152,
			"state": "active", "categoryUuid": "001",
			"details": map[string]any{
				"loginFields": []any{map[string]any{"designation": "username", "value": "alice", "name": "username", "fieldType": "T"}},
				"notesPlain":  "", "sections": []any{}, "passwordHistory": []any{},
			},
			"overview": map[string]any{"title": "My Login", "url": ""},
		})
		setFirstItems(m, items)
	})
	r := parsePux(t, data, false)
	if len(r.Ciphers) != 1 || r.Ciphers[0].Name != "My Login" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	if len(r.FolderRelationships) != 0 || len(r.Folders) != 0 {
		t.Errorf("folders %s relationships %v", importertest.Dump(r.Folders), r.FolderRelationships)
	}
}

func TestPuxFolders(t *testing.T) {
	r := parsePux(t, puxData(t, "SanitizedExport"), false)
	want := []string{"Movies", "Finance", "Travel", "Education", "Starter Kit"}
	if len(r.Folders) != len(want) {
		t.Fatalf("folders %s", importertest.Dump(r.Folders))
	}
	for k, name := range want {
		if r.Folders[k].Name != name {
			t.Errorf("folder %d = %q, want %q", k, r.Folders[k].Name, name)
		}
		found := false
		for _, rel := range r.FolderRelationships {
			if rel.GroupIndex() == k {
				found = true
			}
		}
		if !found {
			t.Errorf("no cipher in folder %d", k)
		}
	}
}

func TestPuxCollectionsForOrganization(t *testing.T) {
	o := puxOptions(false)
	o.OrganizationID = importer.NewGuid()
	r := importertest.Parse(t, New1Pux(o), puxData(t, "SanitizedExport"))
	want := []string{"Movies", "Finance", "Travel", "Education", "Starter Kit"}
	if len(r.Collections) != len(want) {
		t.Fatalf("collections %s", importertest.Dump(r.Collections))
	}
	for k, name := range want {
		if r.Collections[k].Name != name {
			t.Errorf("collection %d = %q, want %q", k, r.Collections[k].Name, name)
		}
	}
}

// The CLI reads the "export.data" entry of a .1pux zip (ImportCommand / importer.ReadImportFile).
func TestPuxZipFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "export.1pux")
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fh)
	w, _ := zw.Create("export.attributes")
	w.Write([]byte(`{"version":3}`))
	w, _ = zw.Create("export.data")
	w.Write([]byte(puxData(t, "LoginData")))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	fh.Close()

	contents, err := importer.ReadImportFile("1password1pux", p)
	if err != nil {
		t.Fatal(err)
	}
	imp, err := importer.New("1password1pux", puxOptions(false))
	if err != nil {
		t.Fatal(err)
	}
	r, err := importer.Import(imp, contents, importer.ImportParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Ciphers) != 1 || r.Ciphers[0].Name != "eToro" {
		t.Errorf("%s", importertest.Dump(r.Ciphers))
	}
}

func TestPuxInvalidJSON(t *testing.T) {
	if _, err := New1Pux(puxOptions(false)).Parse("{"); !importer.IsSyntaxError(err) {
		t.Fatalf("got %v", err)
	}
	// exportData.accounts[0].vaults throws outside the per-item try/catch.
	if _, err := New1Pux(puxOptions(false)).Parse(`{"accounts":[]}`); err == nil {
		t.Fatal("expected a TypeError")
	}
}

func TestCapitalize(t *testing.T) {
	for in, want := range map[string]string{
		"  starter kit ": "Starter Kit",
		"foo-bar baz":    "Foo-bar Baz",
		"ünïcode word":   "üNïcode Word", // ü is not \w in JavaScript
		"_x 1y":          "_x 1y",
	} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}
