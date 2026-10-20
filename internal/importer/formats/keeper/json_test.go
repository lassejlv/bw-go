package keeper

import (
	"errors"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/keeper/keeper-json-importer.spec.ts.

func TestMain(m *testing.M) {
	// Pin locale time zone so date formatting is machine-independent (the spec pins en-US/UTC).
	localeLocation = time.UTC
	os.Exit(m.Run())
}

func newJson(orgID string, newItemTypes bool) importer.Importer {
	o := importertest.OrgOptions(orgID)
	o.Features.NewItemTypes = newItemTypes
	return NewJson(o)
}

func expectParse(t *testing.T, imp importer.Importer, file string, count int) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, imp, importertest.ReadFile(t, file))
	if !r.Success || len(r.Ciphers) != count {
		t.Fatalf("%s: success=%v, %d ciphers, want %d", file, r.Success, len(r.Ciphers), count)
	}
	return r
}

func cliWeb(t *testing.T) []*model.ImportResult {
	return []*model.ImportResult{
		expectParse(t, newJson("", false), "CliTestData.json", 24),
		expectParse(t, newJson("", false), "WebTestData.json", 24),
	}
}

func cliWebFlagOn(t *testing.T) []*model.ImportResult {
	return []*model.ImportResult{
		expectParse(t, newJson("", true), "CliTestData.json", 26),
		expectParse(t, newJson("", true), "WebTestData.json", 26),
	}
}

func getCipher(t *testing.T, r *model.ImportResult, name string) *model.CipherView {
	t.Helper()
	for _, c := range r.Ciphers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cipher %q not found", name)
	return nil
}

func getField(c *model.CipherView, name string) *model.FieldView {
	for _, f := range c.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func getFields(c *model.CipherView, name string) []*model.FieldView {
	var out []*model.FieldView
	for _, f := range c.Fields {
		if f.Name == name {
			out = append(out, f)
		}
	}
	return out
}

func values(fields []*model.FieldView) []string {
	out := []string{}
	for _, f := range fields {
		out = append(out, f.Value)
	}
	return out
}

func expectField(t *testing.T, c *model.CipherView, name, value string, typ ...model.FieldType) {
	t.Helper()
	f := getField(c, name)
	if f == nil {
		t.Errorf("%s: field %q missing", c.Name, name)
		return
	}
	if f.Value != value {
		t.Errorf("%s: field %q = %q, want %q", c.Name, name, f.Value, value)
	}
	if len(typ) > 0 && f.Type != typ[0] {
		t.Errorf("%s: field %q type %d, want %d", c.Name, name, f.Type, typ[0])
	}
}

func expectType(t *testing.T, c *model.CipherView, typ model.CipherType) {
	t.Helper()
	if c.Type != typ {
		t.Errorf("%s: type %d, want %d", c.Name, c.Type, typ)
	}
}

func expectEq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func expectFieldCount(t *testing.T, c *model.CipherView, n int) {
	t.Helper()
	if len(c.Fields) != n {
		t.Errorf("%s: %d fields, want %d: %s", c.Name, len(c.Fields), n, importertest.Dump(c.Fields))
	}
}

func sshAvailable(t *testing.T) {
	t.Helper()
	if _, err := importer.ImportSSHKey("x", ""); errors.Is(err, importer.ErrSSHKeyImportUnsupported) {
		t.Skip("importer.ImportSSHKey is not implemented yet")
	}
}

func TestJsonAddress(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Home Address")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Primary residence - mailing and billing address")
		expectFieldCount(t, c, 1)
		expectField(t, c, "address", "742 Evergreen Terrace, Apt 3B, Springfield, Oregon, 97477, US")
	}
}

func TestJsonBankAccountFlagOff(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Wells Fargo Checking")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "Primary checking account for direct deposit and bill payments")
		expectEq(t, "username", c.Login.Username, "m.thompson@email.com")
		expectEq(t, "password", c.Login.Password, "BankS3cur3!Pass")
		if !containsStr(c.Login.Totp, "otpauth://totp/") {
			t.Errorf("totp = %q", c.Login.Totp)
		}
		expectFieldCount(t, c, 2)
		expectField(t, c, "bankAccount", "Type: Checking, Account Number: 8472651938, Routing Number: 121000248")
		expectField(t, c, "name", "Michael James Thompson")
	}
}

func containsStr(s, sub string) bool {
	return len(sub) <= len(s) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestJsonBankAccountFlagOn(t *testing.T) {
	// There are two banks in the test data, and both get an extra cipher when the flag is on.
	for _, r := range cliWebFlagOn(t) {
		loginIdx := slices.IndexFunc(r.Ciphers, func(c *model.CipherView) bool {
			return c.Name == "Wells Fargo Checking" && c.Type == model.CipherTypeLogin
		})
		bankIdx := slices.IndexFunc(r.Ciphers, func(c *model.CipherView) bool {
			return c.Name == "Wells Fargo Checking" && c.Type == model.CipherTypeBankAccount
		})
		if loginIdx == -1 || bankIdx == -1 {
			t.Fatalf("login %d, bank %d", loginIdx, bankIdx)
		}

		login := r.Ciphers[loginIdx]
		expectEq(t, "notes", login.Notes, "Primary checking account for direct deposit and bill payments")
		expectEq(t, "username", login.Login.Username, "m.thompson@email.com")
		expectEq(t, "password", login.Login.Password, "BankS3cur3!Pass")
		if !containsStr(login.Login.Totp, "otpauth://totp/") {
			t.Errorf("totp = %q", login.Login.Totp)
		}
		expectFieldCount(t, login, 0)

		bank := r.Ciphers[bankIdx]
		want := model.BankAccountView{AccountNumber: "8472651938", RoutingNumber: "121000248",
			NameOnAccount: "Michael James Thompson", AccountType: model.BankAccountTypeChecking}
		if *bank.BankAccount != want {
			t.Errorf("bank account: %s", importertest.Dump(bank.BankAccount))
		}
		expectFieldCount(t, bank, 0)

		var loginRels []model.Relationship
		for _, rel := range r.FolderRelationships {
			if rel[0] == loginIdx {
				loginRels = append(loginRels, rel)
			}
		}
		if len(loginRels) != 1 {
			t.Fatalf("login folder relationships: %v", loginRels)
		}
		// The bank account cipher should have the same folder as the login cipher
		if !slices.Contains(r.FolderRelationships, model.Relationship{bankIdx, loginRels[0][1]}) {
			t.Errorf("bank account cipher is not in the login's folder: %v", r.FolderRelationships)
		}
	}
}

func TestJsonBankAccountOtherType(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Other bank")
		expectType(t, c, model.CipherTypeSecureNote)
		expectFieldCount(t, c, 2)
		expectField(t, c, "bankAccount", "Type: Crypto, Account Number: 12345678")
		expectField(t, c, "name", "Mark Zwei")
	}
}

func TestJsonBankCard(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Chase Visa")
		expectType(t, c, model.CipherTypeCard)
		expectEq(t, "notes", c.Notes, "Primary credit card for everyday purchases and rewards")
		want := model.CardView{Number: "4532123456789010", CardholderName: "Sarah Johnson", Brand: "Visa", ExpMonth: "06", ExpYear: "2030"}
		got := *c.Card
		got.Code = "" // not checked upstream
		if got != want {
			t.Errorf("card: %s", importertest.Dump(c.Card))
		}
		expectFieldCount(t, c, 3)
		expectField(t, c, "PIN", "8426", model.FieldTypeHidden)
		urls := values(getFields(c, "URL"))
		sort.Strings(urls)
		importertest.AssertEqualJSON(t, urls, []string{"https://bank.card/test", "https://bank.card/test/with/label"})
	}
}

func TestJsonBirthCertificate(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "John Doe Birth Certificate")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Official birth certificate for identification purposes")
		expectFieldCount(t, c, 2)
		expectField(t, c, "name", "John Michael Doe")
		expectField(t, c, "birthDate", "5/14/1990, 10:00:00 PM")
	}
}

func TestJsonContact(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Dr. Emily Chen")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Primary care physician - office visits and consultations")
		expectFieldCount(t, c, 5)
		expectField(t, c, "name", "Emily Marie Chen")
		expectField(t, c, "company", "Springfield Medical Center")
		expectField(t, c, "email", "emily.chen@smc.org")
		expectField(t, c, "phone", "(AF) 5415558723 ext. 5577 (Work)")
		// Resolved reference field
		expectField(t, c, "address", "1428 Elm Street, Suite 200, Portland, Oregon, 97204, US")
	}
}

func TestJsonDatabaseCredentials(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Production MySQL Database")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "Production database server for main application - handle with care")
		expectEq(t, "username", c.Login.Username, "db_admin")
		expectEq(t, "password", c.Login.Password, "SecureDb#2024$Pass")
		expectFieldCount(t, c, 3)
		expectField(t, c, "type", "MySQL")
		expectField(t, c, "Hostname", "db.production.company.com")
		expectField(t, c, "Port", "3306")
	}
}

func TestJsonDriverLicenseFlagOff(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Oregon Driver's License")
		expectType(t, c, model.CipherTypeIdentity)
		expectEq(t, "notes", c.Notes, "Valid Oregon driver's license - Class C")
		expectEq(t, "licenseNumber", c.Identity.LicenseNumber, "DL-7482693")
		expectEq(t, "firstName", c.Identity.FirstName, "Robert")
		expectEq(t, "middleName", c.Identity.MiddleName, "William")
		expectEq(t, "lastName", c.Identity.LastName, "Anderson")
		expectFieldCount(t, c, 2)
		expectField(t, c, "birthDate", "3/14/1985, 11:00:00 PM")
		expectField(t, c, "expirationDate", "3/14/2028, 11:00:00 PM")
	}
}

func TestJsonDriverLicenseFlagOn(t *testing.T) {
	for _, r := range cliWebFlagOn(t) {
		c := getCipher(t, r, "Oregon Driver's License")
		expectType(t, c, model.CipherTypeDriversLicense)
		expectEq(t, "notes", c.Notes, "Valid Oregon driver's license - Class C")
		want := model.DriversLicenseView{LicenseNumber: "DL-7482693", FirstName: "Robert", MiddleName: "William",
			LastName: "Anderson", DateOfBirth: "1985-03-14", ExpirationDate: "2028-03-14"}
		if *c.DriversLicense != want {
			t.Errorf("drivers license: %s", importertest.Dump(c.DriversLicense))
		}
		expectFieldCount(t, c, 0)
	}
}

func TestJsonEncryptedNotes(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Important Meeting Notes")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Confidential meeting with executive team - requires follow-up by end of month")
		expectFieldCount(t, c, 2)
		expectField(t, c, "note", "Q4 2024 Strategic Planning - Discussed budget allocations, team restructuring, and new product launch timeline")
		expectField(t, c, "date", "10/14/2024, 10:00:00 PM")
	}
}

func TestJsonFile(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Project Proposal Document")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Annual project proposal for Q1 2025 business development initiatives")
		expectFieldCount(t, c, 0)
	}
}

func TestJsonGeneral(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "General Information Record")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "General purpose record for miscellaneous information and credentials")
		expectEq(t, "username", c.Login.Username, "general_user@example.com")
		expectEq(t, "password", c.Login.Password, "GeneralPass#2024!Secure")
		expectEq(t, "uri", c.Login.Uri(), "https://general.example.com")
		if !containsStr(c.Login.Totp, "otpauth://totp/") {
			t.Errorf("totp = %q", c.Login.Totp)
		}
		expectFieldCount(t, c, 0)
	}
}

func TestJsonHealthInsurance(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Blue Cross Blue Shield")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "PPO plan with nationwide coverage - family deductible $2500")
		expectEq(t, "username", c.Login.Username, "david.martinez@email.com")
		expectEq(t, "password", c.Login.Password, "Health$ecure789")
		expectEq(t, "uri", c.Login.Uri(), "https://www.bcbs.com")
		expectFieldCount(t, c, 2)
		expectField(t, c, "accountNumber", "BCBS-12345678")
		expectField(t, c, "insuredsName", "David Alan Martinez")
	}
}

func TestJsonLogin(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Amazon Account")
		expectType(t, c, model.CipherTypeLogin)
		if !containsStr(c.Login.Totp, "otpauth://totp/") {
			t.Errorf("totp = %q", c.Login.Totp)
		}
		expectEq(t, "notes", c.Notes, "Primary Amazon account for online shopping and Prime membership")
		expectEq(t, "username", c.Login.Username, "john.martinez@email.com")
		expectEq(t, "password", c.Login.Password, "Sp@rkl3Sun!2024")
		expectEq(t, "uri", c.Login.Uri(), "https://www.amazon.com")
		importertest.AssertEqualJSON(t, importertest.URIs(c), []string{
			"https://www.amazon.com",
			"https://login.amazon.com",
			"https://logout.amazon.com",
			"https://account.amazon.com",
			"https://profile.amazon.com",
		})

		expectFieldCount(t, c, 17)
		expectField(t, c, "some label", "some text")
		expectField(t, c, "some more text", "some lines\nsome more lines\nblah blah blah")
		expectField(t, c, "pin-pin-pin", "1234", model.FieldTypeHidden)

		importertest.AssertEqualJSON(t, values(getFields(c, "Security question")), []string{
			"how old were you when you were born?", "how are you?", "how old are you?",
		})
		answers := getFields(c, "Security question answer")
		importertest.AssertEqualJSON(t, values(answers), []string{"zero", "good, thanks!", "five"})
		for _, a := range answers {
			if a.Type != model.FieldTypeHidden {
				t.Errorf("answer type %d", a.Type)
			}
		}

		importertest.AssertEqualJSON(t, values(getFields(c, "phone")), []string{"(AZ) 123123123 (Home)", "(CZ) 555555555 ext. 444"})
		expectField(t, c, "some date", "11/30/2025, 8:50:48 PM")
		expectField(t, c, "email", "blah@blah.com")
		expectField(t, c, "someone", "Maria Smith")
		expectField(t, c, "special secret", "big secret", model.FieldTypeHidden)

		addresses := values(getFields(c, "address"))
		sort.Strings(addresses)
		importertest.AssertEqualJSON(t, addresses, []string{
			"1428 Elm Street, Suite 200, Portland, Oregon, 97204, US",
			"742 Evergreen Terrace, Apt 3B, Springfield, Oregon, 97477, US",
		})
	}
}

func TestJsonMembership(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "LA Fitness Gym")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "Annual membership - full gym access including pool and classes")
		expectFieldCount(t, c, 2)
		expectField(t, c, "accountNumber", "LAF-987654321")
		expectField(t, c, "name", "Lisa Marie Rodriguez")
	}
}

func TestJsonPassportFlagOff(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "US Passport")
		expectType(t, c, model.CipherTypeIdentity)
		expectEq(t, "notes", c.Notes, "Valid US passport for international travel")
		expectEq(t, "passportNumber", c.Identity.PassportNumber, "543826194")
		expectEq(t, "firstName", c.Identity.FirstName, "Jennifer")
		expectEq(t, "middleName", c.Identity.MiddleName, "Lynn")
		expectEq(t, "lastName", c.Identity.LastName, "Williams")
		expectFieldCount(t, c, 4)
		expectField(t, c, "Password", "Passport2023!Secure", model.FieldTypeHidden)
		expectField(t, c, "birthDate", "7/21/1990, 10:00:00 PM")
		expectField(t, c, "expirationDate", "7/21/2033, 10:00:00 PM")
		expectField(t, c, "dateIssued", "8/14/2023, 10:00:00 PM")
	}
}

func TestJsonPassportFlagOn(t *testing.T) {
	for _, r := range cliWebFlagOn(t) {
		c := getCipher(t, r, "US Passport")
		expectType(t, c, model.CipherTypePassport)
		expectEq(t, "notes", c.Notes, "Valid US passport for international travel")
		want := model.PassportView{PassportNumber: "543826194", GivenName: "Jennifer Lynn", Surname: "Williams",
			DateOfBirth: "1990-07-21", ExpirationDate: "2033-07-21", IssueDate: "2023-08-14"}
		if *c.Passport != want {
			t.Errorf("passport: %s", importertest.Dump(c.Passport))
		}
		importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("Password", "Passport2023!Secure", model.FieldTypeHidden))
	}
}

func TestJsonPhoto(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Family Vacation 2024")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Summer vacation photos from Hawaii trip - scenic beach views")
		expectFieldCount(t, c, 0)
	}
}

func TestJsonServerCredentials(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Web Server - Production")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "Primary production web server - Apache 2.4.52 - Ubuntu 22.04")
		expectEq(t, "username", c.Login.Username, "sysadmin")
		expectEq(t, "password", c.Login.Password, "Srv#Prod2024!Sec")
		expectFieldCount(t, c, 2)
		expectField(t, c, "Hostname", "web01.company.com")
		expectField(t, c, "Port", "22")
	}
}

func TestJsonSoftwareLicense(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Adobe Creative Cloud")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Annual subscription - full access to Photoshop, Illustrator, Premiere Pro")
		expectFieldCount(t, c, 3)
		expectField(t, c, "licenseNumber", "ACDB-7849-2635-1947-8520")
		expectField(t, c, "expirationDate", "12/30/2025, 11:00:00 PM")
		expectField(t, c, "dateActive", "1/14/2024, 11:00:00 PM")
	}
}

func TestJsonSshKeys(t *testing.T) {
	sshAvailable(t)
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Production Server SSH Key")
		expectType(t, c, model.CipherTypeSshKey)
		expectEq(t, "notes", c.Notes, "SSH key for production server deployment - RSA 2048 bit")
		expectFieldCount(t, c, 3)
		expectField(t, c, "Username", "deploy_user")
		expectField(t, c, "Hostname", "prod-server.company.com")
		expectField(t, c, "Port", "22")
	}
}

func TestJsonSshKeysWithPassphrase(t *testing.T) {
	sshAvailable(t)
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Production Server SSH Key with a passphrase")
		expectType(t, c, model.CipherTypeSshKey)
		expectEq(t, "notes", c.Notes, "SSH key for production server deployment - RSA 2048 bit")
		expectFieldCount(t, c, 4)
		expectField(t, c, "Username", "deploy_user")
		expectField(t, c, "Password", "blah-blah-blah", model.FieldTypeHidden)
		expectField(t, c, "Hostname", "prod-server.company.com")
		expectField(t, c, "Port", "22")
	}
}

// Without an SSH key implementation every key falls back to a secure note, keeping the key pair
// and the passphrase as custom fields.
func TestJsonSshKeysUnsupportedFallback(t *testing.T) {
	saved := importer.ImportSSHKey
	importer.ImportSSHKey = func(string, string) (*model.SshKeyView, error) {
		return nil, importer.ErrSSHKeyImportUnsupported
	}
	defer func() { importer.ImportSSHKey = saved }()

	var warnings []string
	o := importertest.Options()
	o.Warn = func(s string) { warnings = append(warnings, s) }
	r := expectParse(t, NewJson(o), "CliTestData.json", 24)
	c := getCipher(t, r, "Production Server SSH Key with a passphrase")
	expectType(t, c, model.CipherTypeSecureNote)
	expectField(t, c, "Passphrase", "blah-blah-blah", model.FieldTypeHidden)
	if getField(c, "Private key") == nil || getField(c, "Public key") == nil {
		t.Errorf("key pair fields missing: %s", importertest.Dump(c.Fields))
	}
	if len(warnings) != 3 || !containsStr(warnings[0], "Unable to import SSH key (id: ") {
		t.Errorf("warnings: %q", warnings)
	}
}

// The success path with a stub hook (the real one is tested above once it exists).
func TestJsonSshKeysStubbedHook(t *testing.T) {
	saved := importer.ImportSSHKey
	var passwords []string
	importer.ImportSSHKey = func(key, pw string) (*model.SshKeyView, error) {
		if !containsStr(key, "BEGIN OPENSSH PRIVATE KEY") {
			return nil, errors.New("invalid key")
		}
		passwords = append(passwords, pw)
		return &model.SshKeyView{PrivateKey: "priv", PublicKey: "pub", KeyFingerprint: "SHA256:fp"}, nil
	}
	defer func() { importer.ImportSSHKey = saved }()

	r := expectParse(t, newJson("", false), "CliTestData.json", 24)
	c := getCipher(t, r, "Production Server SSH Key with a passphrase")
	expectType(t, c, model.CipherTypeSshKey)
	if *c.SshKey != (model.SshKeyView{PrivateKey: "priv", PublicKey: "pub", KeyFingerprint: "SHA256:fp"}) {
		t.Errorf("ssh key: %s", importertest.Dump(c.SshKey))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Username", "deploy_user"),
		importertest.F("Password", "blah-blah-blah", model.FieldTypeHidden),
		importertest.F("Hostname", "prod-server.company.com"),
		importertest.F("Port", "22"))
	c = getCipher(t, r, "Production Server SSH Key")
	expectType(t, c, model.CipherTypeSshKey)
	expectFieldCount(t, c, 3)
	importertest.AssertEqualJSON(t, passwords, []string{"", "blah-blah-blah"})
	expectType(t, getCipher(t, r, "Invalid SSH key"), model.CipherTypeSecureNote)
}

func TestJsonInvalidSshKey(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Invalid SSH key")
		expectType(t, c, model.CipherTypeSecureNote)
		expectEq(t, "notes", c.Notes, "Broken ssh key")
		expectFieldCount(t, c, 5)
		expectField(t, c, "Public key", "blah blah public key")
		expectField(t, c, "Private key", "blah blah blah private key")
		expectField(t, c, "Passphrase", "blah-blah-blah")
		expectField(t, c, "Hostname", "prod-server.company.com")
		expectField(t, c, "Port", "22")
	}
}

func TestJsonSsnCard(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "National Identity Card")
		expectType(t, c, model.CipherTypeIdentity)
		expectEq(t, "notes", c.Notes, "National identification card - Valid through 2028")
		expectEq(t, "ssn", c.Identity.Ssn, "ID-7849521")
		expectEq(t, "firstName", c.Identity.FirstName, "Sarah")
		expectEq(t, "middleName", c.Identity.MiddleName, "Elizabeth")
		expectEq(t, "lastName", c.Identity.LastName, "Johnson")
		expectFieldCount(t, c, 0)
	}
}

func TestJsonWifiCredentials(t *testing.T) {
	for _, r := range cliWeb(t) {
		c := getCipher(t, r, "Home Wi-Fi")
		expectType(t, c, model.CipherTypeLogin)
		expectEq(t, "notes", c.Notes, "My cozy home wi-fi")
		expectEq(t, "password", c.Login.Password, "secure-password-123")
		expectFieldCount(t, c, 1)
		expectField(t, c, "SSID", "cozy-home-netz")
	}
}

// localeSorted sorts case-insensitively. Upstream sorts both sides with localeCompare to compare
// the name sets independent of order; any consistent order does the same here.
func localeSorted(names []string) []string {
	out := slices.Clone(names)
	sort.SliceStable(out, func(i, j int) bool { return localeLess(out[i], out[j]) })
	return out
}

func assertInFolder(t *testing.T, r *model.ImportResult, cipherName, folderName string) {
	t.Helper()
	ci := slices.IndexFunc(r.Ciphers, func(c *model.CipherView) bool { return c.Name == cipherName })
	fi := slices.IndexFunc(r.Folders, func(f *model.FolderView) bool { return f.Name == folderName })
	if !slices.Contains(r.FolderRelationships, model.Relationship{ci, fi}) {
		t.Errorf("%q is not in folder %q (%d, %d)", cipherName, folderName, ci, fi)
	}
}

var allFolderNames = []string{
	"CanManageRecords-CanEdit",
	"CanManageUsers-ViewOnly",
	"Clients",
	"Clients/Enterprise",
	"Clients/Enterprise/North America",
	"Clients/Enterprise/North America/TechCorp",
	"Clients/Enterprise/North America/TechCorp/Shared-Needsted-Deep-Inside-Normal-Folder",
	"Development",
	"Development/Name-with-both-slashes",
	"Development/Name-with-both-slashes/Android",
	"Development/Name-with-both-slashes/Name-with-forward-slashes",
	"Development/Name-with-both-slashes/Name-with-forward-slashes/Name-with-backslashes",
	"Development/Web",
	"Education",
	"Empty Folder",
	"Empty Folder/Empty Nested Folder Level 2",
	"Empty Folder/Empty Nested Folder Level 2/Empty Nested Folder Level 3",
	"Empty Folder/Empty Nested Folder Level 2/Empty Nested Folder Level 3/Shared Folder Inside Empty Nested Folder",
	"FullAccess-CanShare",
	"NoUserPerms-EditAndShare",
	"Personal",
	"Personal/Finance",
	"Personal/Finance/Banking",
	"Personal/Finance/Banking/Accounts",
	"Shared-With-Slashes",
	"Work",
	"Work/Documents",
	"Work/Projects",
	"Work/Projects/2025",
	"Work/Projects/2025/Q4",
}

var legacyFolderNames = []string{
	"abc",
	"Dev build ",
	"dfdfgh",
	"Inheritance",
	"IT Project",
	"IT Project/Folder 1",
	"IT Project/Folder 1/PersonalNested-1-1",
	"IT Project/Folder 1/PersonalNested-1-2",
	"IT Project/Folder 2",
	"Marketing",
	"name change-folder",
	"New Marketing Folder",
	"Personal",
	"Personal/Shared with Family",
	"Shared Project Folder",
	"Social Media",
	"Social Media/Cards",
	"Sub-inheritance",
	"Transferred: Account",
	"Transferred: Account/Test Item",
	"Transferred: garrisonconsultinguser@gmail.com",
	"Transferred: garrisonconsultinguser@gmail.com/Marketing",
}

func localeLess(a, b string) bool {
	return collationKey(a) < collationKey(b)
}

func collationKey(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func folderNames(folders []*model.FolderView) []string {
	var out []string
	for _, f := range folders {
		out = append(out, f.Name)
	}
	return out
}

func TestJsonFolders(t *testing.T) {
	for _, r := range cliWeb(t) {
		if len(r.Folders) != 30 {
			t.Errorf("%d folders", len(r.Folders))
		}
		importertest.AssertEqualJSON(t, localeSorted(folderNames(r.Folders)), localeSorted(allFolderNames))
		if len(r.Collections) != 0 {
			t.Errorf("%d collections", len(r.Collections))
		}

		assertInFolder(t, r, "Home Address", "Personal/Finance/Banking")
		assertInFolder(t, r, "Production Server SSH Key", "Development/Name-with-both-slashes/Android")
		assertInFolder(t, r, "Home Wi-Fi", "Shared-With-Slashes")
		assertInFolder(t, r, "Chase Visa", "Work/Projects/2025/Q4")
		assertInFolder(t, r, "John Doe Birth Certificate", "Work/Documents")

		// In two folders at the same time
		assertInFolder(t, r, "Production MySQL Database",
			"Development/Name-with-both-slashes/Name-with-forward-slashes/Name-with-backslashes")
		assertInFolder(t, r, "Production MySQL Database", "Development/Name-with-both-slashes/Name-with-forward-slashes")
	}
}

func TestJsonCollections(t *testing.T) {
	r := expectParse(t, newJson(importer.NewGuid(), false), "CliTestData.json", 24)
	if len(r.Collections) != 30 {
		t.Errorf("%d collections", len(r.Collections))
	}
	var names []string
	for _, c := range r.Collections {
		names = append(names, c.Name)
	}
	importertest.AssertEqualJSON(t, localeSorted(names), localeSorted(allFolderNames))
	if len(r.Folders) != 0 {
		t.Errorf("%d folders", len(r.Folders))
	}
}

func legacy(t *testing.T) *model.ImportResult {
	return expectParse(t, newJson("", false), "LegacyTestData.json", 78)
}

func TestJsonLegacyLogin(t *testing.T) {
	r := legacy(t)
	c := getCipher(t, r, "AARP")
	expectType(t, c, model.CipherTypeLogin)
	expectEq(t, "uri", c.Login.Uri(), "https://aarp.org")
	assertInFolder(t, r, "AARP", "Inheritance")
	assertInFolder(t, r, "AARP", "Sub-inheritance")
}

func TestJsonLegacyLoginWithCustomFields(t *testing.T) {
	c := getCipher(t, legacy(t), "cipher item")
	expectType(t, c, model.CipherTypeLogin)
	expectEq(t, "notes", c.Notes, "the quick brown fox jumps over the lazy dog.")
	expectEq(t, "username", c.Login.Username, "username123")
	expectEq(t, "password", c.Login.Password, "password123")
	expectFieldCount(t, c, 1)
	expectField(t, c, "kasjdfiauefaikjsjdf8as7878", "custom")
}

func TestJsonLegacyMultipleTotp(t *testing.T) {
	c := getCipher(t, legacy(t), "Comp Test with OTP")
	expectType(t, c, model.CipherTypeLogin)
	expectEq(t, "username", c.Login.Username, "test")
	expectEq(t, "password", c.Login.Password, "l3}9%aI6Hh33k2CJcsXB")
	expectEq(t, "totp", c.Login.Totp, "otpauth://totp/Iterable:justin.tulk@iterable.com?secret=YW6CMSUJOHCE3H33&issuer=Iterable")
	expectFieldCount(t, c, 1)
	expectField(t, c, "TOTP", "otpauth://totp/Google%3Asbolina%40bitwarden.com?secret=6whhjvsb3taxmlf4e7fk4v7lsusuv2m5&issuer=Google")
}

func TestJsonLegacyBankCard(t *testing.T) {
	r := legacy(t)
	c := getCipher(t, r, "VISA")
	expectType(t, c, model.CipherTypeCard)
	expectEq(t, "number", c.Card.Number, "5555555555555555")
	expectEq(t, "cardholderName", c.Card.CardholderName, "Ted Lasso")
	expectEq(t, "expMonth", c.Card.ExpMonth, "02")
	expectEq(t, "expYear", c.Card.ExpYear, "2028")
	expectFieldCount(t, c, 1)
	expectField(t, c, "PIN", "1235", model.FieldTypeHidden)
	assertInFolder(t, r, "VISA", "Social Media/Cards")
}

func TestJsonLegacyFolders(t *testing.T) {
	r := legacy(t)
	if len(r.Folders) != 22 {
		t.Errorf("%d folders", len(r.Folders))
	}
	importertest.AssertEqualJSON(t, localeSorted(folderNames(r.Folders)), localeSorted(legacyFolderNames))
}

func enterprise(t *testing.T) *model.ImportResult {
	return expectParse(t, newJson("", false), "EnterpriseTestData.json", 19)
}

func TestJsonPamRemoteBrowser(t *testing.T) {
	c := getCipher(t, enterprise(t), "Admin Dashboard Connection")
	expectType(t, c, model.CipherTypeSecureNote)
	expectFieldCount(t, c, 1)
	expectField(t, c, "rbiUrl", "https://admin.company.internal/dashboard")
}

func TestJsonPamDatabase(t *testing.T) {
	c := getCipher(t, enterprise(t), "Database Tunnel to Production MySQL")
	expectType(t, c, model.CipherTypeSecureNote)
	expectFieldCount(t, c, 7)
	expectField(t, c, "pamHostname", `{"hostName":"mysql-prod.company.internal","port":"3306"}`)
	expectField(t, c, "useSSL", "true")
	expectField(t, c, "pamSettings", `{"connection":{"port":"3307"},"portForward":{"port":"8306"}}`)
	expectField(t, c, "databaseId", "db-prod-mysql-01")
	expectField(t, c, "databaseType", "mysql")
	expectField(t, c, "providerGroup", "Production-Databases")
	expectField(t, c, "providerRegion", "us-east-1")
}

func TestJsonPamUser(t *testing.T) {
	c := getCipher(t, enterprise(t), "Production Gateway Server - MySQL Admin User")
	expectType(t, c, model.CipherTypeLogin)
	expectEq(t, "username", c.Login.Username, "root")
	expectEq(t, "password", c.Login.Password, "r7gJ6Zl5BXktS4IPGh4D")
}

func TestJsonPamMachine(t *testing.T) {
	c := getCipher(t, enterprise(t), "Production Gateway Server - RDP Machine")
	expectType(t, c, model.CipherTypeSecureNote)
	expectFieldCount(t, c, 3)
	expectField(t, c, "pamHostname", `{"hostName":"server-rdp","port":"22"}`)
	expectField(t, c, "trafficEncryptionSeed", "yJsgoM7cuMAqkf5u8VTTVGNCKOirobWXOjthBRlb2bw=")
	expectField(t, c, "pamSettings", `{"connection":{"protocol":"rdp","port":"3389","recordingIncludeKeys":true,"security":"any","ignoreCert":true,"resizeMethod":"display-update","enableFullWindowDrag":false,"enableWallpaper":false},"portForward":{"port":"3389","reusePort":true}}`)
}

func TestJsonPamHardware(t *testing.T) {
	c := getCipher(t, enterprise(t), "Dell PowerEdge R740 Server")
	expectType(t, c, model.CipherTypeSecureNote)
	expectFieldCount(t, c, 3)
	expectField(t, c, "Serial Number", "SN-R740-2024-001")
	expectField(t, c, "Purchase Date", "3/14/2024, 11:00:00 PM")
	expectField(t, c, "Warranty Expiration", "3/14/2027, 11:00:00 PM")
}

func TestJsonSaasSubscription(t *testing.T) {
	c := getCipher(t, enterprise(t), "GitHub Enterprise Plan")
	expectType(t, c, model.CipherTypeSecureNote)
	expectFieldCount(t, c, 3)
	expectField(t, c, "Service Name", "GitHub")
	expectField(t, c, "Renewal Date", "6/29/2026, 10:00:00 PM")
	expectField(t, c, "Plan Type", "Enterprise")
}

func TestParseFieldKey(t *testing.T) {
	// undefined and null keys behave like "" (isNullOrWhitespace).
	for _, c := range [][3]string{
		{"", "", ""},
		{"$", "", ""},
		{"$text", "text", ""},
		{"$text:cardholderName", "text", "cardholderName"},
		{"$text:cardholderName:1", "text", "cardholderName"}, // Suffix is stripped
		{"nameOnly", "", "nameOnly"},
		{"nameOnly:1", "", "nameOnly"},       // Suffix is stripped
		{"nameOnly:123", "", "nameOnly:123"}, // Suffix is only one digit as it is in the original code
	} {
		typ, name := parseFieldKey(c[0])
		if typ != c[1] || name != c[2] {
			t.Errorf("parseFieldKey(%q) = (%q, %q), want (%q, %q)", c[0], typ, name, c[1], c[2])
		}
	}
}

// Go-only checks of the JavaScript helpers.

func TestJsonEmptyAndInvalid(t *testing.T) {
	for _, in := range []string{`{}`, `null`, `{"records":[]}`, `{"records":null}`, `5`} {
		r := importertest.Parse(t, newJson("", false), in)
		if r.Success {
			t.Errorf("%s: success", in)
		}
	}
	if _, err := newJson("", false).Parse(`{"records":[`); !importer.IsSyntaxError(err) {
		t.Errorf("want syntax error, got %v", err)
	}
}

func TestJsonKeyOrderAndStringify(t *testing.T) {
	r := importertest.Parse(t, newJson("", false), `{"records":[{"title":"x","custom_fields":{
		"$text:b":"B","2":"two","$text:a":"A","1":"one",
		"$obj":{"z":1,"10":true,"y":"q\"\n","a":[1.5,null,"s"]},
		"$num":0,"$bool":false}}]}`)
	c := r.Ciphers[0]
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("1", "one"),
		importertest.F("2", "two"),
		importertest.F("b", "B"),
		importertest.F("a", "A"),
		importertest.F("obj", `{"10":true,"z":1,"y":"q\"\n","a":[1.5,null,"s"]}`),
		importertest.F("num", "0"),
		importertest.F("bool", "false"),
	)
}

func TestJsonUrlFieldOnLoginWithoutUrlThrows(t *testing.T) {
	_, err := newJson("", false).Parse(`{"records":[{"title":"x","login":"u","custom_fields":{"$url":"https://a.b"}}]}`)
	if err == nil || err.Error() != "Cannot read properties of null (reading 'push')" {
		t.Errorf("err = %v", err)
	}
}

func TestJSHelpers(t *testing.T) {
	tm, _ := dateFromMillis(479689200000)
	if s := toUTCString(tm); s != "Thu, 14 Mar 1985 23:00:00 GMT" {
		t.Errorf("toUTCString = %q", s)
	}
	if s := toLocaleString(tm); s != "3/14/1985, 11:00:00 PM" {
		t.Errorf("toLocaleString = %q", s)
	}
	t0, _ := dateFromMillis(0)
	if s := toLocaleString(t0); s != "1/1/1970, 12:00:00 AM" {
		t.Errorf("toLocaleString(0) = %q", s)
	}
	for in, want := range map[string]float64{" 12 ": 12, "0x10": 16, "1e3": 1000, "": 0, "-5": -5, ".5": 0.5} {
		if got := jsStringToNumber(in); got != want {
			t.Errorf("Number(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"abc", "1_000", "inf", "0x", "1e"} {
		if got := jsStringToNumber(in); got == got {
			t.Errorf("Number(%q) = %v, want NaN", in, got)
		}
	}
}
