package protonpass

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/protonpass/protonpass-json-importer.spec.ts and
// protonpass-import-utils.spec.ts. Fixtures: spec-data/protonpass-json/*.json.ts (extracted with
// testdata/extract-spec-data.mjs; the spec JSON.stringify()s them).

var (
	text   = model.FieldTypeText
	hidden = model.FieldTypeHidden
	F      = importertest.F
)

func newImporter(newItemTypes bool, orgID string) importer.Importer {
	o := importertest.Options()
	o.OrganizationID = orgID
	o.Features.NewItemTypes = newItemTypes
	return New(o)
}

func expectParse(t *testing.T, imp importer.Importer, fixture string, expectedNumberOfCiphers int) *model.ImportResult {
	t.Helper()
	result := importertest.Parse(t, imp, importertest.ReadFile(t, fixture))
	if len(result.Ciphers) != expectedNumberOfCiphers {
		t.Fatalf("got %d ciphers, want %d", len(result.Ciphers), expectedNumberOfCiphers)
	}
	return result
}

const testData = "protonpass.json"
const dedicatedItemsTestData = "protonpass-dedicated-types.json"

func TestParseLoginData(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	cipher := result.Ciphers[0]
	if cipher.Name != "Test Login - Personal Vault" || cipher.Type != model.CipherTypeLogin ||
		cipher.Login.Username != "Username" || cipher.Login.Password != "Password" ||
		len(cipher.Login.Uris) != 2 || cipher.Login.Uris[0].Uri != "https://example.com/" ||
		cipher.Notes != "My login secure note." {
		t.Fatalf("%s", importertest.Dump(cipher))
	}
	importertest.AssertCustomFieldsStructure(t, cipher.Fields,
		F("email", "Email", text),
		F("non-hidden field", "non-hidden field content", text),
		F("hidden field", "hidden field content", hidden),
		F("second 2fa secret", "TOTPCODE", hidden),
	)
}

func TestParseNoteData(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	c := result.Ciphers[1]
	if c.Type != model.CipherTypeSecureNote || c.Name != "My Secure Note" || c.Notes != "Secure note contents." {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("note text field", "note text value", text),
		F("note hidden field", "note hidden value", hidden),
	)
}

func TestParseCreditCardData(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	c := result.Ciphers[2]
	if c.Type != model.CipherTypeCard || c.Card.Number != "1234222233334444" || c.Card.CardholderName != "Test name" ||
		c.Card.ExpMonth != "1" || c.Card.ExpYear != "2025" || c.Card.Code != "333" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("PIN", "1234", hidden),
		F("card text field", "card text value", text),
		F("card hidden field", "card hidden value", hidden),
	)
}

func TestCreateFolders(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	if len(result.Folders) != 2 || result.Folders[0].Name != "Personal" || result.Folders[1].Name != "Test" {
		t.Fatalf("%s", importertest.Dump(result.Folders))
	}
	if result.FolderRelationships[1] != (model.Relationship{1, 0}) || result.FolderRelationships[9] != (model.Relationship{9, 1}) {
		t.Fatalf("%v", result.FolderRelationships)
	}
}

func TestCreateCollections(t *testing.T) {
	result := expectParse(t, newImporter(false, importer.NewGuid()), testData, 10)
	if len(result.Collections) != 2 || result.Collections[0].Name != "Personal" || result.Collections[1].Name != "Test" {
		t.Fatalf("%s", importertest.Dump(result.Collections))
	}
	if result.CollectionRelationships[1] != (model.Relationship{1, 0}) || result.CollectionRelationships[9] != (model.Relationship{9, 1}) {
		t.Fatalf("%v", result.CollectionRelationships)
	}
}

func TestNoDeletedItems(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	for _, c := range result.Ciphers {
		if c.Name == "My Deleted Note" {
			t.Fatal("deleted item imported")
		}
	}
}

func TestFavorites(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	if !result.Ciphers[0].Favorite || result.Ciphers[1].Favorite || !result.Ciphers[2].Favorite {
		t.Fatal("favorites mismatch")
	}
}

func TestAliasAsLogin(t *testing.T) {
	result := importertest.Parse(t, newImporter(false, ""), importertest.ReadFile(t, testData))
	c := result.Ciphers[4]
	if c.Name != "Alias" || c.Type != model.CipherTypeLogin || c.Login.Username != "alias.removing005@passinbox.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestCustomItemAsSecureNote(t *testing.T) {
	result := importertest.Parse(t, newImporter(false, ""), importertest.ReadFile(t, testData))
	c := result.Ciphers[5]
	if c.Name != "Custom Item" || c.Type != model.CipherTypeSecureNote || c.Notes != "custom item note" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("Account number", "123456789", text),
		F("PIN", "0000", hidden),
		// Fields nested in content sections are preserved as custom fields
		F("SectionField", "section value", text),
	)
}

func TestSshKey(t *testing.T) {
	result := importertest.Parse(t, newImporter(false, ""), importertest.ReadFile(t, testData))
	c := result.Ciphers[6]
	if c.Name != "SSH Key Item" || c.Type != model.CipherTypeSshKey ||
		c.SshKey.PrivateKey != "-----BEGIN PRIVATE KEY-----\nPRIVATEKEYCONTENT\n-----END PRIVATE KEY-----\n" ||
		c.SshKey.PublicKey != "ssh-ed25519 AAAAPUBLICKEY" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, F("Host", "example.com"))
}

var identityFields = []importertest.Field{
	F("gender", "Male", text),
	F("TestPersonal", "Personal", text),
	F("TestAddress", "Address", text),
	F("xHandle", "@twitter", text),
	F("secondPhoneNumber", "243538978", text),
	F("instagram", "@insta", text),
	F("TestContact", "Contact", hidden),
	F("jobTitle", "Engineer", text),
	F("workPhoneNumber", "78236476238746", text),
	F("TestWork", "Work", hidden),
	F("TestSection", "Section", text),
	F("TestSectionHidden", "SectionHidden", hidden),
	F("TestExtra", "Extra", text),
}

func checkIdentity(t *testing.T, c *model.CipherView, passport, license string) {
	t.Helper()
	want := model.IdentityView{
		FirstName: "Test", MiddleName: "1", LastName: "1", Email: "test@gmail.com", Phone: "7507951789",
		Company: "Bitwarden", Ssn: "98378264782", PassportNumber: passport, LicenseNumber: license,
		Address1: "Bitwarden", Address2: "23 Street", Address3: "12th Floor Test County", City: "New York",
		State: "Test", PostalCode: "4038456", Country: "US",
	}
	if c.Type != model.CipherTypeIdentity || *c.Identity != want {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, identityFields...)
}

func TestIdentityFlagOff(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	checkIdentity(t, result.Ciphers[3], "7173716378612", "21234")
}

func TestIdentityFlagOn(t *testing.T) {
	// Since the test data has an identity that includes both a driver's license number and a
	// passport number there are two extra ciphers
	result := expectParse(t, newImporter(true, ""), testData, 12)

	var identityRels []model.Relationship
	for _, rel := range result.FolderRelationships {
		if rel[0] == 5 {
			identityRels = append(identityRels, rel)
		}
	}
	if len(identityRels) != 1 {
		t.Fatalf("%v", result.FolderRelationships)
	}
	hasRel := func(cipherIdx int) bool {
		for _, rel := range result.FolderRelationships {
			if rel[0] == cipherIdx && rel[1] == identityRels[0][1] {
				return true
			}
		}
		return false
	}

	if dl := result.Ciphers[3]; dl.Type != model.CipherTypeDriversLicense || dl.DriversLicense.LicenseNumber != "21234" || !hasRel(3) {
		t.Fatalf("%s", importertest.Dump(dl))
	}
	if pp := result.Ciphers[4]; pp.Type != model.CipherTypePassport || pp.Passport.PassportNumber != "7173716378612" || !hasRel(4) {
		t.Fatalf("%s", importertest.Dump(pp))
	}
	checkIdentity(t, result.Ciphers[5], "", "")
}

func TestBankAccountFlagOff(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[0]
	if c.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("Bank Name", "Bank of the Shire", text),
		F("Account Number", "1234567890", text),
		F("Routing Number", "123456", text),
		F("Account Type", "Checking", text),
		F("IBAN", "123456", hidden),
		F("SWIFT/BIC", "1234", text),
		F("Holder Name", "Bilbo Baggins", text),
	)
}

func TestBankAccountFlagOn(t *testing.T) {
	result := expectParse(t, newImporter(true, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[0]
	want := model.BankAccountView{
		BankName: "Bank of the Shire", AccountNumber: "1234567890", RoutingNumber: "123456",
		AccountType: model.BankAccountTypeChecking, Iban: "123456", SwiftCode: "1234", NameOnAccount: "Bilbo Baggins",
	}
	if c.Type != model.CipherTypeBankAccount || *c.BankAccount != want {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestDriversLicenseFlagOff(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[1]
	if c.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("Full Name", "Bilbo Baggins", text),
		F("License Number", "123456789", text),
		F("Issuing State/Country", "The Shire", text),
		F("Expiry Date", "2951-06-19", text),
		F("Date of Birth", "2890-09-22", text),
		F("Class", "D", text),
	)
}

func TestDriversLicenseFlagOn(t *testing.T) {
	result := expectParse(t, newImporter(true, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[1]
	want := model.DriversLicenseView{
		FirstName: "Bilbo", LastName: "Baggins", LicenseNumber: "123456789", IssuingState: "The Shire",
		ExpirationDate: "2951-06-19", DateOfBirth: "2890-09-22", LicenseClass: "D",
	}
	if c.Type != model.CipherTypeDriversLicense || *c.DriversLicense != want {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestPassportFlagOff(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[2]
	if c.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("Full Name", "Bilbo Baggins", text),
		F("Passport Number", "1234567890", hidden),
		F("Country", "The Shire", text),
		F("Expiry Date", "2951-06-19", text),
		F("Date of Birth", "2890-09-22", text),
		F("Issuing Authority", "Hobbiton Consulate", text),
	)
}

func TestPassportFlagOn(t *testing.T) {
	result := expectParse(t, newImporter(true, ""), dedicatedItemsTestData, 3)
	c := result.Ciphers[2]
	want := model.PassportView{
		GivenName: "Bilbo", Surname: "Baggins", PassportNumber: "1234567890", IssuingCountry: "The Shire",
		ExpirationDate: "2951-06-19", DateOfBirth: "2890-09-22", IssuingAuthority: "Hobbiton Consulate",
	}
	if c.Type != model.CipherTypePassport || *c.Passport != want {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestWifi(t *testing.T) {
	// The spec mocks i18nService.t; the Go port uses the CLI's English messages.
	result := expectParse(t, newImporter(false, ""), testData, 10)
	c := result.Ciphers[7]
	if c.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("Password", "SECRETSECRETSECRET", hidden),
		F("SSID", "Test Network", text),
		F("Security", "WPA3", text),
		F("Custom Field", "Custom Field Value", text),
	)
}

func TestUnknownItemType(t *testing.T) {
	result := expectParse(t, newImporter(false, ""), testData, 10)
	c := result.Ciphers[8]
	if c.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		F("newNumberProperty", "1", text),
		F("newStringProperty", "test", text),
		F("Custom Field", "Custom Field Value", text),
	)
}

// Go-only checks of the result-level branches.

func TestEncryptedAndInvalid(t *testing.T) {
	r := importertest.Parse(t, newImporter(false, ""), `{"encrypted":true,"vaults":{}}`)
	if r.Success || r.ErrorMessage != "Importing encrypted files is currently not supported." {
		t.Fatalf("%s", importertest.Dump(r))
	}
	for _, in := range []string{`null`, `{}`, `[]`, `{"vaults":null}`} {
		r := importertest.Parse(t, newImporter(false, ""), in)
		if r.Success {
			t.Errorf("%s: expected success=false", in)
		}
	}
	if _, err := newImporter(false, "").Parse(`{`); !importer.IsSyntaxError(err) {
		t.Errorf("expected a syntax error, got %v", err)
	}
	if _, err := newImporter(false, "").Parse(`{"vaults":{"a":{"name":"x"}}}`); err == nil {
		t.Error("expected a TypeError for missing items")
	}
	// Short expiration dates must not panic (String.prototype.substring clamps).
	r = importertest.Parse(t, newImporter(false, ""), `{"vaults":{"a":{"name":"x","items":[{"state":1,"pinned":false,
		"data":{"type":"creditCard","metadata":{"name":"c","note":""},"extraFields":[],"content":{"expirationDate":"2025"}}}]}}}`)
	if c := r.Ciphers[0]; c.Card.ExpYear != "2025" || c.Card.ExpMonth != "" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestProcessNames(t *testing.T) {
	cases := []struct {
		title                           string
		full, first, middle, last       string
		wantFirst, wantMiddle, wantLast string
	}{
		{"should use only fullName to map names if it contains at least three words, ignoring individual name fields",
			"Alice Beth Carter", "Kevin", "", "", "Alice", "Beth", "Carter"},
		{"should map extra words to the middle name if fullName contains more than three words",
			"Alice Beth Middle Carter", "", "", "", "Alice", "Beth Middle", "Carter"},
		{"should map names correctly even if fullName has words separated by more than one space",
			"Alice    Carter", "", "", "", "Alice", "", "Carter"},
		{"should handle a single name in fullName and use middleName and lastName to populate rest of names",
			"Alice", "", "Beth", "Carter", "Alice", "Beth", "Carter"},
		{"should correctly map fullName when it only contains two words",
			"Alice Carter", "", "", "", "Alice", "", "Carter"},
		{"should map middle name from middleName if fullName only contains two words",
			"Alice Carter", "", "Beth", "", "Alice", "Beth", "Carter"},
		{"should fall back to firstName, middleName, and lastName if fullName is empty",
			"", "Alice", "Beth", "Carter", "Alice", "Beth", "Carter"},
	}
	for _, c := range cases {
		f, m, l := processNames(c.full, c.first, c.middle, c.last)
		if f != c.wantFirst || m != c.wantMiddle || l != c.wantLast {
			t.Errorf("%s: got (%q, %q, %q)", c.title, f, m, l)
		}
	}
}
