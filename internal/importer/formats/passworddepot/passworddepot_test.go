package passworddepot

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/password-depot/password-depot-17-xml-importer.spec.ts
// and password-depot-17-macos-xml-importer.spec.ts. testdata/*.txt were extracted from
// spec-data/password-depot-xml/index.ts.

func parseWith(t *testing.T, opts importer.Options, file string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(opts), importertest.ReadFile(t, file))
}

func parse(t *testing.T, file string) *model.ImportResult {
	t.Helper()
	return parseWith(t, importertest.Options(), file)
}

func parseNewTypes(t *testing.T, file string) *model.ImportResult {
	t.Helper()
	o := importertest.Options()
	o.Features.NewItemTypes = true
	return parseWith(t, o, file)
}

// localeDate is new Date(iso).toLocaleDateString() in en-US ("M/D/YYYY", local time).
func localeDate(iso string) string {
	tm, _ := time.Parse(time.RFC3339, iso)
	l := tm.In(time.Local)
	return fmt.Sprintf("%d/%d/%d", int(l.Month()), l.Day(), l.Year())
}

func single(t *testing.T, r *model.ImportResult) *model.CipherView {
	t.Helper()
	if len(r.Ciphers) != 1 {
		t.Fatalf("got %d ciphers: %s", len(r.Ciphers), importertest.Dump(r.Ciphers))
	}
	return r.Ciphers[0]
}

func TestErrors(t *testing.T) {
	if r := parse(t, "InvalidRootNodeData.txt"); r.ErrorMessage != "Missing `passwordfile` node." {
		t.Errorf("root: %q", r.ErrorMessage)
	}
	if r := parse(t, "InvalidVersionData.txt"); r.ErrorMessage != "Unsupported export version detected - (only 17.0 is supported)" {
		t.Errorf("version: %q", r.ErrorMessage)
	}
	if r := parse(t, "EncryptedFileData.txt"); r.ErrorMessage != "Encrypted Password Depot files are not supported." {
		t.Errorf("encrypted: %q", r.ErrorMessage)
	}
	if r := parse(t, "MissingPasswordsNodeData.txt"); r.Success || r.ErrorMessage != "Missing `passwordfile > passwords` node." {
		t.Errorf("passwords: %q", r.ErrorMessage)
	}
}

func TestGroupsIntoFolders(t *testing.T) {
	r := parse(t, "PasswordTestData.txt")
	if len(r.Folders) != 1 || r.Folders[0].Name != "tempDB" || r.Folders[0].ID != "" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
}

func TestPasswordType(t *testing.T) {
	r := parse(t, "PasswordTestData.txt")
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "password type" || c.Notes != "someComment" || c.Login == nil ||
		c.Login.Username != "someUser" || c.Login.Password != "p6J<]fmjv!:H&iJ7/Mwt@3i8" || c.Login.Uri() != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestUnmappedFields(t *testing.T) {
	r := parse(t, "PasswordTestData.txt")
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "password type" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	F := importertest.F
	text, hidden, boolean := model.FieldTypeText, model.FieldTypeHidden, model.FieldTypeBoolean
	importertest.AssertCustomFieldsExist(t, c.Fields,
		F("lastmodified", "07.05.2025 13:37:56", text),
		F("expirydate", "07.05.2025", text),
		F("importance", "0"),
		F("passwort", "password", hidden),
		F("memo", "memo", text),
		F("datum", localeDate("2025-05-13T00:00:00Z"), text),
		F("nummer", "1", text),
		F("boolean", "1", boolean),
		F("decimal", "1,01", text),
		F("email", "who@cares.com", text),
		F("url", "example.com", text),
	)
}

func TestCreditCard(t *testing.T) {
	c := single(t, parse(t, "CreditCardTestData.txt"))
	if c.Name != "some CreditCard" || c.Notes != "someComment" || c.Card == nil {
		t.Fatalf("%s", importertest.Dump(c))
	}
	want := model.CardView{CardholderName: "some CC holder", Number: "4222422242224222", Brand: "Visa", ExpMonth: "5", ExpYear: "2026", Code: "123"}
	if got := *c.Card; got.CardholderName != want.CardholderName || got.Number != want.Number || got.Brand != want.Brand ||
		got.ExpMonth != want.ExpMonth || got.ExpYear != want.ExpYear || got.Code != want.Code {
		t.Fatalf("%s", importertest.Dump(c.Card))
	}
}

func TestIdentity(t *testing.T) {
	c := single(t, parse(t, "IdentityTestData.txt"))
	if c.Name != "identity type" || c.Notes != "someNote" || c.Identity == nil {
		t.Fatalf("%s", importertest.Dump(c))
	}
	id := c.Identity
	got := []string{id.FirstName, id.LastName, id.Email, id.Company, id.Address1, id.Address2, id.City, id.State, id.PostalCode, id.Country, id.Phone}
	want := []string{"firstName", "surName", "email", "someCompany", "someStreet", "address 2", "town", "state", "zipCode", "country", "phoneNumber"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestRDP(t *testing.T) {
	c := single(t, parse(t, "RDPTestData.txt"))
	if c.Type != model.CipherTypeLogin || c.Name != "rdp type" || c.Notes != "someNote" || c.Login == nil ||
		c.Login.Username != "someUser" || c.Login.Password != "somePassword" || c.Login.Uri() != "ms-rd:subscribe?url=https://contoso.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestSoftwareLicense(t *testing.T) {
	c := single(t, parse(t, "SoftwareLicenseTestData.txt"))
	if c.Type != model.CipherTypeSecureNote || c.Name != "software-license type" || c.Notes != "someComment" ||
		c.SecureNote == nil || c.SecureNote.Type != model.SecureNoteTypeGeneric {
		t.Fatalf("%s", importertest.Dump(c))
	}
	F := importertest.F
	importertest.AssertCustomFieldsExist(t, c.Fields,
		F("IDS_LicenseProduct", "someProduct"),
		F("IDS_LicenseVersion", "someVersion"),
		F("IDS_LicenseName", "some User"),
		F("IDS_LicenseKey", "license-key"),
		F("IDS_LicenseAdditionalKey", "additional-license-key"),
		F("IDS_LicenseURL", "example.com"),
		F("IDS_LicenseProtected", "1"),
		F("IDS_LicenseUserName", "someUserName"),
		F("IDS_LicensePassword", "somePassword"),
		F("IDS_LicensePurchaseDate", localeDate("2025-05-12T00:00:00Z")),
		F("IDS_LicenseOrderNumber", "order number"),
		F("IDS_LicenseEmail", "someEmail"),
		F("IDS_LicenseExpires", "Nie"),
	)
}

func TestTeamViewer(t *testing.T) {
	c := single(t, parse(t, "TeamViewerTestData.txt"))
	if c.Type != model.CipherTypeLogin || c.Name != "TeamViewer type" || c.Notes != "someNote" || c.Login == nil ||
		c.Login.Password != "somePassword" || c.Login.Username != "" || c.Login.Uri() != "partnerId" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsExist(t, c.Fields, importertest.F("IDS_TeamViewerMode", "0"))
}

func TestPutty(t *testing.T) {
	c := single(t, parse(t, "PuttyTestData.txt"))
	if c.Type != model.CipherTypeLogin || c.Name != "Putty type" || c.Notes != "someNote" || c.Login == nil ||
		c.Login.Password != "somePassword" || c.Login.Username != "someUser" || c.Login.Uri() != "localhost" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	F := importertest.F
	importertest.AssertCustomFieldsExist(t, c.Fields,
		F("IDS_PuTTyProtocol", "0"),
		F("IDS_PuTTyKeyFile", "pathToKeyFile"),
		F("IDS_PuTTyKeyPassword", "passwordForKeyFile"),
		F("IDS_PuTTyPort", "8080"),
	)
}

var tanFields = []importertest.Field{
	importertest.F("tan_1_value", "1234"),
	importertest.F("tan_1_used", "12.05.2025 15:10:54"),
	importertest.F("tan_1_amount", " 100,00"),
	importertest.F("tan_1_comment", "some TAN note"),
	importertest.F("tan_1_ccode", "123"),
	importertest.F("tan_2_value", "4321"),
	importertest.F("tan_2_amount", " 0,00"),
}

func checkBankingLogin(t *testing.T, c *model.CipherView) {
	t.Helper()
	if c.Type != model.CipherTypeLogin || c.Name != "banking type" || c.Notes != "someNote" || c.Login == nil ||
		c.Login.Password != "somePassword" || c.Login.Username != "someUser" || c.Login.Uri() != "http://some-bank.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestBankingFlagOff(t *testing.T) {
	c := single(t, parse(t, "BankingTestData.txt"))
	checkBankingLogin(t, c)
	F := importertest.F
	importertest.AssertCustomFieldsExist(t, c.Fields, append([]importertest.Field{
		F("IDS_ECHolder", "account holder"),
		F("IDS_ECAccountNumber", "1234567890"),
		F("IDS_ECBLZ", "12345678"),
		F("IDS_ECBankName", "someBank"),
		F("IDS_ECBIC", "bic"),
		F("IDS_ECIBAN", "iban"),
		F("IDS_ECCardNumber", "12345678"),
		F("IDS_ECPhone", "0049"),
		F("IDS_ECLegitimacyID", "1234"),
		F("IDS_ECPIN", "123"),
	}, tanFields...)...)
}

func TestBankingFlagOn(t *testing.T) {
	r := parseNewTypes(t, "BankingTestData.txt")
	if len(r.Ciphers) != 2 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	var login, bank *model.CipherView
	for _, c := range r.Ciphers {
		switch c.Type {
		case model.CipherTypeLogin:
			if login == nil {
				login = c
			}
		case model.CipherTypeBankAccount:
			if bank == nil {
				bank = c
			}
		}
	}
	if login == nil || bank == nil {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	if len(r.Folders) != 1 || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {1, 0}}) {
		t.Fatalf("folders %s %v", importertest.Dump(r.Folders), r.FolderRelationships)
	}
	checkBankingLogin(t, login)
	F := importertest.F
	importertest.AssertCustomFieldsExist(t, login.Fields, append([]importertest.Field{
		F("IDS_ECBIC", "bic"),
		F("IDS_ECCardNumber", "12345678"),
		F("IDS_ECLegitimacyID", "1234"),
	}, tanFields...)...)

	b := bank.BankAccount
	if bank.Name != "banking type" || b.NameOnAccount != "account holder" || b.AccountNumber != "1234567890" ||
		b.RoutingNumber != "12345678" || b.BankName != "someBank" || b.Iban != "iban" || b.BankContactPhone != "0049" || b.Pin != "123" {
		t.Fatalf("%s", importertest.Dump(bank))
	}
	if len(bank.Fields) != 0 {
		t.Fatalf("bank fields %s", importertest.Dump(bank.Fields))
	}
}

func TestInformation(t *testing.T) {
	c := single(t, parse(t, "InformationTestData.txt"))
	if c.Type != model.CipherTypeSecureNote || c.Name != "information type" || c.Notes != "some note content" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestCertificate(t *testing.T) {
	c := single(t, parse(t, "CertificateTestData.txt"))
	if c.Type != model.CipherTypeLogin || c.Name != "certificate type" || c.Notes != "someNote" || c.Login == nil || c.Login.Password != "somePassword" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestEncryptedFile(t *testing.T) {
	c := single(t, parse(t, "EncryptedFileTestData.txt"))
	if c.Type != model.CipherTypeLogin || c.Name != "encrypted file type" || c.Notes != "some comment" || c.Login == nil || c.Login.Password != "somePassword" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestDocument(t *testing.T) {
	c := single(t, parse(t, "DocumentTestData.txt"))
	if c.Type != model.CipherTypeSecureNote || c.Name != "document type" || c.Notes != "document comment" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	F := importertest.F
	importertest.AssertCustomFieldsExist(t, c.Fields,
		F("IDS_DocumentSize", "27071"),
		F("IDS_DocumentFolder", `C:\Users\DJSMI\Downloads\`),
		F("IDS_DocumentFile", `C:\Users\DJSMI\Downloads\some.pdf`),
	)
}

func TestFavourites(t *testing.T) {
	r := parse(t, "PasswordTestData.txt")
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	for i, want := range []struct {
		name string
		fav  bool
	}{{"password type", false}, {"password type (2)", true}, {"password type (3)", true}} {
		if r.Ciphers[i].Name != want.name || r.Ciphers[i].Favorite != want.fav {
			t.Errorf("cipher %d: %q favorite=%v", i, r.Ciphers[i].Name, r.Ciphers[i].Favorite)
		}
	}
}

func TestCollections(t *testing.T) {
	r := parseWith(t, importertest.OrgOptions("someOrgId"), "PasswordTestData.txt")
	importertest.AssertEqualJSON(t, r.Collections, []*model.CollectionView{{Name: "tempDB", OrganizationID: "someOrgId"}})
}

// password-depot-17-macos-xml-importer.spec.ts

func TestMacOSWrongVersion(t *testing.T) {
	if r := parse(t, "MacOS_WrongVersion.txt"); r.ErrorMessage != "Unsupported export version detected - (only 17.0 is supported)" {
		t.Errorf("%q", r.ErrorMessage)
	}
}

func TestMacOSNullFingerprint(t *testing.T) {
	if r := parse(t, "MacOS_PasswordDepotXmlFile.txt"); len(r.Folders) != 0 {
		t.Errorf("%s", importertest.Dump(r.Folders))
	}
}

func TestMacOSMultipleFolders(t *testing.T) {
	for _, tc := range []struct {
		newTypes bool
		ciphers  int
		rels     []model.Relationship
	}{
		{false, 10, []model.Relationship{{5, 0}, {6, 0}, {7, 0}, {8, 1}, {9, 1}}},
		{true, 11, []model.Relationship{{6, 0}, {7, 0}, {8, 0}, {9, 1}, {10, 1}}},
	} {
		var r *model.ImportResult
		if tc.newTypes {
			r = parseNewTypes(t, "MacOS_MultipleFolders.txt")
		} else {
			r = parse(t, "MacOS_MultipleFolders.txt")
		}
		if len(r.Ciphers) != tc.ciphers {
			t.Errorf("newTypes=%v: got %d ciphers", tc.newTypes, len(r.Ciphers))
		}
		if len(r.Folders) != 2 || r.Folders[0].Name != "folder macos" || r.Folders[1].Name != "folder 2" {
			t.Errorf("folders %s", importertest.Dump(r.Folders))
		}
		if len(r.FolderRelationships) < 5 || !reflect.DeepEqual(r.FolderRelationships[:5], tc.rels) {
			t.Errorf("newTypes=%v: relationships %v", tc.newTypes, r.FolderRelationships)
		}
	}
}

func TestMacOSCustomFields(t *testing.T) {
	c := single(t, parse(t, "MacOS_PasswordDepotXmlFile.txt"))
	if c.Name != "card 1" || c.Notes != "comment" || c.Card == nil || c.Card.CardholderName != "some CC holder" ||
		c.Card.Number != "4242424242424242" || c.Card.Brand != "Visa" || c.Card.ExpMonth != "8" || c.Card.ExpYear != "2028" || c.Card.Code != "125" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestJSHelpers(t *testing.T) {
	for in, want := range map[string]bool{"45790": false, "": false, " 1e3 ": false, "0x1F": false, "1,01": true, "abc": true, "Infinity": false} {
		if got := isNaNNumber(in); got != want {
			t.Errorf("isNaN(%q) = %v", in, got)
		}
	}
	if got := excelDateToLocaleDateString("", false); got != "Invalid Date" {
		t.Errorf("null date: %q", got)
	}
	if s, err := atob("YWJj\nZA"); err != nil || s != "abcd" {
		t.Errorf("atob: %q %v", s, err)
	}
	if _, err := atob("a"); err == nil {
		t.Error("atob should fail")
	}
}
