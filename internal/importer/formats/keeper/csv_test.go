package keeper

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/keeper/keeper-csv-importer.spec.ts.

func newCsv(orgID string, newItemTypes bool) importer.Importer {
	o := importertest.OrgOptions(orgID)
	o.Features.NewItemTypes = newItemTypes
	return NewCsv(o)
}

func rel(a, b int) model.Relationship { return model.Relationship{a, b} }

func TestCsvParseLoginData(t *testing.T) {
	r := importertest.Parse(t, newCsv("", false), importertest.ReadFile(t, "testData.txt"))
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	if c.Name != "Bar" || c.Login.Username != "john.doe@example.com" || c.Login.Password != "1234567890abcdef" ||
		len(c.Login.Uris) != 1 || c.Login.Uris[0].Uri != "https://example.com/" || c.Notes != "These are some notes." {
		t.Errorf("cipher 0: %s", importertest.Dump(c))
	}
	c2 := r.Ciphers[1]
	if c2.Name != "Bar 1" || c2.Login.Username != "john.doe1@example.com" || c2.Login.Password != "234567890abcdef1" ||
		len(c2.Login.Uris) != 1 || c2.Login.Uris[0].Uri != "https://an.example.com/" || c2.Notes != "" {
		t.Errorf("cipher 1: %s", importertest.Dump(c2))
	}
	c3 := r.Ciphers[2]
	if c3.Name != "Bar 2" || c3.Login.Username != "john.doe2@example.com" || c3.Login.Password != "34567890abcdef12" ||
		c3.Notes != "" || len(c3.Login.Uris) != 1 || c3.Login.Uris[0].Uri != "https://another.example.com/" {
		t.Errorf("cipher 2: %s", importertest.Dump(c3))
	}
}

func TestCsvImportTotp(t *testing.T) {
	r := importertest.Parse(t, newCsv("", false), importertest.ReadFile(t, "testData.txt"))
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	if r.Ciphers[0].Login.Totp != "" || r.Ciphers[1].Login.Totp != "" {
		t.Errorf("unexpected totp")
	}
	want := "otpauth://totp/Amazon:me@company.com?secret=JBSWY3DPEHPK3PXP&issuer=Amazon&algorithm=SHA1&digits=6&period=30"
	if r.Ciphers[2].Login.Totp != want {
		t.Errorf("totp = %q", r.Ciphers[2].Login.Totp)
	}
}

func TestCsvCustomFields(t *testing.T) {
	r := importertest.Parse(t, newCsv("", false), importertest.ReadFile(t, "testData.txt"))
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	if len(r.Ciphers[0].Fields) != 0 {
		t.Errorf("cipher 0 fields: %s", importertest.Dump(r.Ciphers[0].Fields))
	}
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[1].Fields,
		importertest.F("Account ID", "12345"), importertest.F("Org ID", "54321"))
	f := r.Ciphers[2].Fields
	if len(f) == 0 || f[0].Name != "Account ID" || f[0].Value != "23456" {
		t.Errorf("cipher 2 fields: %s", importertest.Dump(f))
	}
}

func checkGroups(t *testing.T, names []string, rels []model.Relationship, wantNames []string, wantRels []model.Relationship) {
	t.Helper()
	importertest.AssertEqualJSON(t, names, wantNames)
	importertest.AssertEqualJSON(t, rels, wantRels)
}

func TestCsvFolders(t *testing.T) {
	r := importertest.Parse(t, newCsv("", false), importertest.ReadFile(t, "testData.txt"))
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	checkGroups(t, names, r.FolderRelationships, []string{"Foo", "Foo/Baz"},
		[]model.Relationship{rel(0, 0), rel(1, 0), rel(2, 1)})
}

func TestCsvCollections(t *testing.T) {
	r := importertest.Parse(t, newCsv(importer.NewGuid(), false), importertest.ReadFile(t, "testData.txt"))
	var names []string
	for _, c := range r.Collections {
		names = append(names, c.Name)
	}
	checkGroups(t, names, r.CollectionRelationships, []string{"Foo", "Foo/Baz"},
		[]model.Relationship{rel(0, 0), rel(1, 0), rel(2, 1)})
}

func TestCsvCollectionsTree(t *testing.T) {
	r := importertest.Parse(t, newCsv(importer.NewGuid(), false), importertest.ReadFile(t, "testDataMultiCollection.txt"))
	var names []string
	for _, c := range r.Collections {
		names = append(names, c.Name)
	}
	checkGroups(t, names, r.CollectionRelationships, []string{"Foo/Baz/Bar", "Foo/Baz", "Foo"},
		[]model.Relationship{rel(0, 0), rel(1, 1), rel(2, 2)})
}

const address = "Bag End, Bagshot Row | Under-Hill | Hobbiton | Westfarthing, The Shire | US"

func TestCsvDedicatedTypesFlagOff(t *testing.T) {
	r := importertest.Parse(t, newCsv("", false), importertest.ReadFile(t, "dedicatedItemTypesData.txt"))
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	F := importertest.F

	bank := r.Ciphers[0]
	if bank.Type != model.CipherTypeLogin || bank.Name != "Test Bank Account" || bank.Login.Username != "bbaggins@gmail.com" ||
		bank.Login.Password != "d{24|452Jv/p`m7bZpJ[" || len(bank.Login.Uris) != 1 || bank.Login.Uris[0].Uri != "https://bankoftheshire.com" {
		t.Errorf("bank: %s", importertest.Dump(bank))
	}
	importertest.AssertCustomFieldsStructure(t, bank.Fields,
		F("Bank Account", "Checking | 1234567890 | 12345"), F("Name", "Bilbo Baggins"))

	passport := r.Ciphers[1]
	if passport.Type != model.CipherTypeLogin || passport.Name != "Test Passport" {
		t.Errorf("passport: %s", importertest.Dump(passport))
	}
	importertest.AssertCustomFieldsStructure(t, passport.Fields,
		F("Passport Number", "1234567890"), F("Name", "Bilbo Baggins"), F("Date of Birth", "09/22/2890"),
		F("Address", address), F("Date", "06/19/2951"), F("Date Issued", "06/19/2941"))

	dl := r.Ciphers[2]
	if dl.Type != model.CipherTypeLogin || dl.Name != "Test Drivers License" {
		t.Errorf("drivers license: %s", importertest.Dump(dl))
	}
	importertest.AssertCustomFieldsStructure(t, dl.Fields,
		F("Driver's License Number", "1234567890"), F("Name", "Bilbo Baggins"), F("Date of Birth", "09/22/2890"),
		F("Address", address), F("Date", "09/22/2916"))
}

func TestCsvDedicatedTypesFlagOn(t *testing.T) {
	r := importertest.Parse(t, newCsv("", true), importertest.ReadFile(t, "dedicatedItemTypesData.txt"))
	if len(r.Ciphers) != 4 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}

	login := r.Ciphers[0]
	if login.Type != model.CipherTypeLogin || login.Name != "Test Bank Account" || login.Login.Username != "bbaggins@gmail.com" ||
		login.Login.Password != "d{24|452Jv/p`m7bZpJ[" || len(login.Login.Uris) != 1 || login.Login.Uris[0].Uri != "https://bankoftheshire.com" {
		t.Errorf("bank login: %s", importertest.Dump(login))
	}
	importertest.AssertCustomFieldsStructure(t, login.Fields)

	bank := r.Ciphers[1]
	wantBank := model.BankAccountView{AccountType: model.BankAccountTypeChecking, AccountNumber: "1234567890", RoutingNumber: "12345", NameOnAccount: "Bilbo Baggins"}
	if bank.Type != model.CipherTypeBankAccount || bank.Name != "Test Bank Account" || *bank.BankAccount != wantBank {
		t.Errorf("bank: %s", importertest.Dump(bank))
	}
	importertest.AssertCustomFieldsStructure(t, bank.Fields)

	// The new bank account cipher should be in the same folder as the login
	if len(r.Folders) != 1 || r.Folders[0].Name != "Banks" {
		t.Errorf("folders: %s", importertest.Dump(r.Folders))
	}
	importertest.AssertEqualJSON(t, r.FolderRelationships, []model.Relationship{rel(0, 0), rel(1, 0)})

	passport := r.Ciphers[2]
	wantPassport := model.PassportView{PassportNumber: "1234567890", GivenName: "Bilbo", Surname: "Baggins",
		DateOfBirth: "2890-09-22", ExpirationDate: "2951-06-19", IssueDate: "2941-06-19"}
	if passport.Type != model.CipherTypePassport || passport.Name != "Test Passport" || *passport.Passport != wantPassport {
		t.Errorf("passport: %s", importertest.Dump(passport))
	}
	importertest.AssertCustomFieldsStructure(t, passport.Fields, importertest.F("Address", address))

	dl := r.Ciphers[3]
	wantDL := model.DriversLicenseView{LicenseNumber: "1234567890", FirstName: "Bilbo", LastName: "Baggins",
		DateOfBirth: "2890-09-22", ExpirationDate: "2916-09-22"}
	if dl.Type != model.CipherTypeDriversLicense || dl.Name != "Test Drivers License" || *dl.DriversLicense != wantDL {
		t.Errorf("drivers license: %s", importertest.Dump(dl))
	}
	importertest.AssertCustomFieldsStructure(t, dl.Fields, importertest.F("Address", address))
}
