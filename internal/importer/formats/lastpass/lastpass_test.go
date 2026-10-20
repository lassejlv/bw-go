package lastpass

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/lastpass/lastpass-csv-importer.spec.ts.

func newImporter(newItemTypes bool) importer.Importer {
	o := importertest.Options()
	o.Features.NewItemTypes = newItemTypes
	return New(o)
}

func TestCardNotes(t *testing.T) {
	cases := []struct {
		title, csv, name, notes string
		card                    model.CardView
		fields                  []importertest.Field
	}{
		{
			title: "should parse expiration date",
			csv: `url,username,password,extra,name,grouping,fav
http://sn,,,"NoteType:Credit Card
Name on Card:John Doe
Type:
Number:1234567812345678
Security Code:123
Start Date:October,2017
Expiration Date:June,2020
Notes:some text
",Credit-card,,0`,
			name:   "Credit-card",
			notes:  "some text\n",
			card:   model.CardView{CardholderName: "John Doe", Number: "1234567812345678", Code: "123", ExpYear: "2020", ExpMonth: "6"},
			fields: []importertest.Field{importertest.F("Start Date", "October,2017", model.FieldTypeText)},
		},
		{
			title: "should parse blank card note",
			csv: `url,username,password,extra,name,grouping,fav
http://sn,,,"NoteType:Credit Card
Name on Card:
Type:
Number:
Security Code:
Start Date:,
Expiration Date:,
Notes:",empty,,0`,
			name:   "empty",
			card:   model.CardView{},
			fields: []importertest.Field{importertest.F("Start Date", ",", model.FieldTypeText)},
		},
		{
			title: "should parse card expiration date w/ no exp year",
			csv: `url,username,password,extra,name,grouping,fav
http://sn,,,"NoteType:Credit Card
Name on Card:John Doe
Type:Visa
Number:1234567887654321
Security Code:321
Start Date:,
Expiration Date:January,
Notes:",noyear,,0`,
			name: "noyear",
			card: model.CardView{CardholderName: "John Doe", Number: "1234567887654321", Code: "321", ExpMonth: "1"},
			fields: []importertest.Field{
				importertest.F("Type", "Visa", model.FieldTypeText),
				importertest.F("Start Date", ",", model.FieldTypeText),
			},
		},
		{
			title: "should parse card expiration date w/ no month",
			csv: `url,username,password,extra,name,grouping,fav
http://sn,,,"NoteType:Credit Card
Name on Card:John Doe
Type:Mastercard
Number:8765432112345678
Security Code:987
Start Date:,
Expiration Date:,2020
Notes:",nomonth,,0`,
			name: "nomonth",
			card: model.CardView{CardholderName: "John Doe", Number: "8765432112345678", Code: "987", ExpYear: "2020"},
			fields: []importertest.Field{
				importertest.F("Type", "Mastercard", model.FieldTypeText),
				importertest.F("Start Date", ",", model.FieldTypeText),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, newImporter(false), c.csv)
			if len(r.Ciphers) != 1 {
				t.Fatalf("%s", importertest.Dump(r))
			}
			cipher := r.Ciphers[0]
			if cipher.Name != c.name || cipher.Type != model.CipherTypeCard || (c.notes != "" && cipher.Notes != c.notes) || *cipher.Card != c.card {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
			importertest.AssertCustomFieldsStructure(t, cipher.Fields, c.fields...)
		})
	}
}

func TestLoginWithTotp(t *testing.T) {
	input := `url,username,password,totp,extra,name,grouping,fav
        http://example.com,someUser,myPassword,Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G,super secure notes,example.com,,0`
	r := importertest.Parse(t, newImporter(false), input)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "example.com" || c.Notes != "super secure notes" ||
		c.Login.Uri() != "http://example.com" || c.Login.Username != "someUser" || c.Login.Password != "myPassword" ||
		c.Login.Totp != "Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

const bankAccountCSV = `url,username,password,totp,extra,name,grouping,fav
http://sn,,,,"NoteType:Bank Account
Language:
Bank Name:Bank of the Shire
Account Type:Checking
Routing Number:123456
Account Number:1234567890
SWIFT Code:123
IBAN Number:1234
Pin:1111
Branch Address:1 Main Street, Bree, Bree-hill, Eriador
Branch Phone:1112223333
Notes:",Test Bank Account,Tools Test Items,0`

const passportCSV = `url,username,password,totp,extra,name,grouping,fav
http://sn,,,,"NoteType:Passport
Language:en-US
Type:Shire Passport
Name:Bilbo Baggins
Country:The Shire
Number:1234567890
Sex:Male
Nationality:Shire-folk
Issuing Authority:The Shire
Date of Birth:September,22,2890
Issued Date:June,19,2941
Expiration Date:June,19,2951
Notes:",Test Passport,Tools Test Items,0`

const driversLicenseCSV = `url,username,password,totp,extra,name,grouping,fav
http://sn,,,,"NoteType:Driver's License
Language:en-US
Number:1234567890
Expiration Date:September,22,2926
License Class:D
Name:Bilbo Baggins
Address:Bag End, Bagshot Row, Underhill
City / Town:Hobbiton
State:Westfarthing
ZIP / Postal Code:00000
Country:The Shire
Date of Birth:September,22,2890
Sex:Male
Height:4'0""
Notes:",Test Drivers License,Tools Test Items,0`

func single(t *testing.T, newTypes bool, csv string) *model.CipherView {
	t.Helper()
	r := importertest.Parse(t, newImporter(newTypes), csv)
	if len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != "Tools Test Items" || len(r.FolderRelationships) != 1 {
		t.Fatalf("folders %s", importertest.Dump(r.Folders))
	}
	return r.Ciphers[0]
}

func TestBankAccount(t *testing.T) {
	c := single(t, false, bankAccountCSV)
	if c.Name != "Test Bank Account" || c.Type != model.CipherTypeSecureNote || c.Notes != `NoteType:Bank Account
Language:
Bank Name:Bank of the Shire
Account Type:Checking
Routing Number:123456
Account Number:1234567890
SWIFT Code:123
IBAN Number:1234
Pin:1111
Branch Address:1 Main Street, Bree, Bree-hill, Eriador
Branch Phone:1112223333
Notes:` {
		t.Fatalf("flag off: %s", importertest.Dump(c))
	}

	c = single(t, true, bankAccountCSV)
	want := model.BankAccountView{BankName: "Bank of the Shire", AccountType: model.BankAccountTypeChecking, RoutingNumber: "123456",
		AccountNumber: "1234567890", SwiftCode: "123", Iban: "1234", Pin: "1111", BankContactPhone: "1112223333"}
	if c.Name != "Test Bank Account" || c.Type != model.CipherTypeBankAccount || *c.BankAccount != want {
		t.Fatalf("flag on: %s", importertest.Dump(c))
	}
}

func TestPassport(t *testing.T) {
	c := single(t, false, passportCSV)
	if c.Type != model.CipherTypeSecureNote || c.Notes != `NoteType:Passport
Language:en-US
Type:Shire Passport
Name:Bilbo Baggins
Country:The Shire
Number:1234567890
Sex:Male
Nationality:Shire-folk
Issuing Authority:The Shire
Date of Birth:September,22,2890
Issued Date:June,19,2941
Expiration Date:June,19,2951
Notes:` {
		t.Fatalf("flag off: %s", importertest.Dump(c))
	}

	c = single(t, true, passportCSV)
	want := model.PassportView{PassportType: "Shire Passport", GivenName: "Bilbo", Surname: "Baggins", IssuingCountry: "The Shire",
		PassportNumber: "1234567890", Nationality: "Shire-folk", IssuingAuthority: "The Shire",
		DateOfBirth: "2890-09-22", IssueDate: "2941-06-19", ExpirationDate: "2951-06-19"}
	if c.Name != "Test Passport" || c.Type != model.CipherTypePassport || *c.Passport != want {
		t.Fatalf("flag on: %s", importertest.Dump(c))
	}
}

func TestDriversLicense(t *testing.T) {
	c := single(t, false, driversLicenseCSV)
	if c.Type != model.CipherTypeSecureNote || c.Notes != `NoteType:Driver's License
Language:en-US
Number:1234567890
Expiration Date:September,22,2926
License Class:D
Name:Bilbo Baggins
Address:Bag End, Bagshot Row, Underhill
City / Town:Hobbiton
State:Westfarthing
ZIP / Postal Code:00000
Country:The Shire
Date of Birth:September,22,2890
Sex:Male
Height:4'0"
Notes:` {
		t.Fatalf("flag off: %s", importertest.Dump(c))
	}

	c = single(t, true, driversLicenseCSV)
	want := model.DriversLicenseView{LicenseNumber: "1234567890", ExpirationDate: "2926-09-22", LicenseClass: "D",
		FirstName: "Bilbo", LastName: "Baggins", IssuingState: "Westfarthing", IssuingCountry: "The Shire", DateOfBirth: "2890-09-22"}
	if c.Name != "Test Drivers License" || c.Type != model.CipherTypeDriversLicense || *c.DriversLicense != want {
		t.Fatalf("flag on: %s", importertest.Dump(c))
	}
}

func TestFormFillProfiles(t *testing.T) {
	csv := `profilename,profilelanguage,title,firstname,lastname,ccname,ccnum,cccsc,ccexp,notes
Me,en-US,mr,John,Doe,John Doe,4111111111111111,123,2025-03,profile notes
Card only,en-US,,,,Jane,5555555555554444,456,2026-11,`
	r := importertest.Parse(t, newImporter(false), csv)
	if len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	card, id, cardOnly := r.Ciphers[0], r.Ciphers[1], r.Ciphers[2]
	if card.Type != model.CipherTypeCard || card.Name != "Me" || card.Card.Brand != "Visa" || card.Card.ExpYear != "2025" || card.Card.ExpMonth != "3" {
		t.Fatalf("card %s", importertest.Dump(card))
	}
	if id.Type != model.CipherTypeIdentity || id.Identity.Title != "Mr" || id.Identity.FirstName != "John" || id.Notes != "profile notes" {
		t.Fatalf("identity %s", importertest.Dump(id))
	}
	if cardOnly.Type != model.CipherTypeCard || cardOnly.Card.Brand != "Mastercard" || cardOnly.Card.ExpMonth != "11" {
		t.Fatalf("card only %s", importertest.Dump(cardOnly))
	}
}

func TestGroupingAndOrganization(t *testing.T) {
	csv := "url,username,password,extra,name,grouping,fav\n" +
		"https://a.com,u,p,,a,Work\\Mail,1\n" +
		"https://b.com,u,p,,b,(none),0\n" +
		"https://c.com,u,p,,c,Work\\Mail,0\n"
	r := importertest.Parse(t, newImporter(false), csv)
	if len(r.Folders) != 1 || r.Folders[0].Name != "Work/Mail" || len(r.FolderRelationships) != 2 ||
		r.FolderRelationships[1] != (model.Relationship{2, 0}) || !r.Ciphers[0].Favorite {
		t.Fatalf("%s", importertest.Dump(r))
	}
	org := importertest.Parse(t, New(importertest.OrgOptions("org")), csv)
	if len(org.Collections) != 1 || len(org.Folders) != 0 || org.Ciphers[0].Favorite {
		t.Fatalf("%s", importertest.Dump(org))
	}
}
