package dashlane

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/dashlane/dashlane-csv-importer.spec.ts.

func getImportResult(t *testing.T, newItemTypes bool, name string) *model.ImportResult {
	t.Helper()
	o := importertest.Options()
	o.Features.NewItemTypes = newItemTypes
	r := importertest.Parse(t, NewCsv(o), importertest.ReadFile(t, name+".txt"))
	if !r.Success {
		t.Fatalf("import failed: %s", importertest.Dump(r))
	}
	return r
}

func fields(kv ...string) []importertest.Field {
	var out []importertest.Field
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, importertest.F(kv[i], kv[i+1]))
	}
	return out
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

func TestParseLoginRecords(t *testing.T) {
	r := getImportResult(t, false, "credentialsData")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	eq(t, "name", c.Name, "example.com")
	eq(t, "username", c.Login.Username, "jdoe")
	eq(t, "password", c.Login.Password, "somePassword")
	eq(t, "totp", c.Login.Totp, "someTOTPSeed")
	if len(c.Login.Uris) != 1 {
		t.Fatalf("uris: %s", importertest.Dump(c.Login.Uris))
	}
	eq(t, "uri", c.Login.Uris[0].Uri, "https://www.example.com")
	eq(t, "notes", c.Notes, "some note for example.com")
}

func TestParseLoginWithOtpUrl(t *testing.T) {
	r := getImportResult(t, false, "credentialsData_otpUrl")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	eq(t, "totp", r.Ciphers[0].Login.Totp, "anotherTOTPSeed")
}

func TestParseItemAndCreateFolder(t *testing.T) {
	r := getImportResult(t, false, "credentialsData")
	if len(r.Folders) != 1 || r.Folders[0].Name != "Entertainment" {
		t.Fatalf("folders: %s", importertest.Dump(r.Folders))
	}
	if len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("relationships: %v", r.FolderRelationships)
	}
}

func TestParseItemIntoCollectionForOrganization(t *testing.T) {
	r := importertest.Parse(t, NewCsv(importertest.OrgOptions("org")), importertest.ReadFile(t, "credentialsData.txt"))
	if len(r.Folders) != 0 || len(r.Collections) != 1 || r.Collections[0].Name != "Entertainment" ||
		len(r.CollectionRelationships) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestParsePaymentRecords(t *testing.T) {
	for _, flag := range []bool{false, true} {
		r := getImportResult(t, flag, "paymentsData")
		if len(r.Ciphers) != 2 {
			t.Fatalf("%d ciphers", len(r.Ciphers))
		}
		c := r.Ciphers[0]
		eq(t, "name", c.Name, "John's savings account")
		if !flag {
			eq(t, "type", c.Type, model.CipherTypeCard)
			eq(t, "brand", c.Card.Brand, "")
			eq(t, "cardholder", c.Card.CardholderName, "John Doe")
			eq(t, "number", c.Card.Number, "accountNumber")
			eq(t, "code", c.Card.Code, "")
			eq(t, "expMonth", c.Card.ExpMonth, "")
			eq(t, "expYear", c.Card.ExpYear, "")
			importertest.AssertCustomFieldsStructure(t, c.Fields, fields(
				"type", "bank", "routing_number", "routingNumber", "country", "US", "issuing_bank", "US-ALLY")...)
		} else {
			eq(t, "type", c.Type, model.CipherTypeBankAccount)
			eq(t, "nameOnAccount", c.BankAccount.NameOnAccount, "John Doe")
			eq(t, "accountNumber", c.BankAccount.AccountNumber, "accountNumber")
			importertest.AssertCustomFieldsStructure(t, c.Fields, fields(
				"routing_number", "routingNumber", "country", "US", "issuing_bank", "US-ALLY")...)
		}

		c2 := r.Ciphers[1]
		eq(t, "type", c2.Type, model.CipherTypeCard)
		eq(t, "name", c2.Name, "John Doe")
		eq(t, "brand", c2.Card.Brand, "Visa")
		eq(t, "cardholder", c2.Card.CardholderName, "John Doe")
		eq(t, "number", c2.Card.Number, "41111111111111111")
		eq(t, "code", c2.Card.Code, "123")
		eq(t, "expMonth", c2.Card.ExpMonth, "1")
		eq(t, "expYear", c2.Card.ExpYear, "2023")
		importertest.AssertCustomFieldsStructure(t, c2.Fields, fields("type", "credit_card", "country", "US")...)
	}
}

func TestParseIdRecords(t *testing.T) {
	for _, flag := range []bool{false, true} {
		r := getImportResult(t, flag, "identityData")
		if len(r.Ciphers) != 5 {
			t.Fatalf("%d ciphers", len(r.Ciphers))
		}

		// Type card
		c := r.Ciphers[0]
		eq(t, "type", c.Type, model.CipherTypeIdentity)
		eq(t, "name", c.Name, "John Doe card")
		eq(t, "fullName", identityFullName(c.Identity), "John Doe")
		eq(t, "firstName", c.Identity.FirstName, "John")
		eq(t, "middleName", c.Identity.MiddleName, "")
		eq(t, "lastName", c.Identity.LastName, "Doe")
		eq(t, "licenseNumber", c.Identity.LicenseNumber, "123123123")
		importertest.AssertCustomFieldsStructure(t, c.Fields, fields(
			"type", "card", "issue_date", "2022-1-30", "expiration_date", "2032-1-30")...)

		// Type passport
		c2 := r.Ciphers[1]
		eq(t, "name", c2.Name, "John Doe passport")
		if !flag {
			eq(t, "type", c2.Type, model.CipherTypeIdentity)
			eq(t, "fullName", identityFullName(c2.Identity), "John Doe")
			eq(t, "firstName", c2.Identity.FirstName, "John")
			eq(t, "middleName", c2.Identity.MiddleName, "")
			eq(t, "lastName", c2.Identity.LastName, "Doe")
			eq(t, "passportNumber", c2.Identity.PassportNumber, "123123123")
			importertest.AssertCustomFieldsStructure(t, c2.Fields, fields(
				"type", "passport", "issue_date", "2022-1-30", "expiration_date", "2032-1-30",
				"place_of_issue", "somewhere in Germany")...)
		} else {
			eq(t, "type", c2.Type, model.CipherTypePassport)
			eq(t, "givenName", c2.Passport.GivenName, "John")
			eq(t, "surname", c2.Passport.Surname, "Doe")
			eq(t, "passportNumber", c2.Passport.PassportNumber, "123123123")
			eq(t, "issueDate", c2.Passport.IssueDate, "2022-01-30")
			eq(t, "expirationDate", c2.Passport.ExpirationDate, "2032-01-30")
			eq(t, "issuingCountry", c2.Passport.IssuingCountry, "somewhere in Germany")
			importertest.AssertCustomFieldsStructure(t, c2.Fields)
		}

		// Type license
		c3 := r.Ciphers[2]
		eq(t, "name", c3.Name, "John Doe license")
		if !flag {
			eq(t, "type", c3.Type, model.CipherTypeIdentity)
			eq(t, "fullName", identityFullName(c3.Identity), "John Doe")
			eq(t, "firstName", c3.Identity.FirstName, "John")
			eq(t, "middleName", c3.Identity.MiddleName, "")
			eq(t, "lastName", c3.Identity.LastName, "Doe")
			eq(t, "licenseNumber", c3.Identity.LicenseNumber, "1234556")
			eq(t, "state", c3.Identity.State, "DC")
			importertest.AssertCustomFieldsStructure(t, c3.Fields, fields(
				"type", "license", "issue_date", "2022-8-10", "expiration_date", "2022-10-10")...)
		} else {
			eq(t, "type", c3.Type, model.CipherTypeDriversLicense)
			eq(t, "firstName", c3.DriversLicense.FirstName, "John")
			eq(t, "middleName", c3.DriversLicense.MiddleName, "")
			eq(t, "lastName", c3.DriversLicense.LastName, "Doe")
			eq(t, "licenseNumber", c3.DriversLicense.LicenseNumber, "1234556")
			eq(t, "issueDate", c3.DriversLicense.IssueDate, "2022-08-10")
			eq(t, "expirationDate", c3.DriversLicense.ExpirationDate, "2022-10-10")
			eq(t, "issuingCountry", c3.DriversLicense.IssuingCountry, "")
			eq(t, "issuingState", c3.DriversLicense.IssuingState, "DC")
			importertest.AssertCustomFieldsStructure(t, c3.Fields)
		}

		// Type social_security
		c4 := r.Ciphers[3]
		eq(t, "type", c4.Type, model.CipherTypeIdentity)
		eq(t, "name", c4.Name, "John Doe social_security")
		eq(t, "fullName", identityFullName(c4.Identity), "John Doe")
		eq(t, "firstName", c4.Identity.FirstName, "John")
		eq(t, "middleName", c4.Identity.MiddleName, "")
		eq(t, "lastName", c4.Identity.LastName, "Doe")
		eq(t, "ssn", c4.Identity.Ssn, "123123123")
		importertest.AssertCustomFieldsStructure(t, c4.Fields, fields("type", "social_security")...)

		// Type tax_number
		c5 := r.Ciphers[4]
		eq(t, "type", c5.Type, model.CipherTypeIdentity)
		eq(t, "name", c5.Name, "tax_number")
		eq(t, "licenseNumber", c5.Identity.LicenseNumber, "123123123")
		importertest.AssertCustomFieldsStructure(t, c5.Fields, fields("type", "tax_number")...)
	}
}

func TestParseSecureNoteRecords(t *testing.T) {
	r := getImportResult(t, false, "secureNoteData")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeSecureNote)
	eq(t, "name", c.Name, "01")
	eq(t, "notes", c.Notes, "test")
}

func TestParsePersonalInformationRecordsMultiple(t *testing.T) {
	r := getImportResult(t, false, "multiplePersonalInfoData")
	if len(r.Ciphers) != 6 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	want := []struct {
		name   string
		fields []importertest.Field
	}{
		{"MR John Doe", fields("type", "name", "title", "MR", "first_name", "John", "last_name", "Doe",
			"login", "jdoe", "date_of_birth", "2022-01-30", "place_of_birth", "world")},
		{"Johns email", fields("type", "email", "email", "jdoe@example.com", "email_type", "personal",
			"item_name", "Johns email")},
		{"John's number", fields("type", "number", "item_name", "John's number", "phone_number", "+49123123123")},
		{"John's home address", fields("type", "address", "item_name", "John's home address",
			"address", "1 some street", "country", "de", "state", "DE-0-NW", "city", "some city", "zip", "123123",
			"address_recipient", "John", "address_building", "1", "address_apartment", "1", "address_floor", "1",
			"address_door_code", "123")},
		{"Website", fields("type", "website", "item_name", "Website", "url", "website.com")},
		{"Mrs Jane Doe", fields("type", "name", "title", "Mrs", "first_name", "Jane", "last_name", "Doe",
			"login", "jdoe", "date_of_birth", "2022-01-30", "place_of_birth", "earth")},
	}
	for n, w := range want {
		c := r.Ciphers[n]
		eq(t, "type", c.Type, model.CipherTypeSecureNote)
		eq(t, "name", c.Name, w.name)
		importertest.AssertCustomFieldsStructure(t, c.Fields, w.fields...)
	}
}

func TestCombinePersonalInformationRecordsToOneIdentity(t *testing.T) {
	r := getImportResult(t, false, "personalInfoData")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%d ciphers", len(r.Ciphers))
	}
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeIdentity)
	eq(t, "name", c.Name, "MR John Doe")
	eq(t, "fullName", identityFullName(c.Identity), "MR John Doe")
	eq(t, "title", c.Identity.Title, "MR")
	eq(t, "firstName", c.Identity.FirstName, "John")
	eq(t, "middleName", c.Identity.MiddleName, "")
	eq(t, "lastName", c.Identity.LastName, "Doe")
	eq(t, "username", c.Identity.Username, "jdoe")
	eq(t, "email", c.Identity.Email, "jdoe@example.com")
	eq(t, "phone", c.Identity.Phone, "+49123123123")
	importertest.AssertCustomFieldsStructure(t, c.Fields, fields(
		"date_of_birth", "2022-01-30", "place_of_birth", "world", "email_type", "personal",
		"address_recipient", "John", "address_building", "1", "address_apartment", "1", "address_floor", "1",
		"address_door_code", "123", "url", "website.com")...)
}

func TestRegistered(t *testing.T) {
	for _, id := range []string{"dashlanecsv", "dashlanejson"} {
		if !importer.IsImplemented(id) {
			t.Errorf("%s not registered", id)
		}
	}
}
