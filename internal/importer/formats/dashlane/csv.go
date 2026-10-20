// Package dashlane ports libs/importer/src/importers/dashlane: dashlane-csv-importer.ts
// ("dashlanecsv") and dashlane-json-importer.ts ("dashlanejson").
package dashlane

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.Register("dashlanecsv", NewCsv)
	importer.Register("dashlanejson", NewJson)
}

var mappedCredentialsColumns = setOf(
	"title",
	"note",
	"username",
	"password",
	"url",
	"otpSecret",
	"category",
)

var mappedPersonalInfoAsIdentityColumns = setOf(
	"type",
	"title",
	"first_name",
	"middle_name",
	"last_name",
	"login",
	"email",
	"phone_number",
	"address",
	"country",
	"state",
	"city",
	"zip",
	// Skip item_name as we already have set a combined name
	"item_name",
)

var mappedSecureNoteColumns = setOf("title", "note")

func setOf(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// CsvImporter is DashlaneCsvImporter.
type CsvImporter struct {
	importer.Base
	useNewDedicatedTypes bool
}

// NewCsv builds a DashlaneCsvImporter.
func NewCsv(opts importer.Options) importer.Importer {
	return &CsvImporter{Base: importer.NewBase(opts), useNewDedicatedTypes: opts.Features.NewItemTypes}
}

// tmpl is the value of row[key] as a JavaScript template literal renders it ("undefined" when the
// column is missing).
func tmpl(row importer.Record, key string) string {
	if v, ok := row.Lookup(key); ok {
		return v
	}
	return "undefined"
}

// Parse implements importer.Importer.
func (i *CsvImporter) Parse(data string) (*model.ImportResult, error) {
	useNewDedicatedTypes := i.useNewDedicatedTypes
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	if results[0].Has("type") && results[0].Has("title") {
		// If personalRecords has only one "name" then create an Identity-Cipher
		names := 0
		for _, x := range results {
			if v, ok := x.Lookup("type"); ok && v == "name" {
				names++
			}
		}
		if names == 1 {
			cipher := i.InitLoginCipher()
			cipher.Type = model.CipherTypeIdentity
			cipher.Identity = &model.IdentityView{}
			for _, row := range results {
				i.parsePersonalInformationRecordAsIdentity(cipher, row)
			}
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
			result.Success = true
			return result, nil
		}
	}

	for _, row := range results {
		cipher := i.InitLoginCipher()

		rowKeys := row.Keys()
		key := func(n int) string {
			if n < len(rowKeys) {
				return rowKeys[n]
			}
			return ""
		}
		if key(0) == "username" {
			i.ProcessFolder(result, row.Get("category"))
			i.parseCredentialsRecord(cipher, row)
		}

		if key(0) == "type" && key(1) == "account_name" {
			i.parsePaymentRecord(cipher, row, useNewDedicatedTypes)
		}

		if key(0) == "type" && key(1) == "number" {
			i.parseIdRecord(cipher, row, useNewDedicatedTypes)
		}

		if key(0) == "type" && key(1) == "title" {
			i.parsePersonalInformationRecord(cipher, row)
		}

		if key(0) == "title" && key(1) == "note" {
			i.parseSecureNoteRecords(cipher, row)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

func (i *CsvImporter) parseCredentialsRecord(cipher *model.CipherView, row importer.Record) {
	cipher.Type = model.CipherTypeLogin
	cipher.Login = &model.LoginView{}

	cipher.Name = row.Get("title")
	cipher.Notes = row.Get("note")
	cipher.Login.Username = row.Get("username")
	cipher.Login.Password = row.Get("password")
	if row.Has("otpUrl") {
		cipher.Login.Totp = row.Get("otpUrl")
	} else {
		cipher.Login.Totp = row.Get("otpSecret")
	}
	if url, ok := row.Lookup("url"); ok {
		cipher.Login.Uris = i.MakeUriArray(url)
	} else {
		cipher.Login.Uris = nil
	}

	i.importUnmappedFields(cipher, row, mappedCredentialsColumns)
}

func (i *CsvImporter) parsePaymentRecord(cipher *model.CipherView, row importer.Record, useNewDedicatedTypes bool) {
	cipher.Type = model.CipherTypeCard
	cipher.Card = &model.CardView{}

	cipher.Name = row.Get("account_name")
	var mappedValues []string
	switch row.Get("type") {
	case "credit_card":
		cipher.Card.CardholderName = row.Get("account_name")
		cipher.Card.Number = row.Get("cc_number")
		cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
		cipher.Card.Code = row.Get("code")
		i.SetCardExpiration(cipher, tmpl(row, "expiration_month")+"/"+tmpl(row, "expiration_year"))

		// If you add more mapped fields please extend this
		mappedValues = []string{
			"account_name",
			"account_holder",
			"cc_number",
			"code",
			"expiration_month",
			"expiration_year",
		}
	case "bank":
		// If you add more mapped fields please extend this
		mappedValues = []string{"account_name", "account_holder", "account_number"}
		if useNewDedicatedTypes {
			cipher.Type = model.CipherTypeBankAccount
			bankAccount := &model.BankAccountView{}
			bankAccount.NameOnAccount = row.Get("account_holder")
			bankAccount.AccountNumber = row.Get("account_number")
			cipher.BankAccount = bankAccount
			// Type isn't mapped to a property but we don't want it as a custom field
			mappedValues = append(mappedValues, "type")
		} else {
			cipher.Card.CardholderName = row.Get("account_holder")
			cipher.Card.Number = row.Get("account_number")
		}
	}

	i.importUnmappedFields(cipher, row, setOf(mappedValues...))
}

func (i *CsvImporter) parseIdRecord(cipher *model.CipherView, row importer.Record, useNewDedicatedTypes bool) {
	cipher.Type = model.CipherTypeIdentity
	cipher.Identity = &model.IdentityView{}

	mappedValues := []string{"name", "number"}
	typ := row.Get("type")
	switch typ {
	case "card":
		cipher.Name = tmpl(row, "name") + " " + typ
		i.ProcessFullName(cipher, row.Get("name"))
		cipher.Identity.LicenseNumber = row.Get("number")
	case "passport":
		cipher.Name = tmpl(row, "name") + " " + typ
		if useNewDedicatedTypes {
			cipher.Type = model.CipherTypePassport
			passport := &model.PassportView{}
			firstName, middleName, lastName := i.GetFullName(row.Get("name"))
			passport.GivenName = firstName
			if !i.IsNullOrWhitespace(middleName) {
				passport.GivenName = tmplStr(passport.GivenName) + " " + middleName
			}
			passport.Surname = lastName
			passport.PassportNumber = row.Get("number")
			passport.IssueDate = i.parseDashlaneDateString(row.Get("issue_date"))
			passport.ExpirationDate = i.parseDashlaneDateString(row.Get("expiration_date"))
			passport.IssuingCountry = row.Get("place_of_issue")
			cipher.Passport = passport
			// Type isn't mapped to a property but we don't want it as a custom field
			mappedValues = append(mappedValues, "issue_date", "expiration_date", "place_of_issue", "type")
		} else {
			i.ProcessFullName(cipher, row.Get("name"))
			cipher.Identity.PassportNumber = row.Get("number")
		}
	case "license":
		cipher.Name = tmpl(row, "name") + " " + typ
		if useNewDedicatedTypes {
			cipher.Type = model.CipherTypeDriversLicense
			license := &model.DriversLicenseView{}
			firstName, middleName, lastName := i.GetFullName(row.Get("name"))
			license.FirstName = firstName
			license.MiddleName = middleName
			license.LastName = lastName
			license.LicenseNumber = row.Get("number")
			license.IssueDate = i.parseDashlaneDateString(row.Get("issue_date"))
			license.ExpirationDate = i.parseDashlaneDateString(row.Get("expiration_date"))
			license.IssuingCountry = row.Get("place_of_issue")
			license.IssuingState = row.Get("state")
			cipher.DriversLicense = license
			// Type isn't mapped to a property but we don't want it as a custom field
			mappedValues = append(mappedValues, "issue_date", "expiration_date", "place_of_issue", "type")
		} else {
			i.ProcessFullName(cipher, row.Get("name"))
			cipher.Identity.LicenseNumber = row.Get("number")
			cipher.Identity.State = row.Get("state")
		}
		mappedValues = append(mappedValues, "state")
	case "social_security":
		cipher.Name = tmpl(row, "name") + " " + typ
		i.ProcessFullName(cipher, row.Get("name"))
		cipher.Identity.Ssn = row.Get("number")
	case "tax_number":
		cipher.Name = typ
		cipher.Identity.LicenseNumber = row.Get("number")
	}

	// If you add more mapped fields please extend this
	i.importUnmappedFields(cipher, row, setOf(mappedValues...))
}

// tmplStr renders getFullName's first name the way `a + " " + b` does in JS: when a middle name
// was parsed, an empty first name was getValueOrDefault's null.
func tmplStr(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

// parseDashlaneDateString: Dashlane dates are formatted as `YYYY-MM-DD` but the month and day omit
// leading zeros.
func (i *CsvImporter) parseDashlaneDateString(dateString string) string {
	if i.IsNullOrWhitespace(dateString) {
		return ""
	}
	parts := strings.Split(dateString, "-")
	part := func(n int) string {
		if n < len(parts) {
			return parts[n]
		}
		return ""
	}
	year, month, day := part(0), part(1), part(2)
	if i.IsNullOrWhitespace(year) || i.IsNullOrWhitespace(month) || i.IsNullOrWhitespace(day) {
		return ""
	}
	return year + "-" + padStart2(month) + "-" + padStart2(day)
}

func padStart2(s string) string {
	for importer.Len16(s) < 2 {
		s = "0" + s
	}
	return s
}

func (i *CsvImporter) parsePersonalInformationRecord(cipher *model.CipherView, row importer.Record) {
	cipher.Type = model.CipherTypeSecureNote
	cipher.SecureNote.Type = model.SecureNoteTypeGeneric
	if row.Get("type") == "name" {
		name := tmpl(row, "title") + " " + tmpl(row, "first_name") + " " + tmpl(row, "middle_name") + " " + tmpl(row, "last_name")
		cipher.Name = importer.JSTrim(strings.Replace(name, "  ", " ", 1))
	} else {
		cipher.Name = row.Get("item_name")
	}

	for _, key := range row.Keys() {
		i.ProcessKvp(cipher, key, row.Get(key))
	}
}

func (i *CsvImporter) parsePersonalInformationRecordAsIdentity(cipher *model.CipherView, row importer.Record) {
	switch row.Get("type") {
	case "name":
		i.ProcessFullName(cipher, tmpl(row, "first_name")+" "+tmpl(row, "middle_name")+" "+tmpl(row, "last_name"))
		cipher.Identity.Title = row.Get("title")
		cipher.Name = identityFullName(cipher.Identity)

		cipher.Identity.Username = row.Get("login")
	case "email":
		cipher.Identity.Email = row.Get("email")
	case "number":
		cipher.Identity.Phone = row.Get("phone_number")
	case "address":
		cipher.Identity.Address1 = row.Get("address")
		cipher.Identity.City = row.Get("city")
		cipher.Identity.PostalCode = row.Get("zip")
		cipher.Identity.State = row.Get("state")
		cipher.Identity.Country = row.Get("country")
	}

	i.importUnmappedFields(cipher, row, mappedPersonalInfoAsIdentityColumns)
}

func (i *CsvImporter) parseSecureNoteRecords(cipher *model.CipherView, row importer.Record) {
	cipher.Type = model.CipherTypeSecureNote
	cipher.SecureNote.Type = model.SecureNoteTypeGeneric
	cipher.Name = row.Get("title")
	cipher.Notes = row.Get("note")

	i.importUnmappedFields(cipher, row, mappedSecureNoteColumns)
}

func (i *CsvImporter) importUnmappedFields(cipher *model.CipherView, row importer.Record, mappedValues map[string]bool) {
	for _, key := range row.Keys() {
		if mappedValues[key] {
			continue
		}
		i.ProcessKvp(cipher, key, row.Get(key))
	}
}

// identityFullName is the IdentityView.fullName getter ("" for undefined).
func identityFullName(id *model.IdentityView) string {
	if id.Title == "" && id.FirstName == "" && id.MiddleName == "" && id.LastName == "" {
		return ""
	}
	name := ""
	if !importer.IsNullOrWhitespace(id.Title) {
		name += id.Title + " "
	}
	if !importer.IsNullOrWhitespace(id.FirstName) {
		name += id.FirstName + " "
	}
	if !importer.IsNullOrWhitespace(id.MiddleName) {
		name += id.MiddleName + " "
	}
	if !importer.IsNullOrWhitespace(id.LastName) {
		name += id.LastName
	}
	return importer.JSTrim(name)
}
