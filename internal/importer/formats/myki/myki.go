// Package myki ports libs/importer/src/importers/myki-csv-importer.ts (format id "mykicsv").
package myki

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("mykicsv", New) }

func set(base []string, extra ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range append(append([]string{}, base...), extra...) {
		m[k] = true
	}
	return m
}

var (
	mappedBaseColumns        = []string{"nickname", "additionalInfo"}
	mappedUserAccountColumns = set(mappedBaseColumns, "url", "username", "password", "twofaSecret")
	mappedCreditCardColumns  = set(mappedBaseColumns, "cardNumber", "cardName", "exp_month", "exp_year", "cvv")
	mappedIdentityColumns    = set(mappedBaseColumns, "title", "firstName", "middleName", "lastName", "email", "firstAddressLine", "secondAddressLine", "city", "country", "zipCode")
	mappedIdCardColumns      = set(mappedBaseColumns, "idName", "idNumber", "idCountry")
	mappedTwoFaColumns       = set(mappedBaseColumns, "authToken")
	mappedUserNoteColumns    = set(mappedBaseColumns, "content")
)

// Importer is MykiCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("nickname"), "--")
		cipher.Notes = importer.JSTrimEnd(i.GetValueOrDefault(value.Get("additionalInfo"), ""))

		switch {
		case value.Has("url"):
			// Accounts
			cipher.Login.Uris = i.MakeUriArray(value.Get("url"))
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
			cipher.Login.Totp = i.GetValueOrDefault(value.Get("twofaSecret"))

			i.importUnmappedFields(cipher, value, mappedUserAccountColumns)
		case value.Has("authToken"):
			// TwoFA
			cipher.Login.Totp = i.GetValueOrDefault(value.Get("authToken"))

			i.importUnmappedFields(cipher, value, mappedTwoFaColumns)
		case value.Has("cardNumber"):
			// Cards
			cipher.Card = &model.CardView{}
			cipher.Type = model.CipherTypeCard
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("cardName"))
			cipher.Card.Number = i.GetValueOrDefault(value.Get("cardNumber"))
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			cipher.Card.ExpMonth = i.GetValueOrDefault(value.Get("exp_month"))
			cipher.Card.ExpYear = i.GetValueOrDefault(value.Get("exp_year"))
			cipher.Card.Code = i.GetValueOrDefault(value.Get("cvv"))

			i.importUnmappedFields(cipher, value, mappedCreditCardColumns)
		case value.Has("firstName"):
			// Identities
			cipher.Identity = &model.IdentityView{}
			cipher.Type = model.CipherTypeIdentity
			cipher.Identity.Title = i.GetValueOrDefault(value.Get("title"))
			cipher.Identity.FirstName = i.GetValueOrDefault(value.Get("firstName"))
			cipher.Identity.MiddleName = i.GetValueOrDefault(value.Get("middleName"))
			cipher.Identity.LastName = i.GetValueOrDefault(value.Get("lastName"))
			cipher.Identity.Phone = i.GetValueOrDefault(value.Get("number"))
			cipher.Identity.Email = i.GetValueOrDefault(value.Get("email"))
			cipher.Identity.Address1 = i.GetValueOrDefault(value.Get("firstAddressLine"))
			cipher.Identity.Address2 = i.GetValueOrDefault(value.Get("secondAddressLine"))
			cipher.Identity.City = i.GetValueOrDefault(value.Get("city"))
			cipher.Identity.Country = i.GetValueOrDefault(value.Get("country"))
			cipher.Identity.PostalCode = i.GetValueOrDefault(value.Get("zipCode"))

			i.importUnmappedFields(cipher, value, mappedIdentityColumns)
		case value.Has("idType"):
			// IdCards
			cipher.Identity = &model.IdentityView{}
			cipher.Type = model.CipherTypeIdentity
			i.ProcessFullName(cipher, value.Get("idName"))
			cipher.Identity.Country = i.GetValueOrDefault(value.Get("idCountry"))

			switch value.Get("idType") {
			// case "Driver's License":
			// case "ID Card":
			// case "Outdoor License":
			// case "Software License":
			// case "Tax Number":
			// case "Bank Account":
			// case "Insurance Card":
			// case "Health Card":
			// case "Membership":
			// case "Database":
			// case "Reward Program":
			// case "Tour Visa":
			case "Passport":
				cipher.Identity.PassportNumber = value.Get("idNumber")
			case "Social Security":
				cipher.Identity.Ssn = value.Get("idNumber")
			default:
				cipher.Identity.LicenseNumber = value.Get("idNumber")
			}

			i.importUnmappedFields(cipher, value, mappedIdCardColumns)
		case value.Has("content"):
			// Notes
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
			cipher.Type = model.CipherTypeSecureNote
			cipher.Notes = importer.JSTrimEnd(i.GetValueOrDefault(value.Get("content"), ""))

			i.importUnmappedFields(cipher, value, mappedUserNoteColumns)
		default:
			continue
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// importUnmappedFields adds every column not in mappedValues as a custom field (Object.keys order;
// `__parsed_extra` is skipped because processKvp ignores non-string values).
func (i *Importer) importUnmappedFields(cipher *model.CipherView, row importer.Record, mappedValues map[string]bool) {
	for _, key := range row.Keys() {
		if mappedValues[key] {
			continue
		}
		i.ProcessKvp(cipher, key, row.Get(key))
	}
}
