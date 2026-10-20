// Package nordpass ports libs/importer/src/importers/nordpass-csv-importer.ts (format id
// "nordpasscsv").
package nordpass

import (
	"fmt"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("nordpasscsv", New) }

// Importer is NordPassCsvImporter.
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

	for _, record := range results {
		recordType, ok := evaluateType(record)
		if !ok {
			continue
		}

		i.ProcessFolder(result, record.Get("folder"))

		cipher := model.NewCipherView()
		cipher.Name = i.GetValueOrDefault(record.Get("name"), "--")
		cipher.Notes = i.GetValueOrDefault(record.Get("note"))

		if customFields := record.Get("custom_fields"); customFields != "" {
			if err := i.processCustomFields(cipher, customFields); err != nil {
				return nil, err
			}
		}

		switch recordType {
		case model.CipherTypeLogin:
			cipher.Type = model.CipherTypeLogin
			cipher.Login = &model.LoginView{}
			cipher.Login.Username = i.GetValueOrDefault(record.Get("username"))
			cipher.Login.Password = i.GetValueOrDefault(record.Get("password"))
			if additionalUrls := record.Get("additional_urls"); additionalUrls != "" {
				uris, err := additionalUris(record.Get("url"), additionalUrls)
				if err != nil {
					return nil, err
				}
				cipher.Login.Uris = i.MakeUriArray(uris...)
			} else {
				cipher.Login.Uris = i.MakeUriArray(record.Get("url"))
			}
		case model.CipherTypeCard:
			cipher.Type = model.CipherTypeCard
			cipher.Card.CardholderName = i.GetValueOrDefault(record.Get("cardholdername"))
			cipher.Card.Number = i.GetValueOrDefault(record.Get("cardnumber"))
			cipher.Card.Code = i.GetValueOrDefault(record.Get("cvc"))
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			i.SetCardExpiration(cipher, record.Get("expirydate"))
		case model.CipherTypeIdentity:
			cipher.Type = model.CipherTypeIdentity

			i.ProcessFullName(cipher, i.GetValueOrDefault(record.Get("full_name")))
			cipher.Identity.Address1 = i.GetValueOrDefault(record.Get("address1"))
			cipher.Identity.Address2 = i.GetValueOrDefault(record.Get("address2"))
			cipher.Identity.City = i.GetValueOrDefault(record.Get("city"))
			cipher.Identity.State = i.GetValueOrDefault(record.Get("state"))
			cipher.Identity.PostalCode = i.GetValueOrDefault(record.Get("zipcode"))
			cipher.Identity.Country = i.GetValueOrDefault(record.Get("country"))
			if cipher.Identity.Country != "" {
				cipher.Identity.Country = cases.Upper(language.Und).String(cipher.Identity.Country)
			}
			cipher.Identity.Email = i.GetValueOrDefault(record.Get("email"))
			cipher.Identity.Phone = i.GetValueOrDefault(record.Get("phone_number"))
		case model.CipherTypeSecureNote:
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote.Type = model.SecureNoteTypeGeneric
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

// processCustomFields ports the `JSON.parse(record.custom_fields)` block, including the cases
// where upstream throws (malformed JSON, a non-empty string instead of an array, null entries).
func (i *Importer) processCustomFields(cipher *model.CipherView, customFields string) error {
	var parsed any
	if err := importer.UnmarshalJSONLenient(customFields, &parsed); err != nil {
		return err
	}
	switch p := parsed.(type) {
	case string:
		if p != "" { // "...".forEach is not a function
			return fmt.Errorf("TypeError: customFieldsParsed.forEach is not a function")
		}
	case []any:
		for _, f := range p {
			if f == nil {
				return fmt.Errorf("TypeError: Cannot read properties of null (reading 'type')")
			}
			field, _ := f.(map[string]any) // primitives have no label/type/value
			fieldType := model.FieldTypeText
			if t, _ := field["type"].(string); t == "hidden" {
				fieldType = model.FieldTypeHidden
			}
			label, _ := field["label"].(string) // non-strings are treated as null keys
			value, isString := field["value"].(string)
			if !isString {
				continue // processKvp ignores non-string values
			}
			i.ProcessKvp(cipher, label, value, fieldType)
		}
	}
	return nil
}

// additionalUris is `[record.url, ...JSON.parse(record.additional_urls)]`, checked for the
// values makeUriArray/fixUri would throw on.
func additionalUris(url, additionalUrls string) ([]string, error) {
	var parsed any
	if err := importer.UnmarshalJSONLenient(additionalUrls, &parsed); err != nil {
		return nil, err
	}
	uris := []string{url}
	switch p := parsed.(type) {
	case string:
		for _, r := range p {
			uris = append(uris, string(r))
		}
	case []any:
		for _, u := range p {
			switch s := u.(type) {
			case nil:
				uris = append(uris, "") // fixUri(null) -> null, skipped
			case string:
				uris = append(uris, s)
			default:
				return nil, fmt.Errorf("TypeError: uri.trim is not a function")
			}
		}
	default:
		return nil, fmt.Errorf("TypeError: additionalUrlsParsed is not iterable")
	}
	return uris, nil
}

func evaluateType(record importer.Record) (model.CipherType, bool) {
	switch record.Get("type") {
	case "password":
		return model.CipherTypeLogin, true
	case "credit_card":
		return model.CipherTypeCard, true
	case "note":
		return model.CipherTypeSecureNote, true
	case "identity":
		return model.CipherTypeIdentity, true
	}
	return 0, false
}
