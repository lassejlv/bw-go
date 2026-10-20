// Package avast ports libs/importer/src/importers/avast/avast-csv-importer.ts (avastcsv) and
// avast-json-importer.ts (avastjson).
package avast

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.Register("avastcsv", NewCsv)
	importer.Register("avastjson", NewJson)
}

// CsvImporter is AvastCsvImporter.
type CsvImporter struct{ importer.Base }

// NewCsv constructs AvastCsvImporter.
func NewCsv(opts importer.Options) importer.Importer {
	return &CsvImporter{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *CsvImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("name"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("web"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Username = i.GetValueOrDefault(value.Get("login"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// JsonImporter is AvastJsonImporter.
type JsonImporter struct{ importer.Base }

// NewJson constructs AvastJsonImporter.
func NewJson(opts importer.Options) importer.Importer {
	return &JsonImporter{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *JsonImporter) Parse(data string) (_ *model.ImportResult, err error) {
	defer jsvalue.CatchTypeError(&err)
	result := model.NewImportResult()
	results, err := jsvalue.Parse(data)
	if err != nil {
		return nil, err
	}
	if results.Nullish() {
		result.Success = false
		return result, nil
	}

	if logins := results.Get("logins"); !logins.Nullish() {
		logins.ForEach("results.logins", func(value *jsvalue.Value) {
			cipher := i.InitLoginCipher()
			cipher.Name = i.GetValueOrDefault(value.Get("custName").Str())
			cipher.Notes = i.GetValueOrDefault(value.Get("note").Str())
			cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, value.Get("url"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("pwd").Str())
			cipher.Login.Username = i.GetValueOrDefault(value.Get("loginName").Str())
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
		})
	}

	if notes := results.Get("notes"); !notes.Nullish() {
		notes.ForEach("results.notes", func(value *jsvalue.Value) {
			cipher := i.InitLoginCipher()
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote.Type = model.SecureNoteTypeGeneric
			cipher.Name = i.GetValueOrDefault(value.Get("label").Str())
			cipher.Notes = i.GetValueOrDefault(value.Get("text").Str())
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
		})
	}

	if cards := results.Get("cards"); !cards.Nullish() {
		cards.ForEach("results.cards", func(value *jsvalue.Value) {
			cipher := i.InitLoginCipher()
			cipher.Type = model.CipherTypeCard
			cipher.Name = i.GetValueOrDefault(value.Get("custName").Str())
			cipher.Notes = i.GetValueOrDefault(value.Get("note").Str())
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("holderName").Str())
			cipher.Card.Number = i.GetValueOrDefault(value.Get("cardNumber").Str())
			cipher.Card.Code = i.GetValueOrDefault(value.Get("cvv").Str())
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			if exp := value.Get("expirationDate"); !exp.Nullish() {
				if month := exp.Get("month"); !month.Nullish() {
					cipher.Card.ExpMonth = month.JSString()
				}
				if year := exp.Get("year"); !year.Nullish() {
					cipher.Card.ExpYear = year.JSString()
				}
			}
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
		})
	}

	result.Success = true
	return result, nil
}
