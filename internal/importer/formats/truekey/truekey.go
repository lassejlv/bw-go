// Package truekey ports libs/importer/src/importers/truekey-csv-importer.ts (truekeycsv).
package truekey

import (
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("truekeycsv", New) }

var propertiesToIgnore = []string{
	"kind",
	"autologin",
	"favorite",
	"hexcolor",
	"protectedwithpassword",
	"subdomainonly",
	"type",
	"tk_export_version",
	"note",
	"title",
	"document_content",
}

// Importer is TrueKeyCsvImporter.
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
		cipher.Favorite = strings.ToLower(i.GetValueOrDefault(value.Get("favorite"), "")) == "true"
		cipher.Name = i.GetValueOrDefault(value.Get("name"), "--")
		cipher.Notes = i.GetValueOrDefault(value.Get("memo"), "")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("login"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("url"))

		kind, hasKind := value.Lookup("kind")
		isLogin := hasKind && kind == "login"
		if !isLogin {
			cipher.Name = i.GetValueOrDefault(value.Get("title"), "--")
			cipher.Notes = i.GetValueOrDefault(value.Get("note"), "")
		}

		if hasKind && kind == "cc" {
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("cardholder"))
			cipher.Card.Number = i.GetValueOrDefault(value.Get("number"))
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			if !i.IsNullOrWhitespace(value.Get("expiryDate")) {
				// new Date(...).getFullYear()/getMonth() (local time); an Invalid Date yields "NaN".
				if expDate, ok := importer.ParseJSDate(value.Get("expiryDate")); ok {
					expDate = expDate.In(time.Local)
					cipher.Card.ExpYear = strconv.Itoa(expDate.Year())
					cipher.Card.ExpMonth = strconv.Itoa(int(expDate.Month()))
				} else {
					cipher.Card.ExpYear = "NaN"
					cipher.Card.ExpMonth = "NaN"
				}
			}
		} else if !isLogin {
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
			if !i.IsNullOrWhitespace(cipher.Notes) {
				cipher.Notes = i.GetValueOrDefault(value.Get("document_content"), "")
			}
			for _, property := range value.Keys() {
				if !contains(propertiesToIgnore, strings.ToLower(property)) &&
					!i.IsNullOrWhitespace(value.Get(property)) {
					i.ProcessKvp(cipher, property, value.Get(property))
				}
			}
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
