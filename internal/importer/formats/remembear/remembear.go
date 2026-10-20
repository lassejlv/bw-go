// Package remembear ports libs/importer/src/importers/remembear-csv-importer.ts (remembearcsv).
package remembear

import (
	"math"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("remembearcsv", New) }

// Importer is RememBearCsvImporter.
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
		if value.Get("trash") == "true" {
			continue
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("name"))
		cipher.Notes = i.GetValueOrDefault(value.Get("notes"))
		switch value.Get("type") {
		case "LoginItem":
			cipher.Login.Uris = i.MakeUriArray(value.Get("website"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		case "CreditCardItem":
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("cardholder"))
			cipher.Card.Number = i.GetValueOrDefault(value.Get("number"))
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			cipher.Card.Code = i.GetValueOrDefault(value.Get("verification"))

			if expMonth := i.GetValueOrDefault(value.Get("expiryMonth")); expMonth != "" {
				// parseInt(expMonth, null): NaN fails the range check.
				if n, ok := parseInt(expMonth); ok && n >= 1 && n <= 12 {
					cipher.Card.ExpMonth = importer.FormatJSNumber(n)
				}
			}
			if expYear := i.GetValueOrDefault(value.Get("expiryYear")); expYear != "" {
				// NaN != null, so a non-numeric year becomes "NaN".
				if n, ok := parseInt(expYear); ok {
					cipher.Card.ExpYear = importer.FormatJSNumber(n)
				} else {
					cipher.Card.ExpYear = "NaN"
				}
			}

			if pin := i.GetValueOrDefault(value.Get("pin")); pin != "" {
				i.ProcessKvp(cipher, "PIN", pin)
			}
			if zip := i.GetValueOrDefault(value.Get("zipCode")); zip != "" {
				i.ProcessKvp(cipher, "Zip Code", zip)
			}
		}
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// parseInt is JavaScript's parseInt(s, null): radix 0 means 10, or 16 after a "0x"/"0X" prefix.
// ok is false for NaN.
func parseInt(s string) (float64, bool) {
	s = importer.JSTrimStart(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	radix := 10.0
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		radix = 16
		s = s[2:]
	}
	n, digits := 0.0, 0
	for _, c := range []byte(s) {
		var d float64
		switch {
		case c >= '0' && c <= '9':
			d = float64(c - '0')
		case radix == 16 && c >= 'a' && c <= 'f':
			d = float64(c-'a') + 10
		case radix == 16 && c >= 'A' && c <= 'F':
			d = float64(c-'A') + 10
		default:
			d = -1
		}
		if d < 0 {
			break
		}
		n = n*radix + d
		digits++
	}
	if digits == 0 {
		return math.NaN(), false
	}
	if neg && n != 0 { // (-0).toString() is "0"
		n = -n
	}
	return n, true
}
