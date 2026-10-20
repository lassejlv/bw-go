// Package encryptr ports libs/importer/src/importers/encryptr-csv-importer.ts (format id
// "encryptrcsv").
package encryptr

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("encryptrcsv", New) }

// Importer is EncryptrCsvImporter.
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
		cipher.Name = i.GetValueOrDefault(value.Get("Label"), "--")
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"))
		text := i.GetValueOrDefault(value.Get("Text"))
		if !i.IsNullOrWhitespace(text) {
			if i.IsNullOrWhitespace(cipher.Notes) {
				cipher.Notes = text
			} else {
				cipher.Notes += "\n\n" + text
			}
		}

		typ := value.Get("Entry Type")
		if typ == "Password" {
			cipher.Login.Username = i.GetValueOrDefault(value.Get("Username"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
			cipher.Login.Uris = i.MakeUriArray(value.Get("Site URL"))
		} else if typ == "Credit Card" {
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("Name on card"))
			cipher.Card.Number = i.GetValueOrDefault(value.Get("Card Number"))
			cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			cipher.Card.Code = i.GetValueOrDefault(value.Get("CVV"))
			expiry := i.GetValueOrDefault(value.Get("Expiry"))
			if !i.IsNullOrWhitespace(expiry) {
				expParts := strings.Split(expiry, "/")
				if len(expParts) > 1 {
					// parseInt(expParts[0], null).toString()
					cipher.Card.ExpMonth = jsNumberString(0, expParts[0])
					// (2000 + parseInt(expParts[1], null)).toString()
					cipher.Card.ExpYear = jsNumberString(2000, expParts[1])
				}
			}
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// parseIntAuto is parseInt(s, null): a null radix behaves like 0, i.e. base 16 for a "0x"/"0X"
// prefix and base 10 otherwise. ok=false means NaN.
func parseIntAuto(s string) (n float64, ok bool) {
	s = importer.JSTrimStart(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	base := 10
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		base = 16
		s = s[2:]
	}
	j := 0
	for j < len(s) && digitVal(s[j]) < base {
		j++
	}
	if j == 0 {
		return 0, false
	}
	for _, c := range []byte(s[:j]) {
		n = n*float64(base) + float64(digitVal(c))
	}
	if neg {
		n = -n
	}
	return n, true
}

func digitVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	}
	return 99
}

// jsNumberString is (add + parseInt(s, null)).toString() ("NaN" when s has no digits).
func jsNumberString(add float64, s string) string {
	n, ok := parseIntAuto(s)
	if !ok {
		return "NaN"
	}
	r := add + n
	if r == 0 {
		r = 0 // (-0).toString() === "0"
	}
	return importer.FormatJSNumber(r)
}
