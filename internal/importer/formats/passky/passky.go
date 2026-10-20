// Package passky ports libs/importer/src/importers/passky/passky-json-importer.ts (passkyjson).
package passky

import (
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passkyjson", New) }

// Importer is PasskyJsonImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (_ *model.ImportResult, err error) {
	defer jsvalue.CatchTypeError(&err)
	result := model.NewImportResult()
	passkyExport, err := jsvalue.Parse(data)
	if err != nil {
		return nil, err
	}
	if passkyExport.Nullish() || passkyExport.Get("passwords").Nullish() ||
		passkyExport.Get("passwords").LengthIs(0) {
		result.Success = false
		return result, nil
	}

	if looseEqualsTrue(passkyExport.Get("encrypted")) {
		result.Success = false
		result.ErrorMessage = "Unable to import an encrypted passky backup."
		return result, nil
	}

	passkyExport.Get("passwords").ForEach("passkyExport.passwords", func(record *jsvalue.Value) {
		cipher := i.InitLoginCipher()
		cipher.Name = record.Get("website").Str()
		cipher.Login.Username = record.Get("username").Str()
		cipher.Login.Password = record.Get("password").Str()

		cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, record.Get("website"))
		cipher.Notes = record.Get("message").Str()

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	})

	result.Success = true
	return result, nil
}

// looseEqualsTrue is `v == true`: true == 1, so booleans, numbers and strings/arrays whose
// ToNumber is 1 match.
func looseEqualsTrue(v *jsvalue.Value) bool {
	if v.Nullish() {
		return false
	}
	switch v.Kind() {
	case jsvalue.Bool:
		return v.Bool()
	case jsvalue.Number:
		return v.Num() == 1
	case jsvalue.String, jsvalue.Array:
		return stringToNumber(v.JSString()) == 1
	}
	return false // "[object Object]" is NaN
}

// stringToNumber is ToNumber(string) for the forms that can equal 1 (decimal, 0x/0o/0b).
func stringToNumber(s string) float64 {
	s = importer.JSTrim(s)
	if s == "" {
		return 0
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			if n, err := strconv.ParseUint(s[2:], base, 64); err == nil {
				return float64(n)
			}
			return -1
		}
	}
	if strings.ContainsAny(s, "_xXpP") {
		return -1 // not a JavaScript StrDecimalLiteral, though Go would accept it
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return f
}
