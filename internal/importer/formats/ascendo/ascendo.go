// Package ascendo ports libs/importer/src/importers/ascendo-csv-importer.ts (format id
// "ascendocsv").
package ascendo

import (
	"slices"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("ascendocsv", New) }

// Importer is AscendoCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsvRows(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		if len(value) < 2 {
			continue
		}

		cipher := i.InitLoginCipher()
		cipher.Notes = i.GetValueOrDefault(value[len(value)-1])
		cipher.Name = i.GetValueOrDefault(value[0], "--")

		if len(value) > 2 && len(value)%2 == 0 {
			for j := 0; j < len(value)-2; j += 2 {
				val := value[j+2]
				field := value[j+1]
				if i.IsNullOrWhitespace(val) || i.IsNullOrWhitespace(field) {
					continue
				}

				fieldLower := cases.Lower(language.Und).String(field)
				if cipher.Login.Password == "" && slices.Contains(importer.PasswordFieldNames, fieldLower) {
					cipher.Login.Password = i.GetValueOrDefault(val)
				} else if cipher.Login.Username == "" && slices.Contains(importer.UsernameFieldNames, fieldLower) {
					cipher.Login.Username = i.GetValueOrDefault(val)
				} else if len(cipher.Login.Uris) == 0 && slices.Contains(importer.UriFieldNames, fieldLower) {
					cipher.Login.Uris = i.MakeUriArray(val)
				} else {
					i.ProcessKvp(cipher, field, val)
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
