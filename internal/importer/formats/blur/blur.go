// Package blur ports libs/importer/src/importers/blur-csv-importer.ts (format id "blurcsv").
package blur

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("blurcsv", New) }

// Importer is BlurCsvImporter.
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
		label := value.Get("label")
		if label == "null" {
			label = ""
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(label,
			i.GetValueOrDefault(i.NameFromUrl(value.Get("domain")), "--"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("domain"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))

		if i.IsNullOrWhitespace(value.Get("email")) && !i.IsNullOrWhitespace(value.Get("username")) {
			cipher.Login.Username = value.Get("username")
		} else {
			cipher.Login.Username = i.GetValueOrDefault(value.Get("email"))
			cipher.Notes = i.GetValueOrDefault(value.Get("username"))
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
