// Package avira ports libs/importer/src/importers/avira-csv-importer.ts (format id "aviracsv").
package avira

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("aviracsv", New) }

// Importer is AviraCsvImporter.
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
		cipher.Name = i.GetValueOrDefault(value.Get("name"),
			i.GetValueOrDefault(i.NameFromUrl(value.Get("website")), "--"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("website"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))

		if i.IsNullOrWhitespace(value.Get("username")) && !i.IsNullOrWhitespace(value.Get("secondary_username")) {
			cipher.Login.Username = value.Get("secondary_username")
		} else {
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
			cipher.Notes = i.GetValueOrDefault(value.Get("secondary_username"))
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
