// Package blackberry ports libs/importer/src/importers/blackberry-csv-importer.ts (format id
// "blackberrycsv").
package blackberry

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("blackberrycsv", New) }

// Importer is BlackBerryCsvImporter.
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
		if value.Get("grouping") == "list" {
			continue
		}
		cipher := i.InitLoginCipher()
		cipher.Favorite = value.Get("fav") == "1"
		cipher.Name = i.GetValueOrDefault(value.Get("name"))
		cipher.Notes = i.GetValueOrDefault(value.Get("extra"))
		if value.Get("grouping") != "note" {
			cipher.Login.Uris = i.MakeUriArray(value.Get("url"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		}
		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
