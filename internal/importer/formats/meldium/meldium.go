// Package meldium ports libs/importer/src/importers/meldium-csv-importer.ts (format id
// "meldiumcsv").
package meldium

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("meldiumcsv", New) }

// Importer is MeldiumCsvImporter.
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
		cipher.Name = i.GetValueOrDefault(value.Get("DisplayName"), "--")
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"))
		cipher.Login.Username = i.GetValueOrDefault(value.Get("UserName"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("Url"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
