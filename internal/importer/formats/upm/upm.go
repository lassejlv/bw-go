// Package upm ports libs/importer/src/importers/upm-csv-importer.ts (upmcsv).
package upm

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("upmcsv", New) }

// Importer is UpmCsvImporter.
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
		if len(value) != 5 {
			continue
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value[0], "--")
		cipher.Notes = i.GetValueOrDefault(value[4])
		cipher.Login.Username = i.GetValueOrDefault(value[1])
		cipher.Login.Password = i.GetValueOrDefault(value[2])
		cipher.Login.Uris = i.MakeUriArray(value[3])
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
