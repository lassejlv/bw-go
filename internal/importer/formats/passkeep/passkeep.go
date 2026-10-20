// Package passkeep ports libs/importer/src/importers/passkeep-csv-importer.ts (format id
// "passkeepcsv").
package passkeep

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passkeepcsv", New) }

// Importer is PassKeepCsvImporter.
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
		i.ProcessFolder(result, i.getValue("category", value))
		cipher := i.InitLoginCipher()
		cipher.Notes = i.getValue("description", value)
		cipher.Name = i.GetValueOrDefault(i.getValue("title", value), "--")
		cipher.Login.Username = i.getValue("username", value)
		cipher.Login.Password = i.getValue("password", value)
		cipher.Login.Uris = i.MakeUriArray(i.getValue("site", value))
		i.ProcessKvp(cipher, "Password 2", i.getValue("password2", value))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

func (i *Importer) getValue(key string, value importer.Record) string {
	return i.GetValueOrDefault(value.Get(key), i.GetValueOrDefault(value.Get(" "+key)))
}
