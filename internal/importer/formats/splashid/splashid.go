// Package splashid ports libs/importer/src/importers/splashid-csv-importer.ts (splashidcsv).
package splashid

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("splashidcsv", New) }

// Importer is SplashIdCsvImporter.
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
		if len(value) < 3 {
			continue
		}

		i.ProcessFolder(result, i.GetValueOrDefault(value[len(value)-1]))
		cipher := i.InitLoginCipher()
		cipher.Notes = i.GetValueOrDefault(value[len(value)-2], "")
		cipher.Name = i.GetValueOrDefault(value[1], "--")

		if value[0] == "Web Logins" || value[0] == "Servers" || value[0] == "Email Accounts" {
			cipher.Login.Username = i.GetValueOrDefault(value[2])
			cipher.Login.Password = i.GetValueOrDefault(at(value, 3))
			cipher.Login.Uris = i.MakeUriArray(at(value, 4))
			i.parseFieldsToNotes(cipher, 5, value)
		} else {
			i.parseFieldsToNotes(cipher, 2, value)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

// at is value[idx] ("" for undefined).
func at(value []string, idx int) string {
	if idx < len(value) {
		return value[idx]
	}
	return ""
}

func (i *Importer) parseFieldsToNotes(cipher *model.CipherView, startIndex int, value []string) {
	// last 3 rows do not get parsed
	for j := startIndex; j < len(value)-3; j++ {
		if i.IsNullOrWhitespace(value[j]) {
			continue
		}
		cipher.Notes += value[j] + "\n"
	}
}
