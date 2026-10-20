// Package passwordagent ports libs/importer/src/importers/passwordagent-csv-importer.ts
// (passwordagentcsv).
package passwordagent

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passwordagentcsv", New) }

// Importer is PasswordAgentCsvImporter.
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

	newVersion := true
	at := func(value []string, idx int) string {
		if idx < len(value) {
			return value[idx]
		}
		return ""
	}
	for _, value := range results {
		if len(value) != 5 && len(value) < 9 {
			continue
		}
		altFormat := len(value) == 10 && value[0] == "0"
		pick := func(alt, normal int) int {
			if altFormat {
				return alt
			}
			return normal
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(at(value, pick(1, 0)), "--")
		cipher.Login.Username = i.GetValueOrDefault(at(value, pick(2, 1)))
		cipher.Login.Password = i.GetValueOrDefault(at(value, pick(3, 2)))
		if len(value) == 5 {
			newVersion = false
			cipher.Notes = i.GetValueOrDefault(value[4])
			cipher.Login.Uris = i.MakeUriArray(value[3])
		} else {
			folder := i.GetValueOrDefault(at(value, pick(9, 8)), "(None)")
			folderName := ""
			if folder != "(None)" {
				// Upstream computes split("\\") and split(" > ") variants, but only the last
				// assignment (from the original folder) survives.
				folderName = strings.Join(strings.Split(folder, ">"), "/")
			}
			i.ProcessFolder(result, folderName)
			cipher.Notes = i.GetValueOrDefault(at(value, pick(5, 3)))
			cipher.Login.Uris = i.MakeUriArray(value[4])
		}
		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if newVersion && i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}
