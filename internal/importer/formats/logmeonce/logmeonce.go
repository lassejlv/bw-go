// Package logmeonce ports libs/importer/src/importers/logmeonce-csv-importer.ts (format id
// "logmeoncecsv").
package logmeonce

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("logmeoncecsv", New) }

// Importer is LogMeOnceCsvImporter.
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
		if value.Get("name") == "" {
			continue
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("name"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("url"))

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)

		// Map groups to folders
		if group := value.Get("group"); group != "" {
			folderIdx := -1
			for idx, f := range result.Folders {
				if f.Name == group {
					folderIdx = idx
					break
				}
			}
			if folderIdx == -1 {
				result.Folders = append(result.Folders, &model.FolderView{Name: group})
				folderIdx = len(result.Folders) - 1
			}
			result.FolderRelationships = append(result.FolderRelationships,
				model.Relationship{len(result.Ciphers) - 1, folderIdx})
		}
	}

	result.Success = true
	return result, nil
}
