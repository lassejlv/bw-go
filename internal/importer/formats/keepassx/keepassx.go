// Package keepassx ports libs/importer/src/importers/keepassx-csv-importer.ts (format id
// "keepassxcsv").
package keepassx

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("keepassxcsv", New) }

// Importer is KeePassXCsvImporter.
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
		if i.IsNullOrWhitespace(value.Get("Title")) {
			continue
		}

		group := value.Get("Group")
		if !i.IsNullOrWhitespace(group) && strings.HasPrefix(group, "Root/") {
			group = strings.Replace(group, "Root/", "", 1)
		}
		groupName := ""
		if !i.IsNullOrWhitespace(group) {
			groupName = group
		}
		i.ProcessFolder(result, groupName)

		cipher := i.InitLoginCipher()
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"))
		cipher.Name = i.GetValueOrDefault(value.Get("Title"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("Username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("URL"))
		cipher.Login.Totp = i.GetValueOrDefault(value.Get("TOTP"))

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}
