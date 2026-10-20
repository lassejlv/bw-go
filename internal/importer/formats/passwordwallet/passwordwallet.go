// Package passwordwallet ports libs/importer/src/importers/passwordwallet-txt-importer.ts
// (passwordwallettxt).
package passwordwallet

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passwordwallettxt", New) }

// Importer is PasswordWalletTxtImporter.
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
		if len(value) < 1 {
			continue
		}
		if len(value) > 5 {
			i.ProcessFolder(result, value[5])
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value[0], "--")
		if len(value) > 4 {
			cipher.Notes = strings.Join(strings.Split(i.GetValueOrDefault(value[4], ""), "¬"), "\n")
		}
		if len(value) > 2 {
			cipher.Login.Username = i.GetValueOrDefault(value[2])
		}
		if len(value) > 3 {
			cipher.Login.Password = i.GetValueOrDefault(value[3])
		}
		if len(value) > 1 {
			cipher.Login.Uris = i.MakeUriArray(value[1])
		}
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}
