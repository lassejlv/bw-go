// Package codebook ports libs/importer/src/importers/codebook-csv-importer.ts (format id
// "codebookcsv").
package codebook

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("codebookcsv", New) }

// Importer is CodebookCsvImporter.
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
		i.ProcessFolder(result, i.GetValueOrDefault(value.Get("Category")))

		cipher := i.InitLoginCipher()
		cipher.Favorite = i.GetValueOrDefault(value.Get("Favorite")) == "True"
		cipher.Name = i.GetValueOrDefault(value.Get("Entry"), "--")
		cipher.Notes = i.GetValueOrDefault(value.Get("Note"))
		cipher.Login.Username = i.GetValueOrDefault(value.Get("Username"), value.Get("Email"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		cipher.Login.Totp = i.GetValueOrDefault(value.Get("TOTP"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("Website"))

		if !i.IsNullOrWhitespace(value.Get("Username")) {
			i.ProcessKvp(cipher, "Email", value.Get("Email"))
		}
		i.ProcessKvp(cipher, "Phone", value.Get("Phone"))
		i.ProcessKvp(cipher, "PIN", value.Get("PIN"))
		i.ProcessKvp(cipher, "Account", value.Get("Account"))
		i.ProcessKvp(cipher, "Date", value.Get("Date"))

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
