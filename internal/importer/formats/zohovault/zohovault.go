// Package zohovault ports libs/importer/src/importers/zohovault-csv-importer.ts (zohovaultcsv).
package zohovault

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("zohovaultcsv", New) }

// Importer is ZohoVaultCsvImporter.
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
		if i.IsNullOrWhitespace(value.Get("Password Name")) && i.IsNullOrWhitespace(value.Get("Secret Name")) {
			continue
		}
		i.ProcessFolder(result, i.GetValueOrDefault(value.Get("Folder Name")))
		cipher := i.InitLoginCipher()
		cipher.Favorite = i.GetValueOrDefault(value.Get("Favorite"), "0") == "1"
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"))
		cipher.Name = i.GetValueOrDefault(
			value.Get("Password Name"),
			i.GetValueOrDefault(value.Get("Secret Name"), "--"),
		)
		cipher.Login.Uris = i.MakeUriArray(
			i.GetValueOrDefault(value.Get("Password URL"), i.GetValueOrDefault(value.Get("Secret URL"))),
		)
		cipher.Login.Totp = i.GetValueOrDefault(
			value.Get("TOTP"),
			i.GetValueOrDefault(value.Get("login_totp")),
		)
		i.parseData(cipher, value.Get("SecretData"))
		i.parseData(cipher, value.Get("CustomData"))
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

func (i *Importer) parseData(cipher *model.CipherView, data string) {
	if i.IsNullOrWhitespace(data) {
		return
	}
	// login.username/password are null ("") until set here; the values set are never whitespace.
	for _, line := range i.SplitNewLine(data) {
		delimPosition := strings.Index(line, ":")
		if delimPosition < 0 {
			continue
		}
		field := line[:delimPosition]
		value := line[delimPosition+1:]
		if i.IsNullOrWhitespace(field) || i.IsNullOrWhitespace(value) || field == "SecretType" {
			continue
		}
		fieldLower := strings.ToLower(field)
		if cipher.Login.Username == "" && contains(importer.UsernameFieldNames, fieldLower) {
			cipher.Login.Username = value
		} else if cipher.Login.Password == "" && contains(importer.PasswordFieldNames, fieldLower) {
			cipher.Login.Password = value
		} else {
			i.ProcessKvp(cipher, field, value)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
