// Package bitwarden ports libs/importer/src/importers/bitwarden (bitwardencsv, bitwardenjson
// including account-encrypted and password-protected exports) and bitwarden-upgrade.
package bitwarden

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("bitwardencsv", NewCsv) }

// CsvImporter is BitwardenCsvImporter.
type CsvImporter struct {
	importer.Base
}

// NewCsv constructs the importer.
func NewCsv(opts importer.Options) importer.Importer {
	return &CsvImporter{Base: importer.NewBase(opts)}
}

// firstNonEmpty is `a || b` for strings.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Parse implements importer.Importer.
func (i *CsvImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		if i.Organization() && !i.IsNullOrWhitespace(value.Get("collections")) {
			// processFolder creates the collections: folders become collections at the end.
			for _, col := range strings.Split(value.Get("collections"), ",") {
				i.ProcessFolder(result, col)
			}
		} else if !i.Organization() {
			i.ProcessFolder(result, value.Get("folder"))
		}

		cipher := model.NewCipherView()
		cipher.Favorite = !i.Organization() && i.GetValueOrDefault(value.Get("favorite"), "0") != "0"
		cipher.Type = model.CipherTypeLogin
		cipher.Notes = i.GetValueOrDefault(value.Get("notes"))
		cipher.Name = i.GetValueOrDefault(value.Get("name"), "--")
		if n, ok := importer.ParseInt(i.GetValueOrDefault(value.Get("reprompt"), "0")); ok {
			cipher.Reprompt = model.CipherRepromptType(n)
		} else {
			// parseInt yields NaN (no exception) upstream; None is the closest valid value.
			cipher.Reprompt = model.CipherRepromptNone
		}

		if archived := value.Get("archivedDate"); !i.IsNullOrWhitespace(archived) {
			if t, ok := importer.ParseJSDate(archived); ok {
				cipher.ArchivedDate = &t
			}
		}

		if fields := value.Get("fields"); !i.IsNullOrWhitespace(fields) {
			for _, line := range i.SplitNewLine(fields) {
				if i.IsNullOrWhitespace(line) {
					continue
				}
				delim := strings.LastIndex(line, ": ")
				if delim == -1 {
					continue
				}
				field := &model.FieldView{Name: line[:delim], Type: model.FieldTypeText}
				if len(line) > delim+2 {
					field.Value = line[delim+2:]
				}
				cipher.Fields = append(cipher.Fields, field)
			}
		}

		valueType := ""
		if t, ok := value.Lookup("type"); ok {
			valueType = strings.ToLower(t)
		}
		switch valueType {
		case "note":
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
		default:
			cipher.Type = model.CipherTypeLogin
			cipher.Login = &model.LoginView{}
			cipher.Login.Totp = i.GetValueOrDefault(firstNonEmpty(value.Get("login_totp"), value.Get("totp")))
			cipher.Login.Username = i.GetValueOrDefault(firstNonEmpty(value.Get("login_username"), value.Get("username")))
			cipher.Login.Password = i.GetValueOrDefault(firstNonEmpty(value.Get("login_password"), value.Get("password")))
			uris := i.ParseSingleRowCsv(firstNonEmpty(value.Get("login_uri"), value.Get("uri")))
			cipher.Login.Uris = i.MakeUriArray(uris...)
		}

		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}
	result.Success = true
	return result, nil
}
