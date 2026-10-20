// Package delineacsv ports libs/importer/src/importers/delinea-csv-importer.ts (delineacsv).
package delineacsv

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("delineacsv", New) }

// Importer is DelineaCsvImporter. Like upstream, the result is an instance field, so repeated
// Parse calls on one importer accumulate into the same result.
type Importer struct {
	importer.Base
	result *model.ImportResult
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts), result: model.NewImportResult()}
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	parseCsvResults := i.ParseCsv(data, nil)
	if parseCsvResults == nil {
		i.result.Success = false
		return i.result, nil
	}

	for _, line := range parseCsvResults {
		cipher := i.InitLoginCipher()

		cipher.Name = i.GetValueOrDefault(line.Get("Secret Name"), "--")
		if line.Get("URL") != "" {
			cipher.Type = model.CipherTypeLogin
		} else {
			cipher.Type = model.CipherTypeSecureNote
		}

		// Object.entries(line); __parsed_extra (an array) would be skipped by isNullOrWhitespace.
		for _, key := range line.Keys() {
			value := line.Get(key)
			switch {
			case key == "Secret Name":
				continue
			case key == "Password" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Password = value
			case key == "URL" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Uris = i.MakeUriArray(value)
			case key == "Username" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Username = value
			case key == "Folder":
				// Skip if no folder
				if i.IsNullOrWhitespace(value) {
					continue
				}
				i.ProcessFolder(i.result, value, true)
			case key == "Notes":
				cipher.Notes = value
			default:
				if !i.IsNullOrWhitespace(value) {
					field := &model.FieldView{Name: key, Value: value}
					if key == "Password" {
						field.Type = model.FieldTypeHidden
					}
					cipher.Fields = append(cipher.Fields, field)
				}
			}
		}

		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(i.result)
	}

	i.result.Success = true
	return i.result, nil
}
