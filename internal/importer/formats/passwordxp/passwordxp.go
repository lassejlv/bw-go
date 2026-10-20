// Package passwordxp ports libs/importer/src/importers/passsordxp/passwordxp-csv-importer.ts
// (passwordxpcsv) and its German/Dutch header tables.
package passwordxp

import (
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passwordxpcsv", New) }

var mappedColumns = map[string]bool{"Title": true, "Username": true, "URL": true, "Password": true, "Description": true}

// germanHeaderTranslations is german-csv-headers.ts.
var germanHeaderTranslations = map[string]string{
	"Titel":        "Title",
	"Benutzername": "Username",
	"Konto":        "Account",
	"Passwort":     "Password",
	"Geändert am":  "Modified",
	"Erstellt am":  "Created",
	"Läuft ab am":  "Expire on",
	"Beschreibung": "Description",
	"Geändert von": "Modified by",
}

// dutchHeaderTranslations is dutch-csv-headers.ts.
var dutchHeaderTranslations = map[string]string{
	"Titel":          "Title",
	"Gebruikersnaam": "Username",
	"Wachtwoord":     "Password",
	"Gewijzigd":      "Modified",
	"Gemaakt":        "Created",
	"Verloopt op":    "Expire on",
	"Beschrijving":   "Description",
	"Gewijzigd door": "Modified by",
}

// translations is { "User name": "Username", ...german, ...dutch }.
var translations = func() map[string]string {
	t := map[string]string{
		// The header column 'User name' is parsed by the parser, but cannot be used as a variable.
		// This converts it to a valid variable name, prior to parsing.
		"User name": "Username",
	}
	for k, v := range germanHeaderTranslations {
		t[k] = v
	}
	for k, v := range dutchHeaderTranslations {
		t[k] = v
	}
	return t
}()

// translateIntoEnglishHeaders translates the headers from non-English (German, Dutch) to English.
func translateIntoEnglishHeaders(header string, _ int) string {
	if t, ok := translations[header]; ok && t != "" {
		return t
	}
	return header
}

// Importer is PasswordXPCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, &importer.CsvOptions{
		SkipEmptyLines:  importer.SkipEmptyLines,
		TransformHeader: translateIntoEnglishHeaders,
	})
	if results == nil {
		result.Success = false
		return result, nil
	}

	// If the first row (header check) does not contain the column "Title", then the data is
	// invalid (no translation found)
	if results[0].Get("Title") == "" {
		result.Success = false
		return result, nil
	}

	currentFolderName := ""
	for _, row := range results {
		title, ok := row.Lookup("Title")
		// Skip rows starting with '>>>' as they indicate items following have no folder assigned
		// to them
		if ok && title == ">>>" {
			continue
		}

		if !ok {
			return nil, errors.New("Cannot read properties of undefined (reading 'startsWith')")
		}
		// If the title is in the format [title], then it is a folder name
		if strings.HasPrefix(title, "[") && strings.HasSuffix(title, "]") {
			if strings.HasPrefix(title, "/") {
				currentFolderName = strings.Replace(title, "/", "", 1)
			} else {
				currentFolderName = importer.Substring16(title, 1, importer.Len16(title)-1)
			}
			continue
		}

		if !importer.IsNullOrWhitespace(currentFolderName) {
			i.ProcessFolder(result, currentFolderName)
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(row.Get("Title"))
		cipher.Login.Username = i.GetValueOrDefault(row.Get("Username"))
		cipher.Notes = i.GetValueOrDefault(row.Get("Description"))
		cipher.Login.Uris = i.MakeUriArray(row.Get("URL"))
		cipher.Login.Password = i.GetValueOrDefault(row.Get("Password"))

		i.importUnmappedFields(cipher, row, mappedColumns)

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

func (i *Importer) importUnmappedFields(cipher *model.CipherView, row importer.Record, mappedValues map[string]bool) {
	for _, key := range row.Keys() {
		if mappedValues[key] {
			continue
		}
		i.ProcessKvp(cipher, key, row.Get(key))
	}
}
