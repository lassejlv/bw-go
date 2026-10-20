// Package netwrix ports libs/importer/src/importers/netwrix/netwrix-passwordsecure-csv-importer.ts
// (format id "netwrixpasswordsecure").
package netwrix

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("netwrixpasswordsecure", New) }

// Netwrix Password Secure exports the same logical field under different column headers depending
// on the export's language/version. Each logical field lists every known header; the first column
// that is present and non-empty for a given row is used.
var (
	folderColumns   = []string{"Organisationseinheit", "Organisational unit"}
	nameColumns     = []string{"Beschreibung"}
	usernameColumns = []string{"Benutzername"}
	passwordColumns = []string{"Passwort"}
	uriColumns      = []string{
		"Internetseite",
		"Internetadresse",
		"Webseite",
		"Webseite1",
		"Website",
		"Webmail",
		"Web page",
		"URL",
	}
	notesColumns = []string{"Informationen", "Kommentare"}
	totpColumns  = []string{"One-Time Passwort"}

	// mappedColumns are the columns that map to a cipher property. Anything else (e.g. DataTags,
	// EMail-Adresse) is preserved as a custom field by importUnmappedFields.
	mappedColumns = func() map[string]bool {
		m := map[string]bool{}
		for _, list := range [][]string{folderColumns, nameColumns, usernameColumns, passwordColumns, uriColumns, notesColumns, totpColumns} {
			for _, c := range list {
				m[c] = true
			}
		}
		return m
	}()
)

// Netwrix uses a semicolon delimiter. Setting it explicitly avoids papaparse's delimiter
// auto-detection, which fails on exports where each row is wrapped in an extra layer of quotes.
const delimiter = ";"

// Importer is NetwrixPasswordSecureCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, &importer.CsvOptions{Delimiter: delimiter})
	if results == nil {
		result.Success = false
		return result, nil
	}

	results = i.unwrapEnclosingQuotes(results)

	for _, row := range results {
		i.ProcessFolder(result, i.firstPopulated(row, folderColumns))
		cipher := i.InitLoginCipher()

		notes := i.GetValueOrDefault(i.firstPopulated(row, notesColumns))
		if notes != "" {
			cipher.Notes = importer.JSTrimEnd(notes)
		}

		cipher.Name = i.GetValueOrDefault(i.firstPopulated(row, nameColumns), "--")
		cipher.Login.Username = i.GetValueOrDefault(i.firstPopulated(row, usernameColumns))
		cipher.Login.Password = i.GetValueOrDefault(i.firstPopulated(row, passwordColumns))
		var uris []string
		for _, column := range uriColumns {
			if v, ok := row.Lookup(column); ok {
				uris = append(uris, v)
			}
		}
		cipher.Login.Uris = i.MakeUriArray(uris...)

		cipher.Login.Totp = i.GetValueOrDefault(i.firstPopulated(row, totpColumns))

		i.importUnmappedFields(cipher, row, mappedColumns)

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

// unwrapEnclosingQuotes handles exports that wrap each entire row in an extra layer of CSV quoting
// (`"Organisationseinheit;""DataTags"";..."`): papaparse reads the whole line as a single field,
// so the already-unwrapped values are re-parsed. Well-formed exports are returned as-is.
func (i *Importer) unwrapEnclosingQuotes(rows []importer.Record) []importer.Record {
	columns := rows[0].Keys()
	// Object.keys(rows[0]) also lists `__parsed_extra` when present.
	numColumns := len(columns)
	if rows[0].Extra != nil {
		numColumns++
	}
	if numColumns != 1 || !strings.Contains(columns[0], delimiter) {
		return rows
	}

	headerLine := columns[0]
	lines := []string{headerLine}
	for _, row := range rows {
		lines = append(lines, row.Get(headerLine))
	}
	// parseCsv returns null when the re-parse yields no data rows; fall back to the original rows.
	if reparsed := i.ParseCsv(strings.Join(lines, "\n"), &importer.CsvOptions{Delimiter: delimiter}); reparsed != nil {
		return reparsed
	}
	return rows
}

// firstPopulated returns the value of the first candidate column that is present and non-empty,
// or "".
func (i *Importer) firstPopulated(row importer.Record, columns []string) string {
	for _, candidate := range columns {
		if !i.IsNullOrWhitespace(row.Get(candidate)) {
			return row.Get(candidate)
		}
	}
	return ""
}

func (i *Importer) importUnmappedFields(cipher *model.CipherView, row importer.Record, mappedValues map[string]bool) {
	// `__parsed_extra` (an array) is skipped by processKvp's isNullOrWhitespace check.
	for _, key := range row.Keys() {
		if mappedValues[key] {
			continue
		}
		i.ProcessKvp(cipher, key, row.Get(key))
	}
}
