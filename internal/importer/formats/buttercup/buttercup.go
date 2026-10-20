// Package buttercup ports libs/importer/src/importers/buttercup-csv-importer.ts (format id
// "buttercupcsv").
package buttercup

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("buttercupcsv", New) }

var officialProps = []string{
	"!group_id",
	"!group_name",
	"!type",
	"title",
	"username",
	"password",
	"URL",
	"url",
	"note",
	"id",
}

// Importer is ButtercupCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// firstTruthy is `a || b || ...` on (possibly undefined) string properties.
func firstTruthy(value importer.Record, keys ...string) string {
	for _, k := range keys {
		if v := value.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		i.ProcessFolder(result, i.GetValueOrDefault(value.Get("!group_name")))

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("title"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))

		// Handle URL field (case-insensitive)
		urlValue := firstTruthy(value, "URL", "url", "Url")
		cipher.Login.Uris = i.MakeUriArray(urlValue)

		// Handle note field (case-insensitive)
		if noteValue := firstTruthy(value, "note", "Note", "notes", "Notes"); noteValue != "" {
			cipher.Notes = noteValue
		}

		// Process custom fields, excluding official props (case-insensitive). The
		// `__parsed_extra` array is also visited upstream but processKvp ignores non-strings.
		for _, prop := range value.Keys() {
			lowerProp := cases.Lower(language.Und).String(prop)
			isOfficialProp := false
			for _, p := range officialProps {
				if cases.Lower(language.Und).String(p) == lowerProp {
					isOfficialProp = true
					break
				}
			}
			if !isOfficialProp && value.Get(prop) != "" {
				i.ProcessKvp(cipher, prop, value.Get(prop))
			}
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
