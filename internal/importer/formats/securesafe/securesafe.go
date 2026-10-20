// Package securesafe ports libs/importer/src/importers/securesafe-csv-importer.ts (securesafecsv).
package securesafe

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("securesafecsv", New) }

// Importer is SecureSafeCsvImporter.
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

	// The url field can be in different case formats.
	urlField, hasURLField := "", false
	for _, k := range results[0].Keys() { // Object.keys(results[0]).find((k) => /url/i.test(k))
		if strings.Contains(strings.ToLower(k), "url") {
			urlField, hasURLField = k, true
			break
		}
	}
	for _, value := range results {
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("Title"))
		cipher.Notes = i.GetValueOrDefault(value.Get("Comment"))
		if hasURLField {
			cipher.Login.Uris = i.MakeUriArray(value.Get(urlField))
		}
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		cipher.Login.Username = i.GetValueOrDefault(value.Get("Username"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
