// Package safari ports libs/importer/src/importers/safari-csv-importer.ts (safaricsv).
package safari

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("safaricsv", New) }

// Importer is SafariCsvImporter.
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
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("Title"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("Username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		url, ok := value.Lookup("Url") // value.Url ?? value.URL
		if !ok {
			url = value.Get("URL")
		}
		cipher.Login.Uris = i.MakeUriArray(url)
		cipher.Login.Totp = i.GetValueOrDefault(value.Get("OTPAuth"))
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
