// Package firefox ports libs/importer/src/importers/firefox-csv-importer.ts (format id
// "firefoxcsv").
package firefox

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("firefoxcsv", New) }

// Importer is FirefoxCsvImporter.
type Importer struct {
	importer.Base
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
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
		if value.Get("url") == "chrome://FirefoxAccounts" {
			continue
		}
		cipher := i.InitLoginCipher()
		url := i.GetValueOrDefault(value.Get("url"), i.GetValueOrDefault(value.Get("hostname")))
		cipher.Name = i.GetValueOrDefault(i.NameFromUrl(url), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Uris = i.MakeUriArray(url)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
