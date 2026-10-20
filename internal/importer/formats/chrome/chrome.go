// Package chrome ports libs/importer/src/importers/chrome-csv-importer.ts, which upstream uses for
// chromecsv and the Chromium-family exports edgecsv, operacsv, vivaldicsv and bravecsv.
package chrome

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// IDs are the format ids served by this importer (import.service.ts getImporterInstance).
var IDs = []string{"edgecsv", "chromecsv", "operacsv", "vivaldicsv", "bravecsv"}

func init() {
	for _, id := range IDs {
		importer.Register(id, New)
	}
}

// Importer is ChromeCsvImporter.
type Importer struct {
	importer.Base
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// extractAndroidPackageName extracts the package name from android://[base64]@[package.name]/.
func extractAndroidPackageName(url string) (string, bool) {
	if !strings.HasPrefix(url, "android://") {
		return "", false
	}
	at := strings.Index(url, "@")
	if at == -1 {
		return "", false
	}
	rest := url[at+1:]
	if slash := strings.Index(rest, "/"); slash != -1 {
		return rest[:slash], true
	}
	return rest, true
}

func normalizeAndroidURL(url string) string {
	if pkg, ok := extractAndroidPackageName(url); ok {
		return "androidapp://" + pkg
	}
	return url
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
		cipher := i.InitLoginCipher()
		url := value.Get("url")
		normalizedURI := normalizeAndroidURL(url)

		name := value.Get("name")
		if name == "" {
			if pkg, ok := extractAndroidPackageName(url); ok {
				name = pkg
			}
		}
		cipher.Name = i.GetValueOrDefault(name, "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Uris = i.MakeUriArray(normalizedURI)
		cipher.Notes = i.GetValueOrDefault(value.Get("note"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
