// Package padlock ports libs/importer/src/importers/padlock-csv-importer.ts (format id
// "padlockcsv").
package padlock

import (
	"slices"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("padlockcsv", New) }

// Importer is PadlockCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsvRows(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	var headers []string
	for _, value := range results {
		if headers == nil {
			headers = append([]string{}, value...)
			continue
		}

		if len(value) < 2 || len(value) != len(headers) {
			continue
		}

		if !i.IsNullOrWhitespace(value[1]) {
			if i.Organization() {
				tags := strings.Split(value[1], ",")
				for _, tag := range tags {
					tag = importer.JSTrim(tag)
					addCollection := true
					collectionIndex := len(result.Collections)

					for j, c := range result.Collections {
						if c.Name == tag {
							addCollection = false
							collectionIndex = j
							break
						}
					}

					if addCollection {
						result.Collections = append(result.Collections, &model.CollectionView{Name: tag})
					}

					result.CollectionRelationships = append(result.CollectionRelationships,
						model.Relationship{len(result.Ciphers), collectionIndex})
				}
			} else {
				tags := strings.Split(value[1], ",")
				tag := importer.JSTrim(tags[0])
				i.ProcessFolder(result, tag)
			}
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value[0], "--")

		for j := 2; j < len(value); j++ {
			header := cases.Lower(language.Und).String(importer.JSTrim(headers[j]))
			if i.IsNullOrWhitespace(value[j]) || i.IsNullOrWhitespace(header) {
				continue
			}

			if slices.Contains(importer.UsernameFieldNames, header) {
				cipher.Login.Username = value[j]
			} else if slices.Contains(importer.PasswordFieldNames, header) {
				cipher.Login.Password = value[j]
			} else if slices.Contains(importer.UriFieldNames, header) {
				cipher.Login.Uris = i.MakeUriArray(value[j])
			} else {
				i.ProcessKvp(cipher, headers[j], value[j])
			}
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
