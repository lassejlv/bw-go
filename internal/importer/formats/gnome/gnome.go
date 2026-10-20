// Package gnome ports libs/importer/src/importers/gnome-json-importer.ts (gnomejson).
package gnome

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("gnomejson", New) }

// Importer is GnomeJsonImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (_ *model.ImportResult, err error) {
	defer jsvalue.CatchTypeError(&err)
	result := model.NewImportResult()
	results, err := jsvalue.Parse(data)
	if err != nil {
		return nil, err
	}
	if results.Nullish() || len(results.OwnKeys()) == 0 {
		result.Success = false
		return result, nil
	}

	for _, keyRing := range results.OwnKeys() {
		if i.IsNullOrWhitespace(keyRing) || results.Get(keyRing).LengthIs(0) {
			continue
		}

		results.Get(keyRing).ForEach("results[keyRing]", func(value *jsvalue.Value) {
			displayName := value.Get("display_name")
			if displayName.IsNullOrWhitespace() || !strings.HasPrefix(displayName.Str(), "http") {
				return
			}

			i.ProcessFolder(result, keyRing)
			cipher := i.InitLoginCipher()
			cipher.Name = strings.Replace(strings.Replace(displayName.Str(), "http://", "", 1), "https://", "", 1)
			if importer.Len16(cipher.Name) > 30 {
				cipher.Name = importer.Substring16(cipher.Name, 0, 30)
			}
			cipher.Login.Password = i.GetValueOrDefault(value.Get("secret").Str())
			cipher.Login.Uris = i.MakeUriArray(displayName.Str())

			if attributes := value.Get("attributes"); !attributes.Nullish() {
				cipher.Login.Username = i.GetValueOrDefault(attributes.Get("username_value").Str())
				for _, attr := range attributes.OwnKeys() {
					if attr == "username_value" || attr == "xdg:schema" {
						continue
					}
					i.ProcessKvp(cipher, attr, attributes.Get(attr).Str())
				}
			}

			i.ConvertToNoteIfNeeded(cipher)
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
		})
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}
