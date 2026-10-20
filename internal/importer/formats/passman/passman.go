// Package passman ports libs/importer/src/importers/passman-json-importer.ts (passmanjson).
package passman

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passmanjson", New) }

// Importer is PassmanJsonImporter.
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
	if results.Nullish() || results.LengthIs(0) {
		result.Success = false
		return result, nil
	}

	results.ForEach("results", func(credential *jsvalue.Value) {
		if tags := credential.Get("tags"); !tags.Nullish() && tags.LengthGreaterThan(0) {
			folderName := tags.Index(0).Get("text")
			i.ProcessFolder(result, folderName.Str())
		}

		cipher := i.InitLoginCipher()
		cipher.Name = credential.Get("label").Str()

		cipher.Login.Username = i.GetValueOrDefault(credential.Get("username").Str())
		email := credential.Get("email")
		if i.IsNullOrWhitespace(cipher.Login.Username) {
			cipher.Login.Username = i.GetValueOrDefault(email.Str())
		} else if !email.IsNullOrWhitespace() {
			cipher.Notes = "Email: " + email.Str() + "\n"
		}

		cipher.Login.Password = i.GetValueOrDefault(credential.Get("password").Str())
		cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, credential.Get("url"))
		cipher.Notes += i.GetValueOrDefault(credential.Get("description").Str(), "")
		if otp := credential.Get("otp"); !otp.Nullish() {
			cipher.Login.Totp = i.GetValueOrDefault(otp.Get("secret").Str())
		}

		if customFields := credential.Get("custom_fields"); !customFields.Nullish() {
			customFields.ForEach("credential.custom_fields", func(customField *jsvalue.Value) {
				switch customField.Get("field_type").Str() {
				case "text", "password":
					i.ProcessKvp(cipher, customField.Get("label").Str(), customField.Get("value").Str())
				}
			})
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	})

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}
