// Package roboform ports libs/importer/src/importers/roboform-csv-importer.ts (roboformcsv).
package roboform

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("roboformcsv", New) }

// Importer is RoboFormCsvImporter.
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

	n := 1
	for _, value := range results {
		folder := value.Get("Folder")
		if !i.IsNullOrWhitespace(folder) && strings.HasPrefix(folder, "/") {
			folder = strings.Replace(folder, "/", "", 1)
		}
		folderName := ""
		if !i.IsNullOrWhitespace(folder) {
			folderName = folder
		}
		i.ProcessFolder(result, folderName)

		cipher := i.InitLoginCipher()
		cipher.Notes = i.GetValueOrDefault(value.Get("Note"))
		cipher.Name = i.GetValueOrDefault(value.Get("Name"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("Login"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Pwd"))
		if cipher.Login.Password == "" {
			cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		}
		cipher.Login.Uris = i.MakeUriArray(value.Get("Url"))
		if cipher.Login.Uris == nil {
			cipher.Login.Uris = i.MakeUriArray(value.Get("URL"))
		}

		if !i.IsNullOrWhitespace(value.Get("Rf_fields")) {
			i.parseRfFields(cipher, value)
		} else if !i.IsNullOrWhitespace(value.Get("RfFieldsV2")) {
			i.parseRfFieldsV2(cipher, value)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)

		// Upstream quirk: i only advances for pushed ciphers.
		if n == len(results) && cipher.Name == "--" {
			if cipher.Login == nil {
				// cleanupCipher nulled login (the row became a secure note): upstream throws here.
				return nil, errors.New("Cannot read properties of null (reading 'password')")
			}
			if i.IsNullOrWhitespace(cipher.Login.Password) {
				continue
			}
		}

		result.Ciphers = append(result.Ciphers, cipher)
		n++
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

func (i *Importer) parseRfFields(cipher *model.CipherView, value importer.Record) {
	fields := append([]string{value.Get("Rf_fields")}, value.Extra...)
	for _, field := range fields {
		parts := strings.Split(field, ":")
		if len(parts) < 3 {
			continue
		}
		key := parts[0]
		if key == "-no-name-" {
			key = ""
		}
		val := parts[2]
		if len(parts) == 4 && parts[2] == "rck" {
			val = parts[1]
		}
		i.ProcessKvp(cipher, key, val)
	}
}

func (i *Importer) parseRfFieldsV2(cipher *model.CipherView, value importer.Record) {
	fields := append([]string{value.Get("RfFieldsV2")}, value.Extra...)

	userIDCount := 1
	passwordCount := 1

	for _, field := range fields {
		parts := strings.Split(field, ",")
		if len(parts) < 5 {
			continue
		}

		key := parts[0]
		if key == "-no-name-" {
			key = ""
		}
		typ := model.FieldTypeText
		if parts[3] == "pwd" {
			typ = model.FieldTypeHidden
		}
		val := parts[4]

		if key == "TOTP KEY$" {
			cipher.Login.Totp = val
			continue
		}

		// Skip if value matches login fields ("" is null there, which never equals a string)
		if key == "User ID$" && cipher.Login.Username != "" && val == cipher.Login.Username {
			continue
		}
		if key == "Password$" && cipher.Login.Password != "" && val == cipher.Login.Password {
			continue
		}

		// Index any extra User IDs or Passwords
		displayKey := key
		if key == "User ID$" {
			displayKey = fmt.Sprintf("Alternate User ID %d", userIDCount)
			userIDCount++
		} else if key == "Password$" {
			displayKey = fmt.Sprintf("Alternate Password %d", passwordCount)
			passwordCount++
		}

		i.ProcessKvp(cipher, displayKey, val, typ)
	}
}
