// Package msecure ports libs/importer/src/importers/msecure-csv-importer.ts (format id
// "msecurecsv").
package msecure

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("msecurecsv", New) }

// Importer is MSecureCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

var (
	securityCodeRegex = regexp.MustCompile(`^Security Code\|\d*\|`)
	cardNameRegex     = regexp.MustCompile(`^Name on Card\|\d*\|`)
	noteRegex         = regexp.MustCompile(`\|\d*\|`)
)

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsvRows(data, &importer.CsvOptions{Delimiter: ","})
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		if len(value) < 3 {
			continue
		}
		// at(k) is value[k] (undefined -> "").
		at := func(k int) string {
			if k < len(value) {
				return value[k]
			}
			return ""
		}

		folderName := ""
		if i.GetValueOrDefault(value[2], "Unassigned") != "Unassigned" {
			folderName = value[2]
		}
		i.ProcessFolder(result, folderName)

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(strings.Split(value[0], "|")[0], "--")

		if value[1] == "Web Logins" || value[1] == "Login" {
			cipher.Login.Username = i.GetValueOrDefault(splitValueRetainingLastPart(at(5)))
			cipher.Login.Uris = i.MakeUriArray(splitValueRetainingLastPart(at(4)))
			cipher.Login.Password = i.GetValueOrDefault(splitValueRetainingLastPart(at(6)))
			if !i.IsNullOrWhitespace(at(3)) {
				cipher.Notes = strings.Join(strings.Split(at(3), `\n`), "\n")
			} else {
				cipher.Notes = ""
			}
		} else if value[1] == "Credit Card" {
			cipher.Type = model.CipherTypeCard
			cipher.Card.Number = i.GetValueOrDefault(splitValueRetainingLastPart(at(4)))

			expiry := i.GetValueOrDefault(splitValueRetainingLastPart(at(5)))
			if expiry == "" {
				// null.split("/") throws upstream.
				return nil, errors.New("TypeError: Cannot read properties of null (reading 'split')")
			}
			parts := strings.Split(expiry, "/")
			if len(parts) < 2 {
				// year is undefined, year.trim() throws upstream.
				return nil, errors.New("TypeError: Cannot read properties of undefined (reading 'trim')")
			}
			month, year := parts[0], parts[1]
			cipher.Card.ExpMonth = importer.JSTrim(month)
			cipher.Card.ExpYear = importer.JSTrim(year)

			securityCodeEntry := ""
			for _, entry := range value {
				if securityCodeRegex.MatchString(entry) {
					securityCodeEntry = entry
					break
				}
			}
			cipher.Card.Code = i.GetValueOrDefault(splitValueRetainingLastPart(securityCodeEntry))

			nameOnCardEntry := ""
			for _, entry := range value {
				if cardNameRegex.MatchString(entry) {
					nameOnCardEntry = entry
					break
				}
			}
			cipher.Card.CardholderName = i.GetValueOrDefault(splitValueRetainingLastPart(nameOnCardEntry))

			cipher.Card.Brand = i.GetValueOrDefault(splitValueRetainingLastPart(at(9)), "")

			var notes []string
			for _, entry := range value[2:] {
				if !i.IsNullOrWhitespace(entry) && !noteRegex.MatchString(entry) {
					notes = append(notes, entry)
				}
			}
			for _, idx := range []int{8, 10, 11} {
				val := at(idx)
				if val == "" || !noteRegex.MatchString(val) {
					continue
				}
				key := strings.Split(val, "|")[0]
				v := i.GetValueOrDefault(splitValueRetainingLastPart(val), "")
				notes = append(notes, fmt.Sprintf("%s: %s", key, v))
			}
			cipher.Notes = strings.Join(notes, "\n")
		} else if len(value) > 3 {
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
			for j := 3; j < len(value); j++ {
				if !i.IsNullOrWhitespace(value[j]) {
					cipher.Notes += value[j] + "\n"
				}
			}
		}

		if !i.IsNullOrWhitespace(value[1]) && cipher.Type != model.CipherTypeLogin && cipher.Type != model.CipherTypeCard {
			cipher.Name = value[1] + ": " + cipher.Name
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

// splitValueRetainingLastPart: mSecure returns values separated by "|" where after the second
// separator is the value like "Password|8|myPassword", we want to keep the "myPassword" but also
// ensure that if the value contains any "|" it works fine. ("" for an empty/undefined value.)
func splitValueRetainingLastPart(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "|")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[2:], "|")
}
