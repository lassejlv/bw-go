// Package passwordsafe ports libs/importer/src/importers/passwordsafe-xml-importer.ts (format id
// "pwsafexml", the xml format from pwsafe.org).
package passwordsafe

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("pwsafexml", New) }

// Importer is PasswordSafeXmlImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	doc := i.ParseXml(data)
	if doc == nil {
		result.Success = false
		return result, nil
	}

	passwordSafe := doc.QuerySelector("passwordsafe")
	if passwordSafe == nil {
		result.ErrorMessage = "Missing `passwordsafe` node."
		result.Success = false
		return result, nil
	}

	// JS: str.split(null) splits on the string "null" when the attribute is missing.
	notesDelimiter, ok := passwordSafe.GetAttribute("delimiter")
	if !ok {
		notesDelimiter = "null"
	}
	for _, entry := range doc.QuerySelectorAll("passwordsafe > entry") {
		group := i.QuerySelectorDirectChild(entry, "group")
		groupText := ""
		if group != nil && !i.IsNullOrWhitespace(group.TextContent()) {
			groupText = strings.ReplaceAll(group.TextContent(), ".", "/")
		}
		i.ProcessFolder(result, groupText)

		title := i.QuerySelectorDirectChild(entry, "title")
		username := i.QuerySelectorDirectChild(entry, "username")
		email := i.QuerySelectorDirectChild(entry, "email")
		password := i.QuerySelectorDirectChild(entry, "password")
		url := i.QuerySelectorDirectChild(entry, "url")
		notes := i.QuerySelectorDirectChild(entry, "notes")
		cipher := i.InitLoginCipher()
		cipher.Name = "--"
		if title != nil {
			cipher.Name = i.GetValueOrDefault(title.TextContent(), "--")
		}
		cipher.Notes = ""
		if notes != nil {
			cipher.Notes = strings.Join(strings.Split(i.GetValueOrDefault(notes.TextContent(), ""), notesDelimiter), "\n")
		}
		if username != nil {
			cipher.Login.Username = i.GetValueOrDefault(username.TextContent())
		}
		if password != nil {
			cipher.Login.Password = i.GetValueOrDefault(password.TextContent())
		}
		if url != nil {
			cipher.Login.Uris = i.MakeUriArray(url.TextContent())
		}

		if i.IsNullOrWhitespace(cipher.Login.Username) && email != nil {
			cipher.Login.Username = i.GetValueOrDefault(email.TextContent())
		} else if email != nil && !i.IsNullOrWhitespace(email.TextContent()) {
			if i.IsNullOrWhitespace(cipher.Notes) {
				cipher.Notes = "Email: " + email.TextContent()
			} else {
				cipher.Notes = cipher.Notes + "\n" + "Email: " + email.TextContent()
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
