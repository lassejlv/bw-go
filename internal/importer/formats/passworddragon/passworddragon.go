// Package passworddragon ports libs/importer/src/importers/passworddragon-xml-importer.ts (format
// id "passworddragonxml").
package passworddragon

import (
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passworddragonxml", New) }

// Importer is PasswordDragonXmlImporter.
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

	for _, record := range doc.QuerySelectorAll("PasswordManager > record") {
		category := i.QuerySelectorDirectChild(record, "Category")
		categoryText := ""
		if category != nil && !i.IsNullOrWhitespace(category.TextContent()) && category.TextContent() != "Unfiled" {
			categoryText = category.TextContent()
		}
		i.ProcessFolder(result, categoryText)

		accountName := i.QuerySelectorDirectChild(record, "Account-Name")
		userID := i.QuerySelectorDirectChild(record, "User-Id")
		password := i.QuerySelectorDirectChild(record, "Password")
		url := i.QuerySelectorDirectChild(record, "URL")
		notes := i.QuerySelectorDirectChild(record, "Notes")
		cipher := i.InitLoginCipher()
		cipher.Name = "--"
		if accountName != nil {
			cipher.Name = i.GetValueOrDefault(accountName.TextContent(), "--")
		}
		if notes != nil {
			cipher.Notes = i.GetValueOrDefault(notes.TextContent())
		}
		if userID != nil {
			cipher.Login.Username = i.GetValueOrDefault(userID.TextContent())
		}
		if password != nil {
			cipher.Login.Password = i.GetValueOrDefault(password.TextContent())
		}
		if url != nil {
			cipher.Login.Uris = i.MakeUriArray(url.TextContent())
		}

		attributes := make([]string, 0, 10)
		for n := 1; n <= 10; n++ {
			attributes = append(attributes, "Attribute-"+strconv.Itoa(n))
		}
		for _, attr := range i.QuerySelectorAllDirectChild(record, strings.Join(attributes, ",")) {
			if i.IsNullOrWhitespace(attr.TextContent()) || attr.TextContent() == "null" {
				continue
			}
			i.ProcessKvp(cipher, attr.TagName(), attr.TextContent())
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
