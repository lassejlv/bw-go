// Package delineaxml ports libs/importer/src/importers/delinea-xml-importer.ts (format id
// "delineaxml").
package delineaxml

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("delineaxml", New) }

// Importer is DelineaXmlImporter.
type Importer struct {
	importer.Base
	result *model.ImportResult
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts), result: model.NewImportResult()}
}

type slugValue struct{ slug, value string }

// textOf is `this.querySelectorDirectChild(node, sel)?.textContent ?? ""` (ok=false when missing).
func (i *Importer) textOf(node *dom.Node, sel string) (string, bool) {
	el := i.QuerySelectorDirectChild(node, sel)
	if el == nil {
		return "", false
	}
	return el.TextContent(), true
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	doc := i.ParseXml(data)
	if doc == nil {
		i.result.ErrorMessage = "Unable to parse XML file."
		i.result.Success = false
		return i.result, nil
	}

	importFileNode := doc.QuerySelector("ImportFile")
	if importFileNode == nil {
		i.result.ErrorMessage = "Missing `ImportFile` node."
		i.result.Success = false
		return i.result, nil
	}

	for _, folderNode := range i.getFolderNodes(importFileNode) {
		if folderPath, _ := i.textOf(folderNode, "FolderPath"); folderPath != "" {
			i.ProcessFolder(i.result, folderPath, false)
		}
	}

	for _, secretNode := range i.getSecretNodes(importFileNode) {
		cipher := i.InitLoginCipher()

		if name, ok := i.textOf(secretNode, "SecretName"); ok {
			cipher.Name = name
		} else {
			cipher.Name = "--"
		}

		slugValues := i.getSlugValues(secretNode)
		// Currently the only specialized item type we support is login, which is distinguished by
		// the presence of a "url" slug.
		cipher.Type = model.CipherTypeSecureNote
		for _, s := range slugValues {
			if s.slug == "url" {
				cipher.Type = model.CipherTypeLogin
				break
			}
		}

		// Only the password, url, and username fields require special handling, and only if the
		// cipher is a login. Everything else is parsed as a custom field.
		for _, item := range slugValues {
			switch {
			case item.slug == "password" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Password = item.value
			case item.slug == "url" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Uris = i.MakeUriArray(item.value)
			case item.slug == "username" && cipher.Type == model.CipherTypeLogin:
				cipher.Login.Username = item.value
			case item.slug == "notes":
				cipher.Notes = item.value
			default:
				field := &model.FieldView{Name: item.slug, Value: item.value}
				if item.slug == "password" {
					field.Type = model.FieldTypeHidden
				}
				cipher.Fields = append(cipher.Fields, field)
			}
		}

		fp, _ := i.textOf(secretNode, "FolderPath")
		if folderPath := i.GetValueOrDefault(fp); folderPath != "" {
			i.ProcessFolder(i.result, folderPath, true)
		}

		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(i.result)
	}

	i.result.Success = true
	return i.result, nil
}

func (i *Importer) getFolderNodes(importFileNode *dom.Node) []*dom.Node {
	foldersNode := i.QuerySelectorDirectChild(importFileNode, "Folders")
	if foldersNode == nil {
		return nil
	}
	return i.QuerySelectorAllDirectChild(foldersNode, "Folder")
}

func (i *Importer) getSecretNodes(importFileNode *dom.Node) []*dom.Node {
	secretsNode := i.QuerySelectorDirectChild(importFileNode, "Secrets")
	if secretsNode == nil {
		return nil
	}
	return i.QuerySelectorAllDirectChild(secretsNode, "Secret")
}

// getSlugValues: each <Secret> can contain a <SecretItems> tag with zero or more <SecretItem>
// tags, identified by <Slug> with the value in <Value>. Empty, missing, or all-whitespace values
// are ignored.
func (i *Importer) getSlugValues(secretNode *dom.Node) []slugValue {
	var out []slugValue
	secretItemsNode := i.QuerySelectorDirectChild(secretNode, "SecretItems")
	if secretItemsNode == nil {
		return out
	}
	for _, item := range i.QuerySelectorAllDirectChild(secretItemsNode, "SecretItem") {
		s, _ := i.textOf(item, "Slug")
		v, _ := i.textOf(item, "Value")
		slug := i.GetValueOrDefault(s)
		value := i.GetValueOrDefault(v)
		if slug != "" && value != "" {
			out = append(out, slugValue{slug, value})
		}
	}
	return out
}
