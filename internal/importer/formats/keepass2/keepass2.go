// Package keepass2 ports libs/importer/src/importers/keepass2-xml-importer.ts (format id
// "keepass2xml").
package keepass2

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("keepass2xml", New) }

// Importer is KeePass2XmlImporter.
type Importer struct {
	importer.Base
	result *model.ImportResult
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	i.result = model.NewImportResult()
	doc := i.ParseXml(data)
	if doc == nil {
		i.result.Success = false
		return i.result, nil
	}

	// Upstream breaks "KeePassFile > Root > Group" down node by node.
	keePassFileNode := doc.QuerySelector("KeePassFile")
	if keePassFileNode == nil {
		i.result.ErrorMessage = "Missing `KeePassFile` node."
		i.result.Success = false
		return i.result, nil
	}
	rootNode := keePassFileNode.QuerySelector("Root")
	if rootNode == nil {
		i.result.ErrorMessage = "Missing `KeePassFile > Root` node."
		i.result.Success = false
		return i.result, nil
	}
	rootGroup := rootNode.QuerySelector("Group")
	if rootGroup == nil {
		i.result.ErrorMessage = "Missing `KeePassFile > Root > Group` node."
		i.result.Success = false
		return i.result, nil
	}

	i.traverse(rootGroup, true, "")

	if i.Organization() {
		i.MoveFoldersToCollections(i.result)
	}
	i.result.Success = true
	return i.result, nil
}

func (i *Importer) traverse(node *dom.Node, isRootNode bool, groupPrefixName string) {
	folderIndex := len(i.result.Folders)
	groupName := groupPrefixName

	if !isRootNode {
		if groupName != "" {
			groupName += "/"
		}
		nameEl := i.QuerySelectorDirectChild(node, "Name")
		if nameEl == nil {
			groupName += "-"
		} else {
			groupName += nameEl.TextContent()
		}
		i.result.Folders = append(i.result.Folders, &model.FolderView{Name: groupName})
	}

	for _, entry := range i.QuerySelectorAllDirectChild(node, "Entry") {
		cipherIndex := len(i.result.Ciphers)
		cipher := i.InitLoginCipher()

		for _, entryString := range i.QuerySelectorAllDirectChild(entry, "String") {
			valueEl := i.QuerySelectorDirectChild(entryString, "Value")
			value := ""
			if valueEl != nil {
				value = valueEl.TextContent()
			}
			if i.IsNullOrWhitespace(value) {
				continue
			}
			key := ""
			hasKey := false
			if keyEl := i.QuerySelectorDirectChild(entryString, "Key"); keyEl != nil {
				key, hasKey = keyEl.TextContent(), true
			}

			switch {
			case hasKey && key == "URL":
				cipher.Login.Uris = i.MakeUriArray(value)
			case hasKey && key == "UserName":
				cipher.Login.Username = value
			case hasKey && key == "Password":
				cipher.Login.Password = value
			case hasKey && key == "otp":
				cipher.Login.Totp = strings.Replace(value, "key=", "", 1)
			case hasKey && key == "Title":
				cipher.Name = value
			case hasKey && key == "Notes":
				cipher.Notes += value + "\n"
			default:
				if protect, ok := valueEl.GetAttribute("ProtectInMemory"); ok && protect == "True" {
					// Protected fields are always imported as hidden fields, regardless of length or
					// newlines (fixes #16897).
					cipher.Fields = append(cipher.Fields, &model.FieldView{Type: model.FieldTypeHidden, Name: key, Value: value})
				} else {
					i.ProcessKvp(cipher, key, value, model.FieldTypeText)
				}
			}
		}

		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		if !isRootNode {
			i.result.FolderRelationships = append(i.result.FolderRelationships, model.Relationship{cipherIndex, folderIndex})
		}
	}

	for _, group := range i.QuerySelectorAllDirectChild(node, "Group") {
		i.traverse(group, false, groupName)
	}
}
