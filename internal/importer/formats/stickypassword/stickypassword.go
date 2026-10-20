// Package stickypassword ports libs/importer/src/importers/stickypassword-xml-importer.ts (format
// id "stickypasswordxml").
package stickypassword

import (
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("stickypasswordxml", New) }

// Importer is StickyPasswordXmlImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// attrJS is getAttribute as concatenated into a selector or string in JS: a missing attribute is
// null, which stringifies to "null".
func attrJS(n *dom.Node, name string) string {
	if v, ok := n.GetAttribute(name); ok {
		return v
	}
	return "null"
}

// querySelectorByAttr is doc.querySelector(prefix + '[attr="value"]'), matched without building
// a selector string (upstream would throw a selector SyntaxError for values containing quotes).
func querySelectorByAttr(doc *dom.Node, prefix, attr, value string) *dom.Node {
	for _, n := range doc.QuerySelectorAll(prefix) {
		if v, ok := n.GetAttribute(attr); ok && v == value {
			return n
		}
	}
	return nil
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	doc := i.ParseXml(data)
	if doc == nil {
		result.Success = false
		return result, nil
	}

	for _, loginNode := range doc.QuerySelectorAll("root > Database > Logins > Login") {
		accountID, _ := loginNode.GetAttribute("ID")
		if i.IsNullOrWhitespace(accountID) {
			continue
		}

		usernameText := loginNode.Attr("Name")
		passwordText := loginNode.Attr("Password")
		var titleText, linkText, notesText, groupID, groupText string

		accountLogin := querySelectorByAttr(doc, "root > Database > Accounts > Account > LoginLinks > Login", "SourceLoginID", accountID)
		if accountLogin != nil && accountLogin.Parent != nil {
			if account := accountLogin.Parent.Parent; account != nil && account.Type == dom.ElementNode {
				titleText = account.Attr("Name")
				linkText = account.Attr("Link")
				groupID = account.Attr("ParentID")
				notesText = account.Attr("Comments")
				if !i.IsNullOrWhitespace(notesText) {
					notesText = strings.ReplaceAll(notesText, "/n", "\n")
				}
			}
		}

		if !i.IsNullOrWhitespace(groupID) {
			var err error
			groupText, err = i.buildGroupText(doc, groupID, "", 0)
			if err != nil {
				return nil, err
			}
			i.ProcessFolder(result, groupText)
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(titleText, "--")
		cipher.Notes = i.GetValueOrDefault(notesText)
		cipher.Login.Username = i.GetValueOrDefault(usernameText)
		cipher.Login.Password = i.GetValueOrDefault(passwordText)
		cipher.Login.Uris = i.MakeUriArray(linkText)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

// maxGroupDepth bounds the recursion: upstream recurses without limit and throws a RangeError
// (stack overflow) for cyclic ParentIDs.
const maxGroupDepth = 10000

func (i *Importer) buildGroupText(doc *dom.Node, groupID, groupText string, depth int) (string, error) {
	group := querySelectorByAttr(doc, "root > Database > Groups > Group", "ID", groupID)
	if group == nil {
		return groupText, nil
	}
	if depth >= maxGroupDepth {
		return "", errors.New("Maximum call stack size exceeded")
	}
	if !i.IsNullOrWhitespace(groupText) {
		groupText = "/" + groupText
	}
	groupText = attrJS(group, "Name") + groupText
	return i.buildGroupText(doc, attrJS(group, "ParentID"), groupText, depth+1)
}
