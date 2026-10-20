// Package safeincloud ports libs/importer/src/importers/safeincloud-xml-importer.ts (format id
// "safeincloudxml").
package safeincloud

import (
	"slices"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("safeincloudxml", New) }

// Importer is SafeInCloudXmlImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	// SafeInCloud's XML export can contain a leading BOM or whitespace before the `<?xml ?>`
	// declaration. DOMParser treats that as a parse error, so strip it (/^[\s\uFEFF]+/).
	doc := i.ParseXml(strings.TrimLeftFunc(data, func(r rune) bool { return importer.IsJSSpace(r) || r == '\uFEFF' }))
	if doc == nil {
		result.Success = false
		return result, nil
	}

	if doc.QuerySelector("database") == nil {
		result.ErrorMessage = "Missing `database` node."
		result.Success = false
		return result, nil
	}

	for _, cardEl := range doc.QuerySelectorAll("database > card") {
		if attrIs(cardEl, "template", "true") || attrIs(cardEl, "deleted", "true") {
			continue
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(cardEl.Attr("title"), "--")

		if attrIs(cardEl, "star", "true") {
			cipher.Favorite = true
		}

		cardType, hasType := cardEl.GetAttribute("type")
		fieldEls := i.QuerySelectorAllDirectChild(cardEl, "field")

		switch {
		case hasType && cardType == "note":
			cipher.Type = model.CipherTypeSecureNote
			cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
		case i.isCreditCard(fieldEls):
			i.processCreditCard(cipher, fieldEls)
		default:
			i.processLogin(cipher, fieldEls)
		}

		for _, notesEl := range i.QuerySelectorAllDirectChild(cardEl, "notes") {
			cipher.Notes += notesEl.TextContent() + "\n"
		}

		if cipher.Type == model.CipherTypeLogin {
			i.setPassword(cipher)
		}
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

func attrIs(el *dom.Node, name, want string) bool {
	v, ok := el.GetAttribute(name)
	return ok && v == want
}

// setPassword chooses a password from all hidden fields: one whose name is a password field
// name (which is then removed from the fields), or else the first one (kept as a hidden field).
func (i *Importer) setPassword(cipher *model.CipherView) {
	var candidates []*model.FieldView
	for _, f := range cipher.Fields {
		if f.Type == model.FieldTypeHidden {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		return
	}

	var choice *model.FieldView
	for _, field := range candidates {
		if slices.Contains(importer.PasswordFieldNames, strings.ToLower(field.Name)) {
			choice = field
			kept := []*model.FieldView{}
			for _, f := range cipher.Fields {
				if f != choice {
					kept = append(kept, f)
				}
			}
			cipher.Fields = kept
			break
		}
	}

	if choice == nil {
		choice = candidates[0]
	}

	cipher.Login.Password = choice.Value
}

func (i *Importer) isCreditCard(fieldEls []*dom.Node) bool {
	for _, f := range fieldEls {
		if attrIs(f, "autofill", "cc-number") && !i.IsNullOrWhitespace(f.TextContent()) {
			return true
		}
	}
	return false
}

func (i *Importer) processCreditCard(cipher *model.CipherView, fieldEls []*dom.Node) {
	cipher.Type = model.CipherTypeCard
	cipher.Card = &model.CardView{}

	for _, fieldEl := range fieldEls {
		text := fieldEl.TextContent()
		if i.IsNullOrWhitespace(text) {
			continue
		}
		name := fieldEl.Attr("name")
		autofill, hasAutofill := fieldEl.GetAttribute("autofill")
		if !hasAutofill {
			autofill = "\x00" // null never equals a string
		}
		fieldType := strings.ToLower(i.GetValueOrDefault(fieldEl.Attr("type"), ""))

		if autofill == "cc-number" {
			cipher.Card.Number = text
			cipher.Card.Brand = model.GetCardBrandByPatterns(text)
			continue
		}
		if autofill == "cc-name" {
			cipher.Card.CardholderName = text
			continue
		}
		if autofill == "cc-exp" && i.SetCardExpiration(cipher, text) {
			continue
		}
		if autofill == "cc-csc" {
			cipher.Card.Code = text
			continue
		}

		if fieldType == "notes" {
			cipher.Notes += text + "\n"
		} else {
			t := model.FieldTypeText
			if fieldType == "pin" {
				t = model.FieldTypeHidden
			}
			i.ProcessKvp(cipher, name, text, t)
		}
	}
}

func (i *Importer) processLogin(cipher *model.CipherView, fieldEls []*dom.Node) {
	for _, fieldEl := range fieldEls {
		text := fieldEl.TextContent()
		if i.IsNullOrWhitespace(text) {
			continue
		}
		name := fieldEl.Attr("name")
		fieldType := strings.ToLower(i.GetValueOrDefault(fieldEl.Attr("type"), ""))

		switch fieldType {
		case "login":
			if i.IsNullOrWhitespace(cipher.Login.Username) {
				cipher.Login.Username = text
			} else {
				i.ProcessKvp(cipher, name, text)
			}
		case "password", "secret":
			// SafeInCloud allows for more than one password. Insert them here and find the one
			// used as password later.
			i.ProcessKvp(cipher, name, text, model.FieldTypeHidden)
		case "one_time_password":
			cipher.Login.Totp = text
		case "notes":
			cipher.Notes += text + "\n"
		case "weblogin", "website":
			cipher.Login.Uris = append(cipher.Login.Uris, i.MakeUriArray(text)...)
		default:
			i.ProcessKvp(cipher, name, text)
		}
	}
}
