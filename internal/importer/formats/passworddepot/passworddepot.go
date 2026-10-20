// Package passworddepot ports
// libs/importer/src/importers/password-depot/password-depot-17-xml-importer.ts (format id
// "passworddepot17xml").
package passworddepot

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passworddepot17xml", New) }

// PasswordDepotItemType values.
const (
	itemTypePassword        = "0"
	itemTypeCreditCard      = "1"
	itemTypeSoftwareLicense = "2"
	itemTypeIdentity        = "3"
	itemTypeInformation     = "4"
	itemTypeBanking         = "5"
	itemTypeEncryptedFile   = "6"
	itemTypeDocument        = "7"
	itemTypeRDP             = "8"
	itemTypePutty           = "9"
	itemTypeTeamViewer      = "10"
	itemTypeCertificate     = "11"
)

// PasswordDepotCustomFieldType values.
const (
	customFieldTypePassword = "1"
	customFieldTypeMemo     = "2"
	customFieldTypeDate     = "3"
	customFieldTypeNumber   = "4"
	customFieldTypeBoolean  = "5"
	customFieldTypeDecimal  = "6"
	customFieldTypeEmail    = "7"
	customFieldTypeURL      = "8"
)

// Importer is PasswordDepot17XmlImporter.
type Importer struct {
	importer.Base
	useNewDedicatedTypes bool

	result                *model.ImportResult
	favouritesLookupTable map[string]bool
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{
		Base:                  importer.NewBase(opts),
		useNewDedicatedTypes:  opts.Features.NewItemTypes,
		result:                model.NewImportResult(),
		favouritesLookupTable: map[string]bool{},
	}
}

// errNullFingerprint is the TypeError the TS code throws for a <group> without a fingerprint
// attribute (`groupFingerprint.textContent` on null).
var errNullFingerprint = errors.New("Cannot read properties of null (reading 'textContent')")

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	useNewDedicatedTypes := i.useNewDedicatedTypes
	doc := i.ParseXml(data)
	if doc == nil {
		i.result.Success = false
		return i.result, nil
	}

	// Check if the root node is present
	rootNode := doc.QuerySelector("passwordfile")
	if rootNode == nil {
		i.result.ErrorMessage = "Missing `passwordfile` node."
		i.result.Success = false
		return i.result, nil
	}

	// Check if the version is supported
	headerNode := i.QuerySelectorDirectChild(rootNode, "header")
	if headerNode == nil {
		i.result.Success = false
		return i.result, nil
	}

	versionNode := i.QuerySelectorDirectChild(headerNode, "version")
	if versionNode == nil {
		// Fallback for MacOS Password Depot 17.0 export files, which have a dataformat node instead
		versionNode = i.QuerySelectorDirectChild(headerNode, "dataformat")
		if versionNode == nil {
			i.result.Success = false
			return i.result, nil
		}
	}

	version := versionNode.TextContent()
	if !strings.HasPrefix(version, "17") {
		i.result.ErrorMessage = "Unsupported export version detected - (only 17.0 is supported)"
		i.result.Success = false
		return i.result, nil
	}

	// Abort import if the file is encrypted
	encryptedNode := i.QuerySelectorDirectChild(headerNode, "encrypted")
	if encryptedNode != nil && encryptedNode.TextContent() == "True" {
		i.result.ErrorMessage = "Encrypted Password Depot files are not supported."
		i.result.Success = false
		return i.result, nil
	}

	// The passwords node contains all the password entries
	passwordsNode := rootNode.QuerySelector("passwords")
	if passwordsNode == nil {
		i.result.ErrorMessage = "Missing `passwordfile > passwords` node."
		i.result.Success = false
		return i.result, nil
	}

	if err := i.buildFavouritesLookupTable(rootNode); err != nil {
		return nil, err
	}

	for _, group := range i.QuerySelectorAllDirectChild(passwordsNode, "group") {
		if err := i.traverse(group, "", useNewDedicatedTypes); err != nil {
			return nil, err
		}
	}

	if i.Organization() {
		i.MoveFoldersToCollections(i.result)
	}

	i.result.Success = true
	return i.result, nil
}

func isLoginSourceType(t string) bool {
	switch t {
	case itemTypePassword, itemTypeRDP, itemTypePutty, itemTypeTeamViewer, itemTypeBanking,
		itemTypeCertificate, itemTypeEncryptedFile:
		return true
	}
	return false
}

// traverse processes a group and its items, then recurses into nested groups.
func (i *Importer) traverse(node *dom.Node, groupPrefixName string, useNewDedicatedTypes bool) error {
	folderIndex := len(i.result.Folders)
	groupName := groupPrefixName

	if groupName != "" {
		groupName += "/"
	}

	// The fingerprint attribute is the GUID of a folder
	groupFingerprint, ok := node.GetAttribute("fingerprint")
	if !ok {
		// `groupFingerprint?.textContent != ""` is true for null, then `.textContent` throws.
		return errNullFingerprint
	}
	if groupFingerprint != "" && groupFingerprint != "null" {
		if nameEl, ok := node.GetAttribute("name"); ok {
			groupName += nameEl
		} else {
			groupName += "-"
		}
		i.result.Folders = append(i.result.Folders, &model.FolderView{Name: groupName})
	}

	for _, entry := range i.QuerySelectorAllDirectChild(node, "item") {
		initialNumCiphers := len(i.result.Ciphers)

		cipher := i.InitLoginCipher()
		// Default item type, similar to how other importers default to Login
		sourceType := itemTypePassword

		for _, entryField := range entry.Children() {
			tagName := entryField.TagName()

			// Skip processing historical entries
			if tagName == "hitems" {
				continue
			}

			if tagName == "description" {
				cipher.Name = entryField.TextContent()
				continue
			}

			if tagName == "comment" {
				cipher.Notes = entryField.TextContent()
				continue
			}

			if tagName == "type" {
				sourceType = entryField.TextContent()
				switch sourceType {
				case itemTypePassword, itemTypeRDP, itemTypePutty, itemTypeTeamViewer, itemTypeBanking,
					itemTypeCertificate, itemTypeEncryptedFile:
					cipher.Type = model.CipherTypeLogin
					cipher.Login = &model.LoginView{}
				case itemTypeCreditCard:
					cipher.Type = model.CipherTypeCard
					cipher.Card = &model.CardView{}
				case itemTypeSoftwareLicense, itemTypeInformation, itemTypeDocument:
					cipher.Type = model.CipherTypeSecureNote
					cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
				case itemTypeIdentity:
					cipher.Type = model.CipherTypeIdentity
					cipher.Identity = &model.IdentityView{}
				}
				continue
			}

			if isLoginSourceType(sourceType) {
				if i.parseLoginFields(entryField, cipher) {
					continue
				}
			}

			// fingerprint is the GUID of the entry; mark previously parsed favourites
			if tagName == "fingerprint" {
				if i.favouritesLookupTable[entryField.TextContent()] {
					cipher.Favorite = true
				}
			}

			if tagName == "customfields" {
				i.parseCustomFields(entryField, sourceType, cipher, useNewDedicatedTypes)
				continue
			}

			if sourceType == itemTypeBanking && tagName == "tans" {
				for _, tanEntry := range i.QuerySelectorAllDirectChild(entryField, "tan") {
					i.parseBankingTANs(tanEntry, cipher)
				}
				continue
			}

			i.ProcessKvp(cipher, tagName, entryField.TextContent(), model.FieldTypeText)
		}

		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)

		if groupName != "" {
			// Several ciphers may be added per item (e.g. bank accounts); put all of them in the
			// same folder.
			for c := initialNumCiphers; c < len(i.result.Ciphers); c++ {
				i.result.FolderRelationships = append(i.result.FolderRelationships, model.Relationship{c, folderIndex})
			}
		}
	}

	for _, group := range i.QuerySelectorAllDirectChild(node, "group") {
		if err := i.traverse(group, groupName, useNewDedicatedTypes); err != nil {
			return err
		}
	}
	return nil
}

// customField is the FieldView parseCustomField returns; hasValue is false where TS has a null
// value.
type customField struct {
	name     string
	value    string
	hasValue bool
	typ      model.FieldType
}

func (i *Importer) parseCustomFields(entryField *dom.Node, sourceType string, cipher *model.CipherView, useNewDedicatedTypes bool) {
	// With the feature flag on, a Banking entry also yields a bank account cipher.
	var bankAccountCipher *model.CipherView
	if useNewDedicatedTypes && sourceType == itemTypeBanking {
		bankAccountCipher = i.InitLoginCipher()
		bankAccountCipher.Name = cipher.Name
		bankAccountCipher.Type = model.CipherTypeBankAccount
	}

	for _, field := range i.QuerySelectorAllDirectChild(entryField, "field") {
		customFieldObject := i.parseCustomField(field)
		if customFieldObject == nil {
			continue
		}

		handled := false
		switch sourceType {
		case itemTypeCreditCard:
			handled = i.parseCreditCardCustomFields(customFieldObject, cipher)
		case itemTypeIdentity:
			handled = i.parseIdentityCustomFields(customFieldObject, cipher)
		case itemTypeInformation:
			handled = i.parseInformationCustomFields(customFieldObject, cipher)
		case itemTypeBanking:
			handled = useNewDedicatedTypes && i.parseBankAccountCustomFields(customFieldObject, bankAccountCipher)
		}
		if handled {
			continue
		}

		i.ProcessKvp(cipher, customFieldObject.name, customFieldObject.value, customFieldObject.typ)
	}

	if bankAccountCipher != nil {
		i.CleanupCipher(bankAccountCipher)
		i.result.Ciphers = append(i.result.Ciphers, bankAccountCipher)
	}
}

func (i *Importer) parseBankAccountCustomFields(entryField *customField, cipher *model.CipherView) bool {
	b := cipher.BankAccount
	var target *string
	switch entryField.name {
	case "IDS_ECHolder":
		target = &b.NameOnAccount
	case "IDS_ECAccountNumber":
		target = &b.AccountNumber
	case "IDS_ECBLZ":
		target = &b.RoutingNumber
	case "IDS_ECBankName":
		target = &b.BankName
	case "IDS_ECIBAN":
		target = &b.Iban
	case "IDS_ECPhone":
		target = &b.BankContactPhone
	case "IDS_ECPIN":
		target = &b.Pin
	default:
		return false
	}
	*target = entryField.value
	return true
}

func (i *Importer) parseLoginFields(entryField *dom.Node, cipher *model.CipherView) bool {
	switch entryField.TagName() {
	case "username":
		cipher.Login.Username = entryField.TextContent()
		return true
	case "password":
		cipher.Login.Password = entryField.TextContent()
		return true
	case "url":
		cipher.Login.Uris = i.MakeUriArray(entryField.TextContent())
		return true
	}
	return false
}

// parseCustomField reads a <field>: Windows exports use <name>/<value>/<type>/<visible> child
// elements, macOS exports use attributes.
func (i *Importer) parseCustomField(field *dom.Node) *customField {
	var key, value string
	var hasValue bool
	sourceFieldType := customFieldTypeMemo
	var visible string
	var hasVisible bool

	if len(field.Attrs) > 0 {
		var ok bool
		key, ok = field.GetAttribute("name")
		if !ok {
			return nil
		}
		value, hasValue = field.GetAttribute("value")
		if typeAttr, ok := field.GetAttribute("type"); ok {
			sourceFieldType = typeAttr
		}
		visible, hasVisible = field.GetAttribute("visible")
	} else {
		keyEl := i.QuerySelectorDirectChild(field, "name")
		if keyEl == nil {
			return nil
		}
		key = keyEl.TextContent()

		if valueEl := i.QuerySelectorDirectChild(field, "value"); valueEl != nil {
			value, hasValue = valueEl.TextContent(), true
		}
		if typeEl := i.QuerySelectorDirectChild(field, "type"); typeEl != nil {
			sourceFieldType = typeEl.TextContent()
		}
		if visibleEl := i.QuerySelectorDirectChild(field, "visible"); visibleEl != nil {
			visible, hasVisible = visibleEl.TextContent(), true
		}
	}

	if sourceFieldType == customFieldTypeDate {
		if !hasValue || !isNaNNumber(value) {
			// Convert the Excel date format to a JavaScript date
			value, hasValue = excelDateToLocaleDateString(value, hasValue), true
		}
	}

	switch {
	case sourceFieldType == customFieldTypePassword:
		return &customField{name: key, value: value, hasValue: hasValue, typ: model.FieldTypeHidden}
	case sourceFieldType == customFieldTypeBoolean:
		return &customField{name: key, value: value, hasValue: hasValue, typ: model.FieldTypeBoolean}
	case hasVisible && visible == "0":
		return &customField{name: key, value: value, hasValue: hasValue, typ: model.FieldTypeHidden}
	}
	return &customField{name: key, value: value, hasValue: hasValue, typ: model.FieldTypeText}
}

func (i *Importer) parseCreditCardCustomFields(customField *customField, cipher *model.CipherView) bool {
	switch customField.name {
	case "IDS_CardHolder":
		cipher.Card.CardholderName = customField.value
	case "IDS_CardNumber":
		cipher.Card.Number = customField.value
		cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
	case "IDS_CardExpires":
		i.SetCardExpiration(cipher, customField.value)
	case "IDS_CardCode":
		cipher.Card.Code = customField.value
	default:
		return false
	}
	return true
}

func (i *Importer) parseIdentityCustomFields(customField *customField, cipher *model.CipherView) bool {
	id := cipher.Identity
	switch customField.name {
	case "IDS_IdentityName":
		i.ProcessFullName(cipher, customField.value)
	case "IDS_IdentityEmail":
		id.Email = customField.value
	case "IDS_IdentityFirstName":
		id.FirstName = customField.value
	case "IDS_IdentityLastName":
		id.LastName = customField.value
	case "IDS_IdentityCompany":
		id.Company = customField.value
	case "IDS_IdentityAddress1":
		id.Address1 = customField.value
	case "IDS_IdentityAddress2":
		id.Address2 = customField.value
	case "IDS_IdentityCity":
		id.City = customField.value
	case "IDS_IdentityState":
		id.State = customField.value
	case "IDS_IdentityZIP":
		id.PostalCode = customField.value
	case "IDS_IdentityCountry":
		id.Country = customField.value
	case "IDS_IdentityPhone":
		id.Phone = customField.value
	default:
		return false
	}
	return true
}

func (i *Importer) parseInformationCustomFields(customField *customField, cipher *model.CipherView) bool {
	if customField.name == "IDS_InformationText" {
		cipher.Notes = customField.value
		return true
	}
	return false
}

// parseBankingTANs adds the fields of one <tan> element as tan_<number>_<tag> fields.
func (i *Importer) parseBankingTANs(tansField *dom.Node, cipher *model.CipherView) {
	tanNumber := "0"
	for _, entryField := range tansField.Children() {
		if entryField.TagName() == "number" {
			tanNumber = entryField.TextContent()
			continue
		}
		i.ProcessKvp(cipher, fmt.Sprintf("tan_%s_%s", tanNumber, entryField.TagName()), entryField.TextContent())
	}
}

// buildFavouritesLookupTable parses the base64 <favorites> node: the fingerprints (GUIDs) of the
// favourite entries, separated by new lines.
func (i *Importer) buildFavouritesLookupTable(rootNode *dom.Node) error {
	favouritesNode := i.QuerySelectorDirectChild(rootNode, "favorites")
	if favouritesNode == nil {
		return nil
	}

	decodedBase64String, err := atob(favouritesNode.TextContent())
	if err != nil {
		return err
	}
	if strings.Index(decodedBase64String, "\r\n") > 0 {
		for _, line := range strings.Split(decodedBase64String, "\r\n") {
			i.favouritesLookupTable[line] = true
		}
		return nil
	}

	for _, line := range strings.Split(decodedBase64String, "\n") {
		i.favouritesLookupTable[line] = true
	}
	return nil
}
