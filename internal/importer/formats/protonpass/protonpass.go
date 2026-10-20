// Package protonpass ports libs/importer/src/importers/protonpass (protonpass-json-importer.ts,
// protonpass-import-utils.ts and types/protonpass-json-type.ts): format id "protonpass".
//
// The importer parses the JSON text only. For a ".zip" export the CLI extracts
// "Proton Pass/data.json" first (importer.ReadImportFile / importer.ExtractZipEntry), like
// upstream's ImportCommand.
//
// The export is walked as raw JSON (see json.go) rather than decoded into Go structs so that
// JavaScript's semantics survive: Object.keys/entries order (vaults, identity fields, unknown item
// contents), case-sensitive keys, typeof checks, and the TypeErrors upstream throws on malformed
// items.
package protonpass

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("protonpass", New) }

// i18n strings from apps/cli/src/locales/en/messages.json.
const (
	msgUnsupportedEncryptedImport = "Importing encrypted files is currently not supported."
	msgPassword                   = "Password"
	msgSecurity                   = "Security"
	msgUnknown                    = "Unknown"
)

// ProtonPassItemState
const protonPassItemStateTrashed = 2

// ProtonPassWifiSecurityType
const (
	wifiSecurityWPA  = 1
	wifiSecurityWPA2 = 2
	wifiSecurityWPA3 = 3
	wifiSecurityWEP  = 4
)

var mappedIdentityItemKeys = []string{
	"fullName",
	"firstName",
	"middleName",
	"lastName",
	"email",
	"phoneNumber",
	"company",
	"socialSecurityNumber",
	"passportNumber",
	"licenseNumber",
	"organization",
	"streetAddress",
	"floor",
	"county",
	"city",
	"stateOrProvince",
	"zipOrPostalCode",
	"countryOrRegion",
}

var identityItemExtraFieldsKeys = []string{
	"extraPersonalDetails",
	"extraAddressDetails",
	"extraContactDetails",
	"extraWorkDetails",
	"extraSections",
}

func includes(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Importer is ProtonPassJsonImporter.
type Importer struct {
	importer.Base
	useNewDedicatedTypes bool
}

// New constructs the importer (configService.getFeatureFlag(PM32009NewItemTypes) comes from
// opts.Features.NewItemTypes).
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts), useNewDedicatedTypes: opts.Features.NewItemTypes}
}

// processExtraFields is processExtraFields(cipher, extraFields = []).
func (i *Importer) processExtraFields(cipher *model.CipherView, extraFields json.RawMessage) error {
	if extraFields == nil {
		return nil
	}
	fields, err := forOf(extraFields, "extraFields")
	if err != nil {
		return err
	}
	for _, extraField := range fields {
		if err := i.processField(cipher, extraField); err != nil {
			return err
		}
	}
	return nil
}

// processField is this.processKvp(cipher, field.fieldName, getExtraFieldValue(field),
// getExtraFieldType(field)).
func (i *Importer) processField(cipher *model.CipherView, field json.RawMessage) error {
	f, err := toObj(field, "fieldName")
	if err != nil {
		return err
	}
	value, err := getExtraFieldValue(f)
	if err != nil {
		return err
	}
	i.ProcessKvp(cipher, str(f.get("fieldName")), value, getExtraFieldType(f))
	return nil
}

func (i *Importer) processIdentityItemUnmappedAndExtraFields(cipher *model.CipherView, identityItem json.RawMessage) error {
	for _, p := range entries(identityItem) {
		key := p.Key
		if !includes(mappedIdentityItemKeys, key) && !includes(identityItemExtraFieldsKeys, key) {
			i.ProcessKvp(cipher, key, str(p.Value))
			continue
		}

		if includes(identityItemExtraFieldsKeys, key) {
			if key != "extraSections" {
				if err := i.processExtraFields(cipher, p.Value); err != nil {
					return err
				}
			} else {
				if isNullish(p.Value) {
					continue
				}
				extraSections, err := forEach(p.Value, "extraSections")
				if err != nil {
					return err
				}
				for _, extraSection := range extraSections {
					s, err := toObj(extraSection, "sectionFields")
					if err != nil {
						return err
					}
					if err := i.processExtraFields(cipher, s.get("sectionFields")); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// processSections is processSections(cipher, sections = []).
func (i *Importer) processSections(cipher *model.CipherView, sections json.RawMessage) error {
	if sections == nil {
		return nil
	}
	list, err := forEach(sections, "sections")
	if err != nil {
		return err
	}
	for _, section := range list {
		s, err := toObj(section, "sectionFields")
		if err != nil {
			return err
		}
		sectionFields := s.get("sectionFields")
		if isNullish(sectionFields) {
			continue
		}
		fields, err := forEach(sectionFields, "section.sectionFields")
		if err != nil {
			return err
		}
		for _, field := range fields {
			if err := i.processField(cipher, field); err != nil {
				return err
			}
		}
	}
	return nil
}

var leadingZeros = regexp.MustCompile(`^0+`)

// Parse is ProtonPassJsonImporter.parse.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	useNewDedicatedTypes := i.useNewDedicatedTypes
	result := model.NewImportResult()
	if !json.Valid([]byte(data)) {
		var v any
		return nil, importer.NewSyntaxError(json.Unmarshal([]byte(data), &v))
	}
	raw := json.RawMessage(data)
	var results obj
	if !isNullish(raw) {
		results, _ = toObj(raw, "vaults")
	}
	if isNullish(raw) || isNullish(results.get("vaults")) {
		result.Success = false
		return result, nil
	}

	if isTruthy(results.get("encrypted")) {
		result.Success = false
		result.ErrorMessage = msgUnsupportedEncryptedImport
		return result, nil
	}

	for _, v := range entries(results.get("vaults")) {
		vault, err := toObj(v.Value, "items")
		if err != nil {
			return nil, err
		}
		items, err := forOf(vault.get("items"), "vault.items")
		if err != nil {
			return nil, err
		}
		vaultName := str(vault.get("name"))
		for _, it := range items {
			item, err := toObj(it, "state")
			if err != nil {
				return nil, err
			}
			if looseEqualsNumber(item.get("state"), protonPassItemStateTrashed) {
				continue
			}

			itemData, err := toObj(item.get("data"), "metadata")
			if err != nil {
				return nil, err
			}
			metadata, err := toObj(itemData.get("metadata"), "name")
			if err != nil {
				return nil, err
			}
			extraFields := itemData.get("extraFields")

			cipher := i.InitLoginCipher()
			cipher.Name = i.GetValueOrDefault(str(metadata.get("name")), "--")
			cipher.Notes = i.GetValueOrDefault(str(metadata.get("note")))
			cipher.Favorite = isTruthy(item.get("pinned"))

			content := itemData.get("content")
			switch str(itemData.get("type")) {
			case "login":
				loginContent, err := toObj(content, "urls")
				if err != nil {
					return nil, err
				}
				cipher.Login.Uris = i.makeUriArray(loginContent.get("urls"))

				cipher.Login.Username = i.GetValueOrDefault(str(loginContent.get("itemUsername")))
				// if the cipher has no username then the email is used as the username
				if cipher.Login.Username == "" {
					cipher.Login.Username = i.GetValueOrDefault(str(loginContent.get("itemEmail")))
				} else {
					i.ProcessKvp(cipher, "email", str(loginContent.get("itemEmail")))
				}

				cipher.Login.Password = i.GetValueOrDefault(str(loginContent.get("password")))
				cipher.Login.Totp = i.GetValueOrDefault(str(loginContent.get("totpUri")))
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
			case "note":
				cipher.Type = model.CipherTypeSecureNote
				cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
			case "creditCard":
				creditCardContent, err := toObj(content, "cardholderName")
				if err != nil {
					return nil, err
				}
				cipher.Type = model.CipherTypeCard
				cipher.Card = &model.CardView{}
				cipher.Card.CardholderName = i.GetValueOrDefault(str(creditCardContent.get("cardholderName")))
				cipher.Card.Number = i.GetValueOrDefault(str(creditCardContent.get("number")))
				cipher.Card.Brand = model.GetCardBrandByPatterns(str(creditCardContent.get("number")))
				cipher.Card.Code = i.GetValueOrDefault(str(creditCardContent.get("verificationNumber")))

				expirationDate := str(creditCardContent.get("expirationDate"))
				if !i.IsNullOrWhitespace(expirationDate) {
					cipher.Card.ExpMonth = substring(expirationDate, 5, 7)
					cipher.Card.ExpMonth = leadingZeros.ReplaceAllString(cipher.Card.ExpMonth, "")
					cipher.Card.ExpYear = substring(expirationDate, 0, 4)
				}

				pin := str(creditCardContent.get("pin"))
				if !i.IsNullOrWhitespace(pin) {
					i.ProcessKvp(cipher, "PIN", pin, model.FieldTypeHidden)
				}
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
			case "identity":
				identityContent, err := toObj(content, "fullName")
				if err != nil {
					return nil, err
				}
				cipher.Type = model.CipherTypeIdentity
				cipher.Identity = &model.IdentityView{}

				mappedFirstName, mappedMiddleName, mappedLastName := processNames(
					i.GetValueOrDefault(str(identityContent.get("fullName"))),
					i.GetValueOrDefault(str(identityContent.get("firstName"))),
					i.GetValueOrDefault(str(identityContent.get("middleName"))),
					i.GetValueOrDefault(str(identityContent.get("lastName"))),
				)
				cipher.Identity.FirstName = mappedFirstName
				cipher.Identity.MiddleName = mappedMiddleName
				cipher.Identity.LastName = mappedLastName

				cipher.Identity.Email = i.GetValueOrDefault(str(identityContent.get("email")))
				cipher.Identity.Phone = i.GetValueOrDefault(str(identityContent.get("phoneNumber")))
				cipher.Identity.Company = i.GetValueOrDefault(str(identityContent.get("company")))
				cipher.Identity.Ssn = i.GetValueOrDefault(str(identityContent.get("socialSecurityNumber")))
				licenseNumber := i.GetValueOrDefault(str(identityContent.get("licenseNumber")))
				if useNewDedicatedTypes {
					if licenseNumber != "" {
						licenseCipher := i.InitLoginCipher()
						licenseCipher.Name = cipher.Name
						licenseCipher.Type = model.CipherTypeDriversLicense
						licenseCipher.DriversLicense = &model.DriversLicenseView{}
						licenseCipher.DriversLicense.LicenseNumber = licenseNumber
						i.ProcessFolder(result, vaultName)
						i.CleanupCipher(licenseCipher)
						result.Ciphers = append(result.Ciphers, licenseCipher)
					}
				} else {
					cipher.Identity.LicenseNumber = licenseNumber
				}
				passportNumber := i.GetValueOrDefault(str(identityContent.get("passportNumber")))
				if useNewDedicatedTypes {
					if passportNumber != "" {
						passportCipher := i.InitLoginCipher()
						passportCipher.Name = cipher.Name
						passportCipher.Type = model.CipherTypePassport
						passportCipher.Passport = &model.PassportView{}
						passportCipher.Passport.PassportNumber = passportNumber
						i.ProcessFolder(result, vaultName)
						i.CleanupCipher(passportCipher)
						result.Ciphers = append(result.Ciphers, passportCipher)
					}
				} else {
					cipher.Identity.PassportNumber = passportNumber
				}

				address3 := importer.JSTrim(nullishTemplate(identityContent.get("floor")) + " " +
					nullishTemplate(identityContent.get("county")))
				cipher.Identity.Address1 = i.GetValueOrDefault(str(identityContent.get("organization")))
				cipher.Identity.Address2 = i.GetValueOrDefault(str(identityContent.get("streetAddress")))
				cipher.Identity.Address3 = i.GetValueOrDefault(address3)

				cipher.Identity.City = i.GetValueOrDefault(str(identityContent.get("city")))
				cipher.Identity.State = i.GetValueOrDefault(str(identityContent.get("stateOrProvince")))
				cipher.Identity.PostalCode = i.GetValueOrDefault(str(identityContent.get("zipOrPostalCode")))
				cipher.Identity.Country = i.GetValueOrDefault(str(identityContent.get("countryOrRegion")))
				if err := i.processIdentityItemUnmappedAndExtraFields(cipher, content); err != nil {
					return nil, err
				}
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
			case "alias":
				// An alias is an email-forwarding address; map it to a login with the
				// alias address as the username so the item (and its data) is preserved.
				cipher.Login.Username = i.GetValueOrDefault(str(item.get("aliasEmail")))
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
			case "sshKey":
				sshKeyContent, err := toObj(content, "privateKey")
				if err != nil {
					return nil, err
				}
				cipher.Type = model.CipherTypeSshKey
				cipher.SshKey = &model.SshKeyView{}
				cipher.SshKey.PrivateKey = i.GetValueOrDefault(str(sshKeyContent.get("privateKey")), "")
				cipher.SshKey.PublicKey = i.GetValueOrDefault(str(sshKeyContent.get("publicKey")), "")
				cipher.SshKey.KeyFingerprint = i.GetValueOrDefault(str(sshKeyContent.get("fingerprint")), "")
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
				if err := i.processSections(cipher, sshKeyContent.get("sections")); err != nil {
					return nil, err
				}
			case "custom":
				if err := i.processCustom(cipher, extraFields, content, useNewDedicatedTypes); err != nil {
					return nil, err
				}
			case "wifi":
				cipher.Type = model.CipherTypeSecureNote
				wifiContent, err := toObj(content, "password")
				if err != nil {
					return nil, err
				}
				i.processWifiFields(cipher, wifiContent)
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
				if err := i.processSections(cipher, wifiContent.get("sections")); err != nil {
					return nil, err
				}
			default:
				cipher.Type = model.CipherTypeSecureNote
				if err := i.processExtraFields(cipher, extraFields); err != nil {
					return nil, err
				}
				if isNullish(content) {
					return nil, errors.New("Cannot convert undefined or null to object")
				}
				for _, p := range entries(content) {
					if p.Key == "sections" {
						if err := i.processSections(cipher, p.Value); err != nil {
							return nil, err
						}
					} else {
						if firstByte(p.Value) == '"' {
							i.ProcessKvp(cipher, p.Key, str(p.Value))
						} else if f, ok := isNumber(p.Value); ok {
							i.ProcessKvp(cipher, p.Key, importer.FormatJSNumber(f))
						} else {
							// We do basic handling of new string and number fields, but anything
							// more complicated should be added to this importer explicitly
							continue
						}
					}
				}
			}

			i.ProcessFolder(result, vaultName)
			i.CleanupCipher(cipher)
			result.Ciphers = append(result.Ciphers, cipher)
		}
	}
	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}
	result.Success = true
	return result, nil
}

func (i *Importer) processCustom(cipher *model.CipherView, extraFields, content json.RawMessage, useNewDedicatedTypes bool) error {
	isBank, isPassport, isLicense := false, false, false
	var err error
	if useNewDedicatedTypes {
		if isBank, err = hasExtraFields([]string{"Bank Name", "Account Number"}, extraFields); err != nil {
			return err
		}
		if !isBank {
			if isPassport, err = hasExtraFields([]string{"Passport Number"}, extraFields); err != nil {
				return err
			}
			if !isPassport {
				if isLicense, err = hasExtraFields([]string{"License Number"}, extraFields); err != nil {
					return err
				}
			}
		}
	}
	switch {
	case isBank:
		cipher.Type = model.CipherTypeBankAccount
		cipher.BankAccount = &model.BankAccountView{}
		return i.processDedicatedExtraFields(cipher, extraFields, i.setBankAccountField)
	case isPassport:
		cipher.Type = model.CipherTypePassport
		cipher.Passport = &model.PassportView{}
		return i.processDedicatedExtraFields(cipher, extraFields, i.setPassportField)
	case isLicense:
		cipher.Type = model.CipherTypeDriversLicense
		cipher.DriversLicense = &model.DriversLicenseView{}
		return i.processDedicatedExtraFields(cipher, extraFields, i.setDriversLicenseField)
	default:
		customContent, err := toObj(content, "sections")
		if err != nil {
			return err
		}
		cipher.Type = model.CipherTypeSecureNote
		cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
		if err := i.processExtraFields(cipher, extraFields); err != nil {
			return err
		}
		return i.processSections(cipher, customContent.get("sections"))
	}
}

// getExtraFieldValue returns field.data.totpUri / .timestamp / .content.
func getExtraFieldValue(field obj) (string, error) {
	key := "content"
	switch str(field.get("type")) {
	case "totp":
		key = "totpUri"
	case "timestamp":
		key = "timestamp"
	}
	d, err := toObj(field.get("data"), key)
	if err != nil {
		return "", err
	}
	return str(d.get(key)), nil
}

func getExtraFieldType(field obj) model.FieldType {
	t := str(field.get("type"))
	if t == "totp" || t == "hidden" {
		return model.FieldTypeHidden
	}
	return model.FieldTypeText
}

// hasExtraFields is fieldNames.every((fn) => item.data.extraFields.some((f) => f.fieldName === fn)).
func hasExtraFields(fieldNames []string, extraFields json.RawMessage) (bool, error) {
	for _, fn := range fieldNames {
		if isNullish(extraFields) {
			return false, errors.New("Cannot read properties of undefined (reading 'some')")
		}
		if firstByte(extraFields) != '[' {
			return false, errors.New("item.data.extraFields.some is not a function")
		}
		fields, err := forOf(extraFields, "item.data.extraFields")
		if err != nil {
			return false, err
		}
		found := false
		for _, f := range fields {
			o, err := toObj(f, "fieldName")
			if err != nil {
				return false, err
			}
			if fv := o.get("fieldName"); firstByte(fv) == '"' && str(fv) == fn {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// processDedicatedExtraFields is the shared loop of processBankAccountExtraFields,
// processDriversLicenseExtraFields and processPassportExtraFields: set reports whether the field
// was mapped onto the dedicated view; unmapped fields become custom fields.
func (i *Importer) processDedicatedExtraFields(cipher *model.CipherView, extraFields json.RawMessage, set func(c *model.CipherView, name, value string) bool) error {
	fields, err := forOf(extraFields, "extraFields")
	if err != nil {
		return err
	}
	for _, field := range fields {
		f, err := toObj(field, "fieldName")
		if err != nil {
			return err
		}
		fieldValue, err := getExtraFieldValue(f)
		if err != nil {
			return err
		}
		name := str(f.get("fieldName"))
		if !set(cipher, name, fieldValue) {
			i.ProcessKvp(cipher, name, fieldValue, getExtraFieldType(f))
		}
	}
	return nil
}

func (i *Importer) setBankAccountField(cipher *model.CipherView, name, value string) bool {
	if i.IsNullOrWhitespace(value) {
		return false
	}
	b := cipher.BankAccount
	switch name {
	case "Bank Name":
		b.BankName = value
	case "Account Number":
		b.AccountNumber = value
	case "Routing Number":
		b.RoutingNumber = value
	case "Account Type":
		b.AccountType = i.ProcessBankAccountType(value)
	case "IBAN":
		b.Iban = value
	case "SWIFT/BIC":
		b.SwiftCode = value
	case "Holder Name":
		b.NameOnAccount = value
	default:
		return false
	}
	return true
}

func (i *Importer) setDriversLicenseField(cipher *model.CipherView, name, value string) bool {
	if i.IsNullOrWhitespace(value) {
		return false
	}
	d := cipher.DriversLicense
	switch name {
	case "Full Name":
		d.FirstName, d.MiddleName, d.LastName = i.GetFullName(value)
	case "License Number":
		d.LicenseNumber = value
	case "Issuing State/Country":
		d.IssuingState = value
	case "Expiry Date":
		d.ExpirationDate = value
	case "Date of Birth":
		d.DateOfBirth = value
	case "Class":
		d.LicenseClass = value
	default:
		return false
	}
	return true
}

func (i *Importer) setPassportField(cipher *model.CipherView, name, value string) bool {
	if i.IsNullOrWhitespace(value) {
		return false
	}
	p := cipher.Passport
	switch name {
	case "Full Name":
		firstName, middleName, lastName := i.GetFullName(value)
		p.GivenName = firstName
		if !i.IsNullOrWhitespace(middleName) {
			p.GivenName += " " + middleName
		}
		p.Surname = lastName
	case "Passport Number":
		p.PassportNumber = value
	case "Country":
		p.IssuingCountry = value
	case "Expiry Date":
		p.ExpirationDate = value
	case "Date of Birth":
		p.DateOfBirth = value
	case "Issuing Authority":
		p.IssuingAuthority = value
	default:
		return false
	}
	return true
}

func (i *Importer) processWifiFields(cipher *model.CipherView, itemContent obj) {
	if password := itemContent.get("password"); isTruthy(password) {
		i.ProcessKvp(cipher, msgPassword, str(password), model.FieldTypeHidden)
	}
	if ssid := itemContent.get("ssid"); isTruthy(ssid) {
		i.ProcessKvp(cipher, "SSID", str(ssid), model.FieldTypeText)
	}
	if security := itemContent.get("security"); !isNullish(security) {
		securityString := msgUnknown
		if n, ok := isNumber(security); ok {
			switch n {
			case wifiSecurityWPA:
				securityString = "WPA"
			case wifiSecurityWPA2:
				securityString = "WPA2"
			case wifiSecurityWPA3:
				securityString = "WPA3"
			case wifiSecurityWEP:
				securityString = "WEP"
			}
		}
		i.ProcessKvp(cipher, msgSecurity, securityString, model.FieldTypeText)
	}
}

// makeUriArray is BaseImporter.makeUriArray(loginContent.urls) for a JSON value.
func (i *Importer) makeUriArray(urls json.RawMessage) []*model.LoginUriView {
	switch firstByte(urls) {
	case '"':
		return i.MakeUriArray(str(urls))
	case '[':
		var arr []json.RawMessage
		_ = json.Unmarshal(urls, &arr)
		list := make([]string, 0, len(arr))
		for _, u := range arr {
			list = append(list, str(u))
		}
		return i.MakeUriArray(list...)
	}
	return nil
}

// nullishTemplate is `${value ?? ""}`.
func nullishTemplate(raw json.RawMessage) string {
	if isNullish(raw) {
		return ""
	}
	return templateString(raw)
}

// substring is String.prototype.substring (UTF-16 indexes, clamped, swapped when start > end).
func substring(s string, start, end int) string {
	n := importer.Len16(s)
	clamp := func(x int) int {
		if x < 0 {
			return 0
		}
		if x > n {
			return n
		}
		return x
	}
	start, end = clamp(start), clamp(end)
	if start > end {
		start, end = end, start
	}
	return importer.Substring16(s, start, end)
}
