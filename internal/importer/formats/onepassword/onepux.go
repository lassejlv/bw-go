package onepassword

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Port of onepassword-1pux-importer.ts. The CLI reads a .1pux file's "export.data" zip entry with
// importer.ReadImportFile (ImportCommand's file reading rules); a .json file is passed as is.

func init() { importer.Register("1password1pux", New1Pux) }

// PuxImporter is OnePassword1PuxImporter.
type PuxImporter struct {
	importer.Base
	useNewDedicatedTypes bool
	// result is the instance field `result = new ImportResult()` (accumulates across parse calls).
	result *model.ImportResult
	now    func() time.Time
}

// New1Pux builds the 1pux importer (opts.Features.NewItemTypes is FeatureFlag.PM32009NewItemTypes).
func New1Pux(opts importer.Options) importer.Importer {
	return &PuxImporter{
		Base:                 importer.NewBase(opts),
		useNewDedicatedTypes: opts.Features.NewItemTypes,
		result:               model.NewImportResult(),
		now:                  time.Now,
	}
}

func (i *PuxImporter) logWarning(msg string) {
	if i.Warn != nil {
		i.Warn(msg)
		return
	}
	importer.DefaultWarn(msg)
}

// sshKeyImportError is the SDK's SshKeyImportError as seen by isSshKeyImportError (the error
// carries a `variant`); internal/sshkey's *ImportError implements it.
type sshKeyImportError interface {
	error
	Variant() string
}

func asSshKeyImportError(err error) (sshKeyImportError, bool) {
	var e sshKeyImportError
	ok := errors.As(err, &e)
	return e, ok
}

// Parse is OnePassword1PuxImporter.parse.
func (i *PuxImporter) Parse(data string) (result *model.ImportResult, err error) {
	defer catch(&err)
	exportData, err := parseJSON(data)
	if err != nil {
		return nil, err
	}

	account := get(get(exportData, "accounts"), "0")
	// TODO upstream: handle multiple vaults
	for _, vault := range array(get(account, "vaults"), "account.vaults") {
		for _, item := range array(get(vault, "items"), "vault.items") {
			i.parseItem(item)
		}
	}

	if i.Organization() {
		i.MoveFoldersToCollections(i.result)
	}

	i.result.Success = true
	return i.result, nil
}

// parseItem is the body of the per-item try/catch.
func (i *PuxImporter) parseItem(item any) {
	// Snapshot folder state so a mid-item failure can be rolled back cleanly.
	folderCount := len(i.result.Folders)
	folderRelationshipCount := len(i.result.FolderRelationships)

	err := func() (err error) {
		defer catch(&err)
		i.processItem(item)
		return nil
	}()
	if err == nil {
		return
	}

	// One bad item must not abort the whole import: roll back its partial folder state, skip it,
	// and report it.
	i.result.Folders = i.result.Folders[:folderCount]
	i.result.FolderRelationships = i.result.FolderRelationships[:folderRelationshipCount]

	reason := importErrorReason(err)
	// Identify the item by its non-sensitive UID (never its name, which is vault data).
	uid := valueOrDefault(get(item, "uuid"), "")
	i.result.Errors = append(i.result.Errors, model.ImportRecordError{ID: uid, Reason: reason})

	shown := uid
	if shown == "" {
		shown = "unknown"
	}
	// Upstream logs SSH key errors with logService.warning and others with logService.error.
	i.logWarning(fmt.Sprintf("1Password import skipped an item (uuid: %s, reason: %s)", shown, reason))
}

// importErrorReason: only the SDK's SshKeyImportError maps to a specific reason.
func importErrorReason(err error) model.ImportRecordErrorReason {
	e, ok := asSshKeyImportError(err)
	if !ok {
		return model.ImportRecordErrorReasonError
	}
	switch e.Variant() {
	case "UnsupportedKeyType":
		return model.ImportRecordErrorReasonUnsupportedType
	case "Parsing":
		return model.ImportRecordErrorReasonSshKeyParseFailed
	}
	return model.ImportRecordErrorReasonError
}

func (i *PuxImporter) processItem(item any) {
	cipher := i.InitLoginCipher()

	category, _ := get(item, "categoryUuid").(string)
	switch category {
	case CategoryLogin, CategoryDatabase, CategoryPassword, CategoryWirelessRouter, CategoryServer, CategoryAPICredential:
		cipher.Type = model.CipherTypeLogin
		cipher.Login = &model.LoginView{}
	case CategoryBankAccount:
		if i.useNewDedicatedTypes {
			cipher.Type = model.CipherTypeBankAccount
			cipher.BankAccount = &model.BankAccountView{}
		} else {
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
		}
	case CategoryCreditCard:
		cipher.Type = model.CipherTypeCard
		cipher.Card = &model.CardView{}
	case CategorySecureNote, CategorySoftwareLicense, CategoryEmailAccount, CategoryMedicalRecord:
		// case Category.Document:
		cipher.Type = model.CipherTypeSecureNote
		cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	case CategoryDriversLicense:
		if i.useNewDedicatedTypes {
			cipher.Type = model.CipherTypeDriversLicense
			cipher.DriversLicense = &model.DriversLicenseView{}
		} else {
			cipher.Type = model.CipherTypeIdentity
			cipher.Identity = &model.IdentityView{}
		}
	case CategoryPassport:
		if i.useNewDedicatedTypes {
			cipher.Type = model.CipherTypePassport
			cipher.Passport = &model.PassportView{}
		} else {
			cipher.Type = model.CipherTypeIdentity
			cipher.Identity = &model.IdentityView{}
		}
	case CategoryIdentity, CategoryOutdoorLicense, CategoryMembership, CategoryRewardsProgram, CategorySocialSecurityNumber:
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
	case CategorySSHKey:
		cipher.Type = model.CipherTypeSshKey
		cipher.SshKey = &model.SshKeyView{}
	}

	fav, ok := get(item, "favIndex").(float64)
	cipher.Favorite = ok && fav == 1

	i.processOverview(get(item, "overview"), cipher)

	i.processLoginFields(item, cipher)

	details := get(item, "details")
	i.processDetails(category, details, cipher)

	if ph := get(details, "passwordHistory"); !isNullish(ph) && toNumber(get(ph, "length")) != 0 {
		parsePasswordHistory(ph, cipher)
	}

	i.processSections(category, get(details, "sections"), cipher)

	if notes := get(details, "notesPlain"); !isNOW(notes) {
		cipher.Notes = importer.JSTrimEnd(strings.Join(i.SplitNewLine(notes.(string)), "\n"))
	}

	i.ConvertToNoteIfNeeded(cipher)
	i.CleanupCipher(cipher)

	// Preserve 1Password's archive state on import (the export only says an item is archived,
	// not when, so the import time is used).
	if state, _ := get(item, "state").(string); state == "archived" {
		now := i.now()
		cipher.ArchivedDate = &now
	}

	i.result.Ciphers = append(i.result.Ciphers, cipher)
}

func (i *PuxImporter) processOverview(overview any, cipher *model.CipherView) {
	if isNullish(overview) {
		return
	}

	cipher.Name = valueOrDefault(get(overview, "title"))

	if urlsVal := get(overview, "urls"); !isNullish(urlsVal) {
		var urls []string
		for _, url := range array(urlsVal, "overview.urls") {
			if u := get(url, "url"); !isNOW(u) {
				urls = append(urls, u.(string))
			}
		}
		cipher.Login.Uris = i.MakeUriArray(urls...)
	}

	if tags := get(overview, "tags"); !isNullish(tags) && toNumber(get(tags, "length")) > 0 {
		folderName := capitalize(get(tags, "0"))
		i.ProcessFolder(i.result, folderName)
	}
}

// capitalize is inputString.trim().replace(/\w\S*/g, (w) => w.replace(/^\w/, (c) => c.toUpperCase())).
func capitalize(v any) string {
	s, ok := v.(string)
	if !ok {
		throwTypeError("inputString.trim is not a function")
	}
	r := []rune(importer.JSTrim(s))
	isWord := func(c rune) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
	}
	for k := 0; k < len(r); {
		if !isWord(r[k]) {
			k++
			continue
		}
		if r[k] >= 'a' && r[k] <= 'z' {
			r[k] -= 'a' - 'A'
		}
		k++
		for k < len(r) && !importer.IsJSSpace(r[k]) {
			k++
		}
	}
	return string(r)
}

// kvp is processKvp for an untyped value (non-strings count as null/whitespace and are skipped).
func (i *PuxImporter) kvp(cipher *model.CipherView, key string, value any, fieldType model.FieldType) {
	if s, ok := value.(string); ok {
		i.ProcessKvp(cipher, key, s, fieldType)
	}
}

func (i *PuxImporter) processLoginFields(item any, cipher *model.CipherView) {
	details := get(item, "details")
	if isNullish(details) {
		return
	}
	loginFields := get(details, "loginFields")
	if isNullish(loginFields) || toNumber(get(loginFields, "length")) == 0 {
		return
	}

	for _, loginField := range array(loginFields, "item.details.loginFields") {
		designation := get(loginField, "designation")
		value := get(loginField, "value")
		if designation == "username" && value != "" {
			cipher.Type = model.CipherTypeLogin
			cipher.Login.Username = toStr(value)
			continue
		}
		if designation == "password" && value != "" {
			cipher.Type = model.CipherTypeLogin
			cipher.Login.Password = toStr(value)
			continue
		}

		fieldValue := value
		fieldType := model.FieldTypeText
		switch get(loginField, "fieldType") {
		case LoginFieldTypePassword:
			fieldType = model.FieldTypeHidden
		case LoginFieldTypeCheckBox:
			if value != "" {
				fieldValue = "true"
			} else {
				fieldValue = "false"
			}
			fieldType = model.FieldTypeBoolean
		}
		i.kvp(cipher, valueOrDefault(get(loginField, "name")), fieldValue, fieldType)
	}
}

func (i *PuxImporter) processDetails(category string, details any, cipher *model.CipherView) {
	if category != CategoryPassword {
		return
	}
	if isNullish(details) {
		return
	}
	cipher.Login.Password = toStr(get(details, "password"))
}

func (i *PuxImporter) processSections(category string, sections any, cipher *model.CipherView) {
	if isNullish(sections) || toNumber(get(sections, "length")) == 0 {
		return
	}
	for _, section := range array(sections, "sections") {
		fields := get(section, "fields")
		if isNullish(fields) {
			continue
		}
		i.parseSectionFields(category, fields, cipher, get(section, "title"))
	}
}

func (i *PuxImporter) parseSectionFields(category string, fields any, cipher *model.CipherView, sectionTitle any) {
	for _, field := range array(fields, "fields") {
		value := get(field, "value")
		keys := objectKeys(value)
		valueKey := "undefined"
		if len(keys) > 0 {
			valueKey = keys[0]
		}

		if isNullish(value) || isNullish(get(value, valueKey)) || get(value, valueKey) == "" {
			continue
		}

		fieldName := getFieldName(get(field, "title"), sectionTitle)
		fieldValue := extractValue(value, valueKey)

		switch cipher.Type {
		case model.CipherTypeLogin:
			if i.fillLogin(field, fieldValue, cipher) {
				continue
			}
			switch category {
			case CategoryLogin, CategoryDatabase, CategoryEmailAccount, CategoryWirelessRouter:
			case CategoryServer:
				if i.IsNullOrWhitespace(cipher.Login.Uri()) && get(field, "id") == "url" {
					cipher.Login.Uris = makeUriArrayAny(&i.Base, fieldValue)
					continue
				}
			case CategoryAPICredential:
				if i.fillApiCredentials(field, fieldValue, cipher) {
					continue
				}
			}
		case model.CipherTypeCard:
			if i.fillCreditCard(field, fieldValue, cipher) {
				continue
			}
			if category == CategoryBankAccount {
				if i.fillBankAccount(field, fieldValue, cipher) {
					continue
				}
			}
		case model.CipherTypeIdentity:
			if i.fillIdentity(field, fieldValue, cipher, valueKey) {
				continue
			}
			if valueKey == "address" {
				// fieldValue is an object cast into a string, so access the plain value instead
				address := get(value, "address")
				street, city, country := get(address, "street"), get(address, "city"), get(address, "country")
				zip, state := get(address, "zip"), get(address, "state")
				cipher.Identity.Address1 = valueOrDefault(street)
				cipher.Identity.City = valueOrDefault(city)
				if !isNOW(country) {
					cipher.Identity.Country = strings.ToUpper(country.(string))
				}
				cipher.Identity.PostalCode = valueOrDefault(zip)
				cipher.Identity.State = valueOrDefault(state)
				continue
			}

			switch category {
			case CategoryIdentity:
			case CategoryDriversLicense:
				if i.fillDriversLicense(field, fieldValue, cipher) {
					continue
				}
			case CategoryOutdoorLicense:
				if i.fillOutdoorLicense(field, fieldValue, cipher) {
					continue
				}
			case CategoryMembership:
				if i.fillMembership(field, fieldValue, cipher) {
					continue
				}
			case CategoryPassport:
				if i.fillPassport(field, fieldValue, cipher) {
					continue
				}
			case CategoryRewardsProgram:
				if i.fillRewardsProgram(field, fieldValue, cipher) {
					continue
				}
			case CategorySocialSecurityNumber:
				if i.fillSSN(field, fieldValue, cipher) {
					continue
				}
			}
		case model.CipherTypeSshKey:
			if valueKey == "sshKey" {
				// Use sshKey.metadata.privateKey instead of sshKey.privateKey (which doesn't have a
				// consistent format for every item). The SDK converts it from PKCS#8 (1Password's
				// format) to OpenSSH; 1Password does not store password-protected SSH keys. A key
				// the SDK can't parse throws here and is handled per item by parse().
				privateKey := path(value, "sshKey", "metadata", "privateKey")
				pk, ok := privateKey.(string)
				if !ok {
					throwTypeError("import_ssh_key: privateKey is not a string")
				}
				parsedKey, err := importer.ImportSSHKey(pk, "")
				if err != nil {
					panic(err)
				}
				cipher.SshKey.PrivateKey = parsedKey.PrivateKey
				cipher.SshKey.PublicKey = parsedKey.PublicKey
				cipher.SshKey.KeyFingerprint = parsedKey.KeyFingerprint
				continue
			}
		case model.CipherTypeBankAccount:
			if i.fillBankAccount(field, fieldValue, cipher) {
				continue
			}
		case model.CipherTypePassport:
			if i.fillPassport(field, fieldValue, cipher) {
				continue
			}
		case model.CipherTypeDriversLicense:
			if i.fillDriversLicense(field, fieldValue, cipher) {
				continue
			}
		}

		if valueKey == "email" {
			// fieldValue is an object cast into a string, so access the plain value instead
			email := get(value, "email")
			i.kvp(cipher, fieldName, get(email, "email_address"), model.FieldTypeText)
			i.kvp(cipher, "provider", get(email, "provider"), model.FieldTypeText)
			continue
		}

		// Do not include a password field if it's already in the history
		if get(field, "title") == "password" && cipher.PasswordHistory != nil {
			if s, ok := fieldValue.(string); ok && passwordInHistory(cipher, s) {
				continue
			}
		}

		// TODO upstream: if one of the fields is guarded, activate password re-prompt for the item
		if truthy(get(field, "guarded")) && cipher.Reprompt == model.CipherRepromptNone {
			cipher.Reprompt = model.CipherRepromptPassword
		}

		fieldType := model.FieldTypeText
		if valueKey == "concealed" {
			fieldType = model.FieldTypeHidden
		}
		i.kvp(cipher, fieldName, fieldValue, fieldType)
	}
}

// makeUriArrayAny is makeUriArray(string | string[]) for an untyped value.
func makeUriArrayAny(b *importer.Base, v any) []*model.LoginUriView {
	switch t := v.(type) {
	case string:
		return b.MakeUriArray(t)
	case []any:
		var urls []string
		for _, u := range t {
			s, ok := u.(string)
			if !ok {
				throwTypeError("uri.trim is not a function")
			}
			urls = append(urls, s)
		}
		return b.MakeUriArray(urls...)
	}
	return nil
}

// getFieldName: the title if available, else the section title if available, else "".
func getFieldName(title any, sectionTitle ...any) string {
	if !isNOW(title) {
		return title.(string)
	}
	if len(sectionTitle) > 0 && !isNOW(sectionTitle[0]) {
		return sectionTitle[0].(string)
	}
	return ""
}

func extractValue(value any, valueKey string) any {
	if valueKey == "date" {
		return dateFromMs(toNumber(get(value, "date")) * 1000).toUTCString()
	}
	if valueKey == "monthYear" {
		v := get(value, "monthYear")
		if isNullish(v) {
			throwTypeError("Cannot read properties of %s (reading 'toString')", nullishName(v))
		}
		return jsString(v)
	}
	return get(value, valueKey)
}

func fieldID(field any) any { return get(field, "id") }

func (i *PuxImporter) fillLogin(field, fieldValue any, cipher *model.CipherView) bool {
	fieldName := getFieldName(get(field, "title"))

	if i.IsNullOrWhitespace(cipher.Login.Username) && fieldName == "username" {
		cipher.Login.Username = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Login.Password) && fieldName == "password" {
		cipher.Login.Password = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Login.Totp) {
		if id := fieldID(field); !isNullish(id) {
			s, ok := id.(string)
			if !ok {
				throwTypeError("field.id.startsWith is not a function")
			}
			if strings.HasPrefix(s, "TOTP_") {
				cipher.Login.Totp = toStr(fieldValue)
				return true
			}
		}
	}
	return false
}

func (i *PuxImporter) fillApiCredentials(field, fieldValue any, cipher *model.CipherView) bool {
	fieldName := getFieldName(get(field, "title"))

	if i.IsNullOrWhitespace(cipher.Login.Password) && fieldName == "credential" {
		cipher.Login.Password = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Login.Uri()) && fieldName == "hostname" {
		cipher.Login.Uris = makeUriArrayAny(&i.Base, fieldValue)
		return true
	}
	return false
}

func (i *PuxImporter) fillCreditCard(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	if i.IsNullOrWhitespace(cipher.Card.Number) && id == "ccnum" {
		cipher.Card.Number = toStr(fieldValue)
		cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Card.Code) && id == "cvv" {
		cipher.Card.Code = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Card.CardholderName) && id == "cardholder" {
		cipher.Card.CardholderName = toStr(fieldValue)
		return true
	}
	if cardExpirationEmpty(cipher.Card) && id == "expiry" {
		monthYear := importer.JSTrim(jsString(fieldValue))
		cipher.Card.ExpMonth = substringJS(monthYear, 4, 6)
		if strings.HasPrefix(cipher.Card.ExpMonth, "0") {
			cipher.Card.ExpMonth = substringJS(cipher.Card.ExpMonth, 1, 2)
		}
		cipher.Card.ExpYear = substringJS(monthYear, 0, 4)
		return true
	}
	if id == "type" {
		// Skip since brand was determined from number above
		return true
	}
	return false
}

// bankAccountFieldMap: 1Password field ids → bank account cipher fields.
var puxBankAccountFields = map[string]func(*model.BankAccountView) *string{
	"bankName":     func(v *model.BankAccountView) *string { return &v.BankName },
	"owner":        func(v *model.BankAccountView) *string { return &v.NameOnAccount },
	"accountType":  func(v *model.BankAccountView) *string { return &v.AccountType },
	"routingNo":    func(v *model.BankAccountView) *string { return &v.RoutingNumber },
	"accountNo":    func(v *model.BankAccountView) *string { return &v.AccountNumber },
	"swift":        func(v *model.BankAccountView) *string { return &v.SwiftCode },
	"iban":         func(v *model.BankAccountView) *string { return &v.Iban },
	"telephonePin": func(v *model.BankAccountView) *string { return &v.Pin },
	"branchPhone":  func(v *model.BankAccountView) *string { return &v.BankContactPhone },
}

func idString(field any) string {
	s, _ := fieldID(field).(string)
	return s
}

func (i *PuxImporter) fillBankAccount(field, fieldValue any, cipher *model.CipherView) bool {
	// With the new item type more fields are available to set
	if i.useNewDedicatedTypes {
		if f, ok := puxBankAccountFields[idString(field)]; ok {
			if idString(field) == "accountType" {
				*f(cipher.BankAccount) = i.ProcessBankAccountType(toStr(fieldValue))
			} else {
				*f(cipher.BankAccount) = toStr(fieldValue)
			}
			return true
		}
		return false
	}
	// Otherwise only the card owner is set when applicable
	if i.IsNullOrWhitespace(cipher.Card.CardholderName) && fieldID(field) == "owner" {
		cipher.Card.CardholderName = toStr(fieldValue)
		return true
	}
	return false
}

func (i *PuxImporter) fillIdentity(field, fieldValue any, cipher *model.CipherView, valueKey string) bool {
	id := fieldID(field)
	identity := cipher.Identity
	if i.IsNullOrWhitespace(identity.FirstName) && id == "firstname" {
		identity.FirstName = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(identity.LastName) && id == "lastname" {
		identity.LastName = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(identity.MiddleName) && id == "initial" {
		identity.MiddleName = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(identity.Phone) && id == "defphone" {
		identity.Phone = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(identity.Company) && id == "company" {
		identity.Company = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(identity.Email) {
		if valueKey == "email" {
			email := path(field, "value", "email")
			identity.Email = valueOrDefault(get(email, "email_address"))
			i.kvp(cipher, "provider", get(email, "provider"), model.FieldTypeText)
			return true
		}
		if id == "email" {
			identity.Email = toStr(fieldValue)
			return true
		}
	}
	if i.IsNullOrWhitespace(identity.Username) && id == "username" {
		identity.Username = toStr(fieldValue)
		return true
	}
	return false
}

// driversLicenseIdentityFieldMap: 1Password field ids → identity fields.
var puxDriversLicenseIdentityFields = map[string]func(*model.IdentityView) *string{
	"address": func(v *model.IdentityView) *string { return &v.Address1 },
	// TODO upstream: ISO code
	"country": func(v *model.IdentityView) *string { return &v.Country },
	"state":   func(v *model.IdentityView) *string { return &v.State },
	"number":  func(v *model.IdentityView) *string { return &v.LicenseNumber },
}

// driversLicenseDedicatedFieldMap: 1Password field ids → driver's license fields.
var puxDriversLicenseDedicatedFields = map[string]func(*model.DriversLicenseView) *string{
	// TODO upstream: ISO code
	"country":   func(v *model.DriversLicenseView) *string { return &v.IssuingCountry },
	"state":     func(v *model.DriversLicenseView) *string { return &v.IssuingState },
	"number":    func(v *model.DriversLicenseView) *string { return &v.LicenseNumber },
	"birthdate": func(v *model.DriversLicenseView) *string { return &v.DateOfBirth },
	"class":     func(v *model.DriversLicenseView) *string { return &v.LicenseClass },
}

func (i *PuxImporter) fullName(v any) (string, string, string) {
	s, _ := v.(string)
	return i.GetFullName(s)
}

func (i *PuxImporter) processFullNameAny(cipher *model.CipherView, v any) {
	s, _ := v.(string)
	i.ProcessFullName(cipher, s)
}

// parseDateStringAny is parseDateString(`new Date(value)`).
func parseDateStringAny(v any) string { return newDate(v).formatDateString() }

func (i *PuxImporter) fillDriversLicense(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	var existingFirstName string
	if i.useNewDedicatedTypes {
		existingFirstName = cipher.DriversLicense.FirstName
	} else {
		existingFirstName = cipher.Identity.FirstName
	}
	if i.IsNullOrWhitespace(existingFirstName) && id == "fullname" {
		if i.useNewDedicatedTypes {
			first, middle, last := i.fullName(fieldValue)
			cipher.DriversLicense.FirstName = first
			cipher.DriversLicense.MiddleName = middle
			cipher.DriversLicense.LastName = last
		} else {
			i.processFullNameAny(cipher, fieldValue)
		}
		return true
	}

	// A single number YYYYMM that expresses a month and year.
	if i.useNewDedicatedTypes && id == "expiry_date" && i.IsNullOrWhitespace(cipher.DriversLicense.ExpirationDate) {
		s, ok := fieldValue.(string)
		if !ok {
			throwTypeError("fieldValue.slice is not a function")
		}
		yearPart := sliceJS(s, 0, 4)
		monthPart := sliceJS(s, 4, -1)
		// The last day of the month: the first of the following month minus one day.
		ms := dateUTC(toNumber(yearPart), toNumber(monthPart), 1) - 24*60*60*1000
		cipher.DriversLicense.ExpirationDate = dateFromMs(ms).formatDateString()
		return true
	}

	if i.useNewDedicatedTypes {
		if f, ok := puxDriversLicenseDedicatedFields[idString(field)]; ok && i.IsNullOrWhitespace(*f(cipher.DriversLicense)) {
			if id == "birthdate" {
				*f(cipher.DriversLicense) = parseDateStringAny(fieldValue)
			} else {
				*f(cipher.DriversLicense) = toStr(fieldValue)
			}
			return true
		}
		return false
	}
	if f, ok := puxDriversLicenseIdentityFields[idString(field)]; ok && i.IsNullOrWhitespace(*f(cipher.Identity)) {
		*f(cipher.Identity) = toStr(fieldValue)
		return true
	}
	return false
}

func (i *PuxImporter) fillOutdoorLicense(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	if i.IsNullOrWhitespace(cipher.Identity.FirstName) && id == "name" {
		i.processFullNameAny(cipher, fieldValue)
		return true
	}
	// TODO upstream: ISO code
	if i.IsNullOrWhitespace(cipher.Identity.Country) && id == "country" {
		cipher.Identity.Country = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Identity.State) && id == "state" {
		cipher.Identity.State = toStr(fieldValue)
		return true
	}
	return false
}

func (i *PuxImporter) fillMembership(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	if i.IsNullOrWhitespace(cipher.Identity.FirstName) && id == "member_name" {
		i.processFullNameAny(cipher, fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Identity.Company) && id == "org_name" {
		cipher.Identity.Company = toStr(fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Identity.Phone) && id == "phone" {
		cipher.Identity.Phone = toStr(fieldValue)
		return true
	}
	return false
}

// passportDedicatedItemFieldMap: 1Password field ids → passport fields.
var puxPassportFields = map[string]func(*model.PassportView) *string{
	"nationality":       func(v *model.PassportView) *string { return &v.Nationality },
	"issuing_authority": func(v *model.PassportView) *string { return &v.IssuingAuthority },
	"birthdate":         func(v *model.PassportView) *string { return &v.DateOfBirth },
	"birthplace":        func(v *model.PassportView) *string { return &v.BirthPlace },
	"issue_date":        func(v *model.PassportView) *string { return &v.IssueDate },
	"expiry_date":       func(v *model.PassportView) *string { return &v.ExpirationDate },
	"type":              func(v *model.PassportView) *string { return &v.PassportType },
}

func (i *PuxImporter) fillPassport(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	var existingFirstName string
	if i.useNewDedicatedTypes {
		existingFirstName = cipher.Passport.GivenName
	} else {
		existingFirstName = cipher.Identity.FirstName
	}
	if i.IsNullOrWhitespace(existingFirstName) && id == "fullname" {
		if i.useNewDedicatedTypes {
			first, middle, last := i.fullName(fieldValue)
			cipher.Passport.GivenName = first
			if !i.IsNullOrWhitespace(middle) {
				cipher.Passport.GivenName += " " + middle
			}
			cipher.Passport.Surname = last
		} else {
			i.processFullNameAny(cipher, fieldValue)
		}
		return true
	}

	// TODO upstream: ISO code
	var existingCountry string
	if i.useNewDedicatedTypes {
		existingCountry = cipher.Passport.IssuingCountry
	} else {
		existingCountry = cipher.Identity.Country
	}
	if i.IsNullOrWhitespace(existingCountry) && id == "issuing_country" {
		if i.useNewDedicatedTypes {
			cipher.Passport.IssuingCountry = toStr(fieldValue)
		} else {
			cipher.Identity.Country = toStr(fieldValue)
		}
		return true
	}

	var existingNumber string
	if i.useNewDedicatedTypes {
		existingNumber = cipher.Passport.PassportNumber
	} else {
		existingNumber = cipher.Identity.PassportNumber
	}
	if i.IsNullOrWhitespace(existingNumber) && id == "number" {
		if i.useNewDedicatedTypes {
			cipher.Passport.PassportNumber = toStr(fieldValue)
		} else {
			cipher.Identity.PassportNumber = toStr(fieldValue)
		}
		return true
	}

	if i.useNewDedicatedTypes {
		if f, ok := puxPassportFields[idString(field)]; ok && i.IsNullOrWhitespace(*f(cipher.Passport)) {
			if id == "birthdate" || id == "issue_date" || id == "expiry_date" {
				*f(cipher.Passport) = parseDateStringAny(fieldValue)
			} else {
				*f(cipher.Passport) = toStr(fieldValue)
			}
			return true
		}
	}
	return false
}

func (i *PuxImporter) fillRewardsProgram(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	if i.IsNullOrWhitespace(cipher.Identity.FirstName) && id == "member_name" {
		i.processFullNameAny(cipher, fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Identity.Company) && id == "company_name" {
		cipher.Identity.Company = toStr(fieldValue)
		return true
	}
	return false
}

func (i *PuxImporter) fillSSN(field, fieldValue any, cipher *model.CipherView) bool {
	id := fieldID(field)
	if i.IsNullOrWhitespace(cipher.Identity.FirstName) && id == "name" {
		i.processFullNameAny(cipher, fieldValue)
		return true
	}
	if i.IsNullOrWhitespace(cipher.Identity.Ssn) && id == "number" {
		cipher.Identity.Ssn = toStr(fieldValue)
		return true
	}
	return false
}
