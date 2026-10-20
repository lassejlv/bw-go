package keeper

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// JsonImporter is KeeperJsonImporter (keeper-json-importer.ts).
type JsonImporter struct {
	keeperImporter
	references   *refMap
	idToCipher   map[string]*model.CipherView
	nextObjectID int
}

type reference struct {
	id    *jsValue
	type_ string
}

// refMap is the insertion-ordered Map<uid, Reference[]>.
type refMap struct {
	keys []string
	m    map[string][]reference
}

func (r *refMap) set(k string, v []reference) {
	if _, ok := r.m[k]; !ok {
		r.keys = append(r.keys, k)
	}
	r.m[k] = v
}

// NewJson builds the keeperjson importer.
func NewJson(opts importer.Options) importer.Importer {
	return &JsonImporter{
		keeperImporter: newKeeperImporter(opts),
		references:     &refMap{m: map[string][]reference{}},
		idToCipher:     map[string]*model.CipherView{},
	}
}

// localeLocation is the time zone Date.prototype.toLocaleString() formats in (the user's time
// zone, like upstream). Tests pin it.
var localeLocation = time.Local

// Parse implements importer.Importer.
func (i *JsonImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	keeperExport, err := parseJS(data)
	if err != nil {
		return nil, err
	}
	// if (!keeperExport?.records?.length)
	records := keeperExport.get("records")
	if records != nil && records.kind == jsString && records.s != "" {
		return nil, newTypeError("keeperExport.records.forEach is not a function")
	}
	if records == nil || records.kind != jsArray || len(records.arr) == 0 {
		result.Success = false
		return result, nil
	}

	if err := i.parseSharedFolders(keeperExport, result); err != nil {
		return nil, err
	}
	if err := i.parseRecords(records.arr, result); err != nil {
		return nil, err
	}
	i.resolveReferences()

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}

	result.Success = true
	return result, nil
}

func (i *JsonImporter) parseSharedFolders(keeperExport *jsValue, result *model.ImportResult) error {
	sharedFolders := keeperExport.get("shared_folders")
	if !sharedFolders.truthy() {
		return nil
	}
	if sharedFolders.kind != jsArray {
		return newTypeError("keeperExport.shared_folders.forEach is not a function")
	}

	for _, folder := range sharedFolders.arr {
		if folder.isNullish() {
			return newTypeError("Cannot read properties of %s (reading 'path')", folder.toString())
		}
		path := folder.get("path")
		name := ""
		if !path.isNullish() {
			if path.kind != jsString {
				return newTypeError("name.replaceAll is not a function")
			}
			name = path.s
		}
		i.ProcessFolder(result, sanitizeFolderName(name), false)
	}
	return nil
}

func (i *JsonImporter) parseRecords(records []*jsValue, result *model.ImportResult) error {
	useNewDedicatedTypes := i.useNewDedicatedTypes
	for _, record := range records {
		if record.isNullish() {
			return newTypeError("Cannot read properties of %s (reading 'title')", record.toString())
		}
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(record.get("title").str())
		cipher.Notes = i.GetValueOrDefault(record.get("notes").str())

		cipher.Login.Username = i.GetValueOrDefault(record.get("login").str())
		cipher.Login.Password = i.GetValueOrDefault(record.get("password").str())
		uris, err := i.makeUriArrayJS(record.get("login_url"))
		if err != nil {
			return err
		}
		cipher.Login.Uris = uris

		customFields := record.get("custom_fields")

		// Force type based on the record type
		switch record.get("$type").str() {
		case "bankCard":
			i.importBankCard(customFields, cipher)
		case "driverLicense":
			i.importDriverLicense(customFields, cipher, useNewDedicatedTypes)
		case "ssnCard":
			i.importSsnCard(customFields, cipher)
		case "passport":
			i.importPassport(customFields, cipher, useNewDedicatedTypes)
		case "sshKeys":
			// In Bitwarden the ssh key is supposed to be valid.
			// So we only set the type if we can actually import a key.
			if !i.importSshKey(record, customFields, cipher) {
				// Otherwise, fallback to secure note
				cipher.Type = model.CipherTypeSecureNote
				// Make sure the passphrase is not lost, if any. The key pair will be imported as a
				// custom field.
				i.addField(cipher, "Passphrase", cipher.Login.Password, model.FieldTypeHidden)
			}
		case "bankAccount":
			// If flag is on we create a second cipher for the bank account directly
			if useNewDedicatedTypes {
				if err := i.importBankAccountDedicatedCipher(result, record, customFields, cipher); err != nil {
					return err
				}
			}
		}

		if customFields.truthy() {
			if err := i.importCustomFields(customFields, cipher); err != nil {
				return err
			}
		}

		uid := record.get("uid")
		uidKey := i.mapKey(uid)
		refsValue := record.get("references")
		if uid.truthy() && refsValue.truthy() {
			var refs []reference
			for _, key := range refsValue.keys() {
				typ, _ := parseFieldKey(key)

				// Web exporter appends "Ref" to the type names
				if strings.HasSuffix(typ, "Ref") {
					typ = typ[:len(typ)-3]
				}

				for _, id := range makeArray(refsValue.get(key)) {
					refs = append(refs, reference{id: id, type_: typ})
				}
			}

			if len(refs) > 0 {
				i.references.set(uidKey, refs)
			}
		}

		i.ConvertToNoteIfNeeded(cipher)
		if err := i.parseFolders(result, record); err != nil {
			return err
		}
		i.CleanupCipher(cipher)

		result.Ciphers = append(result.Ciphers, cipher)

		// This is needed for resolving references later
		if uid.truthy() {
			i.idToCipher[uidKey] = cipher
		}
	}
	return nil
}

// mapKey is the SameValueZero identity of a Map key: primitives compare by value, objects and
// arrays only to themselves (each occurrence is a distinct object after JSON.parse).
func (i *JsonImporter) mapKey(v *jsValue) string {
	if v == nil {
		return "u:"
	}
	switch v.kind {
	case jsNull:
		return "null:"
	case jsBool:
		return "b:" + v.toString()
	case jsNumber:
		return "n:" + v.toString()
	case jsString:
		return "s:" + v.s
	}
	i.nextObjectID++
	return "o:" + strconv.Itoa(i.nextObjectID)
}

func (i *JsonImporter) resolveReferences() {
	for _, uid := range i.references.keys {
		cipher := i.idToCipher[uid]
		if cipher == nil {
			continue
		}

		for _, ref := range i.references.m[uid] {
			refCipher := i.idToCipher[i.mapKey(ref.id)]
			if refCipher == nil {
				continue
			}

			value := ""
			if f := findFieldByName(refCipher, ref.type_); f != nil {
				value = f.Value
			}
			if value != "" {
				i.addField(cipher, ref.type_, value)
			}
		}
	}
}

func findFieldByName(cipher *model.CipherView, name string) *model.FieldView {
	for _, f := range cipher.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// extractNameFromCustomFields parses the $name custom field as [first, middle, last] and removes
// it from the custom fields list. Parts that cannot be parsed are "" (undefined).
func (i *JsonImporter) extractNameFromCustomFields(fields *jsValue) [3]string {
	result := [3]string{
		findCustomField(fields, "$name/first"),
		findCustomField(fields, "$name/middle"),
		findCustomField(fields, "$name/last"),
	}
	deleteTopLevelCustomField(fields, "$name")
	return result
}

func (i *JsonImporter) importBankAccountDedicatedCipher(result *model.ImportResult, record, customFields *jsValue, cipher *model.CipherView) error {
	bankAccountCipher := i.InitLoginCipher()
	bankAccountCipher.Name = cipher.Name
	bankAccountCipher.Type = model.CipherTypeBankAccount

	bankAccount := &model.BankAccountView{}

	bankAccount.AccountNumber = findCustomField(customFields, "$bankAccount/accountNumber")
	bankAccount.RoutingNumber = findCustomField(customFields, "$bankAccount/routingNumber")
	bankAccount.AccountType = i.ProcessBankAccountType(findCustomField(customFields, "$bankAccount/accountType"))
	deleteTopLevelCustomField(customFields, "$bankAccount")

	nameParts := i.extractNameFromCustomFields(customFields)
	var parts []string
	for _, p := range nameParts {
		if p != "" {
			parts = append(parts, p)
		}
	}
	bankAccount.NameOnAccount = strings.Join(parts, " ")

	bankAccountCipher.BankAccount = bankAccount
	if err := i.parseFolders(result, record); err != nil {
		return err
	}
	i.CleanupCipher(bankAccountCipher)
	result.Ciphers = append(result.Ciphers, bankAccountCipher)
	return nil
}

func (i *JsonImporter) importBankCard(customFields *jsValue, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeCard
	cipher.Card.CardholderName = findCustomField(customFields, "$text:cardholderName")
	cipher.Card.Number = findCustomField(customFields, "$paymentCard/cardNumber")
	cipher.Card.Code = findCustomField(customFields, "$paymentCard/cardSecurityCode")
	cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)

	expDate := findCustomField(customFields, "$paymentCard/cardExpirationDate")
	if expDate != "" {
		expDateParts := strings.Split(expDate, "/")
		if len(expDateParts) == 2 {
			cipher.Card.ExpMonth = expDateParts[0]
			cipher.Card.ExpYear = expDateParts[1]
		} else {
			i.addField(cipher, "Expiration date", expDate)
		}
	}

	pinCode := findCustomField(customFields, "$pinCode")
	if pinCode != "" {
		i.addField(cipher, "PIN", pinCode, model.FieldTypeHidden)
	}

	i.copyLoginPropertiesAsCustomFields(cipher)

	// These should not be imported as custom fields since they are mapped to card properties
	deleteTopLevelCustomField(customFields, "$paymentCard")
	deleteTopLevelCustomField(customFields, "$text:cardholderName")
	deleteTopLevelCustomField(customFields, "$pinCode")
}

func (i *JsonImporter) importSshKey(record, customFields *jsValue, cipher *model.CipherView) bool {
	privateKey := findCustomField(customFields, "$keyPair/privateKey")
	if privateKey == "" {
		return false
	}

	keyView, err := importer.ImportSSHKey(privateKey, cipher.Login.Password)
	if err != nil {
		i.warning("Unable to import SSH key (id: " + record.get("uid").toString() + ", title: " + record.get("title").toString() + ")")
		return false
	}
	if keyView == nil {
		return false
	}

	cipher.Type = model.CipherTypeSshKey
	cipher.SshKey.PrivateKey = keyView.PrivateKey
	cipher.SshKey.PublicKey = keyView.PublicKey
	cipher.SshKey.KeyFingerprint = keyView.KeyFingerprint

	i.copyLoginPropertiesAsCustomFields(cipher)

	hostName := findCustomField(customFields, "$host/hostName")
	if hostName != "" {
		i.addField(cipher, "Hostname", hostName)
	}
	port := findCustomField(customFields, "$host/port")
	if port != "" {
		i.addField(cipher, "Port", port)
	}

	// These should not be imported as custom fields since they are mapped to ssh key properties
	deleteTopLevelCustomField(customFields, "$keyPair")
	deleteTopLevelCustomField(customFields, "$host")

	return true
}

// convertMillisToDate is KeeperJsonImporter.convertMillisToDate ("" for undefined).
func (i *JsonImporter) convertMillisToDate(msString string, useNewDedicatedTypes bool) string {
	t, ok := dateFromMillis(jsStringToNumber(msString))
	if !ok {
		return ""
	}
	if useNewDedicatedTypes {
		return i.FormatDateString(&t)
	}
	return toUTCString(t)
}

func (i *JsonImporter) importDriverLicense(customFields *jsValue, cipher *model.CipherView, useNewDedicatedTypes bool) {
	licenseNumber := findCustomField(customFields, "$accountNumber:dlNumber")
	if useNewDedicatedTypes {
		cipher.Type = model.CipherTypeDriversLicense
		driversLicense := &model.DriversLicenseView{}
		driversLicense.LicenseNumber = licenseNumber
		name := i.extractNameFromCustomFields(customFields)
		driversLicense.FirstName = name[0]
		driversLicense.MiddleName = name[1]
		driversLicense.LastName = name[2]
		// Date of birth is returned as a milliseconds string
		birthDateMsString := findCustomField(customFields, "$birthDate")
		if birthDateMsString != "" {
			driversLicense.DateOfBirth = i.convertMillisToDate(birthDateMsString, useNewDedicatedTypes)
			deleteTopLevelCustomField(customFields, "$birthDate")
		}
		// Expiration date is returned as a milliseconds string
		expirationDateMsString := findCustomField(customFields, "$expirationDate")
		if expirationDateMsString != "" {
			driversLicense.ExpirationDate = i.convertMillisToDate(expirationDateMsString, useNewDedicatedTypes)
			deleteTopLevelCustomField(customFields, "$expirationDate")
		}
		cipher.DriversLicense = driversLicense
	} else {
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
		cipher.Identity.LicenseNumber = licenseNumber
		i.importIdentityName(customFields, cipher)
	}
	i.copyLoginPropertiesAsCustomFields(cipher)
	deleteTopLevelCustomField(customFields, "$accountNumber:dlNumber")
}

func (i *JsonImporter) importSsnCard(customFields *jsValue, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeIdentity
	cipher.Identity = &model.IdentityView{}
	cipher.Identity.Ssn = findCustomField(customFields, "$accountNumber:identityNumber")
	i.importIdentityName(customFields, cipher)
	i.copyLoginPropertiesAsCustomFields(cipher)
	deleteTopLevelCustomField(customFields, "$accountNumber:identityNumber")
}

func (i *JsonImporter) importPassport(customFields *jsValue, cipher *model.CipherView, useNewDedicatedTypes bool) {
	passportNumber := findCustomField(customFields, "$accountNumber:passportNumber")
	if useNewDedicatedTypes {
		cipher.Type = model.CipherTypePassport
		passport := &model.PassportView{}
		passport.PassportNumber = passportNumber
		name := i.extractNameFromCustomFields(customFields)
		passport.GivenName = name[0]
		if name[1] != "" {
			// `first` is undefined when the name has no first part.
			passport.GivenName = jsConcatNullable(passport.GivenName, "undefined") + " " + name[1]
		}
		passport.Surname = name[2]
		// Date of birth is returned as a milliseconds string
		birthDateMsString := findCustomField(customFields, "$birthDate")
		if birthDateMsString != "" {
			passport.DateOfBirth = i.convertMillisToDate(birthDateMsString, useNewDedicatedTypes)
			deleteTopLevelCustomField(customFields, "$birthDate")
		}
		// Expiration date is returned as a milliseconds string
		expirationDateMsString := findCustomField(customFields, "$expirationDate")
		if expirationDateMsString != "" {
			passport.ExpirationDate = i.convertMillisToDate(expirationDateMsString, useNewDedicatedTypes)
			deleteTopLevelCustomField(customFields, "$expirationDate")
		}
		// Date of issued is returned as a milliseconds string
		dateOfIssueMsString := findCustomField(customFields, "$date:dateIssued")
		if dateOfIssueMsString != "" {
			passport.IssueDate = i.convertMillisToDate(dateOfIssueMsString, useNewDedicatedTypes)
			deleteTopLevelCustomField(customFields, "$date:dateIssued")
		}
		cipher.Passport = passport
	} else {
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
		cipher.Identity.PassportNumber = passportNumber
		i.importIdentityName(customFields, cipher)
	}
	i.copyLoginPropertiesAsCustomFields(cipher)
	deleteTopLevelCustomField(customFields, "$accountNumber:passportNumber")
}

func (i *JsonImporter) importIdentityName(customFields *jsValue, cipher *model.CipherView) {
	cipher.Identity.FirstName = findCustomField(customFields, "$name/first")
	cipher.Identity.MiddleName = findCustomField(customFields, "$name/middle")
	cipher.Identity.LastName = findCustomField(customFields, "$name/last")
	deleteTopLevelCustomField(customFields, "$name")
}

var keySuffixRe = regexp.MustCompile(`:?:\d$`)

// stripKeySuffix is k.replace(/:?:\d$/, "").
func stripKeySuffix(k string) string {
	if loc := keySuffixRe.FindStringIndex(k); loc != nil {
		return k[:loc[0]] + k[loc[1]:]
	}
	return k
}

// findCustomField is KeeperJsonImporter.findCustomField: matches by the full key with only the
// trailing `:digit` suffix stripped and supports nested path lookups via `/` (e.g.
// "$paymentCard/cardNumber").
func findCustomField(customFields *jsValue, path string) string {
	if customFields.isNullish() {
		return ""
	}

	root := customFields
	for _, part := range strings.Split(path, "/") {
		keys := root.keys()
		if len(keys) == 0 {
			return ""
		}

		key, found := "", false
		for _, k := range keys {
			if stripKeySuffix(k) == part {
				key, found = k, true
				break
			}
		}
		if !found || root.get(key).isNullish() {
			return ""
		}

		root = root.get(key)
	}

	return root.toString()
}

func deleteTopLevelCustomField(customFields *jsValue, name string) {
	if customFields.isNullish() || customFields.kind != jsObject {
		return
	}

	for _, k := range customFields.keys() {
		if stripKeySuffix(k) == name {
			customFields.obj.del(k)
			return
		}
	}
}

func (i *JsonImporter) importCustomFields(customFields *jsValue, cipher *model.CipherView) error {
	for _, originalKey := range customFields.keys() {
		originalValue := customFields.get(originalKey)
		typ, name := parseFieldKey(originalKey)

		// These handle arrays internally
		handled, err := i.tryImportArrayField(typ, originalValue, cipher)
		if err != nil {
			return err
		}
		if handled {
			continue
		}

		importedName := name
		if importedName == "" {
			importedName = typ
		}
		if importedName == "" {
			importedName = originalKey
		}
		values := makeArray(originalValue)

		for _, value := range values {
			// These expand into multiple fields
			handled, err := i.tryImportExpandingField(typ, value, cipher)
			if err != nil {
				return err
			}
			if handled {
				continue
			}

			// Import as a single field with JSON.stringify as the last resort fallback
			if err := i.importSingleField(typ, importedName, value, cipher); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *JsonImporter) tryImportArrayField(typ string, originalValue *jsValue, cipher *model.CipherView) (bool, error) {
	switch typ {
	case "oneTimeCode":
		totps := makeArray(originalValue)
		if len(totps) == 0 {
			break
		}

		// Login has a dedicated TOTP field. All others get added as custom fields.
		if cipher.Type == model.CipherTypeLogin {
			if totps[0].isNullish() {
				cipher.Login.Totp = ""
			} else {
				cipher.Login.Totp = totps[0].toString()
			}
			totps = totps[1:]
		}

		for _, code := range totps {
			i.addFieldJS(cipher, "TOTP", code, model.FieldTypeHidden)
		}
	case "url":
		urls, err := i.makeUriArrayJS(originalValue)
		if err != nil {
			return false, err
		}
		if cipher.Type == model.CipherTypeLogin {
			if cipher.Login.Uris == nil {
				return false, newTypeError("Cannot read properties of null (reading 'push')")
			}
			if urls == nil {
				return false, newTypeError("Spread syntax requires ...iterable[Symbol.iterator] to be a function")
			}
			cipher.Login.Uris = append(cipher.Login.Uris, urls...)
		} else {
			if urls == nil {
				return false, newTypeError("Cannot read properties of null (reading 'forEach')")
			}
			for _, url := range urls {
				i.addField(cipher, "URL", url.Uri)
			}
		}
	default:
		return false, nil
	}

	return true, nil
}

// destructure mirrors `const { a, b } = value`, which throws for null and undefined.
func destructure(value *jsValue, firstProp, varName string) error {
	if value.isNullish() {
		return newTypeError("Cannot destructure property '%s' of '%s' as it is %s.", firstProp, varName, value.toString())
	}
	return nil
}

func (i *JsonImporter) tryImportExpandingField(typ string, originalValue *jsValue, cipher *model.CipherView) (bool, error) {
	switch typ {
	case "host":
		if err := destructure(originalValue, "hostName", "originalValue"); err != nil {
			return false, err
		}
		i.addFieldJS(cipher, "Hostname", originalValue.get("hostName"))
		i.addFieldJS(cipher, "Port", originalValue.get("port"))
	case "keyPair":
		if err := destructure(originalValue, "publicKey", "originalValue"); err != nil {
			return false, err
		}
		i.addFieldJS(cipher, "Public key", originalValue.get("publicKey"))
		i.addFieldJS(cipher, "Private key", originalValue.get("privateKey"), model.FieldTypeHidden)
	case "securityQuestion":
		for _, qa := range makeArray(originalValue) {
			if err := destructure(qa, "question", "object"); err != nil {
				return false, err
			}
			i.addFieldJS(cipher, "Security question", qa.get("question"))
			i.addFieldJS(cipher, "Security question answer", qa.get("answer"), model.FieldTypeHidden)
		}
	case "appFiller":
		// Ignored since it's an implementation detail of Keeper
	default:
		return false, nil
	}

	return true, nil
}

// joinTruthy is [a, b, ...].filter((x) => x).join(sep).trim().
func joinTruthy(sep string, values ...*jsValue) string {
	var parts []string
	for _, v := range values {
		if v.truthy() {
			parts = append(parts, v.toString())
		}
	}
	return importer.JSTrim(strings.Join(parts, sep))
}

func (i *JsonImporter) importSingleField(typ, importedName string, value *jsValue, cipher *model.CipherView) error {
	importedValue := convertToFieldValue(value)
	importedType := model.FieldTypeText

	switch typ {
	case "date", "birthDate", "expirationDate":
		importedValue = parseDate(value)
	case "name":
		if err := destructure(value, "first", "value"); err != nil {
			return err
		}
		importedValue = joinTruthy(" ", value.get("first"), value.get("middle"), value.get("last"))
	case "address":
		if err := destructure(value, "street1", "value"); err != nil {
			return err
		}
		importedValue = joinTruthy(", ", value.get("street1"), value.get("street2"), value.get("city"),
			value.get("state"), value.get("zip"), value.get("country"))
	case "phone":
		if err := destructure(value, "region", "value"); err != nil {
			return err
		}
		region, number, ext, phoneType := value.get("region"), value.get("number"), value.get("ext"), value.get("type")

		var parts []string
		if region.truthy() {
			// TODO: Convert to +<code> format?
			parts = append(parts, "("+region.toString()+")")
		}
		if number.truthy() {
			parts = append(parts, number.toString())
		}
		if ext.truthy() {
			parts = append(parts, "ext. "+ext.toString())
		}
		if phoneType.truthy() {
			parts = append(parts, "("+phoneType.toString()+")")
		}

		importedValue = importer.JSTrim(strings.Join(parts, " "))
	case "bankAccount":
		if err := destructure(value, "accountType", "value"); err != nil {
			return err
		}
		accountType, otherType := value.get("accountType"), value.get("otherType")
		accountNumber, routingNumber := value.get("accountNumber"), value.get("routingNumber")

		var parts []string
		t := otherType
		if !t.truthy() {
			t = accountType
		}
		if t.truthy() {
			parts = append(parts, "Type: "+t.toString())
		}
		if accountNumber.truthy() {
			parts = append(parts, "Account Number: "+accountNumber.toString())
		}
		if routingNumber.truthy() {
			parts = append(parts, "Routing Number: "+routingNumber.toString())
		}

		importedValue = importer.JSTrim(strings.Join(parts, ", "))
	case "pinCode", "secret":
		importedType = model.FieldTypeHidden
	default:
		// Do nothing, default conversion is fine
	}

	i.addField(cipher, importedName, importedValue, importedType)
	return nil
}

// parseDate is KeeperJsonImporter.parseDate: `new Date(timestamp).toLocaleString()` or "".
func parseDate(timestamp *jsValue) string {
	var t time.Time
	var ok bool
	switch {
	case timestamp == nil:
		ok = false // new Date(undefined) is an Invalid Date
	case timestamp.kind == jsNull:
		t, ok = dateFromMillis(0)
	case timestamp.kind == jsBool:
		ms := 0.0
		if timestamp.b {
			ms = 1
		}
		t, ok = dateFromMillis(ms)
	case timestamp.kind == jsNumber:
		t, ok = dateFromMillis(timestamp.n)
	default:
		t, ok = importer.ParseJSDate(timestamp.toString())
	}
	if !ok {
		return ""
	}
	return toLocaleString(t)
}

// parseFieldKey parses custom field keys of the form $<type>:<name>:<suffix> and returns
// [type, name].
func parseFieldKey(key string) (string, string) {
	if importer.IsNullOrWhitespace(key) {
		return "", ""
	}

	fieldType := ""
	fieldName := ""

	if key[0] == '$' {
		pos := strings.Index(key, ":")
		if pos > 0 {
			fieldType = importer.JSTrim(key[1:pos])
			fieldName = importer.JSTrim(key[pos+1:])
		} else {
			fieldType = importer.JSTrim(key[1:])
			fieldName = ""
		}
	} else {
		fieldType = ""
		fieldName = key
	}

	if n := len(fieldName); n >= 2 && fieldName[n-2] == ':' && fieldName[n-1] >= '0' && fieldName[n-1] <= '9' {
		fieldName = fieldName[:n-2]
	}

	return fieldType, fieldName
}

// makeUriArrayJS is BaseImporter.makeUriArray called with an arbitrary JSON value; nil is null.
func (i *JsonImporter) makeUriArrayJS(v *jsValue) ([]*model.LoginUriView, error) {
	if v.isNullish() {
		return nil, nil
	}
	switch v.kind {
	case jsString:
		return i.MakeUriArray(v.s), nil
	case jsArray:
		var out []*model.LoginUriView
		for _, u := range v.arr {
			if u.isNullish() {
				continue // fixUri(null) is null
			}
			if u.kind != jsString {
				return nil, newTypeError("uri.trim is not a function")
			}
			if l := i.MakeUriArray(u.s); l != nil {
				out = append(out, l...)
			}
		}
		return out, nil
	}
	return nil, nil
}

func (i *JsonImporter) parseFolders(result *model.ImportResult, record *jsValue) error {
	folders := record.get("folders")
	if !folders.truthy() {
		return nil
	}
	if folders.kind != jsArray {
		return newTypeError("record.folders.forEach is not a function")
	}

	for _, item := range folders.arr {
		if item.isNullish() {
			return newTypeError("Cannot read properties of %s (reading 'folder')", item.toString())
		}
		for _, prop := range []string{"folder", "shared_folder"} {
			f := item.get(prop)
			if f.isNullish() {
				continue
			}
			if f.kind != jsString {
				return newTypeError("name.replaceAll is not a function")
			}
			i.ProcessFolder(result, sanitizeFolderName(f.s))
		}
	}
	return nil
}

// sanitizeFolderName: `\` and `/` are reserved characters in Bitwarden, but valid in Keeper. The
// upstream code replaces "\\\\" (a JS literal for two backslashes) and "/" with "-".
func sanitizeFolderName(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, `\\`, "-"), "/", "-")
}

// --- JavaScript Number/Date helpers ---

const maxTimeMs = 8.64e15

// dateFromMillis is `new Date(ms)`; ok is false for an Invalid Date.
func dateFromMillis(ms float64) (time.Time, bool) {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > maxTimeMs {
		return time.Time{}, false
	}
	ms = math.Trunc(ms)
	return time.UnixMilli(int64(ms)).UTC(), true
}

var (
	jsDecimalRe = regexp.MustCompile(`^[+-]?(\d+\.?\d*([eE][+-]?\d+)?|\.\d+([eE][+-]?\d+)?)$`)
	jsRadixRe   = regexp.MustCompile(`^0([xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
)

// jsStringToNumber is Number(s) for a string.
func jsStringToNumber(s string) float64 {
	s = importer.JSTrim(s)
	if s == "" {
		return 0
	}
	switch s {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if jsRadixRe.MatchString(s) {
		base := 16
		switch s[1] {
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		f := 0.0
		for _, c := range s[2:] {
			d, _ := strconv.ParseInt(string(c), 16, 64)
			f = f*float64(base) + float64(d)
		}
		return f
	}
	if !jsDecimalRe.MatchString(s) {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f
		}
		return math.NaN()
	}
	return f
}

func padInt(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// toUTCString is Date.prototype.toUTCString, e.g. "Thu, 14 Mar 1985 23:00:00 GMT".
func toUTCString(t time.Time) string {
	u := t.UTC()
	year := u.Year()
	ys := padInt(year, 4)
	if year < 0 {
		ys = "-" + padInt(-year, 4)
	}
	return u.Weekday().String()[:3] + ", " + padInt(u.Day(), 2) + " " + u.Month().String()[:3] + " " + ys +
		" " + padInt(u.Hour(), 2) + ":" + padInt(u.Minute(), 2) + ":" + padInt(u.Second(), 2) + " GMT"
}

// toLocaleString is Date.prototype.toLocaleString() for the en-US locale (Node's default ICU
// locale) in localeLocation, e.g. "3/14/1985, 11:00:00 PM".
func toLocaleString(t time.Time) string {
	l := t.In(localeLocation)
	h := l.Hour() % 12
	if h == 0 {
		h = 12
	}
	ampm := "AM"
	if l.Hour() >= 12 {
		ampm = "PM"
	}
	year := l.Year()
	ys := strconv.Itoa(year)
	if year <= 0 {
		// Intl renders years before 1 CE as the era year (1 BC is year 0).
		ys = strconv.Itoa(1 - year)
	}
	return strconv.Itoa(int(l.Month())) + "/" + strconv.Itoa(l.Day()) + "/" + ys + ", " +
		strconv.Itoa(h) + ":" + padInt(l.Minute(), 2) + ":" + padInt(l.Second(), 2) + " " + ampm
}
