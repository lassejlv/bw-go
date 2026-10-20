package onepassword

import (
	"sort"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Port of onepassword-1pif-importer.ts.

func init() { importer.Register("1password1pif", New1Pif) }

// PifImporter is OnePassword1PifImporter.
type PifImporter struct {
	importer.Base
	useNewDedicatedTypes bool
	// result is the instance field `result = new ImportResult()`: it accumulates across parse
	// calls on the same importer, like upstream.
	result *model.ImportResult
}

// New1Pif builds the 1pif importer (opts.Features.NewItemTypes is FeatureFlag.PM32009NewItemTypes).
func New1Pif(opts importer.Options) importer.Importer {
	return &PifImporter{
		Base:                 importer.NewBase(opts),
		useNewDedicatedTypes: opts.Features.NewItemTypes,
		result:               model.NewImportResult(),
	}
}

// Parse is OnePassword1PifImporter.parse.
func (i *PifImporter) Parse(data string) (result *model.ImportResult, err error) {
	defer catch(&err)
	for _, line := range i.SplitNewLine(data) {
		if i.IsNullOrWhitespace(line) || !strings.HasPrefix(line, "{") {
			continue
		}
		item, err := parseJSON(line)
		if err != nil {
			return nil, err
		}
		if b, ok := get(item, "trashed").(bool); ok && b {
			continue
		}
		cipher := i.InitLoginCipher()

		if isNOW(get(item, "hmac")) {
			i.processStandardItem(item, cipher)
		} else {
			i.processWinOpVaultItem(item, cipher)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
	}

	i.result.Success = true
	return i.result, nil
}

// makeUriArrayAny is makeUriArray(string | string[]) for an untyped value.
func (i *PifImporter) makeUriArrayAny(v any) []*model.LoginUriView {
	switch t := v.(type) {
	case string:
		return i.MakeUriArray(t)
	case []any:
		var urls []string
		for _, u := range t {
			s, ok := u.(string)
			if !ok {
				throwTypeError("uri.trim is not a function")
			}
			urls = append(urls, s)
		}
		return i.MakeUriArray(urls...)
	}
	return nil
}

func (i *PifImporter) processWinOpVaultItem(item any, cipher *model.CipherView) {
	if overview := get(item, "overview"); !isNullish(overview) {
		cipher.Name = valueOrDefault(get(overview, "title"))
		if urlsVal := get(overview, "URLs"); !isNullish(urlsVal) {
			var urls []string
			for _, url := range array(urlsVal, "item.overview.URLs") {
				if u := get(url, "u"); !isNOW(u) {
					urls = append(urls, u.(string))
				}
			}
			cipher.Login.Uris = i.MakeUriArray(urls...)
		}
	}

	if details := get(item, "details"); !isNullish(details) {
		if ph := get(details, "passwordHistory"); !isNullish(ph) {
			parsePasswordHistory(ph, cipher)
		}
		if !isNOW(get(details, "ccnum")) || !isNOW(get(details, "cvv")) {
			cipher.Type = model.CipherTypeCard
			cipher.Card = &model.CardView{}
		} else if !isNOW(get(details, "firstname")) || !isNOW(get(details, "address1")) {
			cipher.Type = model.CipherTypeIdentity
			cipher.Identity = &model.IdentityView{}
		}
		if cipher.Type == model.CipherTypeLogin && !isNOW(get(details, "password")) {
			cipher.Login.Password = get(details, "password").(string)
		}
		if notes := get(details, "notesPlain"); !isNOW(notes) {
			cipher.Notes = strings.Join(i.SplitNewLine(notes.(string)), "\n") + "\n"
		}
		if fields := get(details, "fields"); !isNullish(fields) {
			i.parseFields(fields, cipher, "designation", "value", "name")
		}
		if sections := get(details, "sections"); !isNullish(sections) {
			for _, section := range array(sections, "item.details.sections") {
				if fields := get(section, "fields"); !isNullish(fields) {
					i.parseFields(fields, cipher, "n", "v", "t")
				}
			}
		}
	}
}

func (i *PifImporter) processStandardItem(item any, cipher *model.CipherView) {
	openContents := get(item, "openContents")
	cipher.Favorite = truthy(openContents) && truthy(get(openContents, "faveIndex"))
	cipher.Name = valueOrDefault(get(item, "title"))

	typeName, _ := get(item, "typeName").(string)
	switch {
	case typeName == "securenotes.SecureNote":
		cipher.Type = model.CipherTypeSecureNote
		cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	case typeName == "wallet.financial.CreditCard":
		cipher.Type = model.CipherTypeCard
		cipher.Card = &model.CardView{}
	case typeName == "identities.Identity":
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
	case typeName == "wallet.government.Passport" && i.useNewDedicatedTypes:
		i.processPassport(item, cipher)
	case typeName == "wallet.government.DriversLicense" && i.useNewDedicatedTypes:
		i.processDriversLicense(item, cipher)
	case typeName == "wallet.financial.BankAccountUS" && i.useNewDedicatedTypes:
		i.processBankAccount(item, cipher)
	default:
		cipher.Login.Uris = i.makeUriArrayAny(get(item, "location"))
	}

	secure := get(item, "secureContents")
	if isNullish(secure) {
		return
	}
	if ph := get(secure, "passwordHistory"); !isNullish(ph) {
		parsePasswordHistory(ph, cipher)
	}
	if notes := get(secure, "notesPlain"); !isNOW(notes) {
		cipher.Notes = strings.Join(i.SplitNewLine(notes.(string)), "\n") + "\n"
	}
	if cipher.Type == model.CipherTypeLogin {
		if pw := get(secure, "password"); !isNOW(pw) {
			cipher.Login.Password = pw.(string)
		}
		if urlsVal := get(secure, "URLs"); !isNullish(urlsVal) {
			var urls []string
			for _, u := range array(urlsVal, "item.secureContents.URLs") {
				if url := get(u, "url"); !isNOW(url) {
					urls = append(urls, url.(string))
				}
			}
			if len(urls) > 0 {
				cipher.Login.Uris = i.MakeUriArray(urls...)
			}
		}
	}
	if fields := get(secure, "fields"); !isNullish(fields) {
		i.parseFields(fields, cipher, "designation", "value", "name")
	}
	if sections := get(secure, "sections"); !isNullish(sections) {
		for _, section := range array(sections, "item.secureContents.sections") {
			if fields := get(section, "fields"); !isNullish(fields) {
				i.parseFields(fields, cipher, "n", "v", "t")
			}
		}
	}
}

// filterSectionFields is `section.fields = (section.fields ?? []).flatMap(...)` over
// item?.secureContents?.sections ?? []: fields for which keep returns false are removed from the
// item (so they do not become custom fields later).
func filterSectionFields(item any, keep func(field any) bool) {
	sections := optPath(item, "secureContents", "sections")
	if isNullish(sections) {
		return
	}
	for _, section := range array(sections, "sections") {
		fieldsVal := get(section, "fields")
		var fields []any
		if !isNullish(fieldsVal) {
			fields = array(fieldsVal, "section.fields")
		}
		out := []any{}
		for _, field := range fields {
			if keep(field) {
				if a, ok := field.([]any); ok { // flatMap flattens returned arrays
					out = append(out, a...)
				} else {
					out = append(out, field)
				}
			}
		}
		if obj, ok := section.(*jsObject); ok {
			obj.set("fields", out)
		}
	}
}

// bankAccountFieldMap maps 1pif field names (`n`) to BankAccountView properties.
var pifBankAccountFields = map[string]func(*model.BankAccountView, string){
	"bankName":     func(v *model.BankAccountView, s string) { v.BankName = s },
	"owner":        func(v *model.BankAccountView, s string) { v.NameOnAccount = s },
	"accountType":  func(v *model.BankAccountView, s string) { v.AccountType = s },
	"routingNo":    func(v *model.BankAccountView, s string) { v.RoutingNumber = s },
	"accountNo":    func(v *model.BankAccountView, s string) { v.AccountNumber = s },
	"swift":        func(v *model.BankAccountView, s string) { v.SwiftCode = s },
	"iban":         func(v *model.BankAccountView, s string) { v.Iban = s },
	"telephonePin": func(v *model.BankAccountView, s string) { v.Pin = s },
	"branchPhone":  func(v *model.BankAccountView, s string) { v.BankContactPhone = s },
}

func fieldName(field any) string {
	n, _ := get(field, "n").(string)
	return n
}

func (i *PifImporter) processBankAccount(item any, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeBankAccount
	view := &model.BankAccountView{}
	filterSectionFields(item, func(field any) bool {
		if set, ok := pifBankAccountFields[fieldName(field)]; ok {
			set(view, toStr(get(field, "v")))
			return false
		}
		return true
	})
	view.AccountType = i.ProcessBankAccountType(view.AccountType)
	cipher.BankAccount = view
}

var pifPassportFields = map[string]func(*model.PassportView, string){
	"issuing_country":   func(v *model.PassportView, s string) { v.IssuingCountry = s },
	"number":            func(v *model.PassportView, s string) { v.PassportNumber = s },
	"nationality":       func(v *model.PassportView, s string) { v.Nationality = s },
	"issuing_authority": func(v *model.PassportView, s string) { v.IssuingAuthority = s },
	"birthplace":        func(v *model.PassportView, s string) { v.BirthPlace = s },
	"type":              func(v *model.PassportView, s string) { v.PassportType = s },
}

// fullName is getFullName for an untyped value.
func (i *PifImporter) fullName(v any) (string, string, string) {
	s, _ := v.(string)
	return i.GetFullName(s)
}

func (i *PifImporter) processPassport(item any, cipher *model.CipherView) {
	cipher.Type = model.CipherTypePassport
	view := &model.PassportView{}
	filterSectionFields(item, func(field any) bool {
		n := fieldName(field)
		if set, ok := pifPassportFields[n]; ok {
			set(view, toStr(get(field, "v")))
		} else if n == "fullname" {
			first, middle, last := i.fullName(get(field, "v"))
			view.GivenName = first
			if middle != "" {
				view.GivenName += " " + middle
			}
			view.Surname = last
		} else if n == "birthdate" {
			view.DateOfBirth = dateFromMs(toNumber(get(field, "v")) * 1000).formatDateString()
		} else if n == "issue_date" {
			view.IssueDate = dateFromMs(toNumber(get(field, "v")) * 1000).formatDateString()
		} else if n == "expiry_date" {
			view.ExpirationDate = dateFromMs(toNumber(get(field, "v")) * 1000).formatDateString()
		} else {
			return true
		}
		return false
	})
	cipher.Passport = view
}

var pifDriversLicenseFields = map[string]func(*model.DriversLicenseView, string){
	"number":  func(v *model.DriversLicenseView, s string) { v.LicenseNumber = s },
	"class":   func(v *model.DriversLicenseView, s string) { v.LicenseClass = s },
	"state":   func(v *model.DriversLicenseView, s string) { v.IssuingState = s },
	"country": func(v *model.DriversLicenseView, s string) { v.IssuingCountry = s },
}

func (i *PifImporter) processDriversLicense(item any, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeDriversLicense
	view := &model.DriversLicenseView{}
	filterSectionFields(item, func(field any) bool {
		n := fieldName(field)
		set, mapped := pifDriversLicenseFields[n]
		switch {
		case n == "fullname":
			view.FirstName, view.MiddleName, view.LastName = i.fullName(get(field, "v"))
		case n == "birthdate":
			view.DateOfBirth = dateFromMs(toNumber(get(field, "v")) * 1000).formatDateString()
		case n == "expiry_date":
			if v := get(field, "v"); !isNullish(v) {
				// A single number YYYYMM: the expiration date is the last day of that month.
				strValue := jsString(v)
				yearPart := sliceJS(strValue, 0, 4)
				monthPart := sliceJS(strValue, 4, -1)
				ms := dateUTC(toNumber(yearPart), toNumber(monthPart), 1) - 24*60*60*1000
				view.ExpirationDate = dateFromMs(ms).formatDateString()
			}
		case mapped:
			set(view, toStr(get(field, "v")))
		default:
			return true
		}
		return false
	})
	cipher.DriversLicense = view
}

// sliceJS is String.prototype.slice(start, end) on UTF-16 code units (end < 0: to the end).
func sliceJS(s string, start, end int) string {
	n := importer.Len16(s)
	if end < 0 || end > n {
		end = n
	}
	if start > end {
		return ""
	}
	return importer.Substring16(s, start, end)
}

// parsePasswordHistory is parsePasswordHistory (shared by the 1pif and 1pux importers).
func parsePasswordHistory(itemsVal any, cipher *model.CipherView) {
	items := array(itemsVal, "items")
	maxSize := len(items)
	if maxSize > 5 {
		maxSize = 5
	}
	var filtered []any
	for _, h := range items {
		if !isNOW(get(h, "value")) && !isNullish(get(h, "time")) {
			filtered = append(filtered, h)
		}
	}
	sort.SliceStable(filtered, func(a, b int) bool {
		// comparator (a, b) => b.time - a.time
		d := toNumber(get(filtered[b], "time")) - toNumber(get(filtered[a], "time"))
		return d < 0
	})
	if len(filtered) > maxSize {
		filtered = filtered[:maxSize]
	}
	history := []*model.PasswordHistoryView{}
	for _, h := range filtered {
		t := get(h, "time")
		var d jsDate
		if importer.Len16(jsString(t)) >= 13 {
			d = newDate(t)
		} else {
			d = dateFromMs(toNumber(t) * 1000)
		}
		ph := &model.PasswordHistoryView{Password: get(h, "value").(string)}
		if d.valid {
			ph.LastUsedDate = d.t
		} else {
			ph.LastUsedDate = time.Time{}
		}
		history = append(history, ph)
	}
	cipher.PasswordHistory = history
}

func (i *PifImporter) parseFields(fieldsVal any, cipher *model.CipherView, designationKey, valueKey, nameKey string) {
	for _, field := range array(fieldsVal, "fields") {
		raw := get(field, valueKey)
		if isNullish(raw) || importer.JSTrim(jsString(raw)) == "" {
			continue
		}

		// TODO upstream: store dates as a date field type once it exists.
		var fieldValue string
		if k, _ := get(field, "k").(string); k == "date" {
			fieldValue = dateFromMs(toNumber(raw) * 1000).toUTCString()
		} else {
			fieldValue = jsString(raw)
		}
		designation := get(field, designationKey)
		fieldDesignation, hasDesignation := "", !isNullish(designation)
		if hasDesignation {
			fieldDesignation = jsString(designation)
		}

		switch cipher.Type {
		case model.CipherTypeLogin:
			if i.IsNullOrWhitespace(cipher.Login.Username) && fieldDesignation == "username" {
				cipher.Login.Username = fieldValue
				continue
			} else if i.IsNullOrWhitespace(cipher.Login.Password) && fieldDesignation == "password" {
				cipher.Login.Password = fieldValue
				continue
			} else if i.IsNullOrWhitespace(cipher.Login.Totp) && hasDesignation && strings.HasPrefix(fieldDesignation, "TOTP_") {
				cipher.Login.Totp = fieldValue
				continue
			}
		case model.CipherTypeCard:
			if i.IsNullOrWhitespace(cipher.Card.Number) && fieldDesignation == "ccnum" {
				cipher.Card.Number = fieldValue
				cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
				continue
			} else if i.IsNullOrWhitespace(cipher.Card.Code) && fieldDesignation == "cvv" {
				cipher.Card.Code = fieldValue
				continue
			} else if i.IsNullOrWhitespace(cipher.Card.CardholderName) && fieldDesignation == "cardholder" {
				cipher.Card.CardholderName = fieldValue
				continue
			} else if cardExpirationEmpty(cipher.Card) && fieldDesignation == "expiry" && importer.Len16(fieldValue) == 6 {
				cipher.Card.ExpMonth = substr16(fieldValue, 4, 2)
				if strings.HasPrefix(cipher.Card.ExpMonth, "0") {
					cipher.Card.ExpMonth = substr16(cipher.Card.ExpMonth, 1, 1)
				}
				cipher.Card.ExpYear = substr16(fieldValue, 0, 4)
				continue
			} else if fieldDesignation == "type" {
				// Skip since brand was determined from number above
				continue
			}
		case model.CipherTypeIdentity:
			identity := cipher.Identity
			if i.IsNullOrWhitespace(identity.FirstName) && fieldDesignation == "firstname" {
				identity.FirstName = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.LastName) && fieldDesignation == "lastname" {
				identity.LastName = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.MiddleName) && fieldDesignation == "initial" {
				identity.MiddleName = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.Phone) && fieldDesignation == "defphone" {
				identity.Phone = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.Company) && fieldDesignation == "company" {
				identity.Company = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.Email) && fieldDesignation == "email" {
				identity.Email = fieldValue
				continue
			} else if i.IsNullOrWhitespace(identity.Username) && fieldDesignation == "username" {
				identity.Username = fieldValue
				continue
			} else if fieldDesignation == "address" {
				// fieldValue is an object cast into a string, so access the plain value instead
				street, city, country, zip := get(raw, "street"), get(raw, "city"), get(raw, "country"), get(raw, "zip")
				identity.Address1 = valueOrDefault(street)
				identity.City = valueOrDefault(city)
				if !isNOW(country) {
					identity.Country = strings.ToUpper(country.(string))
				}
				identity.PostalCode = valueOrDefault(zip)
				continue
			}
		}

		name := "no_name"
		if n := get(field, nameKey); !isNOW(n) {
			name = n.(string)
		}
		if name == "password" && cipher.PasswordHistory != nil && passwordInHistory(cipher, fieldValue) {
			continue
		}

		fieldType := model.FieldTypeText
		if k, _ := get(field, "k").(string); k == "concealed" {
			fieldType = model.FieldTypeHidden
		}
		i.ProcessKvp(cipher, name, fieldValue, fieldType)
	}
}

func passwordInHistory(cipher *model.CipherView, password string) bool {
	for _, h := range cipher.PasswordHistory {
		if h.Password == password {
			return true
		}
	}
	return false
}
