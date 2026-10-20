package onepassword

import (
	"regexp"
	"strings"
	"sync"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Port of onepassword-csv-importer.ts (the shared OnePasswordCsvImporter base),
// cipher-import-context.ts, onepassword-mac-csv-importer.ts and onepassword-win-csv-importer.ts.

func init() {
	importer.Register("1passwordwincsv", NewWinCsv)
	importer.Register("1passwordmaccsv", NewMacCsv)
}

// IgnoredProperties is the module-level array exported by onepassword-csv-importer.ts. The Mac
// importer pushes "type" into it (and never removes it), so – exactly like upstream – once a Mac
// CSV with a known item type has been parsed, "type" stays ignored for every later 1Password CSV
// parse in the process.
var (
	ignoredMu         sync.Mutex
	IgnoredProperties = []string{
		"ainfo", "autosubmit", "notesplain", "ps", "scope", "tags", "title", "uuid", "notes",
	}
)

func pushIgnoredProperty(p string) {
	ignoredMu.Lock()
	defer ignoredMu.Unlock()
	IgnoredProperties = append(IgnoredProperties, p)
}

func isIgnoredProperty(p string) bool {
	ignoredMu.Lock()
	defer ignoredMu.Unlock()
	for _, v := range IgnoredProperties {
		if v == p {
			return true
		}
	}
	return false
}

// cipherImportContext is cipher-import-context.ts.
type cipherImportContext struct {
	importRecord  importer.Record
	property      string
	lowerProperty string
	cipher        *model.CipherView
}

func newCipherImportContext(rec importer.Record, property string, cipher *model.CipherView) *cipherImportContext {
	return &cipherImportContext{importRecord: rec, property: property, lowerProperty: strings.ToLower(property), cipher: cipher}
}

func (c *cipherImportContext) value() string { return c.importRecord.Get(c.property) }

type propertyParser func(*cipherImportContext) bool

// CsvImporter is the abstract OnePasswordCsvImporter with its variant hooks.
type CsvImporter struct {
	importer.Base
	setCipherType             func(value importer.Record, cipher *model.CipherView)
	loginPropertyParsers      []propertyParser
	creditCardPropertyParsers []propertyParser
	identityPropertyParsers   []propertyParser
}

func newCsvImporter(opts importer.Options) *CsvImporter {
	i := &CsvImporter{Base: importer.NewBase(opts)}
	i.loginPropertyParsers = []propertyParser{i.setLoginUsername, i.setLoginPassword, i.setLoginUris}
	i.creditCardPropertyParsers = []propertyParser{
		i.setCreditCardNumber, i.setCreditCardVerification, i.setCreditCardCardholderName, i.setCreditCardExpiry,
	}
	i.identityPropertyParsers = []propertyParser{
		i.setIdentityFirstName, i.setIdentityInitial, i.setIdentityLastName, i.setIdentityUserName,
		i.setIdentityEmail, i.setIdentityPhone, i.setIdentityCompany,
	}
	return i
}

// NewMacCsv is OnePasswordMacCsvImporter.
func NewMacCsv(opts importer.Options) importer.Importer {
	i := newCsvImporter(opts)
	i.setCipherType = i.macSetCipherType
	return i
}

// NewWinCsv is OnePasswordWinCsvImporter: its constructor appends setIdentityAddress and its
// setCreditCardExpiry override replaces the base one (the base class resolves
// `this.setCreditCardExpiry` to the subclass method).
func NewWinCsv(opts importer.Options) importer.Importer {
	i := newCsvImporter(opts)
	i.setCipherType = i.winSetCipherType
	i.creditCardPropertyParsers[3] = i.winSetCreditCardExpiry
	i.identityPropertyParsers = append(i.identityPropertyParsers, i.setIdentityAddress)
	return i
}

// Parse is OnePasswordCsvImporter.parse.
func (i *CsvImporter) Parse(data string) (result *model.ImportResult, err error) {
	defer catch(&err)
	result = model.NewImportResult()
	esc := `\`
	results := i.ParseCsv(data, &importer.CsvOptions{QuoteChar: `"`, EscapeChar: &esc})
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		if i.IsNullOrWhitespace(i.getProp(value, "title")) {
			continue
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(i.getProp(value, "title"), "--")

		i.setNotes(value, cipher)

		i.setCipherType(value, cipher)

		altUsername := ""
		for _, property := range value.Keys() {
			if i.IsNullOrWhitespace(value.Get(property)) {
				continue
			}

			context := newCipherImportContext(value, property, cipher)
			if cipher.Type == model.CipherTypeLogin && i.setKnownValue(i.loginPropertyParsers, context) {
				continue
			} else if cipher.Type == model.CipherTypeCard && i.setKnownValue(i.creditCardPropertyParsers, context) {
				continue
			} else if cipher.Type == model.CipherTypeIdentity && i.setKnownValue(i.identityPropertyParsers, context) {
				continue
			}

			altUsername = i.setUnknownValue(context, altUsername)
		}

		if cipher.Type == model.CipherTypeLogin &&
			!i.IsNullOrWhitespace(altUsername) &&
			i.IsNullOrWhitespace(cipher.Login.Username) &&
			!strings.Contains(altUsername, "://") {
			cipher.Login.Username = altUsername
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// getProp: case-insensitive property lookup (the last key with a matching lower-case name wins).
func (i *CsvImporter) getProp(obj importer.Record, name string) string {
	lower := strings.ToLower(name)
	out := ""
	for _, k := range obj.Keys() {
		if strings.ToLower(k) == lower {
			out = obj.Get(k)
		}
	}
	return out
}

// getPropByRegexp returns the value of the first key matching re ("" for null).
func (i *CsvImporter) getPropByRegexp(obj importer.Record, re *regexp.Regexp) string {
	for _, k := range obj.Keys() {
		if re.MatchString(k) {
			return obj.Get(k)
		}
	}
	return ""
}

// getPropIncluding returns the value of the first key containing name (case-insensitive).
func (i *CsvImporter) getPropIncluding(obj importer.Record, name string) string {
	lower := strings.ToLower(name)
	for _, k := range obj.Keys() {
		if strings.Contains(strings.ToLower(k), lower) {
			return obj.Get(k)
		}
	}
	return ""
}

func (i *CsvImporter) setNotes(importRecord importer.Record, cipher *model.CipherView) {
	cipher.Notes = i.GetValueOrDefault(i.getProp(importRecord, "notesPlain"), "") + "\n" +
		i.GetValueOrDefault(i.getProp(importRecord, "notes"), "") + "\n"
	// cipher.notes.trim() – the result is discarded upstream.
}

func (i *CsvImporter) setKnownValue(parsers []propertyParser, context *cipherImportContext) bool {
	for _, f := range parsers {
		if f(context) {
			return true
		}
	}
	return false
}

func (i *CsvImporter) setUnknownValue(context *cipherImportContext, altUsername string) string {
	if !isIgnoredProperty(context.lowerProperty) &&
		!strings.HasPrefix(context.lowerProperty, "section:") &&
		!strings.HasPrefix(context.lowerProperty, "section ") {
		if altUsername == "" && context.lowerProperty == "email" {
			return context.value()
		} else if context.lowerProperty == "created date" || context.lowerProperty == "modified date" {
			readableDate := jsDate{}
			if n, ok := importer.ParseInt(context.value()); ok {
				readableDate = dateFromMs(float64(n) * 1000)
			}
			i.ProcessKvp(context.cipher, "1Password "+context.property, readableDate.toUTCString())
			return ""
		}
		if strings.Contains(context.lowerProperty, "password") ||
			strings.Contains(context.lowerProperty, "key") ||
			strings.Contains(context.lowerProperty, "secret") {
			i.ProcessKvp(context.cipher, context.property, context.value(), model.FieldTypeHidden)
		} else {
			i.ProcessKvp(context.cipher, context.property, context.value())
		}
	}
	return ""
}

func (i *CsvImporter) setIdentityFirstName(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.FirstName) && strings.Contains(c.lowerProperty, "first name") {
		c.cipher.Identity.FirstName = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityInitial(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.MiddleName) && strings.Contains(c.lowerProperty, "initial") {
		c.cipher.Identity.MiddleName = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityLastName(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.LastName) && strings.Contains(c.lowerProperty, "last name") {
		c.cipher.Identity.LastName = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityUserName(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.Username) && strings.Contains(c.lowerProperty, "username") {
		c.cipher.Identity.Username = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityCompany(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.Company) && strings.Contains(c.lowerProperty, "company") {
		c.cipher.Identity.Company = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityPhone(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.Phone) && strings.Contains(c.lowerProperty, "default phone") {
		c.cipher.Identity.Phone = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setIdentityEmail(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Identity.Email) && strings.Contains(c.lowerProperty, "email") {
		c.cipher.Identity.Email = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setCreditCardNumber(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Card.Number) && strings.Contains(c.lowerProperty, "number") {
		c.cipher.Card.Number = c.value()
		c.cipher.Card.Brand = model.GetCardBrandByPatterns(c.cipher.Card.Number)
		return true
	}
	return false
}

func (i *CsvImporter) setCreditCardVerification(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Card.Code) && strings.Contains(c.lowerProperty, "verification number") {
		c.cipher.Card.Code = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setCreditCardCardholderName(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Card.CardholderName) && strings.Contains(c.lowerProperty, "cardholder name") {
		c.cipher.Card.CardholderName = c.value()
		return true
	}
	return false
}

// cardExpirationEmpty is isNullOrWhitespace(card.expiration) (the CardView getter is undefined
// only when there is neither a month nor a normalized year).
func cardExpirationEmpty(card *model.CardView) bool {
	return card.ExpMonth == "" && importer.NormalizeExpiryYearFormat(card.ExpYear) == ""
}

func (i *CsvImporter) setCreditCardExpiry(c *cipherImportContext) bool {
	v := c.value()
	if cardExpirationEmpty(c.cipher.Card) && strings.Contains(c.lowerProperty, "expiry date") && importer.Len16(v) == 7 {
		c.cipher.Card.ExpMonth = substr16(v, 0, 2)
		if strings.HasPrefix(c.cipher.Card.ExpMonth, "0") {
			c.cipher.Card.ExpMonth = substr16(c.cipher.Card.ExpMonth, 1, 1)
		}
		c.cipher.Card.ExpYear = substr16(v, 3, 4)
		return true
	}
	return false
}

func (i *CsvImporter) setLoginPassword(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Login.Password) && c.lowerProperty == "password" {
		c.cipher.Login.Password = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setLoginUsername(c *cipherImportContext) bool {
	if i.IsNullOrWhitespace(c.cipher.Login.Username) && c.lowerProperty == "username" {
		c.cipher.Login.Username = c.value()
		return true
	}
	return false
}

func (i *CsvImporter) setLoginUris(c *cipherImportContext) bool {
	if len(c.cipher.Login.Uris) == 0 && c.lowerProperty == "urls" {
		urls := i.SplitNewLine(c.value())
		c.cipher.Login.Uris = i.MakeUriArray(urls...)
		return true
	} else if c.lowerProperty == "url" {
		if c.cipher.Login.Uris == nil {
			c.cipher.Login.Uris = []*model.LoginUriView{}
		}
		// uris.concat(...) – the result is discarded upstream, so nothing is added.
		return true
	}
	return false
}

// --- Mac ---

func (i *CsvImporter) macSetCipherType(value importer.Record, cipher *model.CipherView) {
	onePassType := i.GetValueOrDefault(i.getProp(value, "type"), "Login")
	switch onePassType {
	case "Credit Card":
		cipher.Type = model.CipherTypeCard
		cipher.Card = &model.CardView{}
		pushIgnoredProperty("type")
	case "Identity":
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
		pushIgnoredProperty("type")
	case "Login", "Secure Note":
		pushIgnoredProperty("type")
	}
}

// --- Windows ---

var (
	reWinNumber     = regexp.MustCompile(`(?i)\d+: number`)
	reWinExpiry     = regexp.MustCompile(`(?i)\d+: expiry date`)
	reWinFirstName  = regexp.MustCompile(`(?i)name \d+: first name`)
	reWinInitial    = regexp.MustCompile(`(?i)name \d+: initial`)
	reWinLastName   = regexp.MustCompile(`(?i)name \d+: last name`)
	reWinEmail      = regexp.MustCompile(`(?i)internet \d+: email`)
	reWinAddressKey = regexp.MustCompile(`(?i)address \d+: address`)
)

func (i *CsvImporter) winSetCipherType(value importer.Record, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeLogin
	cipher.Login = &model.LoginView{}

	if !i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinNumber)) &&
		!i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinExpiry)) {
		cipher.Type = model.CipherTypeCard
		cipher.Card = &model.CardView{}
	}

	if !i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinFirstName)) ||
		!i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinInitial)) ||
		!i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinLastName)) ||
		!i.IsNullOrWhitespace(i.getPropByRegexp(value, reWinEmail)) {
		cipher.Type = model.CipherTypeIdentity
		cipher.Identity = &model.IdentityView{}
	}
}

func (i *CsvImporter) setIdentityAddress(c *cipherImportContext) bool {
	if reWinAddressKey.MatchString(c.lowerProperty) {
		i.ProcessKvp(c.cipher, "address", c.value())
		return true
	}
	return false
}

func (i *CsvImporter) winSetCreditCardExpiry(c *cipherImportContext) bool {
	if cardExpirationEmpty(c.cipher.Card) && strings.Contains(c.lowerProperty, "expiry date") {
		expSplit := strings.Split(c.value(), "/")
		c.cipher.Card.ExpMonth = expSplit[0]
		if strings.HasPrefix(c.cipher.Card.ExpMonth, "0") && importer.Len16(c.cipher.Card.ExpMonth) == 2 {
			c.cipher.Card.ExpMonth = substr16(c.cipher.Card.ExpMonth, 1, 1)
		}
		if len(expSplit) < 3 {
			throwTypeError("Cannot read properties of undefined (reading 'length')")
		}
		if importer.Len16(expSplit[2]) > 4 {
			c.cipher.Card.ExpYear = substr16(expSplit[2], 0, 4)
		} else {
			c.cipher.Card.ExpYear = expSplit[2]
		}
		return true
	}
	return false
}

// substr16 is String.prototype.substr(start, length) on UTF-16 code units.
func substr16(s string, start, length int) string {
	n := importer.Len16(s)
	if start > n {
		return ""
	}
	end := start + length
	if end > n {
		end = n
	}
	return importer.Substring16(s, start, end)
}
