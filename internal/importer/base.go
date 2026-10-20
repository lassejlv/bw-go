package importer

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer/dom"
	"github.com/lassejlv/bw-go/internal/importer/model"
	"github.com/lassejlv/bw-go/internal/importer/papa"
)

// DefaultWarn receives warnings when Options.Warn is nil. Upstream BaseImporter logs through a
// ConsoleLogService, i.e. console.warn, which the Node CLI writes to stderr.
var DefaultWarn = func(msg string) { fmt.Fprintln(os.Stderr, msg) }

// Field-name lists from BaseImporter (passwordFieldNames, usernameFieldNames, notesFieldNames,
// uriFieldNames).
var (
	PasswordFieldNames = []string{
		"password", "pass word", "passphrase", "pass phrase", "pass", "code", "code word", "codeword",
		"secret", "secret word", "personpwd", "key", "keyword", "key word", "keyphrase", "key phrase",
		"form_pw", "wppassword", "pin", "pwd", "pw", "pword", "passwd", "p", "serial", "serial#",
		"license key", "reg #",
		// Non-English names
		"passwort",
	}
	UsernameFieldNames = []string{
		"user", "name", "user name", "username", "login name", "email", "e-mail", "id", "userid",
		"user id", "login", "form_loginname", "wpname", "mail", "loginid", "login id", "log",
		"personlogin", "first name", "last name", "card#", "account #", "member", "member #",
		// Non-English names
		"nom", "benutzername",
	}
	NotesFieldNames = []string{
		"note", "notes", "comment", "comments", "memo", "description", "free form", "freeform",
		"free text", "freetext", "free",
		// Non-English names
		"kommentar",
	}
	UriFieldNames = []string{
		"url", "hyper link", "hyperlink", "link", "host", "hostname", "host name", "server", "address",
		"hyper ref", "href", "web", "website", "web site", "site", "web-site", "uri",
		// Non-English names
		"ort", "adresse",
	}
)

// CsvOptions are the papaparse options an importer passes to parseCsv (the third argument). The
// Header field is ignored: ParseCsv implies header: true and ParseCsvRows header: false.
type CsvOptions = papa.Config

// CsvOptions.SkipEmptyLines values (papaparse skipEmptyLines: true / "greedy").
const (
	SkipEmptyLines       = papa.SkipEmpty
	SkipEmptyLinesGreedy = papa.SkipGreedy
)

// Record is one row of a header-mode CSV parse (the JS object papaparse returns).
type Record = papa.Record

// Base is the Go equivalent of BaseImporter. Embed it in every importer and construct it with
// NewBase(opts); `this.helper(...)` in TypeScript becomes `i.Helper(...)` in Go.
type Base struct {
	// OrganizationID is BaseImporter.organizationId ("" means null).
	OrganizationID string
	// Warn is logService.warning.
	Warn func(string)
}

// NewBase builds the embedded base from the constructor options.
func NewBase(opts Options) Base {
	return Base{OrganizationID: opts.OrganizationID, Warn: opts.Warn}
}

func (b *Base) warn(msg string) {
	if b.Warn != nil {
		b.Warn(msg)
		return
	}
	DefaultWarn(msg)
}

// Organization is the `organization` getter: organizationId != null.
func (b *Base) Organization() bool { return b.OrganizationID != "" }

var (
	entityDeclRe = regexp.MustCompile(`(?i)<!ENTITY`)
	doctypeRe    = regexp.MustCompile(`(?i)<!DOCTYPE[^>\[]*`)
	externalIDRe = regexp.MustCompile(`(?i)\b(?:SYSTEM|PUBLIC)\b`)
)

// ParseXml is BaseImporter.parseXml: nil when the document declares entities, references an
// external DTD, is not well-formed, or contains a <parsererror> element.
func (b *Base) ParseXml(data string) *dom.Node {
	if !validateNoExternalEntities(data) {
		return nil
	}
	doc, err := dom.ParseXML(data)
	if err != nil || doc.QuerySelector("parsererror") != nil {
		return nil
	}
	return doc
}

func validateNoExternalEntities(data string) bool {
	if entityDeclRe.MatchString(data) {
		return false
	}
	for _, m := range doctypeRe.FindAllString(data, -1) {
		if externalIDRe.MatchString(m) {
			return false
		}
	}
	return true
}

// ParseHtml is BaseImporter.parseHtml (lenient HTML parsing; never nil).
func (b *Base) ParseHtml(data string) *dom.Node { return dom.ParseHTML(data) }

func (b *Base) parseCsv(data string, header bool, opts *CsvOptions) papa.Result {
	cfg := papa.Config{}
	if opts != nil {
		cfg = *opts
	}
	cfg.Header = header
	data = JSTrim(strings.Join(SplitNewLine(data), "\n"))
	res := papa.Parse(data, cfg)
	for _, e := range res.Errors {
		if e.Row != nil {
			b.warn(fmt.Sprintf("Error parsing row %d: %s", *e.Row, e.Message))
		}
	}
	return res
}

// ParseCsv is parseCsv(data, true, options): header-mode rows, or nil when there are none.
func (b *Base) ParseCsv(data string, opts *CsvOptions) []Record {
	res := b.parseCsv(data, true, opts)
	if len(res.Records) == 0 {
		return nil
	}
	return res.Records
}

// ParseCsvRows is parseCsv(data, false, options): raw rows, or nil when there are none.
func (b *Base) ParseCsvRows(data string, opts *CsvOptions) [][]string {
	res := b.parseCsv(data, false, opts)
	if len(res.Rows) == 0 {
		return nil
	}
	return res.Rows
}

// ParseSingleRowCsv is BaseImporter.parseSingleRowCsv: the first row's fields, or nil.
func (b *Base) ParseSingleRowCsv(rowData string) []string {
	if IsNullOrWhitespace(rowData) {
		return nil
	}
	rows := b.ParseCsvRows(rowData, nil)
	if len(rows) > 0 && len(rows[0]) > 0 {
		return rows[0]
	}
	return nil
}

// MakeUriArray is BaseImporter.makeUriArray for both the string and the string[] form:
// MakeUriArray(u) / MakeUriArray(list...). Returns nil (null) when no URI survives FixUri.
func (b *Base) MakeUriArray(uris ...string) []*model.LoginUriView {
	var out []*model.LoginUriView
	for _, u := range uris {
		fixed := b.FixUri(u)
		if IsNullOrWhitespace(fixed) {
			continue
		}
		out = append(out, &model.LoginUriView{Uri: fixed})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FixUri is BaseImporter.fixUri: trims, prefixes "http://" to scheme-less URIs that contain a dot
// and caps the length at 1000 UTF-16 code units.
func (b *Base) FixUri(uri string) string {
	uri = JSTrim(uri)
	if !strings.Contains(uri, "://") && strings.Contains(uri, ".") {
		uri = "http://" + uri
	}
	if Len16(uri) > 1000 {
		return Substring16(uri, 0, 1000)
	}
	return uri
}

// NameFromUrl is BaseImporter.nameFromUrl: the hostname without a leading "www.", or "".
func (b *Base) NameFromUrl(url string) string {
	hostname := GetHostname(url)
	if IsNullOrWhitespace(hostname) {
		return ""
	}
	if strings.HasPrefix(hostname, "www.") {
		return strings.Replace(hostname, "www.", "", 1)
	}
	return hostname
}

// IsNullOrWhitespace is BaseImporter.isNullOrWhitespace.
func (b *Base) IsNullOrWhitespace(s string) bool { return IsNullOrWhitespace(s) }

// GetValueOrDefault is BaseImporter.getValueOrDefault(str, defaultValue = null).
func (b *Base) GetValueOrDefault(s string, defaultValue ...string) string {
	if IsNullOrWhitespace(s) {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return ""
	}
	return s
}

// SplitNewLine is BaseImporter.splitNewLine.
func (b *Base) SplitNewLine(s string) []string { return SplitNewLine(s) }

var expiryRe = regexp.MustCompile(`^0?(?P<month>[1-9]|1[0-2])/(?P<year>(?:[1-2][0-9])?[0-9]{2})$`)

// SetCardExpiration is BaseImporter.setCardExpiration ("MM/YY" or "MM/YYYY"). cipher.Card must be
// set.
func (b *Base) SetCardExpiration(cipher *model.CipherView, expiration string) bool {
	if IsNullOrWhitespace(expiration) {
		return false
	}
	expiration = RemoveJSWhitespace(expiration)
	m := expiryRe.FindStringSubmatch(expiration)
	if m == nil {
		return false
	}
	if cipher.Card == nil {
		cipher.Card = &model.CardView{}
	}
	cipher.Card.ExpMonth = m[expiryRe.SubexpIndex("month")]
	cipher.Card.ExpYear = NormalizeExpiryYearFormat(m[expiryRe.SubexpIndex("year")])
	return true
}

// GetCardBrand is CardView.getCardBrandByPatterns.
func (b *Base) GetCardBrand(cardNum string) string { return model.GetCardBrandByPatterns(cardNum) }

// MoveFoldersToCollections is BaseImporter.moveFoldersToCollections.
func (b *Base) MoveFoldersToCollections(result *model.ImportResult) {
	result.CollectionRelationships = append(result.CollectionRelationships, result.FolderRelationships...)
	cols := make([]*model.CollectionView, 0, len(result.Folders))
	for _, f := range result.Folders {
		cols = append(cols, &model.CollectionView{Name: f.Name, OrganizationID: b.OrganizationID, ID: f.ID})
	}
	result.Collections = cols
	result.FolderRelationships = []model.Relationship{}
	result.Folders = []*model.FolderView{}
}

// QuerySelectorDirectChild is BaseImporter.querySelectorDirectChild.
func (b *Base) QuerySelectorDirectChild(parent *dom.Node, query string) *dom.Node {
	return parent.QuerySelectorDirectChild(query)
}

// QuerySelectorAllDirectChild is BaseImporter.querySelectorAllDirectChild.
func (b *Base) QuerySelectorAllDirectChild(parent *dom.Node, query string) []*dom.Node {
	return parent.QuerySelectorAllDirectChild(query)
}

// InitLoginCipher is BaseImporter.initLoginCipher.
func (b *Base) InitLoginCipher() *model.CipherView {
	c := model.NewCipherView()
	c.Favorite = false
	c.Notes = ""
	c.Fields = []*model.FieldView{}
	c.Login = &model.LoginView{}
	c.Type = model.CipherTypeLogin
	return c
}

// CleanupCipher is BaseImporter.cleanupCipher.
func (b *Base) CleanupCipher(cipher *model.CipherView) {
	if cipher == nil {
		return
	}
	if cipher.Type != model.CipherTypeLogin {
		cipher.Login = nil
	}
	if IsNullOrWhitespace(cipher.Name) {
		cipher.Name = "--"
	}
	if IsNullOrWhitespace(cipher.Notes) {
		cipher.Notes = ""
	}
}

// ProcessKvp is BaseImporter.processKvp(cipher, key, value, type = FieldType.Text): long or
// multi-line values are appended to the notes, others become custom fields.
func (b *Base) ProcessKvp(cipher *model.CipherView, key, value string, fieldType ...model.FieldType) {
	if IsNullOrWhitespace(value) {
		return
	}
	if IsNullOrWhitespace(key) {
		key = ""
	}
	if Len16(value) > 200 || ContainsNewLine(JSTrim(value)) {
		cipher.Notes += key + ": " + strings.Join(SplitNewLine(value), "\n") + "\n"
		return
	}
	t := model.FieldTypeText
	if len(fieldType) > 0 {
		t = fieldType[0]
	}
	cipher.Fields = append(cipher.Fields, &model.FieldView{Type: t, Name: key, Value: value})
}

var leadingSlashes = regexp.MustCompile(`^/+`)

// ProcessFolder is BaseImporter.processFolder(result, folderName, addRelationship = true).
func (b *Base) ProcessFolder(result *model.ImportResult, folderName string, addRelationship ...bool) {
	if IsNullOrWhitespace(folderName) {
		return
	}
	folderIndex := len(result.Folders)
	folderName = leadingSlashes.ReplaceAllString(strings.ReplaceAll(folderName, `\`, "/"), "")
	addFolder := true
	for i, f := range result.Folders {
		if f.Name == folderName {
			addFolder = false
			folderIndex = i
			break
		}
	}
	if addFolder {
		result.Folders = append(result.Folders, &model.FolderView{Name: folderName})
	}
	if len(addRelationship) == 0 || addRelationship[0] {
		result.FolderRelationships = append(result.FolderRelationships, model.Relationship{len(result.Ciphers), folderIndex})
	}
	parts := strings.Split(folderName, "/")
	for i := len(parts) - 1; i > 0; i-- {
		parentName := strings.Join(parts[:i], "/")
		found := false
		for _, f := range result.Folders {
			if f.Name == parentName {
				found = true
				break
			}
		}
		if !found {
			result.Folders = append(result.Folders, &model.FolderView{Name: parentName})
		}
	}
}

// ConvertToNoteIfNeeded is BaseImporter.convertToNoteIfNeeded.
func (b *Base) ConvertToNoteIfNeeded(cipher *model.CipherView) {
	if cipher.Type == model.CipherTypeLogin && (cipher.Login == nil ||
		(IsNullOrWhitespace(cipher.Login.Username) && IsNullOrWhitespace(cipher.Login.Password) && len(cipher.Login.Uris) == 0)) {
		cipher.Type = model.CipherTypeSecureNote
		cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
	}
}

// ProcessFullName is BaseImporter.processFullName: splits fullName into cipher.Identity's first,
// middle and last name.
func (b *Base) ProcessFullName(cipher *model.CipherView, fullName string) {
	first, middle, last := b.GetFullName(fullName)
	if cipher.Identity == nil {
		cipher.Identity = &model.IdentityView{}
	}
	if !IsNullOrWhitespace(first) {
		cipher.Identity.FirstName = first
	}
	if !IsNullOrWhitespace(middle) {
		cipher.Identity.MiddleName = middle
	}
	if !IsNullOrWhitespace(last) {
		cipher.Identity.LastName = last
	}
}

// GetFullName is BaseImporter.getFullName: [first, middle, last] ("" for undefined).
func (b *Base) GetFullName(fullName string) (first, middle, last string) {
	if IsNullOrWhitespace(fullName) {
		return "", "", ""
	}
	parts := strings.Split(fullName, " ")
	first = b.GetValueOrDefault(parts[0])
	if len(parts) == 2 {
		last = b.GetValueOrDefault(parts[1])
	} else if len(parts) >= 3 {
		middle = b.GetValueOrDefault(parts[1])
		last = strings.Join(parts[2:], " ")
	}
	return first, middle, last
}

// ParseDateString is BaseImporter.parseDateString: `new Date(s)` formatted as YYYY-MM-DD (UTC),
// or "" for an invalid date.
func (b *Base) ParseDateString(dateString string) string {
	t, ok := ParseJSDate(dateString)
	if !ok {
		return ""
	}
	return FormatDateString(t)
}

// FormatDateString is BaseImporter.formatDateString ("" for a nil date).
func (b *Base) FormatDateString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return FormatDateString(*t)
}

// ProcessBankAccountType is BaseImporter.processBankAccountType.
func (b *Base) ProcessBankAccountType(t string) string {
	if t == "" {
		return model.BankAccountTypeOther
	}
	for _, v := range []string{
		model.BankAccountTypeCertificateOfDeposit, model.BankAccountTypeChecking,
		model.BankAccountTypeInvestmentBrokerage, model.BankAccountTypeLineOfCredit,
		model.BankAccountTypeMoneyMarket, model.BankAccountTypeSavings,
	} {
		if strings.ToLower(t) == strings.ToLower(v) {
			return v
		}
	}
	return model.BankAccountTypeOther
}
