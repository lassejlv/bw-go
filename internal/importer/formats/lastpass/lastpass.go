// Package lastpass ports libs/importer/src/importers/lastpass/lastpass-csv-importer.ts (format ids
// "lastpasscsv" and "passboltcsv", which upstream maps to the same importer).
package lastpass

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
	"github.com/lassejlv/bw-go/internal/importer/papa"
)

func init() {
	importer.Register("lastpasscsv", New)
	importer.Register("passboltcsv", New)
}

// Importer is LastPassCsvImporter.
type Importer struct {
	importer.Base
	features importer.Features
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts), features: opts.Features}
}

var controlChars = regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`)

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	useNewDedicatedTypes := i.features.NewItemTypes
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		cipherIndex := len(result.Ciphers)
		folderIndex := len(result.Folders)
		grouping, hasGrouping := value.Lookup("grouping")
		if hasGrouping {
			grouping = controlChars.ReplaceAllString(strings.ReplaceAll(grouping, `\`, "/"), "")
		}
		hasFolder := i.GetValueOrDefault(grouping, "(none)") != "(none)"
		addFolder := hasFolder

		if hasFolder {
			for idx, f := range result.Folders {
				if f.Name == grouping {
					addFolder = false
					folderIndex = idx
					break
				}
			}
		}

		cipher := i.buildBaseCipher(value)
		switch cipher.Type {
		case model.CipherTypeLogin:
			cipher.Notes = i.GetValueOrDefault(value.Get("extra"))
			cipher.Login = &model.LoginView{}
			cipher.Login.Uris = i.MakeUriArray(value.Get("url"))
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
			cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
			cipher.Login.Totp = i.GetValueOrDefault(value.Get("totp"))
		case model.CipherTypeSecureNote:
			i.parseSecureNote(value, cipher, useNewDedicatedTypes)
		case model.CipherTypeCard:
			cipher.Card = i.parseCard(value)
			cipher.Notes = i.GetValueOrDefault(value.Get("notes"))
		case model.CipherTypeIdentity:
			cipher.Identity = i.parseIdentity(value)
			cipher.Notes = i.GetValueOrDefault(value.Get("notes"))
			if !i.IsNullOrWhitespace(value.Get("ccnum")) {
				// there is a card on this identity too
				cardCipher := i.buildBaseCipher(value)
				cardCipher.Identity = nil
				cardCipher.Type = model.CipherTypeCard
				cardCipher.Card = i.parseCard(value)
				result.Ciphers = append(result.Ciphers, cardCipher)
			}
		}

		result.Ciphers = append(result.Ciphers, cipher)

		if addFolder {
			result.Folders = append(result.Folders, &model.FolderView{Name: grouping})
		}
		if hasFolder {
			result.FolderRelationships = append(result.FolderRelationships, model.Relationship{cipherIndex, folderIndex})
		}
	}

	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}
	result.Success = true
	return result, nil
}

func (i *Importer) buildBaseCipher(value papa.Record) *model.CipherView {
	cipher := model.NewCipherView()
	if value.Has("profilename") && value.Has("profilelanguage") {
		// form fill
		cipher.Favorite = false
		cipher.Name = i.GetValueOrDefault(value.Get("profilename"), "--")
		cipher.Type = model.CipherTypeCard
		for _, k := range []string{"title", "firstname", "lastname", "address1", "phone", "username", "email"} {
			if !i.IsNullOrWhitespace(value.Get(k)) {
				cipher.Type = model.CipherTypeIdentity
				break
			}
		}
	} else {
		// site or secure note
		cipher.Favorite = !i.Organization() && i.GetValueOrDefault(value.Get("fav"), "0") == "1"
		cipher.Name = i.GetValueOrDefault(value.Get("name"), "--")
		if value.Get("url") == "http://sn" {
			cipher.Type = model.CipherTypeSecureNote
		} else {
			cipher.Type = model.CipherTypeLogin
		}
	}
	return cipher
}

func (i *Importer) parseCard(value papa.Record) *model.CardView {
	card := &model.CardView{}
	card.CardholderName = i.GetValueOrDefault(value.Get("ccname"))
	card.Number = i.GetValueOrDefault(value.Get("ccnum"))
	card.Code = i.GetValueOrDefault(value.Get("cccsc"))
	card.Brand = i.GetCardBrand(card.Number)

	ccexp := value.Get("ccexp")
	if !i.IsNullOrWhitespace(ccexp) && strings.Contains(ccexp, "-") {
		parts := strings.Split(ccexp, "-")
		if len(parts) > 1 {
			card.ExpYear = parts[0]
			card.ExpMonth = parts[1]
			if len(card.ExpMonth) == 2 && card.ExpMonth[0] == '0' {
				card.ExpMonth = card.ExpMonth[1:]
			}
		}
	}
	return card
}

func (i *Importer) parseIdentity(value papa.Record) *model.IdentityView {
	g := func(k string) string { return i.GetValueOrDefault(value.Get(k)) }
	id := &model.IdentityView{
		Title:      g("title"),
		FirstName:  g("firstname"),
		MiddleName: g("middlename"),
		LastName:   g("lastname"),
		Username:   g("username"),
		Company:    g("company"),
		Ssn:        g("ssn"),
		Address1:   g("address1"),
		Address2:   g("address2"),
		Address3:   g("address3"),
		City:       g("city"),
		State:      g("state"),
		PostalCode: g("zip"),
		Country:    g("country"),
		Email:      g("email"),
		Phone:      g("phone"),
	}
	if !i.IsNullOrWhitespace(id.Title) {
		r := []rune(id.Title)
		id.Title = string(unicode.ToUpper(r[0])) + string(r[1:])
	}
	return id
}

func (i *Importer) parseSecureNote(value papa.Record, cipher *model.CipherView, useNewDedicatedTypes bool) {
	extraParts := i.SplitNewLine(value.Get("extra"))
	processedNote := false

	if len(extraParts) > 0 {
		typeParts := strings.Split(extraParts[0], ":")
		typeName := ""
		if len(typeParts) > 1 {
			typeName = typeParts[1]
		}
		isNoteType := typeParts[0] == "NoteType"

		if len(typeParts) > 1 && isNoteType && (typeName == "Credit Card" || typeName == "Address") {
			if typeName == "Credit Card" {
				m := i.parseSecureNoteMapping(cipher, extraParts, map[string]string{
					"Number":        "number",
					"Name on Card":  "cardholderName",
					"Security Code": "code",
					// LP provides date in a format like 'June,2020'; store in expMonth, then parse.
					"Expiration Date": "expMonth",
				})
				card := &model.CardView{Number: m["number"], CardholderName: m["cardholderName"], Code: m["code"]}
				expMonth, hasExp := m["expMonth"]
				if !hasExp || i.IsNullOrWhitespace(expMonth) || expMonth == "," {
					card.ExpMonth = ""
				} else {
					parts := strings.Split(expMonth, ",")
					monthString := parts[0]
					if !i.IsNullOrWhitespace(monthString) {
						card.ExpMonth = getMonthNumberFromName(monthString)
					}
					if len(parts) > 1 && !i.IsNullOrWhitespace(parts[1]) {
						card.ExpYear = parts[1]
					}
				}
				cipher.Type = model.CipherTypeCard
				cipher.Card = card
			} else {
				m := i.parseSecureNoteMapping(cipher, extraParts, map[string]string{
					"Title":             "title",
					"First Name":        "firstName",
					"Last Name":         "lastName",
					"Middle Name":       "middleName",
					"Company":           "company",
					"Address 1":         "address1",
					"Address 2":         "address2",
					"Address 3":         "address3",
					"City / Town":       "city",
					"State":             "state",
					"Zip / Postal Code": "postalCode",
					"Country":           "country",
					"Email Address":     "email",
					"Username":          "username",
				})
				cipher.Type = model.CipherTypeIdentity
				cipher.Identity = &model.IdentityView{
					Title: m["title"], FirstName: m["firstName"], LastName: m["lastName"],
					MiddleName: m["middleName"], Company: m["company"], Address1: m["address1"],
					Address2: m["address2"], Address3: m["address3"], City: m["city"], State: m["state"],
					PostalCode: m["postalCode"], Country: m["country"], Email: m["email"], Username: m["username"],
				}
			}
			processedNote = true
		}

		if useNewDedicatedTypes && isNoteType && typeName == "Bank Account" {
			m := i.parseSecureNoteMapping(cipher, extraParts, map[string]string{
				"Bank Name":      "bankName",
				"Account Type":   "accountType",
				"Routing Number": "routingNumber",
				"Account Number": "accountNumber",
				"SWIFT Code":     "swiftCode",
				"IBAN Number":    "iban",
				"Pin":            "pin",
				"Branch Phone":   "bankContactPhone",
			})
			cipher.Type = model.CipherTypeBankAccount
			cipher.BankAccount = &model.BankAccountView{
				BankName: m["bankName"], AccountType: i.ProcessBankAccountType(m["accountType"]),
				RoutingNumber: m["routingNumber"], AccountNumber: m["accountNumber"],
				SwiftCode: m["swiftCode"], Iban: m["iban"], Pin: m["pin"], BankContactPhone: m["bankContactPhone"],
			}
			processedNote = true
		}

		if useNewDedicatedTypes && isNoteType && typeName == "Passport" {
			m := i.parseSecureNoteMapping(cipher, extraParts, map[string]string{
				"Type":              "passportType",
				"Name":              "givenName", // full name, split below
				"Country":           "issuingCountry",
				"Number":            "passportNumber",
				"Nationality":       "nationality",
				"Issuing Authority": "issuingAuthority",
				"Date of Birth":     "dateOfBirth", // 'June,20,2020'
				"Issued Date":       "issueDate",
				"Expiration Date":   "expirationDate",
			})
			p := &model.PassportView{
				PassportType: m["passportType"], GivenName: m["givenName"], IssuingCountry: m["issuingCountry"],
				PassportNumber: m["passportNumber"], Nationality: m["nationality"], IssuingAuthority: m["issuingAuthority"],
			}
			if !i.IsNullOrWhitespace(p.GivenName) {
				first, middle, last := i.GetFullName(p.GivenName)
				p.GivenName = first
				if middle != "" {
					p.GivenName += " " + middle
				}
				p.Surname = last
			}
			p.DateOfBirth = i.FormatDateString(i.parseFullDate(m["dateOfBirth"]))
			p.IssueDate = i.FormatDateString(i.parseFullDate(m["issueDate"]))
			p.ExpirationDate = i.FormatDateString(i.parseFullDate(m["expirationDate"]))
			cipher.Type = model.CipherTypePassport
			cipher.Passport = p
			processedNote = true
		}

		if useNewDedicatedTypes && isNoteType && typeName == "Driver's License" {
			m := i.parseSecureNoteMapping(cipher, extraParts, map[string]string{
				"Number":          "licenseNumber",
				"Expiration Date": "expirationDate", // 'June,20,2020'
				"License Class":   "licenseClass",
				"Name":            "firstName", // full name, split below
				"State":           "issuingState",
				"Country":         "issuingCountry",
				"Date of Birth":   "dateOfBirth",
			})
			dl := &model.DriversLicenseView{
				LicenseNumber: m["licenseNumber"], LicenseClass: m["licenseClass"],
				IssuingState: m["issuingState"], IssuingCountry: m["issuingCountry"],
			}
			dl.ExpirationDate = i.FormatDateString(i.parseFullDate(m["expirationDate"]))
			dl.FirstName, dl.MiddleName, dl.LastName = i.GetFullName(m["firstName"])
			dl.DateOfBirth = i.FormatDateString(i.parseFullDate(m["dateOfBirth"]))
			cipher.Type = model.CipherTypeDriversLicense
			cipher.DriversLicense = dl
			processedNote = true
		}
	}

	if !processedNote {
		cipher.SecureNote = &model.SecureNoteView{Type: model.SecureNoteTypeGeneric}
		cipher.Notes = i.GetValueOrDefault(value.Get("extra"))
	}
}

// parseFullDate takes "<month name>,<day>,<year>" (e.g. "June,20,2020"); nil when a part is
// missing.
func (i *Importer) parseFullDate(dateString string) *time.Time {
	if i.IsNullOrWhitespace(dateString) {
		return nil
	}
	parts := strings.Split(dateString, ",")
	month := getMonthNumberFromName(parts[0])
	if month == "" || len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return nil
	}
	year, okY := jsNumber(parts[2])
	mon, _ := strconv.Atoi(month)
	day, okD := jsNumber(parts[1])
	if !okY || !okD {
		return nil
	}
	// Date.UTC maps years 0-99 to 1900-1999.
	if year >= 0 && year <= 99 {
		year += 1900
	}
	t := time.Date(year, time.Month(mon), day, 0, 0, 0, 0, time.UTC)
	return &t
}

// jsNumber is Number(s) for integer strings (whitespace-trimmed); fractional or non-numeric input
// is reported as NaN.
func jsNumber(s string) (int, bool) {
	s = importer.JSTrim(s)
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// getMonthNumberFromName is new Date(Date.parse(name.trim() + " 1, 2012")).getMonth() + 1, as a
// string ("" for NaN).
func getMonthNumberFromName(monthNameString string) string {
	t, ok := importer.ParseJSDate(importer.JSTrim(monthNameString) + " 1, 2012")
	if !ok {
		return ""
	}
	return strconv.Itoa(int(t.In(time.Local).Month()))
}

// parseSecureNoteMapping parses "<key>:<value>" lines; keys in m are mapped to properties, a
// "Notes" key starts the free-text notes and everything else becomes a custom field.
func (i *Importer) parseSecureNoteMapping(cipher *model.CipherView, extraParts []string, m map[string]string) map[string]string {
	data := map[string]string{}
	processingNotes := false
	for _, extraPart := range extraParts {
		key, val := "", ""
		if !processingNotes {
			if i.IsNullOrWhitespace(extraPart) {
				continue
			}
			colon := strings.Index(extraPart, ":")
			if colon == -1 {
				key = extraPart
			} else {
				key = extraPart[:colon]
				val = extraPart[colon+1:]
			}
			if i.IsNullOrWhitespace(key) || i.IsNullOrWhitespace(val) || key == "NoteType" {
				continue
			}
		}

		if processingNotes {
			cipher.Notes += "\n" + extraPart
		} else if key == "Notes" {
			if !i.IsNullOrWhitespace(cipher.Notes) {
				cipher.Notes += "\n" + val
			} else {
				cipher.Notes = val
			}
			processingNotes = true
		} else if prop, ok := m[key]; ok {
			data[prop] = val
		} else {
			i.ProcessKvp(cipher, key, val)
		}
	}
	return data
}
