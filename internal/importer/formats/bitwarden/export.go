package bitwarden

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// JSON shapes of Bitwarden exports (libs/common/src/models/export and
// libs/tools/export/vault-export/vault-export-core/src/types/bitwarden-json-export-types.ts).
// Scalars use the lenient importer.JSON* types because JSON.parse accepts anything.

type js = importer.JSONString

// exportFile covers BitwardenJsonExport and BitwardenPasswordProtectedFileFormat.
type exportFile struct {
	Encrypted         json.RawMessage     `json:"encrypted"`
	PasswordProtected json.RawMessage     `json:"passwordProtected"`
	Salt              json.RawMessage     `json:"salt"`
	KdfType           importer.JSONNumber `json:"kdfType"`
	KdfIterations     importer.JSONNumber `json:"kdfIterations"`
	KdfMemory         importer.JSONNumber `json:"kdfMemory"`
	KdfParallelism    importer.JSONNumber `json:"kdfParallelism"`
	EncKeyValidation  json.RawMessage     `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              json.RawMessage     `json:"data"`
	Items             []json.RawMessage   `json:"items"`
	Folders           []folderExport      `json:"folders"`
	Collections       []collectionExport  `json:"collections"`
}

func isJSONTrue(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "true" }

// truthy is JavaScript truthiness of a decoded JSON value (missing counts as undefined).
func truthy(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	switch s {
	case "", "null", "false", `""`, "0", "-0", "0.0":
		return false
	}
	return true
}

// rawString returns the string value of raw ("" when it is not a JSON string).
func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func (f *exportFile) isUnencrypted() bool { return !isJSONTrue(f.Encrypted) }
func (f *exportFile) isPasswordProtected() bool {
	return isJSONTrue(f.Encrypted) && isJSONTrue(f.PasswordProtected)
}

// parseExportFile is JSON.parse for an export; a nil file means the JSON was `null`.
func parseExportFile(data string) (*exportFile, error) {
	var f *exportFile
	if err := importer.UnmarshalJSONLenient(data, &f); err != nil {
		return nil, err
	}
	return f, nil
}

type folderExport struct {
	ID   js `json:"id"`
	Name js `json:"name"`
}

type collectionExport struct {
	ID             js `json:"id"`
	OrganizationID js `json:"organizationId"`
	Name           js `json:"name"`
	ExternalID     js `json:"externalId"`
}

type fieldExport struct {
	Name     js                  `json:"name"`
	Value    js                  `json:"value"`
	Type     importer.JSONNumber `json:"type"`
	LinkedID importer.JSONNumber `json:"linkedId"`
}

type loginURIExport struct {
	URI         js                  `json:"uri"`
	URIChecksum js                  `json:"uriChecksum"`
	Match       importer.JSONNumber `json:"match"`
}

type fido2Export struct {
	CredentialID    js  `json:"credentialId"`
	KeyType         js  `json:"keyType"`
	KeyAlgorithm    js  `json:"keyAlgorithm"`
	KeyCurve        js  `json:"keyCurve"`
	KeyValue        js  `json:"keyValue"`
	RpID            js  `json:"rpId"`
	UserHandle      js  `json:"userHandle"`
	UserName        js  `json:"userName"`
	Counter         js  `json:"counter"`
	RpName          js  `json:"rpName"`
	UserDisplayName js  `json:"userDisplayName"`
	Discoverable    js  `json:"discoverable"`
	CreationDate    *js `json:"creationDate"`
}

type loginExport struct {
	URIs             []loginURIExport `json:"uris"`
	Username         js               `json:"username"`
	Password         js               `json:"password"`
	Totp             js               `json:"totp"`
	Fido2Credentials []fido2Export    `json:"fido2Credentials"`
}

type secureNoteExport struct {
	Type importer.JSONNumber `json:"type"`
}

type cardExport struct {
	CardholderName js `json:"cardholderName"`
	Brand          js `json:"brand"`
	Number         js `json:"number"`
	ExpMonth       js `json:"expMonth"`
	ExpYear        js `json:"expYear"`
	Code           js `json:"code"`
}

type identityExport struct {
	Title          js `json:"title"`
	FirstName      js `json:"firstName"`
	MiddleName     js `json:"middleName"`
	LastName       js `json:"lastName"`
	Address1       js `json:"address1"`
	Address2       js `json:"address2"`
	Address3       js `json:"address3"`
	City           js `json:"city"`
	State          js `json:"state"`
	PostalCode     js `json:"postalCode"`
	Country        js `json:"country"`
	Company        js `json:"company"`
	Email          js `json:"email"`
	Phone          js `json:"phone"`
	Ssn            js `json:"ssn"`
	Username       js `json:"username"`
	PassportNumber js `json:"passportNumber"`
	LicenseNumber  js `json:"licenseNumber"`
}

type sshKeyExport struct {
	PrivateKey     js `json:"privateKey"`
	PublicKey      js `json:"publicKey"`
	KeyFingerprint js `json:"keyFingerprint"`
	// Some SDK-produced vectors call it "fingerprint".
	Fingerprint js `json:"fingerprint"`
}

func (s *sshKeyExport) fingerprint() string {
	if s.KeyFingerprint != "" {
		return string(s.KeyFingerprint)
	}
	return string(s.Fingerprint)
}

type bankAccountExport struct {
	BankName         js `json:"bankName"`
	NameOnAccount    js `json:"nameOnAccount"`
	AccountType      js `json:"accountType"`
	AccountNumber    js `json:"accountNumber"`
	RoutingNumber    js `json:"routingNumber"`
	BranchNumber     js `json:"branchNumber"`
	Pin              js `json:"pin"`
	SwiftCode        js `json:"swiftCode"`
	Iban             js `json:"iban"`
	BankContactPhone js `json:"bankContactPhone"`
}

type driversLicenseExport struct {
	FirstName        js `json:"firstName"`
	MiddleName       js `json:"middleName"`
	LastName         js `json:"lastName"`
	DateOfBirth      js `json:"dateOfBirth"`
	LicenseNumber    js `json:"licenseNumber"`
	IssuingCountry   js `json:"issuingCountry"`
	IssuingState     js `json:"issuingState"`
	IssueDate        js `json:"issueDate"`
	ExpirationDate   js `json:"expirationDate"`
	IssuingAuthority js `json:"issuingAuthority"`
	LicenseClass     js `json:"licenseClass"`
}

type passportExport struct {
	Surname                      js `json:"surname"`
	GivenName                    js `json:"givenName"`
	DateOfBirth                  js `json:"dateOfBirth"`
	Sex                          js `json:"sex"`
	BirthPlace                   js `json:"birthPlace"`
	Nationality                  js `json:"nationality"`
	IssuingCountry               js `json:"issuingCountry"`
	PassportNumber               js `json:"passportNumber"`
	PassportType                 js `json:"passportType"`
	NationalIdentificationNumber js `json:"nationalIdentificationNumber"`
	IssuingAuthority             js `json:"issuingAuthority"`
	IssueDate                    js `json:"issueDate"`
	ExpirationDate               js `json:"expirationDate"`
}

type passwordHistoryExport struct {
	Password     js `json:"password"`
	LastUsedDate js `json:"lastUsedDate"`
}

// cipherExport is CipherWithIdExport.
type cipherExport struct {
	ID              js                      `json:"id"`
	Type            importer.JSONNumber     `json:"type"`
	FolderID        *js                     `json:"folderId"`
	OrganizationID  js                      `json:"organizationId"`
	CollectionIDs   []js                    `json:"collectionIds"`
	Name            *js                     `json:"name"`
	Notes           js                      `json:"notes"`
	Favorite        importer.JSONBool       `json:"favorite"`
	Fields          []fieldExport           `json:"fields"`
	Login           *loginExport            `json:"login"`
	SecureNote      *secureNoteExport       `json:"secureNote"`
	Card            *cardExport             `json:"card"`
	Identity        *identityExport         `json:"identity"`
	SshKey          *sshKeyExport           `json:"sshKey"`
	BankAccount     *bankAccountExport      `json:"bankAccount"`
	DriversLicense  *driversLicenseExport   `json:"driversLicense"`
	Passport        *passportExport         `json:"passport"`
	Reprompt        importer.JSONNumber     `json:"reprompt"`
	PasswordHistory []passwordHistoryExport `json:"passwordHistory"`
	RevisionDate    js                      `json:"revisionDate"`
	CreationDate    js                      `json:"creationDate"`
	DeletedDate     js                      `json:"deletedDate"`
	ArchivedDate    js                      `json:"archivedDate"`
	Key             *js                     `json:"key"`
	Data            *js                     `json:"data"`
}

func parseCipherExport(raw json.RawMessage) (*cipherExport, error) {
	var c cipherExport
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	return &c, nil
}

func jsDate(s js) *time.Time {
	if s == "" {
		return nil
	}
	t, ok := importer.ParseJSDate(string(s))
	if !ok {
		return nil
	}
	return &t
}

func linkedID(n importer.JSONNumber) *model.LinkedIdType {
	if !n.Valid {
		return nil
	}
	v := model.LinkedIdType(n.Int())
	return &v
}

// decryptFn maps a (possibly encrypted) export value to its plain text. For unencrypted exports it
// is the identity.
type decryptFn func(string) (string, error)

func plain(s string) (string, error) { return s, nil }

// toView is CipherExport.toView (view = new CipherView()); dec decrypts every string value so the
// legacy-encrypted path can reuse it. Required-field errors match the TS messages.
func (req *cipherExport) toView(dec decryptFn) (*model.CipherView, error) {
	var firstErr error
	d := func(s js) string {
		if s == "" {
			return ""
		}
		v, err := dec(string(s))
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return v
	}

	view := model.NewCipherView()
	view.Type = model.CipherType(req.Type.Int())
	view.FolderID = importer.Str(req.FolderID)
	view.OrganizationID = string(req.OrganizationID)
	for _, id := range req.CollectionIDs {
		view.CollectionIDs = append(view.CollectionIDs, string(id))
	}
	view.Name = d(js(importer.Str(req.Name)))
	view.Notes = d(req.Notes)
	view.Favorite = bool(req.Favorite)
	view.Reprompt = model.CipherRepromptType(req.Reprompt.Int())

	if req.Fields != nil {
		view.Fields = make([]*model.FieldView, 0, len(req.Fields))
		for _, f := range req.Fields {
			view.Fields = append(view.Fields, &model.FieldView{
				Type: model.FieldType(f.Type.Int()), Value: d(f.Value), Name: d(f.Name), LinkedID: linkedID(f.LinkedID),
			})
		}
	}

	switch view.Type {
	case model.CipherTypeLogin:
		if l := req.Login; l != nil {
			lv := &model.LoginView{Username: d(l.Username), Password: d(l.Password), Totp: d(l.Totp)}
			if l.URIs != nil {
				lv.Uris = make([]*model.LoginUriView, 0, len(l.URIs))
				for _, u := range l.URIs {
					uv := &model.LoginUriView{Uri: d(u.URI)}
					if u.Match.Valid {
						m := model.UriMatchStrategy(u.Match.Int())
						uv.Match = &m
					}
					lv.Uris = append(lv.Uris, uv)
				}
			}
			if l.Fido2Credentials != nil {
				lv.Fido2Credentials = make([]*model.Fido2CredentialView, 0, len(l.Fido2Credentials))
				for _, f := range l.Fido2Credentials {
					fv := &model.Fido2CredentialView{
						CredentialID: d(f.CredentialID), KeyType: d(f.KeyType), KeyAlgorithm: d(f.KeyAlgorithm),
						KeyCurve: d(f.KeyCurve), KeyValue: d(f.KeyValue), RpID: d(f.RpID), UserHandle: d(f.UserHandle),
						UserName: d(f.UserName), RpName: d(f.RpName), UserDisplayName: d(f.UserDisplayName),
					}
					fv.Counter, _ = importer.ParseInt(d(f.Counter))
					fv.Discoverable = d(f.Discoverable) == "true"
					if f.CreationDate == nil {
						fv.CreationDate = time.UnixMilli(0).UTC() // new Date(null)
					} else if t := jsDate(*f.CreationDate); t != nil {
						fv.CreationDate = *t
					}
					lv.Fido2Credentials = append(lv.Fido2Credentials, fv)
				}
			}
			view.Login = lv
		}
	case model.CipherTypeSecureNote:
		if req.SecureNote != nil {
			view.SecureNote = &model.SecureNoteView{Type: model.SecureNoteType(req.SecureNote.Type.Int())}
		}
	case model.CipherTypeCard:
		if c := req.Card; c != nil {
			view.Card = &model.CardView{CardholderName: d(c.CardholderName), Brand: d(c.Brand), Number: d(c.Number),
				ExpMonth: d(c.ExpMonth), ExpYear: d(c.ExpYear), Code: d(c.Code)}
		}
	case model.CipherTypeIdentity:
		if i := req.Identity; i != nil {
			view.Identity = &model.IdentityView{Title: d(i.Title), FirstName: d(i.FirstName), MiddleName: d(i.MiddleName),
				LastName: d(i.LastName), Address1: d(i.Address1), Address2: d(i.Address2), Address3: d(i.Address3),
				City: d(i.City), State: d(i.State), PostalCode: d(i.PostalCode), Country: d(i.Country),
				Company: d(i.Company), Email: d(i.Email), Phone: d(i.Phone), Ssn: d(i.Ssn), Username: d(i.Username),
				PassportNumber: d(i.PassportNumber), LicenseNumber: d(i.LicenseNumber)}
		}
	case model.CipherTypeSshKey:
		if s := req.SshKey; s != nil {
			priv, pub, fp := d(s.PrivateKey), d(s.PublicKey), d(js(s.fingerprint()))
			if strings.TrimSpace(priv) == "" {
				return nil, errors.New("SSH key private key is required.")
			}
			if strings.TrimSpace(pub) == "" {
				return nil, errors.New("SSH key public key is required.")
			}
			if strings.TrimSpace(fp) == "" {
				return nil, errors.New("SSH key fingerprint is required.")
			}
			view.SshKey = &model.SshKeyView{PrivateKey: priv, PublicKey: pub, KeyFingerprint: fp}
		}
	case model.CipherTypeBankAccount:
		if b := req.BankAccount; b != nil {
			view.BankAccount = &model.BankAccountView{BankName: d(b.BankName), NameOnAccount: d(b.NameOnAccount),
				AccountType: d(b.AccountType), AccountNumber: d(b.AccountNumber), RoutingNumber: d(b.RoutingNumber),
				BranchNumber: d(b.BranchNumber), Pin: d(b.Pin), SwiftCode: d(b.SwiftCode), Iban: d(b.Iban),
				BankContactPhone: d(b.BankContactPhone)}
		}
	case model.CipherTypeDriversLicense:
		if l := req.DriversLicense; l != nil {
			view.DriversLicense = &model.DriversLicenseView{FirstName: d(l.FirstName), MiddleName: d(l.MiddleName),
				LastName: d(l.LastName), DateOfBirth: d(l.DateOfBirth), LicenseNumber: d(l.LicenseNumber),
				IssuingCountry: d(l.IssuingCountry), IssuingState: d(l.IssuingState), IssueDate: d(l.IssueDate),
				ExpirationDate: d(l.ExpirationDate), IssuingAuthority: d(l.IssuingAuthority), LicenseClass: d(l.LicenseClass)}
		}
	case model.CipherTypePassport:
		if p := req.Passport; p != nil {
			view.Passport = &model.PassportView{Surname: d(p.Surname), GivenName: d(p.GivenName), DateOfBirth: d(p.DateOfBirth),
				Sex: d(p.Sex), BirthPlace: d(p.BirthPlace), Nationality: d(p.Nationality), IssuingCountry: d(p.IssuingCountry),
				PassportNumber: d(p.PassportNumber), PassportType: d(p.PassportType),
				NationalIdentificationNumber: d(p.NationalIdentificationNumber), IssuingAuthority: d(p.IssuingAuthority),
				IssueDate: d(p.IssueDate), ExpirationDate: d(p.ExpirationDate)}
		}
	}

	if req.PasswordHistory != nil {
		view.PasswordHistory = make([]*model.PasswordHistoryView, 0, len(req.PasswordHistory))
		for _, ph := range req.PasswordHistory {
			v := &model.PasswordHistoryView{Password: d(ph.Password), LastUsedDate: time.Now().UTC()}
			if t := jsDate(ph.LastUsedDate); t != nil {
				v.LastUsedDate = *t
			}
			view.PasswordHistory = append(view.PasswordHistory, v)
		}
	}

	view.CreationDate = jsDate(req.CreationDate)
	view.RevisionDate = jsDate(req.RevisionDate)
	view.DeletedDate = jsDate(req.DeletedDate)
	view.ArchivedDate = jsDate(req.ArchivedDate)
	if firstErr != nil {
		return nil, firstErr
	}
	return view, nil
}
