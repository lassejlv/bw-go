package vault

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// Export models (libs/common/src/models/export). The same structs are used for the JSON users
// pass to create/edit (decoded, then converted with ToView) and for output. Property order
// follows JSON.stringify of the TS objects: fields with class initializers first (in declaration
// order), then fields in the order the constructor/build() assigns them. Opt fields are omitted
// when undefined and emitted as null when null.

// ---------- ordered JSON objects (templates) ----------

type kv struct {
	K string
	V any
}

// OrderedObject is a JSON object with a fixed key order.
type OrderedObject []kv

// MarshalJSON implements json.Marshaler.
func (o OrderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, p := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := marshalNoEscape(p.K)
		buf.Write(k)
		buf.WriteByte(':')
		v, err := marshalNoEscape(p.V)
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// ---------- field ----------

// FieldExport mirrors FieldExport (order: type, name, value, linkedId).
type FieldExport struct {
	Type     FieldType     `json:"type"`
	Name     Opt[string]   `json:"name,omitzero"`
	Value    Opt[string]   `json:"value,omitzero"`
	LinkedID Opt[LinkedID] `json:"linkedId,omitzero"`
}

// NewFieldExport mirrors `new FieldExport(view)` (SDK view: absent values are undefined).
func NewFieldExport(f *FieldView) FieldExport {
	return FieldExport{Type: f.Type, Name: FromPtr(f.Name), Value: FromPtr(f.Value), LinkedID: FromPtr(f.LinkedID)}
}

// ToView mirrors FieldExport.toView.
func (f *FieldExport) ToView() FieldView {
	return FieldView{Type: f.Type, Name: f.Name.Ptr(), Value: f.Value.Ptr(), LinkedID: f.LinkedID.Ptr()}
}

// ---------- login ----------

// LoginURIExport mirrors LoginUriExport (order: uri, [uriChecksum], match).
type LoginURIExport struct {
	URI         Opt[string]   `json:"uri,omitzero"`
	URIChecksum Opt[string]   `json:"uriChecksum,omitzero"`
	Match       Opt[UriMatch] `json:"match,omitzero"`
}

// ToView mirrors LoginUriExport.toView.
func (u *LoginURIExport) ToView() LoginURIView {
	return LoginURIView{URI: u.URI.Ptr(), Match: u.Match.Ptr()}
}

// Fido2CredentialExport mirrors Fido2CredentialExport. Initialised fields come first, then the
// optional ones in constructor order.
type Fido2CredentialExport struct {
	CredentialID    string      `json:"credentialId"`
	KeyType         string      `json:"keyType"`
	KeyAlgorithm    string      `json:"keyAlgorithm"`
	KeyCurve        string      `json:"keyCurve"`
	KeyValue        string      `json:"keyValue"`
	RpID            string      `json:"rpId"`
	Counter         string      `json:"counter"`
	Discoverable    string      `json:"discoverable"`
	CreationDate    *cli.Date   `json:"creationDate"`
	UserHandle      Opt[string] `json:"userHandle,omitzero"`
	UserName        Opt[string] `json:"userName,omitzero"`
	RpName          Opt[string] `json:"rpName,omitzero"`
	UserDisplayName Opt[string] `json:"userDisplayName,omitzero"`
}

// NewFido2CredentialExport mirrors `new Fido2CredentialExport(view)`.
func NewFido2CredentialExport(f *Fido2CredentialView) Fido2CredentialExport {
	return Fido2CredentialExport{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm, KeyCurve: f.KeyCurve,
		KeyValue: f.KeyValue, RpID: f.RpID, Counter: f.CounterString(),
		Discoverable: strconv.FormatBool(f.Discoverable), CreationDate: cliDate(f.CreationDate),
		UserHandle: FromPtr(f.UserHandle), UserName: FromPtr(f.UserName), RpName: FromPtr(f.RpName),
		UserDisplayName: FromPtr(f.UserDisplayName),
	}
}

// ToView mirrors Fido2CredentialExport.toView.
func (f *Fido2CredentialExport) ToView() Fido2CredentialView {
	v := Fido2CredentialView{
		CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm, KeyCurve: f.KeyCurve,
		KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle.Ptr(), UserName: f.UserName.Ptr(),
		Counter: jsParseIntString(f.Counter), RpName: f.RpName.Ptr(), UserDisplayName: f.UserDisplayName.Ptr(),
		Discoverable: f.Discoverable == "true",
	}
	if f.CreationDate != nil {
		t := f.CreationDate.Time
		v.CreationDate = &t
	}
	return v
}

// LoginExport mirrors LoginExport (constructor order: uris, fido2Credentials, username, password, totp).
type LoginExport struct {
	URIs             []LoginURIExport        `json:"uris,omitzero"`
	Fido2Credentials []Fido2CredentialExport `json:"fido2Credentials,omitzero"`
	Username         Opt[string]             `json:"username,omitzero"`
	Password         Opt[string]             `json:"password,omitzero"`
	Totp             Opt[string]             `json:"totp,omitzero"`
}

// NewLoginExport mirrors `new LoginExport(view)`.
func NewLoginExport(l *LoginView) *LoginExport {
	e := &LoginExport{Username: FromPtr(l.Username), Password: FromPtr(l.Password), Totp: FromPtr(l.Totp)}
	if l.URIs != nil {
		e.URIs = []LoginURIExport{}
		for _, u := range l.URIs {
			e.URIs = append(e.URIs, LoginURIExport{URI: FromPtr(u.URI), Match: FromPtr(u.Match)})
		}
	}
	if l.Fido2Credentials != nil {
		e.Fido2Credentials = []Fido2CredentialExport{}
		for i := range l.Fido2Credentials {
			e.Fido2Credentials = append(e.Fido2Credentials, NewFido2CredentialExport(&l.Fido2Credentials[i]))
		}
	}
	return e
}

// ToView mirrors LoginExport.toView (a fresh LoginView).
func (l *LoginExport) ToView() *LoginView {
	v := &LoginView{URIs: []LoginURIView{}, Fido2Credentials: []Fido2CredentialView{},
		Username: l.Username.Ptr(), Password: l.Password.Ptr(), Totp: l.Totp.Ptr()}
	if l.URIs != nil {
		for i := range l.URIs {
			v.URIs = append(v.URIs, l.URIs[i].ToView())
		}
	}
	if l.Fido2Credentials != nil {
		for i := range l.Fido2Credentials {
			v.Fido2Credentials = append(v.Fido2Credentials, l.Fido2Credentials[i].ToView())
		}
	}
	return v
}

// ---------- other item types ----------

// SecureNoteExport mirrors SecureNoteExport.
type SecureNoteExport struct {
	Type SecureNoteType `json:"type"`
}

// CardExport mirrors CardExport.
type CardExport struct {
	CardholderName Opt[string] `json:"cardholderName,omitzero"`
	Brand          Opt[string] `json:"brand,omitzero"`
	Number         Opt[string] `json:"number,omitzero"`
	ExpMonth       Opt[string] `json:"expMonth,omitzero"`
	ExpYear        Opt[string] `json:"expYear,omitzero"`
	Code           Opt[string] `json:"code,omitzero"`
}

// NewCardExport mirrors `new CardExport(view)`.
func NewCardExport(c *CardView) *CardExport {
	return &CardExport{FromPtr(c.CardholderName), FromPtr(c.Brand), FromPtr(c.Number), FromPtr(c.ExpMonth),
		FromPtr(c.ExpYear), FromPtr(c.Code)}
}

// ToView mirrors CardExport.toView.
func (c *CardExport) ToView() *CardView {
	return &CardView{CardholderName: c.CardholderName.Ptr(), Brand: c.Brand.Ptr(), Number: c.Number.Ptr(),
		ExpMonth: c.ExpMonth.Ptr(), ExpYear: c.ExpYear.Ptr(), Code: c.Code.Ptr()}
}

// IdentityExport mirrors IdentityExport.
type IdentityExport struct {
	Title          Opt[string] `json:"title,omitzero"`
	FirstName      Opt[string] `json:"firstName,omitzero"`
	MiddleName     Opt[string] `json:"middleName,omitzero"`
	LastName       Opt[string] `json:"lastName,omitzero"`
	Address1       Opt[string] `json:"address1,omitzero"`
	Address2       Opt[string] `json:"address2,omitzero"`
	Address3       Opt[string] `json:"address3,omitzero"`
	City           Opt[string] `json:"city,omitzero"`
	State          Opt[string] `json:"state,omitzero"`
	PostalCode     Opt[string] `json:"postalCode,omitzero"`
	Country        Opt[string] `json:"country,omitzero"`
	Company        Opt[string] `json:"company,omitzero"`
	Email          Opt[string] `json:"email,omitzero"`
	Phone          Opt[string] `json:"phone,omitzero"`
	SSN            Opt[string] `json:"ssn,omitzero"`
	Username       Opt[string] `json:"username,omitzero"`
	PassportNumber Opt[string] `json:"passportNumber,omitzero"`
	LicenseNumber  Opt[string] `json:"licenseNumber,omitzero"`
}

// NewIdentityExport mirrors `new IdentityExport(view)`.
func NewIdentityExport(i *IdentityView) *IdentityExport {
	f := FromPtr[string]
	return &IdentityExport{f(i.Title), f(i.FirstName), f(i.MiddleName), f(i.LastName), f(i.Address1),
		f(i.Address2), f(i.Address3), f(i.City), f(i.State), f(i.PostalCode), f(i.Country), f(i.Company),
		f(i.Email), f(i.Phone), f(i.SSN), f(i.Username), f(i.PassportNumber), f(i.LicenseNumber)}
}

// ToView mirrors IdentityExport.toView.
func (i *IdentityExport) ToView() *IdentityView {
	return &IdentityView{Title: i.Title.Ptr(), FirstName: i.FirstName.Ptr(), MiddleName: i.MiddleName.Ptr(),
		LastName: i.LastName.Ptr(), Address1: i.Address1.Ptr(), Address2: i.Address2.Ptr(),
		Address3: i.Address3.Ptr(), City: i.City.Ptr(), State: i.State.Ptr(), PostalCode: i.PostalCode.Ptr(),
		Country: i.Country.Ptr(), Company: i.Company.Ptr(), Email: i.Email.Ptr(), Phone: i.Phone.Ptr(),
		SSN: i.SSN.Ptr(), Username: i.Username.Ptr(), PassportNumber: i.PassportNumber.Ptr(),
		LicenseNumber: i.LicenseNumber.Ptr()}
}

// SshKeyExport mirrors SshKeyExport.
type SshKeyExport struct {
	PrivateKey     Opt[string] `json:"privateKey,omitzero"`
	PublicKey      Opt[string] `json:"publicKey,omitzero"`
	KeyFingerprint Opt[string] `json:"keyFingerprint,omitzero"`
}

// NewSshKeyExport mirrors `new SshKeyExport(view)`.
func NewSshKeyExport(s *SshKeyView) *SshKeyExport {
	return &SshKeyExport{Some(s.PrivateKey), Some(s.PublicKey), Some(s.KeyFingerprint)}
}

// ToView mirrors SshKeyExport.toView (validation errors match upstream messages).
func (s *SshKeyExport) ToView(allowDerivedKeys bool) (*SshKeyView, error) {
	blank := func(o Opt[string]) bool { return o.Val == nil || strings.TrimSpace(*o.Val) == "" }
	if blank(s.PrivateKey) {
		return nil, errors.New("SSH key private key is required.")
	}
	if !allowDerivedKeys {
		if blank(s.PublicKey) {
			return nil, errors.New("SSH key public key is required.")
		}
		if blank(s.KeyFingerprint) {
			return nil, errors.New("SSH key fingerprint is required.")
		}
	}
	return &SshKeyView{PrivateKey: s.PrivateKey.Get(), PublicKey: s.PublicKey.Get(), KeyFingerprint: s.KeyFingerprint.Get()}, nil
}

// BankAccountExport mirrors BankAccountExport.
type BankAccountExport struct {
	BankName         Opt[string] `json:"bankName,omitzero"`
	NameOnAccount    Opt[string] `json:"nameOnAccount,omitzero"`
	AccountType      Opt[string] `json:"accountType,omitzero"`
	AccountNumber    Opt[string] `json:"accountNumber,omitzero"`
	RoutingNumber    Opt[string] `json:"routingNumber,omitzero"`
	BranchNumber     Opt[string] `json:"branchNumber,omitzero"`
	Pin              Opt[string] `json:"pin,omitzero"`
	SwiftCode        Opt[string] `json:"swiftCode,omitzero"`
	Iban             Opt[string] `json:"iban,omitzero"`
	BankContactPhone Opt[string] `json:"bankContactPhone,omitzero"`
}

// NewBankAccountExport mirrors `new BankAccountExport(view)`.
func NewBankAccountExport(b *BankAccountView) *BankAccountExport {
	f := FromPtr[string]
	return &BankAccountExport{f(b.BankName), f(b.NameOnAccount), f(b.AccountType), f(b.AccountNumber),
		f(b.RoutingNumber), f(b.BranchNumber), f(b.Pin), f(b.SwiftCode), f(b.Iban), f(b.BankContactPhone)}
}

// ToView mirrors BankAccountExport.toView.
func (b *BankAccountExport) ToView() *BankAccountView {
	return &BankAccountView{b.BankName.Ptr(), b.NameOnAccount.Ptr(), b.AccountType.Ptr(), b.AccountNumber.Ptr(),
		b.RoutingNumber.Ptr(), b.BranchNumber.Ptr(), b.Pin.Ptr(), b.SwiftCode.Ptr(), b.Iban.Ptr(), b.BankContactPhone.Ptr()}
}

// DriversLicenseExport mirrors DriversLicenseExport.
type DriversLicenseExport struct {
	FirstName        Opt[string] `json:"firstName,omitzero"`
	MiddleName       Opt[string] `json:"middleName,omitzero"`
	LastName         Opt[string] `json:"lastName,omitzero"`
	DateOfBirth      Opt[string] `json:"dateOfBirth,omitzero"`
	LicenseNumber    Opt[string] `json:"licenseNumber,omitzero"`
	IssuingCountry   Opt[string] `json:"issuingCountry,omitzero"`
	IssuingState     Opt[string] `json:"issuingState,omitzero"`
	IssueDate        Opt[string] `json:"issueDate,omitzero"`
	ExpirationDate   Opt[string] `json:"expirationDate,omitzero"`
	IssuingAuthority Opt[string] `json:"issuingAuthority,omitzero"`
	LicenseClass     Opt[string] `json:"licenseClass,omitzero"`
}

// NewDriversLicenseExport mirrors `new DriversLicenseExport(view)`.
func NewDriversLicenseExport(d *DriversLicenseView) *DriversLicenseExport {
	f := FromPtr[string]
	return &DriversLicenseExport{f(d.FirstName), f(d.MiddleName), f(d.LastName), f(d.DateOfBirth),
		f(d.LicenseNumber), f(d.IssuingCountry), f(d.IssuingState), f(d.IssueDate), f(d.ExpirationDate),
		f(d.IssuingAuthority), f(d.LicenseClass)}
}

// ToView mirrors DriversLicenseExport.toView.
func (d *DriversLicenseExport) ToView() *DriversLicenseView {
	return &DriversLicenseView{d.FirstName.Ptr(), d.MiddleName.Ptr(), d.LastName.Ptr(), d.DateOfBirth.Ptr(),
		d.LicenseNumber.Ptr(), d.IssuingCountry.Ptr(), d.IssuingState.Ptr(), d.IssueDate.Ptr(),
		d.ExpirationDate.Ptr(), d.IssuingAuthority.Ptr(), d.LicenseClass.Ptr()}
}

// PassportExport mirrors PassportExport.
type PassportExport struct {
	Surname                      Opt[string] `json:"surname,omitzero"`
	GivenName                    Opt[string] `json:"givenName,omitzero"`
	DateOfBirth                  Opt[string] `json:"dateOfBirth,omitzero"`
	Sex                          Opt[string] `json:"sex,omitzero"`
	BirthPlace                   Opt[string] `json:"birthPlace,omitzero"`
	Nationality                  Opt[string] `json:"nationality,omitzero"`
	IssuingCountry               Opt[string] `json:"issuingCountry,omitzero"`
	PassportNumber               Opt[string] `json:"passportNumber,omitzero"`
	PassportType                 Opt[string] `json:"passportType,omitzero"`
	NationalIdentificationNumber Opt[string] `json:"nationalIdentificationNumber,omitzero"`
	IssuingAuthority             Opt[string] `json:"issuingAuthority,omitzero"`
	IssueDate                    Opt[string] `json:"issueDate,omitzero"`
	ExpirationDate               Opt[string] `json:"expirationDate,omitzero"`
}

// NewPassportExport mirrors `new PassportExport(view)`.
func NewPassportExport(p *PassportView) *PassportExport {
	f := FromPtr[string]
	return &PassportExport{f(p.Surname), f(p.GivenName), f(p.DateOfBirth), f(p.Sex), f(p.BirthPlace),
		f(p.Nationality), f(p.IssuingCountry), f(p.PassportNumber), f(p.PassportType),
		f(p.NationalIdentificationNumber), f(p.IssuingAuthority), f(p.IssueDate), f(p.ExpirationDate)}
}

// ToView mirrors PassportExport.toView.
func (p *PassportExport) ToView() *PassportView {
	return &PassportView{p.Surname.Ptr(), p.GivenName.Ptr(), p.DateOfBirth.Ptr(), p.Sex.Ptr(), p.BirthPlace.Ptr(),
		p.Nationality.Ptr(), p.IssuingCountry.Ptr(), p.PassportNumber.Ptr(), p.PassportType.Ptr(),
		p.NationalIdentificationNumber.Ptr(), p.IssuingAuthority.Ptr(), p.IssueDate.Ptr(), p.ExpirationDate.Ptr()}
}

// PasswordHistoryExport mirrors PasswordHistoryExport (order: password, lastUsedDate).
type PasswordHistoryExport struct {
	Password     Opt[string]   `json:"password,omitzero"`
	LastUsedDate Opt[cli.Date] `json:"lastUsedDate,omitzero"`
}

// ToView mirrors PasswordHistoryExport.toView (missing lastUsedDate becomes now).
func (p *PasswordHistoryExport) ToView() PasswordHistoryView {
	v := PasswordHistoryView{Password: p.Password.Ptr()}
	if p.LastUsedDate.Val != nil && !p.LastUsedDate.Val.IsZero() {
		t := p.LastUsedDate.Val.Time
		v.LastUsedDate = &t
	} else {
		now := time.Now().UTC()
		v.LastUsedDate = &now
	}
	return v
}

// ---------- cipher ----------

// CipherExport is the item JSON accepted by create/edit (CipherExport / CipherWithIdExport input).
type CipherExport struct {
	ID              Opt[string]             `json:"id,omitzero"`
	Type            *CipherType             `json:"type"`
	FolderID        Opt[string]             `json:"folderId,omitzero"`
	OrganizationID  Opt[string]             `json:"organizationId,omitzero"`
	CollectionIDs   []string                `json:"collectionIds"`
	Name            Opt[string]             `json:"name,omitzero"`
	Notes           Opt[string]             `json:"notes,omitzero"`
	Favorite        *bool                   `json:"favorite"`
	Fields          []FieldExport           `json:"fields"`
	Login           *LoginExport            `json:"login"`
	SecureNote      *SecureNoteExport       `json:"secureNote"`
	Card            *CardExport             `json:"card"`
	Identity        *IdentityExport         `json:"identity"`
	SshKey          *SshKeyExport           `json:"sshKey"`
	BankAccount     *BankAccountExport      `json:"bankAccount"`
	DriversLicense  *DriversLicenseExport   `json:"driversLicense"`
	Passport        *PassportExport         `json:"passport"`
	Reprompt        *RepromptType           `json:"reprompt"`
	PasswordHistory []PasswordHistoryExport `json:"passwordHistory"`
	RevisionDate    Opt[string]             `json:"revisionDate,omitzero"`
	CreationDate    Opt[string]             `json:"creationDate,omitzero"`
	DeletedDate     Opt[string]             `json:"deletedDate,omitzero"`
	ArchivedDate    Opt[string]             `json:"archivedDate,omitzero"`
	Key             Opt[string]             `json:"key,omitzero"`
	Data            Opt[string]             `json:"data,omitzero"`
}

func parseJSDate(o Opt[string]) *time.Time {
	if o.Val == nil || *o.Val == "" {
		return nil
	}
	t, err := cli.ParseDate(*o.Val)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// ToView mirrors CipherExport.toView. When view is nil a new CipherView is created; otherwise
// the existing (decrypted) view is updated in place, as `bw edit` does.
func (req *CipherExport) ToView(view *CipherView, allowDerivedSshKeys bool) (*CipherView, error) {
	if view == nil {
		view = NewCipherView()
	}
	if req.Type != nil {
		view.Type = *req.Type
	} else {
		view.Type = 0
	}
	view.FolderID = req.FolderID.Ptr()
	if view.OrganizationID == nil {
		view.OrganizationID = req.OrganizationID.Ptr()
	}
	if view.CollectionIDs != nil || req.CollectionIDs != nil {
		seen := map[string]bool{}
		out := []string{}
		for _, id := range append(append([]string{}, view.CollectionIDs...), req.CollectionIDs...) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
		view.CollectionIDs = out
	}
	view.Name = req.Name.Get()
	view.Notes = req.Notes.Ptr()
	view.Favorite = req.Favorite != nil && *req.Favorite
	view.Reprompt = RepromptNone
	if req.Reprompt != nil {
		view.Reprompt = *req.Reprompt
	}
	if req.Key.Val != nil && !crypto.IsEncString(*req.Key.Val) {
		if k, err := crypto.KeyFromB64(*req.Key.Val); err == nil {
			view.Key = k
		}
	}
	if req.Fields != nil {
		view.Fields = []FieldView{}
		for i := range req.Fields {
			view.Fields = append(view.Fields, req.Fields[i].ToView())
		}
	}
	switch view.Type {
	case CipherTypeLogin:
		if req.Login != nil {
			view.Login = req.Login.ToView()
		}
	case CipherTypeSecureNote:
		if req.SecureNote != nil {
			view.SecureNote = &SecureNoteView{Type: req.SecureNote.Type}
		}
	case CipherTypeCard:
		if req.Card != nil {
			view.Card = req.Card.ToView()
		}
	case CipherTypeIdentity:
		if req.Identity != nil {
			view.Identity = req.Identity.ToView()
		}
	case CipherTypeSshKey:
		if req.SshKey != nil {
			s, err := req.SshKey.ToView(allowDerivedSshKeys)
			if err != nil {
				return nil, err
			}
			view.SshKey = s
		}
	case CipherTypeBankAccount:
		if req.BankAccount != nil {
			view.BankAccount = req.BankAccount.ToView()
		}
	case CipherTypeDriversLicense:
		if req.DriversLicense != nil {
			view.DriversLicense = req.DriversLicense.ToView()
		}
	case CipherTypePassport:
		if req.Passport != nil {
			view.Passport = req.Passport.ToView()
		}
	}
	ensureTypeView(view)
	if req.PasswordHistory != nil {
		view.PasswordHistory = []PasswordHistoryView{}
		for i := range req.PasswordHistory {
			view.PasswordHistory = append(view.PasswordHistory, req.PasswordHistory[i].ToView())
		}
	}
	if t := parseJSDate(req.CreationDate); t != nil {
		view.CreationDate = *t
	}
	if t := parseJSDate(req.RevisionDate); t != nil {
		view.RevisionDate = *t
	}
	if t := parseJSDate(req.DeletedDate); t != nil {
		view.DeletedDate = t
	}
	if t := parseJSDate(req.ArchivedDate); t != nil {
		view.ArchivedDate = t
	}
	return view, nil
}

// CipherWithIDExport is the output of `new CipherWithIdExport().build(...)` (used by exports).
type CipherWithIDExport struct {
	Type            CipherType              `json:"type"`
	Favorite        bool                    `json:"favorite"`
	Reprompt        RepromptType            `json:"reprompt"`
	ID              string                  `json:"id"`
	CollectionIDs   Opt[[]string]           `json:"collectionIds,omitzero"`
	OrganizationID  Opt[string]             `json:"organizationId,omitzero"`
	FolderID        Opt[string]             `json:"folderId,omitzero"`
	Name            Opt[string]             `json:"name,omitzero"`
	Notes           Opt[string]             `json:"notes,omitzero"`
	Key             Opt[string]             `json:"key,omitzero"`
	Fields          []FieldExport           `json:"fields,omitzero"`
	Login           *LoginExport            `json:"login,omitempty"`
	SecureNote      *SecureNoteExport       `json:"secureNote,omitempty"`
	Card            *CardExport             `json:"card,omitempty"`
	Identity        *IdentityExport         `json:"identity,omitempty"`
	SshKey          *SshKeyExport           `json:"sshKey,omitempty"`
	BankAccount     *BankAccountExport      `json:"bankAccount,omitempty"`
	DriversLicense  *DriversLicenseExport   `json:"driversLicense,omitempty"`
	Passport        *PassportExport         `json:"passport,omitempty"`
	PasswordHistory []PasswordHistoryExport `json:"passwordHistory,omitzero"`
	CreationDate    *cli.Date               `json:"creationDate,omitempty"`
	RevisionDate    *cli.Date               `json:"revisionDate,omitempty"`
	DeletedDate     *cli.Date               `json:"deletedDate,omitempty"`
	ArchivedDate    *cli.Date               `json:"archivedDate,omitempty"`
	Data            Opt[string]             `json:"data,omitzero"`
}

// BuildCipherExport mirrors `new CipherWithIdExport().build(view)`. The decrypted cipher key is
// included as base64 like upstream; callers delete it where upstream does (`delete cipher.key`)
// by setting Key = Opt[string]{}.
func BuildCipherExport(v *CipherView) *CipherWithIDExport {
	e := &CipherWithIDExport{
		Type: v.Type, Favorite: v.Favorite, Reprompt: v.Reprompt, ID: v.ID,
		CollectionIDs:  FromPtr(&v.CollectionIDs),
		OrganizationID: FromPtr(v.OrganizationID),
		FolderID:       FromPtr(v.FolderID),
		Name:           Some(v.Name),
		Notes:          FromPtr(v.Notes),
		CreationDate:   &cli.Date{Time: v.CreationDate},
		RevisionDate:   &cli.Date{Time: v.RevisionDate},
		DeletedDate:    cliDate(v.DeletedDate),
		ArchivedDate:   cliDate(v.ArchivedDate),
	}
	if v.CollectionIDs == nil {
		e.CollectionIDs = Null[[]string]()
	}
	if v.Key != nil {
		e.Key = Some(v.Key.B64())
	}
	if v.Fields != nil {
		e.Fields = []FieldExport{}
		for i := range v.Fields {
			e.Fields = append(e.Fields, NewFieldExport(&v.Fields[i]))
		}
	}
	buildTypeExports(v, &e.Login, &e.SecureNote, &e.Card, &e.Identity, &e.SshKey, &e.BankAccount, &e.DriversLicense, &e.Passport)
	if v.PasswordHistory != nil {
		e.PasswordHistory = []PasswordHistoryExport{}
		for _, p := range v.PasswordHistory {
			pe := PasswordHistoryExport{Password: Some(derefStr(p.Password))}
			if p.LastUsedDate != nil {
				pe.LastUsedDate = Some(cli.Date{Time: *p.LastUsedDate})
			}
			e.PasswordHistory = append(e.PasswordHistory, pe)
		}
	}
	return e
}

func buildTypeExports(v *CipherView, login **LoginExport, note **SecureNoteExport, card **CardExport,
	ident **IdentityExport, ssh **SshKeyExport, bank **BankAccountExport, dl **DriversLicenseExport, pp **PassportExport) {
	switch v.Type {
	case CipherTypeLogin:
		if v.Login != nil {
			*login = NewLoginExport(v.Login)
		} else {
			*login = &LoginExport{}
		}
	case CipherTypeSecureNote:
		n := &SecureNoteExport{}
		if v.SecureNote != nil {
			n.Type = v.SecureNote.Type
		}
		*note = n
	case CipherTypeCard:
		if v.Card != nil {
			*card = NewCardExport(v.Card)
		} else {
			*card = &CardExport{}
		}
	case CipherTypeIdentity:
		if v.Identity != nil {
			*ident = NewIdentityExport(v.Identity)
		} else {
			*ident = &IdentityExport{}
		}
	case CipherTypeSshKey:
		if v.SshKey != nil {
			*ssh = NewSshKeyExport(v.SshKey)
		} else {
			*ssh = &SshKeyExport{Some(""), Some(""), Some("")}
		}
	case CipherTypeBankAccount:
		if v.BankAccount != nil {
			*bank = NewBankAccountExport(v.BankAccount)
		} else {
			*bank = &BankAccountExport{}
		}
	case CipherTypeDriversLicense:
		if v.DriversLicense != nil {
			*dl = NewDriversLicenseExport(v.DriversLicense)
		} else {
			*dl = &DriversLicenseExport{}
		}
	case CipherTypePassport:
		if v.Passport != nil {
			*pp = NewPassportExport(v.Passport)
		} else {
			*pp = &PassportExport{}
		}
	}
}

// BuildCipherExportFromDomain mirrors `new CipherWithIdExport().build(cipherDomain)` used by the
// encrypted JSON export: values are the encrypted strings, `key` is the wrapped cipher key and
// blob ciphers carry only `data`.
func BuildCipherExportFromDomain(c *Cipher) *CipherWithIDExport {
	blob := IsBlobData(c.Data.Val)
	e := &CipherWithIDExport{
		Type: c.Type, Favorite: c.Favorite, Reprompt: c.Reprompt, ID: c.ID,
		CollectionIDs:  Some(append([]string{}, c.CollectionIDs...)),
		OrganizationID: NullFromPtr(c.OrganizationID),
		FolderID:       NullFromPtr(c.FolderID),
		Notes:          FromPtr(c.Notes),
		Key:            FromPtr(c.Key),
		CreationDate:   c.CreationDate,
		RevisionDate:   c.RevisionDate,
		DeletedDate:    c.DeletedDate,
		ArchivedDate:   c.ArchivedDate,
	}
	if blob {
		e.Notes = Opt[string]{}
		e.Data = FromPtr(c.Data.Val)
		return e
	}
	e.Name = Some(derefStr(c.Name))
	if c.Fields != nil {
		e.Fields = []FieldExport{}
		for _, f := range c.Fields {
			e.Fields = append(e.Fields, FieldExport{Type: f.Type, Name: FromPtr(f.Name), Value: FromPtr(f.Value), LinkedID: NullFromPtr(f.LinkedID)})
		}
	}
	switch c.Type {
	case CipherTypeLogin:
		l := &LoginExport{}
		if d := c.Login; d != nil {
			if d.URIs != nil {
				l.URIs = []LoginURIExport{}
				for _, u := range d.URIs {
					l.URIs = append(l.URIs, LoginURIExport{URI: FromPtr(u.URI), URIChecksum: FromPtr(u.URIChecksum), Match: NullFromPtr(u.Match)})
				}
			}
			if d.Fido2Credentials != nil {
				l.Fido2Credentials = []Fido2CredentialExport{}
				for _, f := range d.Fido2Credentials {
					l.Fido2Credentials = append(l.Fido2Credentials, Fido2CredentialExport{
						CredentialID: derefStr(f.CredentialID), KeyType: derefStr(f.KeyType), KeyAlgorithm: derefStr(f.KeyAlgorithm),
						KeyCurve: derefStr(f.KeyCurve), KeyValue: derefStr(f.KeyValue), RpID: derefStr(f.RpID),
						Counter: derefStr(f.Counter), Discoverable: orDefault(f.Discoverable, "false"), CreationDate: f.CreationDate,
						UserHandle: FromPtr(f.UserHandle), UserName: FromPtr(f.UserName), RpName: FromPtr(f.RpName),
						UserDisplayName: FromPtr(f.UserDisplayName),
					})
				}
			}
			l.Username, l.Password, l.Totp = FromPtr(d.Username), FromPtr(d.Password), FromPtr(d.Totp)
		}
		e.Login = l
	case CipherTypeSecureNote:
		n := &SecureNoteExport{}
		if c.SecureNote != nil {
			n.Type = c.SecureNote.Type
		}
		e.SecureNote = n
	case CipherTypeCard:
		if d := c.Card; d != nil {
			e.Card = &CardExport{FromPtr(d.CardholderName), FromPtr(d.Brand), FromPtr(d.Number), FromPtr(d.ExpMonth), FromPtr(d.ExpYear), FromPtr(d.Code)}
		} else {
			e.Card = &CardExport{}
		}
	case CipherTypeIdentity:
		if d := c.Identity; d != nil {
			f := FromPtr[string]
			e.Identity = &IdentityExport{f(d.Title), f(d.FirstName), f(d.MiddleName), f(d.LastName), f(d.Address1),
				f(d.Address2), f(d.Address3), f(d.City), f(d.State), f(d.PostalCode), f(d.Country), f(d.Company),
				f(d.Email), f(d.Phone), f(d.SSN), f(d.Username), f(d.PassportNumber), f(d.LicenseNumber)}
		} else {
			e.Identity = &IdentityExport{}
		}
	case CipherTypeSshKey:
		s := &SshKeyExport{Some(""), Some(""), Some("")}
		if d := c.SshKey; d != nil {
			s = &SshKeyExport{Some(derefStr(d.PrivateKey)), Some(derefStr(d.PublicKey)), Some(derefStr(d.KeyFingerprint))}
		}
		e.SshKey = s
	case CipherTypeBankAccount:
		if d := c.BankAccount; d != nil {
			f := FromPtr[string]
			e.BankAccount = &BankAccountExport{f(d.BankName), f(d.NameOnAccount), f(d.AccountType), f(d.AccountNumber),
				f(d.RoutingNumber), f(d.BranchNumber), f(d.Pin), f(d.SwiftCode), f(d.Iban), f(d.BankContactPhone)}
		} else {
			e.BankAccount = &BankAccountExport{}
		}
	case CipherTypeDriversLicense:
		if d := c.DriversLicense; d != nil {
			f := FromPtr[string]
			e.DriversLicense = &DriversLicenseExport{f(d.FirstName), f(d.MiddleName), f(d.LastName), f(d.DateOfBirth),
				f(d.LicenseNumber), f(d.IssuingCountry), f(d.IssuingState), f(d.IssueDate), f(d.ExpirationDate),
				f(d.IssuingAuthority), f(d.LicenseClass)}
		} else {
			e.DriversLicense = &DriversLicenseExport{}
		}
	case CipherTypePassport:
		if d := c.Passport; d != nil {
			f := FromPtr[string]
			e.Passport = &PassportExport{f(d.Surname), f(d.GivenName), f(d.DateOfBirth), f(d.Sex), f(d.BirthPlace),
				f(d.Nationality), f(d.IssuingCountry), f(d.PassportNumber), f(d.PassportType),
				f(d.NationalIdentificationNumber), f(d.IssuingAuthority), f(d.IssueDate), f(d.ExpirationDate)}
		} else {
			e.Passport = &PassportExport{}
		}
	}
	if c.PasswordHistory != nil {
		e.PasswordHistory = []PasswordHistoryExport{}
		for _, p := range c.PasswordHistory {
			pe := PasswordHistoryExport{Password: Some(derefStr(p.Password))}
			if p.LastUsedDate != nil {
				pe.LastUsedDate = Some(*p.LastUsedDate)
			}
			e.PasswordHistory = append(e.PasswordHistory, pe)
		}
	}
	return e
}

func orDefault(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

// ---------- folder & collection ----------

// FolderExport is the folder JSON accepted by create/edit.
type FolderExport struct {
	ID   Opt[string] `json:"id,omitzero"`
	Name Opt[string] `json:"name,omitzero"`
}

// ToView mirrors FolderExport.toView (updates view in place; nil creates one).
func (f *FolderExport) ToView(view *FolderView) *FolderView {
	if view == nil {
		view = &FolderView{RevisionDate: time.Now().UTC()}
	}
	view.Name = f.Name.Get()
	return view
}

// FolderWithIDExport mirrors FolderWithIdExport output (order: name, id).
type FolderWithIDExport struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// BuildFolderExport mirrors `new FolderWithIdExport().build(view)`.
func BuildFolderExport(f *FolderView) FolderWithIDExport {
	return FolderWithIDExport{Name: f.Name, ID: f.ID}
}

// CollectionExport is the collection JSON accepted by create/edit (incl. org-collection's
// groups/users).
type CollectionExport struct {
	ID             Opt[string]         `json:"id,omitzero"`
	OrganizationID Opt[string]         `json:"organizationId,omitzero"`
	Name           Opt[string]         `json:"name,omitzero"`
	ExternalID     Opt[string]         `json:"externalId,omitzero"`
	Groups         []SelectionReadOnly `json:"groups"`
	Users          []SelectionReadOnly `json:"users"`
}

// ToView mirrors CollectionExport.toView(req, id).
func (c *CollectionExport) ToView(id string) *CollectionView {
	return &CollectionView{ID: id, OrganizationID: c.OrganizationID.Get(), Name: c.Name.Get(), ExternalID: c.ExternalID.Ptr()}
}

// CollectionWithIDExport mirrors CollectionWithIdExport output (order: id, organizationId, name, externalId).
type CollectionWithIDExport struct {
	ID             string      `json:"id"`
	OrganizationID string      `json:"organizationId"`
	Name           string      `json:"name"`
	ExternalID     Opt[string] `json:"externalId,omitzero"`
}

// BuildCollectionExport mirrors `new CollectionWithIdExport().build(view)`.
func BuildCollectionExport(c *CollectionView) CollectionWithIDExport {
	return CollectionWithIDExport{ID: c.ID, OrganizationID: c.OrganizationID, Name: c.DisplayName(), ExternalID: collectionExternalID(c)}
}

// collectionExternalID: decrypted collections carry externalId as null when absent; views built
// from user input keep it undefined.
func collectionExternalID(c *CollectionView) Opt[string] {
	if c.ExternalID == nil && c.Assigned {
		return Null[string]()
	}
	return FromPtr(c.ExternalID)
}

// ---------- templates ----------

// SelectionReadOnly mirrors apps/cli SelectionReadOnly (order: id, readOnly, hidePasswords, manage).
type SelectionReadOnly struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// SelectionReadOnlyTemplate mirrors SelectionReadOnly.template().
func SelectionReadOnlyTemplate() SelectionReadOnly { return SelectionReadOnly{ID: EmptyGUID} }

// TemplateNames lists the names accepted by `bw get template` (get.command.ts getTemplate),
// plus item.sshkey which has an export template but is not exposed by the Node CLI.
var TemplateNames = []string{
	"item", "item.field", "item.login", "item.login.uri", "item.card", "item.identity",
	"item.securenote", "item.bankaccount", "item.driverslicense", "item.passport", "folder",
	"collection", "item-collections", "org-collection",
}

// Template returns the `template()` value for a template name (case-insensitive), or false.
// item.bankaccount / item.driverslicense / item.passport are gated upstream by the
// pm-32009-new-item-types feature flag (default off); callers must apply that check.
func Template(name string) (any, bool) {
	switch strings.ToLower(name) {
	case "item":
		return OrderedObject{{"type", CipherTypeLogin}, {"favorite", false}, {"reprompt", RepromptNone},
			{"name", "Item name"}, {"notes", "Some notes about this item."}, {"fields", []any{}},
			{"passwordHistory", []any{}}}, true
	case "item.field":
		return OrderedObject{{"type", FieldTypeText}, {"name", "Field name"}, {"value", "Some value"}}, true
	case "item.login":
		return OrderedObject{{"uris", []any{}}, {"username", "jdoe"}, {"password", "myp@ssword123"},
			{"totp", "JBSWY3DPEHPK3PXP"}, {"fido2Credentials", []any{}}}, true
	case "item.login.uri":
		return OrderedObject{{"uri", "https://google.com"}}, true
	case "item.card":
		return OrderedObject{{"cardholderName", "John Doe"}, {"brand", "visa"}, {"number", "4242424242424242"},
			{"expMonth", "04"}, {"expYear", "2023"}, {"code", "123"}}, true
	case "item.identity":
		return OrderedObject{{"title", "Mr"}, {"firstName", "John"}, {"middleName", "William"}, {"lastName", "Doe"},
			{"address1", "123 Any St"}, {"address2", "Apt #123"}, {"city", "New York"}, {"state", "NY"},
			{"postalCode", "10001"}, {"country", "US"}, {"company", "Acme Inc."}, {"email", "john@company.com"},
			{"phone", "5555551234"}, {"ssn", "000-123-4567"}, {"username", "jdoe"},
			{"passportNumber", "US-123456789"}, {"licenseNumber", "D123-12-123-12333"}}, true
	case "item.securenote":
		return OrderedObject{{"type", SecureNoteTypeGeneric}}, true
	case "item.sshkey":
		return OrderedObject{{"privateKey", ""}, {"publicKey", ""}, {"keyFingerprint", ""}}, true
	case "item.bankaccount":
		return OrderedObject{{"bankName", "Acme Bank"}, {"nameOnAccount", "John Doe"}, {"accountType", "checking"},
			{"accountNumber", "000123456789"}, {"routingNumber", "000000000"}, {"branchNumber", "000"},
			{"pin", "1234"}, {"swiftCode", "ACMEUS33"}, {"iban", "GB00ACME12345600000001"},
			{"bankContactPhone", "1-800-123-4567"}}, true
	case "item.driverslicense":
		return OrderedObject{{"firstName", "Jane"}, {"middleName", "A."}, {"lastName", "Smith"},
			{"dateOfBirth", "1990-01-15"}, {"licenseNumber", "D12345678"}, {"issuingCountry", "US"},
			{"issuingState", "CA"}, {"issueDate", "2020-06-01"}, {"expirationDate", "2028-06-01"},
			{"issuingAuthority", "California DMV"}, {"licenseClass", "C"}}, true
	case "item.passport":
		return OrderedObject{{"surname", "Smith"}, {"givenName", "Jane"}, {"dateOfBirth", "1990-01-15"},
			{"sex", "F"}, {"birthPlace", "Los Angeles, CA"}, {"nationality", "USA"}, {"issuingCountry", "US"},
			{"passportNumber", "A12345678"}, {"passportType", "P"}, {"nationalIdentificationNumber", "123-45-6789"},
			{"issuingAuthority", "U.S. Department of State"}, {"issueDate", "2020-06-01"},
			{"expirationDate", "2030-06-01"}}, true
	case "item.fido2credential":
		return OrderedObject{{"credentialId", "keyId"}, {"keyType", "keyType"}, {"keyAlgorithm", "keyAlgorithm"},
			{"keyCurve", "keyCurve"}, {"keyValue", "keyValue"}, {"rpId", "rpId"}, {"counter", "counter"},
			{"discoverable", "false"}, {"creationDate", cli.Date{Time: time.Now()}}, {"userHandle", "userHandle"},
			{"userName", "userName"}, {"rpName", "rpName"}, {"userDisplayName", "userDisplayName"}}, true
	case "folder":
		return OrderedObject{{"name", "Folder name"}}, true
	case "collection":
		return OrderedObject{{"organizationId", EmptyGUID}, {"name", "Collection name"}, {"externalId", nil}}, true
	case "item-collections":
		return []string{"collection-id1", "collection-id2"}, true
	case "org-collection":
		sel := []SelectionReadOnly{SelectionReadOnlyTemplate(), SelectionReadOnlyTemplate()}
		return OrderedObject{{"organizationId", EmptyGUID}, {"name", "Collection name"}, {"externalId", nil},
			{"groups", sel}, {"users", sel}}, true
	}
	return nil, false
}
