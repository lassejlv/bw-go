package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// Blob ("v2") ciphers seal all sensitive content in the cipher's `data` field:
//
//	{"format_version":1,"wrapped_cek":"<EncString>","envelope":"<b64 COSE_Encrypt0>"}
//
// The envelope (DataEnvelope, namespace VaultItem) contains {"version":"1","content":CipherBlobV1};
// crypto.OpenBlob/SealBlob convert it to/from JSON. See sdk-internal
// crates/bitwarden-vault/src/cipher/blob and internal/crypto/envelope.go.

// IsBlobData reports whether a cipher `data` value is a sealed blob (CipherExport.isBlob).
func IsBlobData(data *string) bool { return data != nil && crypto.IsSealedBlob(*data) }

// CipherBlobV1 is the sealed content of a blob cipher.
type CipherBlobV1 struct {
	Name            string         `json:"name"`
	Notes           *string        `json:"notes"`
	TypeData        BlobTypeData   `json:"typeData"`
	Fields          []BlobField    `json:"fields"`
	PasswordHistory []BlobPassword `json:"passwordHistory"`
}

// BlobTypeData is the internally tagged CipherTypeDataV1 union ("type" discriminator in
// camelCase: login, card, identity, secureNote, sshKey, bankAccount, passport, driversLicense).
type BlobTypeData struct {
	Type string `json:"type"`
	// login
	Username             *string               `json:"username"`
	Password             *string               `json:"password"`
	PasswordRevisionDate *string               `json:"passwordRevisionDate"`
	URIs                 []BlobURI             `json:"uris"`
	Totp                 *string               `json:"totp"`
	AutofillOnPageLoad   *bool                 `json:"autofillOnPageLoad"`
	Fido2Credentials     []BlobFido2Credential `json:"fido2Credentials"`
	// card
	CardholderName *string `json:"cardholderName"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	// identity (+ shared names with drivers license / passport)
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
	// secure note
	SecureNoteType *SecureNoteType `json:"secureNoteType"`
	// ssh key
	PrivateKey  *string `json:"privateKey"`
	PublicKey   *string `json:"publicKey"`
	Fingerprint *string `json:"fingerprint"`
	// bank account
	BankName         *string `json:"bankName"`
	NameOnAccount    *string `json:"nameOnAccount"`
	AccountType      *string `json:"accountType"`
	AccountNumber    *string `json:"accountNumber"`
	RoutingNumber    *string `json:"routingNumber"`
	BranchNumber     *string `json:"branchNumber"`
	Pin              *string `json:"pin"`
	SwiftCode        *string `json:"swiftCode"`
	Iban             *string `json:"iban"`
	BankContactPhone *string `json:"bankContactPhone"`
	// passport / drivers license
	Surname                      *string `json:"surname"`
	GivenName                    *string `json:"givenName"`
	DateOfBirth                  *string `json:"dateOfBirth"`
	Sex                          *string `json:"sex"`
	BirthPlace                   *string `json:"birthPlace"`
	Nationality                  *string `json:"nationality"`
	IssuingCountry               *string `json:"issuingCountry"`
	IssuingState                 *string `json:"issuingState"`
	PassportType                 *string `json:"passportType"`
	NationalIdentificationNumber *string `json:"nationalIdentificationNumber"`
	IssuingAuthority             *string `json:"issuingAuthority"`
	IssueDate                    *string `json:"issueDate"`
	ExpirationDate               *string `json:"expirationDate"`
	LicenseClass                 *string `json:"licenseClass"`
}

// BlobURI is LoginUriDataV1.
type BlobURI struct {
	URI   *string   `json:"uri"`
	Match *UriMatch `json:"match"`
}

// BlobFido2Credential is Fido2CredentialDataV1.
type BlobFido2Credential struct {
	CredentialID    string  `json:"credentialId"`
	KeyType         string  `json:"keyType"`
	KeyAlgorithm    string  `json:"keyAlgorithm"`
	KeyCurve        string  `json:"keyCurve"`
	KeyValue        string  `json:"keyValue"`
	RpID            string  `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         uint64  `json:"counter"`
	RpName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    bool    `json:"discoverable"`
	CreationDate    string  `json:"creationDate"`
}

// BlobField is FieldDataV1.
type BlobField struct {
	Name     *string   `json:"name"`
	Value    *string   `json:"value"`
	Type     FieldType `json:"type"`
	LinkedID *LinkedID `json:"linkedId"`
}

// BlobPassword is PasswordHistoryDataV1.
type BlobPassword struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// decodeBlob opens a sealed blob with the cipher key and decodes the CipherBlobV1 content.
func decodeBlob(data string, cipherKey *crypto.SymmetricKey) (*CipherBlobV1, error) {
	j, err := crypto.OpenBlob(data, cipherKey)
	if err != nil {
		return nil, err
	}
	return decodeBlobJSON(j)
}

// decodeBlobJSON decodes the versioned content {"version":"1","content":CipherBlobV1}.
func decodeBlobJSON(j []byte) (*CipherBlobV1, error) {
	var versioned struct {
		Version string          `json:"version"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(j, &versioned); err != nil {
		return nil, err
	}
	if versioned.Version != "1" {
		return nil, fmt.Errorf("unsupported cipher blob version %q", versioned.Version)
	}
	blob := &CipherBlobV1{}
	if err := json.Unmarshal(versioned.Content, blob); err != nil {
		return nil, err
	}
	return blob, nil
}

// encodeBlob seals a CipherBlobV1 with a fresh CEK wrapped by the cipher key and returns the
// opaque `data` string.
func encodeBlob(blob *CipherBlobV1, cipherKey *crypto.SymmetricKey) (string, error) {
	j, err := blobVersionedJSON(blob)
	if err != nil {
		return "", err
	}
	return crypto.SealBlob(j, cipherKey)
}

func blobVersionedJSON(blob *CipherBlobV1) ([]byte, error) {
	return marshalNoEscape(OrderedObject{{"version", "1"}, {"content", blob.blobJSON()}})
}

func blobStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// blobJSON builds CipherBlobV1 in serde field order (empty fields/passwordHistory omitted).
func (b *CipherBlobV1) blobJSON() OrderedObject {
	m := OrderedObject{{"name", b.Name}, {"notes", blobStr(b.Notes)}, {"typeData", b.TypeData.blobJSON()}}
	if len(b.Fields) > 0 {
		arr := []any{}
		for _, f := range b.Fields {
			var linked any
			if f.LinkedID != nil {
				linked = int64(*f.LinkedID)
			}
			arr = append(arr, OrderedObject{{"name", blobStr(f.Name)}, {"value", blobStr(f.Value)},
				{"type", int64(f.Type)}, {"linkedId", linked}})
		}
		m = append(m, kv{"fields", arr})
	}
	if len(b.PasswordHistory) > 0 {
		arr := []any{}
		for _, p := range b.PasswordHistory {
			arr = append(arr, OrderedObject{{"password", p.Password}, {"lastUsedDate", p.LastUsedDate}})
		}
		m = append(m, kv{"passwordHistory", arr})
	}
	return m
}

func (t *BlobTypeData) blobJSON() OrderedObject {
	s := blobStr
	m := OrderedObject{{"type", t.Type}}
	add := func(k string, v any) { m = append(m, kv{k, v}) }
	switch t.Type {
	case "login":
		add("username", s(t.Username))
		add("password", s(t.Password))
		add("passwordRevisionDate", s(t.PasswordRevisionDate))
		if len(t.URIs) > 0 {
			arr := []any{}
			for _, u := range t.URIs {
				var match any
				if u.Match != nil {
					match = int64(*u.Match)
				}
				arr = append(arr, OrderedObject{{"uri", s(u.URI)}, {"match", match}})
			}
			add("uris", arr)
		}
		add("totp", s(t.Totp))
		if t.AutofillOnPageLoad != nil {
			add("autofillOnPageLoad", *t.AutofillOnPageLoad)
		} else {
			add("autofillOnPageLoad", nil)
		}
		if len(t.Fido2Credentials) > 0 {
			arr := []any{}
			for _, f := range t.Fido2Credentials {
				arr = append(arr, OrderedObject{{"credentialId", f.CredentialID}, {"keyType", f.KeyType},
					{"keyAlgorithm", f.KeyAlgorithm}, {"keyCurve", f.KeyCurve}, {"keyValue", f.KeyValue},
					{"rpId", f.RpID}, {"userHandle", s(f.UserHandle)}, {"userName", s(f.UserName)},
					{"counter", f.Counter}, {"rpName", s(f.RpName)}, {"userDisplayName", s(f.UserDisplayName)},
					{"discoverable", f.Discoverable}, {"creationDate", f.CreationDate}})
			}
			add("fido2Credentials", arr)
		}
	case "card":
		add("cardholderName", s(t.CardholderName))
		add("expMonth", s(t.ExpMonth))
		add("expYear", s(t.ExpYear))
		add("code", s(t.Code))
		add("brand", s(t.Brand))
		add("number", s(t.Number))
	case "identity":
		for _, kv := range []struct {
			k string
			v *string
		}{{"title", t.Title}, {"firstName", t.FirstName}, {"middleName", t.MiddleName},
			{"lastName", t.LastName}, {"address1", t.Address1}, {"address2", t.Address2},
			{"address3", t.Address3}, {"city", t.City}, {"state", t.State}, {"postalCode", t.PostalCode},
			{"country", t.Country}, {"company", t.Company}, {"email", t.Email}, {"phone", t.Phone},
			{"ssn", t.SSN}, {"username", t.Username}, {"passportNumber", t.PassportNumber},
			{"licenseNumber", t.LicenseNumber}} {
			add(kv.k, s(kv.v))
		}
	case "secureNote":
		nt := int64(0)
		if t.SecureNoteType != nil {
			nt = int64(*t.SecureNoteType)
		}
		add("secureNoteType", nt)
	case "sshKey":
		add("privateKey", derefStr(t.PrivateKey))
		add("publicKey", derefStr(t.PublicKey))
		add("fingerprint", derefStr(t.Fingerprint))
	case "bankAccount":
		for _, kv := range []struct {
			k string
			v *string
		}{{"bankName", t.BankName}, {"nameOnAccount", t.NameOnAccount}, {"accountType", t.AccountType},
			{"accountNumber", t.AccountNumber}, {"routingNumber", t.RoutingNumber},
			{"branchNumber", t.BranchNumber}, {"pin", t.Pin}, {"swiftCode", t.SwiftCode},
			{"iban", t.Iban}, {"bankContactPhone", t.BankContactPhone}} {
			add(kv.k, s(kv.v))
		}
	case "passport":
		for _, kv := range []struct {
			k string
			v *string
		}{{"surname", t.Surname}, {"givenName", t.GivenName}, {"dateOfBirth", t.DateOfBirth},
			{"sex", t.Sex}, {"birthPlace", t.BirthPlace}, {"nationality", t.Nationality},
			{"issuingCountry", t.IssuingCountry}, {"passportNumber", t.PassportNumber},
			{"passportType", t.PassportType}, {"nationalIdentificationNumber", t.NationalIdentificationNumber},
			{"issuingAuthority", t.IssuingAuthority}, {"issueDate", t.IssueDate},
			{"expirationDate", t.ExpirationDate}} {
			add(kv.k, s(kv.v))
		}
	case "driversLicense":
		for _, kv := range []struct {
			k string
			v *string
		}{{"firstName", t.FirstName}, {"middleName", t.MiddleName}, {"lastName", t.LastName},
			{"dateOfBirth", t.DateOfBirth}, {"licenseNumber", t.LicenseNumber},
			{"issuingCountry", t.IssuingCountry}, {"issuingState", t.IssuingState},
			{"issueDate", t.IssueDate}, {"expirationDate", t.ExpirationDate},
			{"issuingAuthority", t.IssuingAuthority}, {"licenseClass", t.LicenseClass}} {
			add(kv.k, s(kv.v))
		}
	}
	return m
}

var blobTypeNames = map[CipherType]string{
	CipherTypeLogin: "login", CipherTypeCard: "card", CipherTypeIdentity: "identity",
	CipherTypeSecureNote: "secureNote", CipherTypeSshKey: "sshKey", CipherTypeBankAccount: "bankAccount",
	CipherTypePassport: "passport", CipherTypeDriversLicense: "driversLicense",
}

// chronoTime formats like chrono's DateTime<Utc> serde (RFC 3339, AutoSi fraction, "Z").
func chronoTime(t time.Time) string {
	t = t.UTC()
	ns := t.Nanosecond()
	base := t.Format("2006-01-02T15:04:05")
	switch {
	case ns == 0:
		return base + "Z"
	case ns%1_000_000 == 0:
		return fmt.Sprintf("%s.%03dZ", base, ns/1_000_000)
	case ns%1_000 == 0:
		return fmt.Sprintf("%s.%06dZ", base, ns/1_000)
	default:
		return fmt.Sprintf("%s.%09dZ", base, ns)
	}
}

func parseTimePtr(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

// applyBlob fills the content of a view from a decoded blob (conversions/mod.rs to_cipher_view).
func applyBlob(v *CipherView, b *CipherBlobV1) {
	v.Name = b.Name
	v.Notes = b.Notes
	t := &b.TypeData
	switch v.Type {
	case CipherTypeLogin:
		l := &LoginView{Username: t.Username, Password: t.Password, Totp: t.Totp,
			AutofillOnPageLoad: t.AutofillOnPageLoad, PasswordRevisionDate: parseTimePtr(t.PasswordRevisionDate),
			URIs: []LoginURIView{}, Fido2Credentials: []Fido2CredentialView{}}
		for _, u := range t.URIs {
			if u.URI == nil || *u.URI == "" {
				continue
			}
			l.URIs = append(l.URIs, LoginURIView{URI: u.URI, Match: u.Match})
		}
		for _, f := range t.Fido2Credentials {
			l.Fido2Credentials = append(l.Fido2Credentials, Fido2CredentialView{
				CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
				KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle,
				UserName: f.UserName, Counter: strconv.FormatUint(f.Counter, 10), RpName: f.RpName,
				UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable,
				CreationDate: parseTimePtr(&f.CreationDate),
			})
		}
		v.Login = l
	case CipherTypeCard:
		v.Card = &CardView{CardholderName: t.CardholderName, Brand: t.Brand, Number: t.Number,
			ExpMonth: t.ExpMonth, ExpYear: t.ExpYear, Code: t.Code}
	case CipherTypeIdentity:
		v.Identity = &IdentityView{Title: t.Title, FirstName: t.FirstName, MiddleName: t.MiddleName,
			LastName: t.LastName, Address1: t.Address1, Address2: t.Address2, Address3: t.Address3,
			City: t.City, State: t.State, PostalCode: t.PostalCode, Country: t.Country,
			Company: t.Company, Email: t.Email, Phone: t.Phone, SSN: t.SSN, Username: t.Username,
			PassportNumber: t.PassportNumber, LicenseNumber: t.LicenseNumber}
	case CipherTypeSecureNote:
		n := &SecureNoteView{}
		if t.SecureNoteType != nil {
			n.Type = *t.SecureNoteType
		}
		v.SecureNote = n
	case CipherTypeSshKey:
		v.SshKey = &SshKeyView{PrivateKey: derefStr(t.PrivateKey), PublicKey: derefStr(t.PublicKey),
			KeyFingerprint: derefStr(t.Fingerprint)}
	case CipherTypeBankAccount:
		v.BankAccount = &BankAccountView{BankName: t.BankName, NameOnAccount: t.NameOnAccount,
			AccountType: t.AccountType, AccountNumber: t.AccountNumber, RoutingNumber: t.RoutingNumber,
			BranchNumber: t.BranchNumber, Pin: t.Pin, SwiftCode: t.SwiftCode, Iban: t.Iban,
			BankContactPhone: t.BankContactPhone}
	case CipherTypeDriversLicense:
		v.DriversLicense = &DriversLicenseView{FirstName: t.FirstName, MiddleName: t.MiddleName,
			LastName: t.LastName, DateOfBirth: t.DateOfBirth, LicenseNumber: t.LicenseNumber,
			IssuingCountry: t.IssuingCountry, IssuingState: t.IssuingState, IssueDate: t.IssueDate,
			ExpirationDate: t.ExpirationDate, IssuingAuthority: t.IssuingAuthority, LicenseClass: t.LicenseClass}
	case CipherTypePassport:
		v.Passport = &PassportView{Surname: t.Surname, GivenName: t.GivenName, DateOfBirth: t.DateOfBirth,
			Sex: t.Sex, BirthPlace: t.BirthPlace, Nationality: t.Nationality, IssuingCountry: t.IssuingCountry,
			PassportNumber: t.PassportNumber, PassportType: t.PassportType,
			NationalIdentificationNumber: t.NationalIdentificationNumber, IssuingAuthority: t.IssuingAuthority,
			IssueDate: t.IssueDate, ExpirationDate: t.ExpirationDate}
	}
	v.Fields = []FieldView{}
	for _, f := range b.Fields {
		v.Fields = append(v.Fields, FieldView{Name: f.Name, Value: f.Value, Type: f.Type, LinkedID: f.LinkedID})
	}
	v.PasswordHistory = []PasswordHistoryView{}
	for _, p := range b.PasswordHistory {
		pw := p.Password
		v.PasswordHistory = append(v.PasswordHistory, PasswordHistoryView{Password: &pw, LastUsedDate: parseTimePtr(&p.LastUsedDate)})
	}
}

// blobFromView builds a CipherBlobV1 from a view (CipherBlobV1::from_cipher_view).
func blobFromView(v *CipherView) (*CipherBlobV1, error) {
	name, ok := blobTypeNames[v.Type]
	if !ok {
		return nil, fmt.Errorf("unsupported cipher type %d", v.Type)
	}
	b := &CipherBlobV1{Name: v.Name, Notes: v.Notes, TypeData: BlobTypeData{Type: name}}
	t := &b.TypeData
	switch v.Type {
	case CipherTypeLogin:
		l := v.Login
		if l == nil {
			return nil, errors.New("Missing field: login")
		}
		t.Username, t.Password, t.AutofillOnPageLoad = l.Username, l.Password, l.AutofillOnPageLoad
		if l.Totp != nil && *l.Totp != "" {
			t.Totp = l.Totp
		}
		if l.PasswordRevisionDate != nil {
			s := chronoTime(*l.PasswordRevisionDate)
			t.PasswordRevisionDate = &s
		}
		for _, u := range l.URIs {
			t.URIs = append(t.URIs, BlobURI{URI: u.URI, Match: u.Match})
		}
		for _, f := range l.Fido2Credentials {
			counter, _ := strconv.ParseUint(strings.TrimSpace(f.Counter), 10, 64)
			cd := ""
			if f.CreationDate != nil {
				cd = chronoTime(*f.CreationDate)
			}
			t.Fido2Credentials = append(t.Fido2Credentials, BlobFido2Credential{
				CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
				KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: f.UserHandle,
				UserName: f.UserName, Counter: counter, RpName: f.RpName, UserDisplayName: f.UserDisplayName,
				Discoverable: f.Discoverable, CreationDate: cd})
		}
	case CipherTypeCard:
		c := v.Card
		if c == nil {
			return nil, errors.New("Missing field: card")
		}
		t.CardholderName, t.Brand, t.Number, t.ExpMonth, t.ExpYear, t.Code =
			c.CardholderName, c.Brand, c.Number, c.ExpMonth, c.ExpYear, c.Code
	case CipherTypeIdentity:
		i := v.Identity
		if i == nil {
			return nil, errors.New("Missing field: identity")
		}
		t.Title, t.FirstName, t.MiddleName, t.LastName = i.Title, i.FirstName, i.MiddleName, i.LastName
		t.Address1, t.Address2, t.Address3, t.City, t.State = i.Address1, i.Address2, i.Address3, i.City, i.State
		t.PostalCode, t.Country, t.Company, t.Email, t.Phone = i.PostalCode, i.Country, i.Company, i.Email, i.Phone
		t.SSN, t.Username, t.PassportNumber, t.LicenseNumber = i.SSN, i.Username, i.PassportNumber, i.LicenseNumber
	case CipherTypeSecureNote:
		nt := SecureNoteTypeGeneric
		if v.SecureNote != nil {
			nt = v.SecureNote.Type
		}
		t.SecureNoteType = &nt
	case CipherTypeSshKey:
		s := v.SshKey
		if s == nil {
			return nil, errors.New("Missing field: sshKey")
		}
		pub, fp := s.PublicKey, s.KeyFingerprint
		if pub == "" || fp == "" {
			dp, dfp := deriveSSHPublicKeyAndFingerprint(s.PrivateKey)
			if pub == "" {
				pub = dp
			}
			if fp == "" {
				fp = dfp
			}
		}
		t.PrivateKey, t.PublicKey, t.Fingerprint = strPtr(s.PrivateKey), &pub, &fp
	case CipherTypeBankAccount:
		a := v.BankAccount
		if a == nil {
			return nil, errors.New("Missing field: bankAccount")
		}
		t.BankName, t.NameOnAccount, t.AccountType, t.AccountNumber = a.BankName, a.NameOnAccount, a.AccountType, a.AccountNumber
		t.RoutingNumber, t.BranchNumber, t.Pin, t.SwiftCode = a.RoutingNumber, a.BranchNumber, a.Pin, a.SwiftCode
		t.Iban, t.BankContactPhone = a.Iban, a.BankContactPhone
	case CipherTypeDriversLicense:
		d := v.DriversLicense
		if d == nil {
			return nil, errors.New("Missing field: driversLicense")
		}
		t.FirstName, t.MiddleName, t.LastName, t.DateOfBirth = d.FirstName, d.MiddleName, d.LastName, d.DateOfBirth
		t.LicenseNumber, t.IssuingCountry, t.IssuingState, t.IssueDate = d.LicenseNumber, d.IssuingCountry, d.IssuingState, d.IssueDate
		t.ExpirationDate, t.IssuingAuthority, t.LicenseClass = d.ExpirationDate, d.IssuingAuthority, d.LicenseClass
	case CipherTypePassport:
		p := v.Passport
		if p == nil {
			return nil, errors.New("Missing field: passport")
		}
		t.Surname, t.GivenName, t.DateOfBirth, t.Sex, t.BirthPlace = p.Surname, p.GivenName, p.DateOfBirth, p.Sex, p.BirthPlace
		t.Nationality, t.IssuingCountry, t.PassportNumber, t.PassportType = p.Nationality, p.IssuingCountry, p.PassportNumber, p.PassportType
		t.NationalIdentificationNumber, t.IssuingAuthority = p.NationalIdentificationNumber, p.IssuingAuthority
		t.IssueDate, t.ExpirationDate = p.IssueDate, p.ExpirationDate
	}
	for _, f := range v.Fields {
		b.Fields = append(b.Fields, BlobField{Name: f.Name, Value: f.Value, Type: f.Type, LinkedID: f.LinkedID})
	}
	for _, p := range v.PasswordHistory {
		lu := ""
		if p.LastUsedDate != nil {
			lu = chronoTime(*p.LastUsedDate)
		}
		b.PasswordHistory = append(b.PasswordHistory, BlobPassword{Password: derefStr(p.Password), LastUsedDate: lu})
	}
	return b, nil
}
