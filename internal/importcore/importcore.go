// Package importcore connects the importer package (format parsing, internal/importer) with the
// vault domain layer (internal/vault) for `bw import`: it decrypts account-encrypted Bitwarden
// exports (importer.Decryptor), converts importer views to vault views, encrypts an ImportResult
// into the POST /ciphers/import[-organization] request bodies and maps server validation errors.
package importcore

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ---------- Decryptor ----------

// Decryptor implements importer.Decryptor with the unlocked account's keys.
type Decryptor struct{ Keys *vault.Keys }

var _ importer.Decryptor = (*Decryptor)(nil)

// NewDecryptor returns a Decryptor for keys.
func NewDecryptor(keys *vault.Keys) *Decryptor { return &Decryptor{Keys: keys} }

// UserKey implements importer.AccountKeys.
func (d *Decryptor) UserKey() (*crypto.SymmetricKey, error) {
	if d.Keys == nil || d.Keys.UserKey() == nil {
		return nil, vault.ErrNoKey
	}
	return d.Keys.UserKey(), nil
}

// OrgKey implements importer.AccountKeys: (nil, nil) when the account has no key for the
// organization (like a missing entry in keyService.orgKeys$).
func (d *Decryptor) OrgKey(organizationID string) (*crypto.SymmetricKey, error) {
	if d.Keys == nil || organizationID == "" {
		return nil, nil
	}
	k, err := d.Keys.OrgKey(organizationID)
	if err != nil {
		return nil, nil
	}
	return k, nil
}

// DecryptExportCipher implements importer.Decryptor: CipherWithIdExport.toDomain (id and
// collectionIds reset, organizationId replaced, password history capped at 5) followed by
// CipherService.decrypt. Legacy field-level EncStrings, per-cipher keys and v2 blob ciphers
// ("data") are handled by vault.DecryptCipher.
func (d *Decryptor) DecryptExportCipher(item json.RawMessage, organizationID string) (*model.CipherView, error) {
	c, err := vault.ParseCipher(item)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	c.ID = ""
	c.CollectionIDs = nil
	c.OrganizationID = nil
	if organizationID != "" {
		org := organizationID
		c.OrganizationID = &org
	}
	if len(c.PasswordHistory) > 5 {
		c.PasswordHistory = c.PasswordHistory[:5]
	}
	v, err := vault.DecryptCipher(c, d.Keys)
	if err != nil {
		return nil, err
	}
	return FromVaultView(v), nil
}

// ---------- view conversion ----------

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// opt maps the importer model's "" (null/undefined) to nil.
func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timePtr(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	c := *t
	return &c
}

// FromVaultView converts a decrypted vault view into the importer model.
func FromVaultView(v *vault.CipherView) *model.CipherView {
	m := model.NewCipherView()
	m.ID = v.ID
	m.OrganizationID = deref(v.OrganizationID)
	m.FolderID = deref(v.FolderID)
	m.Name = v.Name
	m.Notes = deref(v.Notes)
	m.Type = model.CipherType(v.Type)
	m.Favorite = v.Favorite
	m.Reprompt = model.CipherRepromptType(v.Reprompt)
	m.CollectionIDs = append([]string(nil), v.CollectionIDs...)
	if !v.CreationDate.IsZero() {
		t := v.CreationDate
		m.CreationDate = &t
	}
	if !v.RevisionDate.IsZero() {
		t := v.RevisionDate
		m.RevisionDate = &t
	}
	m.DeletedDate = timePtr(v.DeletedDate)
	m.ArchivedDate = timePtr(v.ArchivedDate)

	if l := v.Login; l != nil {
		ml := &model.LoginView{
			Username: deref(l.Username), Password: deref(l.Password), Totp: deref(l.Totp),
			PasswordRevisionDate: timePtr(l.PasswordRevisionDate), AutofillOnPageLoad: l.AutofillOnPageLoad,
		}
		if l.URIs != nil {
			ml.Uris = make([]*model.LoginUriView, 0, len(l.URIs))
			for _, u := range l.URIs {
				uv := &model.LoginUriView{Uri: deref(u.URI)}
				if u.Match != nil {
					mm := model.UriMatchStrategy(*u.Match)
					uv.Match = &mm
				}
				ml.Uris = append(ml.Uris, uv)
			}
		}
		if l.Fido2Credentials != nil {
			ml.Fido2Credentials = make([]*model.Fido2CredentialView, 0, len(l.Fido2Credentials))
			for _, f := range l.Fido2Credentials {
				fv := &model.Fido2CredentialView{
					CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
					KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: deref(f.UserHandle),
					UserName: deref(f.UserName), RpName: deref(f.RpName), UserDisplayName: deref(f.UserDisplayName),
					Discoverable: f.Discoverable,
				}
				fv.Counter, _ = importer.ParseInt(f.Counter)
				if f.CreationDate != nil {
					fv.CreationDate = *f.CreationDate
				}
				ml.Fido2Credentials = append(ml.Fido2Credentials, fv)
			}
		}
		m.Login = ml
	}
	if s := v.SecureNote; s != nil {
		m.SecureNote = &model.SecureNoteView{Type: model.SecureNoteType(s.Type)}
	}
	if c := v.Card; c != nil {
		m.Card = &model.CardView{CardholderName: deref(c.CardholderName), Brand: deref(c.Brand), Number: deref(c.Number),
			ExpMonth: deref(c.ExpMonth), ExpYear: deref(c.ExpYear), Code: deref(c.Code)}
	}
	if i := v.Identity; i != nil {
		m.Identity = &model.IdentityView{Title: deref(i.Title), FirstName: deref(i.FirstName), MiddleName: deref(i.MiddleName),
			LastName: deref(i.LastName), Address1: deref(i.Address1), Address2: deref(i.Address2), Address3: deref(i.Address3),
			City: deref(i.City), State: deref(i.State), PostalCode: deref(i.PostalCode), Country: deref(i.Country),
			Company: deref(i.Company), Email: deref(i.Email), Phone: deref(i.Phone), Ssn: deref(i.SSN),
			Username: deref(i.Username), PassportNumber: deref(i.PassportNumber), LicenseNumber: deref(i.LicenseNumber)}
	}
	if s := v.SshKey; s != nil {
		m.SshKey = &model.SshKeyView{PrivateKey: s.PrivateKey, PublicKey: s.PublicKey, KeyFingerprint: s.KeyFingerprint}
	}
	if b := v.BankAccount; b != nil {
		m.BankAccount = &model.BankAccountView{BankName: deref(b.BankName), NameOnAccount: deref(b.NameOnAccount),
			AccountType: deref(b.AccountType), AccountNumber: deref(b.AccountNumber), RoutingNumber: deref(b.RoutingNumber),
			BranchNumber: deref(b.BranchNumber), Pin: deref(b.Pin), SwiftCode: deref(b.SwiftCode), Iban: deref(b.Iban),
			BankContactPhone: deref(b.BankContactPhone)}
	}
	if d := v.DriversLicense; d != nil {
		m.DriversLicense = &model.DriversLicenseView{FirstName: deref(d.FirstName), MiddleName: deref(d.MiddleName),
			LastName: deref(d.LastName), DateOfBirth: deref(d.DateOfBirth), LicenseNumber: deref(d.LicenseNumber),
			IssuingCountry: deref(d.IssuingCountry), IssuingState: deref(d.IssuingState), IssueDate: deref(d.IssueDate),
			ExpirationDate: deref(d.ExpirationDate), IssuingAuthority: deref(d.IssuingAuthority), LicenseClass: deref(d.LicenseClass)}
	}
	if p := v.Passport; p != nil {
		m.Passport = &model.PassportView{Surname: deref(p.Surname), GivenName: deref(p.GivenName), DateOfBirth: deref(p.DateOfBirth),
			Sex: deref(p.Sex), BirthPlace: deref(p.BirthPlace), Nationality: deref(p.Nationality),
			IssuingCountry: deref(p.IssuingCountry), PassportNumber: deref(p.PassportNumber), PassportType: deref(p.PassportType),
			NationalIdentificationNumber: deref(p.NationalIdentificationNumber), IssuingAuthority: deref(p.IssuingAuthority),
			IssueDate: deref(p.IssueDate), ExpirationDate: deref(p.ExpirationDate)}
	}
	if v.Fields != nil {
		m.Fields = make([]*model.FieldView, 0, len(v.Fields))
		for _, f := range v.Fields {
			fv := &model.FieldView{Name: deref(f.Name), Value: deref(f.Value), Type: model.FieldType(f.Type)}
			if f.LinkedID != nil {
				l := model.LinkedIdType(*f.LinkedID)
				fv.LinkedID = &l
			}
			m.Fields = append(m.Fields, fv)
		}
	}
	if v.PasswordHistory != nil {
		m.PasswordHistory = make([]*model.PasswordHistoryView, 0, len(v.PasswordHistory))
		for _, p := range v.PasswordHistory {
			pv := &model.PasswordHistoryView{Password: deref(p.Password), LastUsedDate: time.Now().UTC()}
			if p.LastUsedDate != nil {
				pv.LastUsedDate = *p.LastUsedDate
			}
			m.PasswordHistory = append(m.PasswordHistory, pv)
		}
	}
	return m
}

// ToVaultView converts an importer view into a vault view ready for vault.EncryptCipher
// (CipherView.toSdkCipherView). "" becomes nil for every optional value; the name is always set.
// Missing creation/revision dates keep `new CipherView()`'s "now".
func ToVaultView(m *model.CipherView) *vault.CipherView {
	v := vault.NewCipherView()
	v.ID = m.ID
	v.OrganizationID = opt(m.OrganizationID)
	v.FolderID = opt(m.FolderID)
	v.Name = m.Name
	v.Notes = opt(m.Notes)
	v.Type = vault.CipherType(m.Type)
	v.Favorite = m.Favorite
	v.Reprompt = vault.RepromptType(m.Reprompt)
	v.CollectionIDs = append([]string{}, m.CollectionIDs...)
	if m.CreationDate != nil {
		v.CreationDate = *m.CreationDate
	}
	if m.RevisionDate != nil {
		v.RevisionDate = *m.RevisionDate
	}
	v.DeletedDate = timePtr(m.DeletedDate)
	v.ArchivedDate = timePtr(m.ArchivedDate)

	v.Login = nil
	if l := m.Login; l != nil {
		vl := &vault.LoginView{
			Username: opt(l.Username), Password: opt(l.Password), Totp: opt(l.Totp),
			PasswordRevisionDate: timePtr(l.PasswordRevisionDate), AutofillOnPageLoad: l.AutofillOnPageLoad,
			URIs: []vault.LoginURIView{},
		}
		for _, u := range l.Uris {
			if u == nil {
				continue
			}
			uv := vault.LoginURIView{URI: opt(u.Uri)}
			if u.Match != nil {
				mm := vault.UriMatch(*u.Match)
				uv.Match = &mm
			}
			vl.URIs = append(vl.URIs, uv)
		}
		if l.Fido2Credentials != nil {
			vl.Fido2Credentials = []vault.Fido2CredentialView{}
			for _, f := range l.Fido2Credentials {
				if f == nil {
					continue
				}
				fv := vault.Fido2CredentialView{
					CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
					KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, UserHandle: opt(f.UserHandle),
					UserName: opt(f.UserName), Counter: strconv.Itoa(f.Counter), RpName: opt(f.RpName),
					UserDisplayName: opt(f.UserDisplayName), Discoverable: f.Discoverable,
				}
				if !f.CreationDate.IsZero() {
					t := f.CreationDate
					fv.CreationDate = &t
				}
				vl.Fido2Credentials = append(vl.Fido2Credentials, fv)
			}
		}
		v.Login = vl
	}
	v.SecureNote = nil
	if s := m.SecureNote; s != nil {
		v.SecureNote = &vault.SecureNoteView{Type: vault.SecureNoteType(s.Type)}
	}
	v.Card = nil
	if c := m.Card; c != nil {
		v.Card = &vault.CardView{CardholderName: opt(c.CardholderName), Brand: opt(c.Brand), Number: opt(c.Number),
			ExpMonth: opt(c.ExpMonth), ExpYear: opt(c.ExpYear), Code: opt(c.Code)}
	}
	v.Identity = nil
	if i := m.Identity; i != nil {
		v.Identity = &vault.IdentityView{Title: opt(i.Title), FirstName: opt(i.FirstName), MiddleName: opt(i.MiddleName),
			LastName: opt(i.LastName), Address1: opt(i.Address1), Address2: opt(i.Address2), Address3: opt(i.Address3),
			City: opt(i.City), State: opt(i.State), PostalCode: opt(i.PostalCode), Country: opt(i.Country),
			Company: opt(i.Company), Email: opt(i.Email), Phone: opt(i.Phone), SSN: opt(i.Ssn),
			Username: opt(i.Username), PassportNumber: opt(i.PassportNumber), LicenseNumber: opt(i.LicenseNumber)}
	}
	v.SshKey = nil
	if s := m.SshKey; s != nil {
		v.SshKey = &vault.SshKeyView{PrivateKey: s.PrivateKey, PublicKey: s.PublicKey, KeyFingerprint: s.KeyFingerprint}
	}
	v.BankAccount = nil
	if b := m.BankAccount; b != nil {
		v.BankAccount = &vault.BankAccountView{BankName: opt(b.BankName), NameOnAccount: opt(b.NameOnAccount),
			AccountType: opt(b.AccountType), AccountNumber: opt(b.AccountNumber), RoutingNumber: opt(b.RoutingNumber),
			BranchNumber: opt(b.BranchNumber), Pin: opt(b.Pin), SwiftCode: opt(b.SwiftCode), Iban: opt(b.Iban),
			BankContactPhone: opt(b.BankContactPhone)}
	}
	v.DriversLicense = nil
	if d := m.DriversLicense; d != nil {
		v.DriversLicense = &vault.DriversLicenseView{FirstName: opt(d.FirstName), MiddleName: opt(d.MiddleName),
			LastName: opt(d.LastName), DateOfBirth: opt(d.DateOfBirth), LicenseNumber: opt(d.LicenseNumber),
			IssuingCountry: opt(d.IssuingCountry), IssuingState: opt(d.IssuingState), IssueDate: opt(d.IssueDate),
			ExpirationDate: opt(d.ExpirationDate), IssuingAuthority: opt(d.IssuingAuthority), LicenseClass: opt(d.LicenseClass)}
	}
	v.Passport = nil
	if p := m.Passport; p != nil {
		v.Passport = &vault.PassportView{Surname: opt(p.Surname), GivenName: opt(p.GivenName), DateOfBirth: opt(p.DateOfBirth),
			Sex: opt(p.Sex), BirthPlace: opt(p.BirthPlace), Nationality: opt(p.Nationality),
			IssuingCountry: opt(p.IssuingCountry), PassportNumber: opt(p.PassportNumber), PassportType: opt(p.PassportType),
			NationalIdentificationNumber: opt(p.NationalIdentificationNumber), IssuingAuthority: opt(p.IssuingAuthority),
			IssueDate: opt(p.IssueDate), ExpirationDate: opt(p.ExpirationDate)}
	}
	ensureOwnTypeView(v)

	v.Fields = nil
	if m.Fields != nil {
		v.Fields = []vault.FieldView{}
		for _, f := range m.Fields {
			if f == nil {
				continue
			}
			fv := vault.FieldView{Name: opt(f.Name), Value: opt(f.Value), Type: vault.FieldType(f.Type)}
			if f.LinkedID != nil {
				l := vault.LinkedID(*f.LinkedID)
				fv.LinkedID = &l
			}
			v.Fields = append(v.Fields, fv)
		}
	}
	v.PasswordHistory = nil
	if m.PasswordHistory != nil {
		v.PasswordHistory = []vault.PasswordHistoryView{}
		for _, p := range m.PasswordHistory {
			if p == nil {
				continue
			}
			pw := p.Password
			pv := vault.PasswordHistoryView{Password: &pw}
			if !p.LastUsedDate.IsZero() {
				t := p.LastUsedDate
				pv.LastUsedDate = &t
			}
			v.PasswordHistory = append(v.PasswordHistory, pv)
		}
	}
	return v
}

// ensureOwnTypeView allocates the view matching the cipher type when the importer left it nil.
func ensureOwnTypeView(v *vault.CipherView) {
	switch v.Type {
	case vault.CipherTypeLogin:
		if v.Login == nil {
			v.Login = &vault.LoginView{URIs: []vault.LoginURIView{}}
		}
	case vault.CipherTypeSecureNote:
		if v.SecureNote == nil {
			v.SecureNote = &vault.SecureNoteView{}
		}
	case vault.CipherTypeCard:
		if v.Card == nil {
			v.Card = &vault.CardView{}
		}
	case vault.CipherTypeIdentity:
		if v.Identity == nil {
			v.Identity = &vault.IdentityView{}
		}
	case vault.CipherTypeSshKey:
		if v.SshKey == nil {
			v.SshKey = &vault.SshKeyView{}
		}
	case vault.CipherTypeBankAccount:
		if v.BankAccount == nil {
			v.BankAccount = &vault.BankAccountView{}
		}
	case vault.CipherTypeDriversLicense:
		if v.DriversLicense == nil {
			v.DriversLicense = &vault.DriversLicenseView{}
		}
	case vault.CipherTypePassport:
		if v.Passport == nil {
			v.Passport = &vault.PassportView{}
		}
	}
}

// RestrictedTypes maps the RestrictedItemTypes policy result (restricted$) to importer types.
func RestrictedTypes(r []vault.RestrictedCipherType) []model.CipherType {
	var out []model.CipherType
	for _, t := range r {
		out = append(out, model.CipherType(t.CipherType))
	}
	return out
}

// ---------- requests ----------

// FolderRequest is FolderWithOptionalIdRequest.
type FolderRequest struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

// KvpRequest is KvpRequest<number, number>.
type KvpRequest struct {
	Key   int `json:"key"`
	Value int `json:"value"`
}

// CollectionRequest is CollectionWithIdRequest (BaseCollectionRequest fields first).
type CollectionRequest struct {
	ExternalID *string                          `json:"externalId,omitempty"`
	Groups     []vault.SelectionReadOnlyRequest `json:"groups"`
	Users      []vault.SelectionReadOnlyRequest `json:"users"`
	Name       string                           `json:"name"`
	ID         *string                          `json:"id"`
}

// ImportCiphersRequest is the body of POST /ciphers/import.
type ImportCiphersRequest struct {
	Ciphers             []*vault.CipherRequest `json:"ciphers"`
	Folders             []FolderRequest        `json:"folders"`
	FolderRelationships []KvpRequest           `json:"folderRelationships"`
}

// ImportOrganizationCiphersRequest is the body of POST /ciphers/import-organization.
type ImportOrganizationCiphersRequest struct {
	Ciphers                 []*vault.CipherRequest `json:"ciphers"`
	Collections             []CollectionRequest    `json:"collections"`
	CollectionRelationships []KvpRequest           `json:"collectionRelationships"`
	Folders                 []FolderRequest        `json:"folders"`
	FolderRelationships     []KvpRequest           `json:"folderRelationships"`
}

func relationships(rs []model.Relationship) []KvpRequest {
	out := make([]KvpRequest, 0, len(rs))
	for _, r := range rs {
		out = append(out, KvpRequest{Key: r[0], Value: r[1]})
	}
	return out
}

// encryptCiphers is cipherService.encryptMany + `new CipherRequest(ctx)`.
func encryptCiphers(ciphers []*model.CipherView, keys *vault.Keys, userID string) ([]*vault.CipherRequest, error) {
	out := make([]*vault.CipherRequest, 0, len(ciphers))
	for _, c := range ciphers {
		enc, _, err := vault.EncryptCipher(ToVaultView(c), keys)
		if err != nil {
			return nil, err
		}
		out = append(out, vault.NewCipherRequest(enc, userID))
	}
	return out, nil
}

// encryptFolders is ImportService.addFolders: folder names are always encrypted with the user key.
func encryptFolders(folders []*model.FolderView, keys *vault.Keys) ([]FolderRequest, error) {
	out := make([]FolderRequest, 0, len(folders))
	userKey := keys.UserKey()
	if userKey == nil && len(folders) > 0 {
		return nil, vault.ErrNoKey
	}
	for _, f := range folders {
		r, err := vault.EncryptFolder(&vault.FolderView{Name: f.Name}, userKey)
		if err != nil {
			return nil, err
		}
		out = append(out, FolderRequest{Name: r.Name, ID: f.ID})
	}
	return out, nil
}

// BuildRequest encrypts a prepared ImportResult like ImportService.handleIndividualImport /
// handleOrganizationalImport and returns the API path and body to POST. For an organization
// import the organization id is set on every cipher and collection of result (as upstream does).
func BuildRequest(result *model.ImportResult, organizationID string, keys *vault.Keys, userID string) (string, any, error) {
	if organizationID == "" {
		ciphers, err := encryptCiphers(result.Ciphers, keys, userID)
		if err != nil {
			return "", nil, err
		}
		folders, err := encryptFolders(result.Folders, keys)
		if err != nil {
			return "", nil, err
		}
		return "/ciphers/import", &ImportCiphersRequest{
			Ciphers: ciphers, Folders: folders, FolderRelationships: relationships(result.FolderRelationships),
		}, nil
	}

	for _, c := range result.Ciphers {
		c.OrganizationID = organizationID
	}
	ciphers, err := encryptCiphers(result.Ciphers, keys, userID)
	if err != nil {
		return "", nil, err
	}
	folders, err := encryptFolders(result.Folders, keys)
	if err != nil {
		return "", nil, err
	}
	collections := make([]CollectionRequest, 0, len(result.Collections))
	for _, c := range result.Collections {
		c.OrganizationID = organizationID
		name, err := vault.EncryptCollectionName(c.Name, organizationID, keys)
		if err != nil {
			return "", nil, err
		}
		collections = append(collections, CollectionRequest{
			ExternalID: opt(c.ExternalID), Groups: []vault.SelectionReadOnlyRequest{},
			Users: []vault.SelectionReadOnlyRequest{}, Name: name, ID: opt(c.ID),
		})
	}
	return "/ciphers/import-organization?organizationId=" + organizationID, &ImportOrganizationCiphersRequest{
		Ciphers: ciphers, Collections: collections, CollectionRelationships: relationships(result.CollectionRelationships),
		Folders: folders, FolderRelationships: relationships(result.FolderRelationships),
	}, nil
}

// ---------- server errors ----------

var (
	firstNumberRe = regexp.MustCompile(`[0-9]+`)
	firstWordRe   = regexp.MustCompile(`^\w+`)
)

// ServerError is the catch block of ImportService.importImportResult: `new ErrorResponse(error,
// 400)` followed by handleServerError. Validation errors are reported in server key order.
func ServerError(err error, result *model.ImportResult) error {
	var er *api.ErrorResponse
	if !errors.As(err, &er) {
		return errors.New(err.Error())
	}
	if er.ValidationErrors == nil {
		return errors.New(er.Message)
	}
	keys := er.OrderedValidationKeys()
	list := make([]importer.ValidationError, 0, len(keys))
	for _, k := range keys {
		list = append(list, importer.ValidationError{Key: k, Messages: er.ValidationErrors[k]})
	}
	return importer.ServerError(er.Message, list, result)
}
