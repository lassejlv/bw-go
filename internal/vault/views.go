package vault

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// Decrypted views. Optional values are pointers; nil means the SDK left the value undefined.

// LoginURIView is a decrypted login URI.
type LoginURIView struct {
	URI   *string
	Match *UriMatch
}

// Fido2CredentialView is a decrypted passkey.
type Fido2CredentialView struct {
	CredentialID    string
	KeyType         string
	KeyAlgorithm    string
	KeyCurve        string
	KeyValue        string
	RpID            string
	UserHandle      *string
	UserName        *string
	Counter         string // decrypted counter string; see CounterNumber
	RpName          *string
	UserDisplayName *string
	Discoverable    bool
	CreationDate    *time.Time
}

// CounterString mirrors String(parseInt(counter)) as done by the TS view round trip.
func (f *Fido2CredentialView) CounterString() string { return jsParseIntString(f.Counter) }

// LoginView is a decrypted login.
type LoginView struct {
	Username             *string
	Password             *string
	PasswordRevisionDate *time.Time
	Totp                 *string
	URIs                 []LoginURIView
	AutofillOnPageLoad   *bool
	Fido2Credentials     []Fido2CredentialView

	uriChecksums []*string // decrypted checksums parallel to URIs (decryption only)
}

// Subtitle mirrors LoginView.subTitle.
func (l *LoginView) Subtitle() *string {
	if isNullOrEmpty(l.Username) && len(l.Fido2Credentials) > 0 {
		return l.Fido2Credentials[0].UserName
	}
	return l.Username
}

// HasTotp mirrors LoginView.hasTotp.
func (l *LoginView) HasTotp() bool { return !isNullOrWhitespace(l.Totp) }

// FirstURI returns the first URI or nil.
func (l *LoginView) FirstURI() *string {
	if len(l.URIs) == 0 {
		return nil
	}
	return l.URIs[0].URI
}

// CardView is a decrypted card.
type CardView struct {
	CardholderName *string
	Brand          *string
	Number         *string
	ExpMonth       *string
	ExpYear        *string
	Code           *string
}

var amexRe = regexp.MustCompile(`^3[47]`)

// Subtitle mirrors CardView.subTitle.
func (c *CardView) Subtitle() *string {
	sub := clonePtr(c.Brand)
	if c.Number != nil && len([]rune(*c.Number)) >= 4 {
		s := ""
		if sub != nil && *sub != "" {
			s = *sub + ", "
		}
		num := []rune(*c.Number)
		count := 4
		if len(num) >= 5 && amexRe.MatchString(*c.Number) {
			count = 5
		}
		s += "*" + string(num[len(num)-count:])
		sub = &s
	}
	return sub
}

// IdentityView is a decrypted identity.
type IdentityView struct {
	Title          *string
	FirstName      *string
	MiddleName     *string
	LastName       *string
	Address1       *string
	Address2       *string
	Address3       *string
	City           *string
	State          *string
	PostalCode     *string
	Country        *string
	Company        *string
	Email          *string
	Phone          *string
	SSN            *string
	Username       *string
	PassportNumber *string
	LicenseNumber  *string
}

// Subtitle mirrors IdentityView.subTitle.
func (i *IdentityView) Subtitle() *string {
	if i.FirstName == nil && i.LastName == nil {
		return nil
	}
	s := ""
	if i.FirstName != nil {
		s = *i.FirstName
	}
	if i.LastName != nil {
		if s != "" {
			s += " "
		}
		s += *i.LastName
	}
	return &s
}

// FullName mirrors IdentityView.fullName.
func (i *IdentityView) FullName() *string {
	if i.Title == nil && i.FirstName == nil && i.MiddleName == nil && i.LastName == nil {
		return nil
	}
	name := ""
	for _, p := range []*string{i.Title, i.FirstName, i.MiddleName} {
		if !isNullOrWhitespace(p) {
			name += *p + " "
		}
	}
	if !isNullOrWhitespace(i.LastName) {
		name += *i.LastName
	}
	name = strings.TrimSpace(name)
	return &name
}

// SecureNoteView is a secure note.
type SecureNoteView struct {
	Type SecureNoteType
}

// SshKeyView is a decrypted SSH key.
type SshKeyView struct {
	PrivateKey     string
	PublicKey      string
	KeyFingerprint string
}

// BankAccountView is a decrypted bank account.
type BankAccountView struct {
	BankName         *string
	NameOnAccount    *string
	AccountType      *string
	AccountNumber    *string
	RoutingNumber    *string
	BranchNumber     *string
	Pin              *string
	SwiftCode        *string
	Iban             *string
	BankContactPhone *string
}

// DriversLicenseView is a decrypted driver's license.
type DriversLicenseView struct {
	FirstName        *string
	MiddleName       *string
	LastName         *string
	DateOfBirth      *string
	LicenseNumber    *string
	IssuingCountry   *string
	IssuingState     *string
	IssueDate        *string
	ExpirationDate   *string
	IssuingAuthority *string
	LicenseClass     *string
}

// PassportView is a decrypted passport.
type PassportView struct {
	Surname                      *string
	GivenName                    *string
	DateOfBirth                  *string
	Sex                          *string
	BirthPlace                   *string
	Nationality                  *string
	IssuingCountry               *string
	PassportNumber               *string
	PassportType                 *string
	NationalIdentificationNumber *string
	IssuingAuthority             *string
	IssueDate                    *string
	ExpirationDate               *string
}

// FieldView is a decrypted custom field.
type FieldView struct {
	Name     *string
	Value    *string
	Type     FieldType
	LinkedID *LinkedID
}

// AttachmentView is decrypted attachment metadata.
type AttachmentView struct {
	ID                 *string
	URL                *string
	Size               *string
	SizeName           *string
	FileName           *string
	Key                *crypto.SymmetricKey
	HasDecryptionError bool
}

// FileSize mirrors AttachmentView.fileSize.
func (a *AttachmentView) FileSize() int64 {
	if a.Size == nil {
		return 0
	}
	n, _ := strconv.ParseInt(jsParseIntString(*a.Size), 10, 64)
	return n
}

// IsLegacy reports a legacy attachment (no per-attachment key).
func (a *AttachmentView) IsLegacy() bool {
	return a.Key == nil && !a.HasDecryptionError && derefStr(a.FileName) != DecryptError
}

// PasswordHistoryView is a decrypted password history entry.
type PasswordHistoryView struct {
	Password     *string
	LastUsedDate *time.Time
}

// CipherView is a decrypted vault item.
type CipherView struct {
	ID                  string
	OrganizationID      *string
	FolderID            *string
	Name                string
	Notes               *string
	Type                CipherType
	Favorite            bool
	OrganizationUseTotp bool
	Permissions         *CipherPermissions
	Edit                bool
	ViewPassword        bool
	Login               *LoginView
	Identity            *IdentityView
	Card                *CardView
	SecureNote          *SecureNoteView
	SshKey              *SshKeyView
	BankAccount         *BankAccountView
	DriversLicense      *DriversLicenseView
	Passport            *PassportView
	Attachments         []AttachmentView
	Fields              []FieldView
	PasswordHistory     []PasswordHistoryView
	CollectionIDs       []string
	RevisionDate        time.Time
	CreationDate        time.Time
	DeletedDate         *time.Time
	ArchivedDate        *time.Time
	Reprompt            RepromptType
	// Key is the decrypted per-cipher key, nil for ciphers without one.
	Key               *crypto.SymmetricKey
	Partial           bool
	DecryptionFailure bool
}

// NewCipherView returns an empty view like `new CipherView()` (dates set to now, empty sub-views).
func NewCipherView() *CipherView {
	now := time.Now().UTC()
	return &CipherView{
		Type:            CipherTypeLogin,
		ViewPassword:    true,
		Permissions:     &CipherPermissions{},
		Login:           &LoginView{URIs: []LoginURIView{}, Fido2Credentials: []Fido2CredentialView{}},
		Identity:        &IdentityView{},
		Card:            &CardView{},
		SecureNote:      &SecureNoteView{},
		SshKey:          &SshKeyView{},
		BankAccount:     &BankAccountView{},
		DriversLicense:  &DriversLicenseView{},
		Passport:        &PassportView{},
		Attachments:     []AttachmentView{},
		Fields:          []FieldView{},
		PasswordHistory: []PasswordHistoryView{},
		CollectionIDs:   []string{},
		RevisionDate:    now,
		CreationDate:    now,
	}
}

// IsDeleted reports whether the item is in the trash.
func (c *CipherView) IsDeleted() bool { return c.DeletedDate != nil }

// IsArchived reports whether the item is archived.
func (c *CipherView) IsArchived() bool { return c.ArchivedDate != nil }

// HasOldAttachments reports legacy attachments without keys.
func (c *CipherView) HasOldAttachments() bool {
	for i := range c.Attachments {
		if c.Attachments[i].IsLegacy() {
			return true
		}
	}
	return false
}

// Subtitle mirrors CipherView.subTitle.
func (c *CipherView) Subtitle() *string {
	switch c.Type {
	case CipherTypeLogin:
		if c.Login != nil {
			return c.Login.Subtitle()
		}
	case CipherTypeCard:
		if c.Card != nil {
			return c.Card.Subtitle()
		}
	case CipherTypeIdentity:
		if c.Identity != nil {
			return c.Identity.Subtitle()
		}
	case CipherTypeSshKey:
		if c.SshKey != nil {
			return strPtr(c.SshKey.KeyFingerprint)
		}
	case CipherTypeBankAccount:
		if c.BankAccount != nil {
			return strPtr(derefStr(c.BankAccount.BankName))
		}
	case CipherTypeDriversLicense:
		if d := c.DriversLicense; d != nil {
			var parts []string
			for _, p := range []*string{d.FirstName, d.LastName} {
				if p != nil && *p != "" {
					parts = append(parts, *p)
				}
			}
			name := strings.Join(parts, " ")
			state := derefStr(d.IssuingState)
			switch {
			case name != "" && state != "":
				return strPtr(name + ", " + state)
			case name != "":
				return &name
			default:
				return &state
			}
		}
	case CipherTypePassport:
		if p := c.Passport; p != nil {
			var parts []string
			for _, s := range []*string{p.GivenName, p.Surname} {
				if s != nil && *s != "" {
					parts = append(parts, *s)
				}
			}
			name := strings.Join(parts, " ")
			var out []string
			if name != "" {
				out = append(out, name)
			}
			if p.IssuingCountry != nil && *p.IssuingCountry != "" {
				out = append(out, *p.IssuingCountry)
			}
			return strPtr(strings.Join(out, ", "))
		}
	}
	return nil
}

// FolderView is a decrypted folder. The "No Folder" entry has ID "".
type FolderView struct {
	ID           string
	Name         string
	RevisionDate time.Time
}

// CollectionView is a decrypted collection.
type CollectionView struct {
	ID                         string
	OrganizationID             string
	Name                       string
	ExternalID                 *string
	ReadOnly                   bool
	HidePasswords              bool
	Manage                     bool
	Assigned                   bool
	Type                       CollectionType
	DefaultUserCollectionEmail *string
	DecryptionFailure          bool
	HasEnabledAccessRule       bool
}

// DisplayName mirrors the CollectionView.name getter (defaultUserCollectionEmail ?? name).
func (c *CollectionView) DisplayName() string {
	if c.DefaultUserCollectionEmail != nil {
		return *c.DefaultUserCollectionEmail
	}
	return c.Name
}

// IsDefaultCollection reports a "My Items" default user collection.
func (c *CollectionView) IsDefaultCollection() bool { return c.Type == CollectionTypeDefaultUser }

// CanEditItems mirrors CollectionView.canEditItems.
func (c *CollectionView) CanEditItems(org *Organization) bool {
	return (org != nil && org.CanEditAllCiphers()) || c.Manage || (c.Assigned && !c.ReadOnly)
}

// CanEdit mirrors CollectionView.canEdit.
func (c *CollectionView) CanEdit(org *Organization) bool {
	if c.IsDefaultCollection() {
		return false
	}
	return c.Manage
}

// CanDelete mirrors CollectionView.canDelete.
func (c *CollectionView) CanDelete(org *Organization) bool {
	canDeleteManaged := org == nil || !org.LimitCollectionDeletion || org.IsAdmin()
	return canDeleteManaged && c.Manage && !c.IsDefaultCollection()
}

// jsParseIntString mirrors String(parseInt(s)) (base 10): leading whitespace, optional sign and
// leading digits; "NaN" when there are none.
func jsParseIntString(s string) string {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	sign := ""
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		if s[0] == '-' {
			sign = "-"
		}
		s = s[1:]
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return "NaN"
	}
	digits := strings.TrimLeft(s[:end], "0")
	if digits == "" {
		return "0"
	}
	return sign + digits
}
