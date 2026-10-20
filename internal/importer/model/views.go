package model

import (
	"regexp"
	"strings"
	"time"
)

// CipherView mirrors libs/common/src/vault/models/view/cipher.view.ts (the importer-relevant part).
type CipherView struct {
	ID             string
	OrganizationID string
	FolderID       string
	Name           string
	Notes          string
	Type           CipherType
	Favorite       bool
	Reprompt       CipherRepromptType

	Login          *LoginView
	SecureNote     *SecureNoteView
	Card           *CardView
	Identity       *IdentityView
	SshKey         *SshKeyView
	BankAccount    *BankAccountView
	DriversLicense *DriversLicenseView
	Passport       *PassportView

	Fields          []*FieldView
	PasswordHistory []*PasswordHistoryView
	CollectionIDs   []string

	CreationDate *time.Time
	RevisionDate *time.Time
	DeletedDate  *time.Time
	ArchivedDate *time.Time
}

// NewCipherView mirrors `new CipherView()`: type Login and every nested view allocated.
// (The TS constructor also stamps creation/revision dates with "now"; those are left nil here and
// the encryption layer decides what to send.)
func NewCipherView() *CipherView {
	return &CipherView{
		Type:           CipherTypeLogin,
		Login:          &LoginView{},
		SecureNote:     &SecureNoteView{},
		Card:           &CardView{},
		Identity:       &IdentityView{},
		SshKey:         &SshKeyView{},
		BankAccount:    &BankAccountView{},
		DriversLicense: &DriversLicenseView{},
		Passport:       &PassportView{},
		Fields:         []*FieldView{},
	}
}

// LoginView mirrors login.view.ts.
type LoginView struct {
	Username             string
	Password             string
	PasswordRevisionDate *time.Time
	Totp                 string
	Uris                 []*LoginUriView
	AutofillOnPageLoad   *bool
	Fido2Credentials     []*Fido2CredentialView
}

// Uri is the `login.uri` getter: the first URI or "".
func (l *LoginView) Uri() string {
	if l == nil || len(l.Uris) == 0 || l.Uris[0] == nil {
		return ""
	}
	return l.Uris[0].Uri
}

// LoginUriView mirrors login-uri.view.ts.
type LoginUriView struct {
	Uri   string
	Match *UriMatchStrategy
}

// Fido2CredentialView mirrors fido2-credential.view.ts.
type Fido2CredentialView struct {
	CredentialID    string
	KeyType         string
	KeyAlgorithm    string
	KeyCurve        string
	KeyValue        string
	RpID            string
	UserHandle      string
	UserName        string
	Counter         int
	RpName          string
	UserDisplayName string
	Discoverable    bool
	CreationDate    time.Time
}

// SecureNoteView mirrors secure-note.view.ts.
type SecureNoteView struct {
	Type SecureNoteType
}

// CardView mirrors card.view.ts.
type CardView struct {
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

var (
	reVisa       = regexp.MustCompile(`^4`)
	reMastercard = regexp.MustCompile(`^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$`)
	reAmex       = regexp.MustCompile(`^3[47]`)
	reDiscover   = regexp.MustCompile(`^(6011|622(12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-1][0-9]|92[0-5]|64[4-9])|65)`)
	reDiners     = regexp.MustCompile(`^36`)
	reDinersCB   = regexp.MustCompile(`^30[0-5]`)
	reJCB        = regexp.MustCompile(`^35(2[89]|[3-8][0-9])`)
	reVisaElec   = regexp.MustCompile(`^(4026|417500|4508|4844|491(3|7))`)
)

// GetCardBrandByPatterns is CardView.getCardBrandByPatterns ("" for undefined).
func GetCardBrandByPatterns(cardNum string) string {
	if strings.TrimSpace(cardNum) == "" {
		return ""
	}
	switch {
	case reVisa.MatchString(cardNum):
		return "Visa"
	case reMastercard.MatchString(cardNum):
		return "Mastercard"
	case reAmex.MatchString(cardNum):
		return "Amex"
	case reDiscover.MatchString(cardNum):
		return "Discover"
	case reDiners.MatchString(cardNum), reDinersCB.MatchString(cardNum):
		return "Diners Club"
	case reJCB.MatchString(cardNum):
		return "JCB"
	case reVisaElec.MatchString(cardNum):
		return "Visa"
	}
	return ""
}

// IdentityView mirrors identity.view.ts.
type IdentityView struct {
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	Ssn            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

// SshKeyView mirrors ssh-key.view.ts.
type SshKeyView struct {
	PrivateKey     string
	PublicKey      string
	KeyFingerprint string
}

// BankAccountView mirrors bank-account.view.ts.
type BankAccountView struct {
	BankName         string
	NameOnAccount    string
	AccountType      string
	AccountNumber    string
	RoutingNumber    string
	BranchNumber     string
	Pin              string
	SwiftCode        string
	Iban             string
	BankContactPhone string
}

// DriversLicenseView mirrors drivers-license.view.ts.
type DriversLicenseView struct {
	FirstName        string
	MiddleName       string
	LastName         string
	DateOfBirth      string
	LicenseNumber    string
	IssuingCountry   string
	IssuingState     string
	IssueDate        string
	ExpirationDate   string
	IssuingAuthority string
	LicenseClass     string
}

// PassportView mirrors passport.view.ts.
type PassportView struct {
	Surname                      string
	GivenName                    string
	DateOfBirth                  string
	Sex                          string
	BirthPlace                   string
	Nationality                  string
	IssuingCountry               string
	PassportNumber               string
	PassportType                 string
	NationalIdentificationNumber string
	IssuingAuthority             string
	IssueDate                    string
	ExpirationDate               string
}

// FieldView mirrors field.view.ts.
type FieldView struct {
	Name     string
	Value    string
	Type     FieldType
	LinkedID *LinkedIdType
}

// PasswordHistoryView mirrors password-history.view.ts.
type PasswordHistoryView struct {
	Password     string
	LastUsedDate time.Time
}

// FolderView mirrors folder.view.ts.
type FolderView struct {
	ID           string
	Name         string
	RevisionDate *time.Time
}

// CollectionView mirrors collection.view.ts (the importer-relevant part).
type CollectionView struct {
	ID             string
	OrganizationID string
	Name           string
	ExternalID     string
	ReadOnly       bool
	HidePasswords  bool
	Manage         bool
	Type           CollectionType
}
