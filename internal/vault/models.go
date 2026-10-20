package vault

import (
	"bytes"
	"encoding/json"

	"github.com/lassejlv/bw-go/internal/cli"
)

// Server (encrypted) models, decoded from the raw sync/API JSON kept in state.Account.Vault.
// encoding/json matches keys case-insensitively, so PascalCase and camelCase payloads both work.
// EncString values are kept as serialized strings (*string, nil when absent/null).

// FlexString accepts a JSON string, null, or any other JSON value (kept verbatim as text). It is
// used for `data`/`partialData`, which servers send as strings but may also send as objects.
type FlexString struct {
	Val *string
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *FlexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		f.Val = nil
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		f.Val = &s
		return nil
	}
	s := string(b)
	f.Val = &s
	return nil
}

// MarshalJSON implements json.Marshaler.
func (f FlexString) MarshalJSON() ([]byte, error) {
	if f.Val == nil {
		return []byte("null"), nil
	}
	return marshalNoEscape(*f.Val)
}

// CipherPermissions mirrors CipherPermissionsApi.
type CipherPermissions struct {
	Delete  bool `json:"delete"`
	Restore bool `json:"restore"`
}

// LoginURIData is an encrypted login URI.
type LoginURIData struct {
	URI         *string   `json:"uri"`
	URIChecksum *string   `json:"uriChecksum"`
	Match       *UriMatch `json:"match"`
}

// Fido2CredentialData is an encrypted passkey.
type Fido2CredentialData struct {
	CredentialID    *string   `json:"credentialId"`
	KeyType         *string   `json:"keyType"`
	KeyAlgorithm    *string   `json:"keyAlgorithm"`
	KeyCurve        *string   `json:"keyCurve"`
	KeyValue        *string   `json:"keyValue"`
	RpID            *string   `json:"rpId"`
	UserHandle      *string   `json:"userHandle"`
	UserName        *string   `json:"userName"`
	Counter         *string   `json:"counter"`
	RpName          *string   `json:"rpName"`
	UserDisplayName *string   `json:"userDisplayName"`
	Discoverable    *string   `json:"discoverable"`
	CreationDate    *cli.Date `json:"creationDate"`
}

// LoginData is an encrypted login.
type LoginData struct {
	URIs                 []LoginURIData        `json:"uris"`
	Username             *string               `json:"username"`
	Password             *string               `json:"password"`
	PasswordRevisionDate *cli.Date             `json:"passwordRevisionDate"`
	Totp                 *string               `json:"totp"`
	AutofillOnPageLoad   *bool                 `json:"autofillOnPageLoad"`
	Fido2Credentials     []Fido2CredentialData `json:"fido2Credentials"`
}

// CardData is an encrypted card.
type CardData struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

// IdentityData is an encrypted identity.
type IdentityData struct {
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
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

// SecureNoteData is a secure note (not encrypted).
type SecureNoteData struct {
	Type SecureNoteType `json:"type"`
}

// SshKeyData is an encrypted SSH key.
type SshKeyData struct {
	PrivateKey     *string `json:"privateKey"`
	PublicKey      *string `json:"publicKey"`
	KeyFingerprint *string `json:"keyFingerprint"`
}

// BankAccountData is an encrypted bank account.
type BankAccountData struct {
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
}

// DriversLicenseData is an encrypted driver's license.
type DriversLicenseData struct {
	FirstName        *string `json:"firstName"`
	MiddleName       *string `json:"middleName"`
	LastName         *string `json:"lastName"`
	DateOfBirth      *string `json:"dateOfBirth"`
	LicenseNumber    *string `json:"licenseNumber"`
	IssuingCountry   *string `json:"issuingCountry"`
	IssuingState     *string `json:"issuingState"`
	IssueDate        *string `json:"issueDate"`
	ExpirationDate   *string `json:"expirationDate"`
	IssuingAuthority *string `json:"issuingAuthority"`
	LicenseClass     *string `json:"licenseClass"`
}

// PassportData is an encrypted passport.
type PassportData struct {
	Surname                      *string `json:"surname"`
	GivenName                    *string `json:"givenName"`
	DateOfBirth                  *string `json:"dateOfBirth"`
	Sex                          *string `json:"sex"`
	BirthPlace                   *string `json:"birthPlace"`
	Nationality                  *string `json:"nationality"`
	IssuingCountry               *string `json:"issuingCountry"`
	PassportNumber               *string `json:"passportNumber"`
	PassportType                 *string `json:"passportType"`
	NationalIdentificationNumber *string `json:"nationalIdentificationNumber"`
	IssuingAuthority             *string `json:"issuingAuthority"`
	IssueDate                    *string `json:"issueDate"`
	ExpirationDate               *string `json:"expirationDate"`
}

// FieldData is an encrypted custom field.
type FieldData struct {
	Type     FieldType `json:"type"`
	Name     *string   `json:"name"`
	Value    *string   `json:"value"`
	LinkedID *LinkedID `json:"linkedId"`
}

// AttachmentData is attachment metadata (fileName and key are encrypted).
type AttachmentData struct {
	ID       *string    `json:"id"`
	URL      *string    `json:"url"`
	FileName *string    `json:"fileName"`
	Key      *string    `json:"key"`
	Size     FlexString `json:"size"`
	SizeName *string    `json:"sizeName"`
}

// PasswordHistoryData is an encrypted password history entry.
type PasswordHistoryData struct {
	Password     *string   `json:"password"`
	LastUsedDate *cli.Date `json:"lastUsedDate"`
}

// Cipher is an encrypted vault item (CipherResponse/CipherData).
type Cipher struct {
	ID                  string                `json:"id"`
	OrganizationID      *string               `json:"organizationId"`
	FolderID            *string               `json:"folderId"`
	Type                CipherType            `json:"type"`
	Name                *string               `json:"name"`
	Notes               *string               `json:"notes"`
	Fields              []FieldData           `json:"fields"`
	Login               *LoginData            `json:"login"`
	Card                *CardData             `json:"card"`
	Identity            *IdentityData         `json:"identity"`
	SecureNote          *SecureNoteData       `json:"secureNote"`
	SshKey              *SshKeyData           `json:"sshKey"`
	BankAccount         *BankAccountData      `json:"bankAccount"`
	DriversLicense      *DriversLicenseData   `json:"driversLicense"`
	Passport            *PassportData         `json:"passport"`
	Favorite            bool                  `json:"favorite"`
	Edit                bool                  `json:"edit"`
	ViewPassword        *bool                 `json:"viewPassword"`
	Permissions         *CipherPermissions    `json:"permissions"`
	OrganizationUseTotp bool                  `json:"organizationUseTotp"`
	RevisionDate        *cli.Date             `json:"revisionDate"`
	CreationDate        *cli.Date             `json:"creationDate"`
	DeletedDate         *cli.Date             `json:"deletedDate"`
	ArchivedDate        *cli.Date             `json:"archivedDate"`
	Attachments         []AttachmentData      `json:"attachments"`
	PasswordHistory     []PasswordHistoryData `json:"passwordHistory"`
	CollectionIDs       []string              `json:"collectionIds"`
	Reprompt            RepromptType          `json:"reprompt"`
	Key                 *string               `json:"key"`
	Data                FlexString            `json:"data"`
	PartialData         FlexString            `json:"partialData"`
}

// CanViewPassword returns viewPassword, defaulting to true when the server omitted it.
func (c *Cipher) CanViewPassword() bool { return c.ViewPassword == nil || *c.ViewPassword }

// IsPartial reports whether this is a PAM-gated ("partial") row.
func (c *Cipher) IsPartial() bool { return c.PartialData.Val != nil }

// IsDeleted reports whether the cipher is in the trash.
func (c *Cipher) IsDeleted() bool { return c.DeletedDate != nil && !c.DeletedDate.IsZero() }

// IsArchived reports whether the cipher is archived.
func (c *Cipher) IsArchived() bool { return c.ArchivedDate != nil && !c.ArchivedDate.IsZero() }

// ParseCipher decodes a raw server cipher and normalises it like CipherResponse's constructor.
func ParseCipher(raw json.RawMessage) (*Cipher, error) {
	c := &Cipher{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if c.FolderID != nil && *c.FolderID == "" {
		c.FolderID = nil // `|| null`
	}
	if c.OrganizationID != nil && *c.OrganizationID == "" {
		c.OrganizationID = nil
	}
	if c.Key != nil && *c.Key == "" {
		c.Key = nil
	}
	if c.CollectionIDs == nil {
		c.CollectionIDs = []string{}
	}
	return c, nil
}

// Folder is an encrypted folder.
type Folder struct {
	ID           string    `json:"id"`
	Name         *string   `json:"name"`
	RevisionDate *cli.Date `json:"revisionDate"`
}

// Collection is an encrypted collection (CollectionDetailsResponse).
type Collection struct {
	ID                         string         `json:"id"`
	OrganizationID             string         `json:"organizationId"`
	Name                       *string        `json:"name"`
	ExternalID                 *string        `json:"externalId"`
	DefaultUserCollectionEmail *string        `json:"defaultUserCollectionEmail"`
	Type                       CollectionType `json:"type"`
	ReadOnly                   bool           `json:"readOnly"`
	Manage                     bool           `json:"manage"`
	HidePasswords              bool           `json:"hidePasswords"`
	HasEnabledAccessRule       bool           `json:"hasEnabledAccessRule"`
}

// Permissions mirrors PermissionsApi (custom role permissions).
type Permissions struct {
	AccessEventLogs      bool `json:"accessEventLogs"`
	AccessImportExport   bool `json:"accessImportExport"`
	AccessReports        bool `json:"accessReports"`
	CreateNewCollections bool `json:"createNewCollections"`
	EditAnyCollection    bool `json:"editAnyCollection"`
	DeleteAnyCollection  bool `json:"deleteAnyCollection"`
	ManageCiphers        bool `json:"manageCiphers"`
	ManageGroups         bool `json:"manageGroups"`
	ManageSso            bool `json:"manageSso"`
	ManagePolicies       bool `json:"managePolicies"`
	ManageUsers          bool `json:"manageUsers"`
	ManageResetPassword  bool `json:"manageResetPassword"`
	ManageScim           bool `json:"manageScim"`
}

// ProfileOrganization mirrors ProfileOrganizationResponse (and the provider-organization variant).
type ProfileOrganization struct {
	ID                                   string                 `json:"id"`
	Name                                 string                 `json:"name"`
	UsePolicies                          bool                   `json:"usePolicies"`
	UseGroups                            bool                   `json:"useGroups"`
	UseDirectory                         bool                   `json:"useDirectory"`
	UseEvents                            bool                   `json:"useEvents"`
	UseTotp                              bool                   `json:"useTotp"`
	Use2fa                               bool                   `json:"use2fa"`
	UseApi                               bool                   `json:"useApi"`
	UseSso                               bool                   `json:"useSso"`
	UseOrganizationDomains               bool                   `json:"useOrganizationDomains"`
	UseKeyConnector                      bool                   `json:"useKeyConnector"`
	UseScim                              bool                   `json:"useScim"`
	UseCustomPermissions                 bool                   `json:"useCustomPermissions"`
	UseResetPassword                     bool                   `json:"useResetPassword"`
	UseSecretsManager                    bool                   `json:"useSecretsManager"`
	UsePasswordManager                   bool                   `json:"usePasswordManager"`
	UsePam                               bool                   `json:"usePam"`
	UseActivateAutofillPolicy            bool                   `json:"useActivateAutofillPolicy"`
	UseAutomaticUserConfirmation         bool                   `json:"useAutomaticUserConfirmation"`
	SelfHost                             bool                   `json:"selfHost"`
	UsersGetPremium                      bool                   `json:"usersGetPremium"`
	Seats                                *int                   `json:"seats"`
	MaxCollections                       *int                   `json:"maxCollections"`
	MaxStorageGb                         *int                   `json:"maxStorageGb"`
	Key                                  *string                `json:"key"`
	HasPublicAndPrivateKeys              bool                   `json:"hasPublicAndPrivateKeys"`
	Status                               OrganizationUserStatus `json:"status"`
	Type                                 OrganizationUserType   `json:"type"`
	Enabled                              bool                   `json:"enabled"`
	SsoBound                             bool                   `json:"ssoBound"`
	Identifier                           *string                `json:"identifier"`
	Permissions                          Permissions            `json:"permissions"`
	ResetPasswordEnrolled                bool                   `json:"resetPasswordEnrolled"`
	UserID                               *string                `json:"userId"`
	OrganizationUserID                   *string                `json:"organizationUserId"`
	ProviderID                           *string                `json:"providerId"`
	ProviderName                         *string                `json:"providerName"`
	ProviderType                         *int                   `json:"providerType"`
	FamilySponsorshipFriendlyName        *string                `json:"familySponsorshipFriendlyName"`
	FamilySponsorshipAvailable           bool                   `json:"familySponsorshipAvailable"`
	ProductTierType                      *int                   `json:"productTierType"`
	KeyConnectorEnabled                  bool                   `json:"keyConnectorEnabled"`
	KeyConnectorURL                      *string                `json:"keyConnectorUrl"`
	AccessSecretsManager                 bool                   `json:"accessSecretsManager"`
	LimitCollectionCreation              bool                   `json:"limitCollectionCreation"`
	LimitCollectionDeletion              bool                   `json:"limitCollectionDeletion"`
	LimitItemDeletion                    bool                   `json:"limitItemDeletion"`
	AllowAdminAccessToAllCollectionItems bool                   `json:"allowAdminAccessToAllCollectionItems"`
	UserIsClaimedByOrganization          bool                   `json:"userIsClaimedByOrganization"`
	UseRiskInsights                      bool                   `json:"useRiskInsights"`
	UseAdminSponsoredFamilies            bool                   `json:"useAdminSponsoredFamilies"`
	IsAdminInitiated                     bool                   `json:"isAdminInitiated"`
	SsoEnabled                           bool                   `json:"ssoEnabled"`
	SsoMemberDecryptionType              *int                   `json:"ssoMemberDecryptionType"`
	UseMyItems                           bool                   `json:"useMyItems"`
}

// ProfileProvider mirrors ProfileProviderResponse.
type ProfileProvider struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Key            *string `json:"key"`
	Status         int     `json:"status"`
	Type           int     `json:"type"`
	Enabled        bool    `json:"enabled"`
	UserID         *string `json:"userId"`
	UseEvents      bool    `json:"useEvents"`
	ProviderStatus int     `json:"providerStatus"`
}

// SecurityState is the account security state from accountKeys.
type SecurityState struct {
	SecurityState   *string `json:"securityState"`
	SecurityVersion *int    `json:"securityVersion"`
}

// AccountKeys is the subset of PrivateKeysResponseModel the vault needs.
type AccountKeys struct {
	PublicKeyEncryptionKeyPair *struct {
		WrappedPrivateKey *string `json:"wrappedPrivateKey"`
		PublicKey         *string `json:"publicKey"`
	} `json:"publicKeyEncryptionKeyPair"`
	SignatureKeyPair json.RawMessage `json:"signatureKeyPair"`
	SecurityState    *SecurityState  `json:"securityState"`
}

// Profile mirrors the sync ProfileResponse.
type Profile struct {
	ID                      string                `json:"id"`
	Name                    *string               `json:"name"`
	Email                   string                `json:"email"`
	EmailVerified           bool                  `json:"emailVerified"`
	Premium                 bool                  `json:"premium"`
	PremiumFromOrganization bool                  `json:"premiumFromOrganization"`
	Key                     *string               `json:"key"`
	PrivateKey              *string               `json:"privateKey"`
	AccountKeys             *AccountKeys          `json:"accountKeys"`
	Organizations           []ProfileOrganization `json:"organizations"`
	OrganizationsNew        []ProfileOrganization `json:"organizationsNew"`
	Providers               []ProfileProvider     `json:"providers"`
	ProviderOrganizations   []ProfileOrganization `json:"providerOrganizations"`
}

// HasPremium mirrors hasPremiumFromAnySource$.
func (p *Profile) HasPremium() bool { return p != nil && (p.Premium || p.PremiumFromOrganization) }

// MemberOrganizations returns organizationsNew when present, else organizations (sync behaviour).
func (p *Profile) MemberOrganizations() []ProfileOrganization {
	if p == nil {
		return nil
	}
	if p.OrganizationsNew != nil {
		return p.OrganizationsNew
	}
	return p.Organizations
}

// Policy mirrors PolicyResponse.
type Policy struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Type           PolicyType      `json:"type"`
	Data           json.RawMessage `json:"data"`
	Enabled        bool            `json:"enabled"`
}

// Domains mirrors the sync DomainsResponse.
type Domains struct {
	EquivalentDomains       [][]string `json:"equivalentDomains"`
	GlobalEquivalentDomains []struct {
		Type     int      `json:"type"`
		Domains  []string `json:"domains"`
		Excluded bool     `json:"excluded"`
	} `json:"globalEquivalentDomains"`
}

// EquivalentDomainSets flattens the domains like DefaultSyncService.syncSettings.
func (d *Domains) EquivalentDomainSets() [][]string {
	if d == nil {
		return nil
	}
	out := append([][]string{}, d.EquivalentDomains...)
	for _, g := range d.GlobalEquivalentDomains {
		if len(g.Domains) > 0 {
			out = append(out, g.Domains)
		}
	}
	return out
}
