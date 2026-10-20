package vault

// CipherType mirrors libs/common/src/vault/enums/cipher-type.ts.
type CipherType int

const (
	CipherTypeLogin          CipherType = 1
	CipherTypeSecureNote     CipherType = 2
	CipherTypeCard           CipherType = 3
	CipherTypeIdentity       CipherType = 4
	CipherTypeSshKey         CipherType = 5
	CipherTypeBankAccount    CipherType = 6
	CipherTypeDriversLicense CipherType = 7
	CipherTypePassport       CipherType = 8
)

// FieldType mirrors the FieldType enum.
type FieldType int

const (
	FieldTypeText    FieldType = 0
	FieldTypeHidden  FieldType = 1
	FieldTypeBoolean FieldType = 2
	FieldTypeLinked  FieldType = 3
)

// SecureNoteType mirrors the SecureNoteType enum.
type SecureNoteType int

const SecureNoteTypeGeneric SecureNoteType = 0

// RepromptType mirrors CipherRepromptType.
type RepromptType int

const (
	RepromptNone     RepromptType = 0
	RepromptPassword RepromptType = 1
)

// UriMatch mirrors UriMatchStrategy.
type UriMatch int

const (
	UriMatchDomain            UriMatch = 0
	UriMatchHost              UriMatch = 1
	UriMatchStartsWith        UriMatch = 2
	UriMatchExact             UriMatch = 3
	UriMatchRegularExpression UriMatch = 4
	UriMatchNever             UriMatch = 5
)

// LinkedID is a LinkedIdType value (login/card/identity linked field ids).
type LinkedID int

// OrganizationUserType mirrors OrganizationUserType.
type OrganizationUserType int

const (
	OrgUserOwner  OrganizationUserType = 0
	OrgUserAdmin  OrganizationUserType = 1
	OrgUserUser   OrganizationUserType = 2
	OrgUserCustom OrganizationUserType = 4
)

// OrganizationUserStatus mirrors OrganizationUserStatusType.
type OrganizationUserStatus int

const (
	OrgUserStatusRevoked   OrganizationUserStatus = -1
	OrgUserStatusInvited   OrganizationUserStatus = 0
	OrgUserStatusAccepted  OrganizationUserStatus = 1
	OrgUserStatusConfirmed OrganizationUserStatus = 2
)

// PolicyType mirrors the SDK PolicyType enum.
type PolicyType int

const (
	PolicyTwoFactorAuthentication           PolicyType = 0
	PolicyMasterPassword                    PolicyType = 1
	PolicyPasswordGenerator                 PolicyType = 2
	PolicySingleOrg                         PolicyType = 3
	PolicyRequireSso                        PolicyType = 4
	PolicyOrganizationDataOwnership         PolicyType = 5
	PolicyDisableSend                       PolicyType = 6
	PolicySendOptions                       PolicyType = 7
	PolicyResetPassword                     PolicyType = 8
	PolicyMaximumVaultTimeout               PolicyType = 9
	PolicyDisablePersonalVaultExport        PolicyType = 10
	PolicyActivateAutofill                  PolicyType = 11
	PolicyAutomaticAppLogIn                 PolicyType = 12
	PolicyFreeFamiliesSponsorship           PolicyType = 13
	PolicyRemoveUnlockWithPin               PolicyType = 14
	PolicyRestrictedItemTypes               PolicyType = 15
	PolicyUriMatchDefaults                  PolicyType = 16
	PolicyAutotypeDefaultSetting            PolicyType = 17
	PolicyAutomaticUserConfirmation         PolicyType = 18
	PolicyBlockClaimedDomainAccountCreation PolicyType = 19
	PolicyOrganizationUserNotification      PolicyType = 20
	PolicySendControls                      PolicyType = 21
	PolicyFillAssist                        PolicyType = 22
)

// CollectionType mirrors CollectionTypes.
type CollectionType int

const (
	CollectionTypeShared      CollectionType = 0
	CollectionTypeDefaultUser CollectionType = 1
)

// DecryptError is the placeholder used for values that cannot be decrypted (DECRYPT_ERROR).
const DecryptError = "[error: cannot decrypt]"

// EmptyGUID is the all-zero GUID used by templates.
const EmptyGUID = "00000000-0000-0000-0000-000000000000"
