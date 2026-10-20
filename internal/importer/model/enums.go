// Package model holds plain Go mirrors of the TypeScript view models that the importers in
// libs/importer produce (CipherView and friends, FolderView, CollectionView) plus ImportResult.
//
// Conventions (see internal/importer/README.md):
//
//   - Optional strings are plain `string`; "" stands for JavaScript's null/undefined/"". Encryption
//     code must therefore treat "" as "absent" (emit null) for every optional field.
//   - Nested views are pointers so importers can share/replace them like the TS code does
//     (`cipher.card = new CardView()`); NewCipherView populates all of them, mirroring the TS
//     constructor. CleanupCipher sets Login to nil for non-login ciphers.
//   - Values that can legitimately be 0 but also null (UriMatchStrategy, LinkedId, autofill flag)
//     are pointers.
package model

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

var cipherTypeNames = map[CipherType]string{
	CipherTypeLogin:          "Login",
	CipherTypeSecureNote:     "SecureNote",
	CipherTypeCard:           "Card",
	CipherTypeIdentity:       "Identity",
	CipherTypeSshKey:         "SshKey",
	CipherTypeBankAccount:    "BankAccount",
	CipherTypeDriversLicense: "DriversLicense",
	CipherTypePassport:       "Passport",
}

// Name is toCipherTypeName: "Login", "SecureNote", ... or "" for an unknown type.
func (t CipherType) Name() string { return cipherTypeNames[t] }

// IsValid reports whether t is a known cipher type (isCipherType).
func (t CipherType) IsValid() bool { _, ok := cipherTypeNames[t]; return ok }

// FieldType mirrors field-type.enum.ts.
type FieldType int

const (
	FieldTypeText    FieldType = 0
	FieldTypeHidden  FieldType = 1
	FieldTypeBoolean FieldType = 2
	FieldTypeLinked  FieldType = 3
)

// SecureNoteType mirrors secure-note-type.enum.ts.
type SecureNoteType int

const SecureNoteTypeGeneric SecureNoteType = 0

// CipherRepromptType mirrors cipher-reprompt-type.ts.
type CipherRepromptType int

const (
	CipherRepromptNone     CipherRepromptType = 0
	CipherRepromptPassword CipherRepromptType = 1
)

// UriMatchStrategy mirrors UriMatchStrategy in domain-service.ts.
type UriMatchStrategy int

const (
	UriMatchDomain            UriMatchStrategy = 0
	UriMatchHost              UriMatchStrategy = 1
	UriMatchStartsWith        UriMatchStrategy = 2
	UriMatchExact             UriMatchStrategy = 3
	UriMatchRegularExpression UriMatchStrategy = 4
	UriMatchNever             UriMatchStrategy = 5
)

// LinkedIdType mirrors linked-id-type.enum.ts (LoginLinkedId | CardLinkedId | IdentityLinkedId).
type LinkedIdType int

const (
	LoginLinkedIdUsername LinkedIdType = 100
	LoginLinkedIdPassword LinkedIdType = 101

	CardLinkedIdCardholderName LinkedIdType = 300
	CardLinkedIdExpMonth       LinkedIdType = 301
	CardLinkedIdExpYear        LinkedIdType = 302
	CardLinkedIdCode           LinkedIdType = 303
	CardLinkedIdBrand          LinkedIdType = 304
	CardLinkedIdNumber         LinkedIdType = 305

	IdentityLinkedIdTitle          LinkedIdType = 400
	IdentityLinkedIdMiddleName     LinkedIdType = 401
	IdentityLinkedIdAddress1       LinkedIdType = 402
	IdentityLinkedIdAddress2       LinkedIdType = 403
	IdentityLinkedIdAddress3       LinkedIdType = 404
	IdentityLinkedIdCity           LinkedIdType = 405
	IdentityLinkedIdState          LinkedIdType = 406
	IdentityLinkedIdPostalCode     LinkedIdType = 407
	IdentityLinkedIdCountry        LinkedIdType = 408
	IdentityLinkedIdCompany        LinkedIdType = 409
	IdentityLinkedIdEmail          LinkedIdType = 410
	IdentityLinkedIdPhone          LinkedIdType = 411
	IdentityLinkedIdSsn            LinkedIdType = 412
	IdentityLinkedIdUsername       LinkedIdType = 413
	IdentityLinkedIdPassportNumber LinkedIdType = 414
	IdentityLinkedIdLicenseNumber  LinkedIdType = 415
	IdentityLinkedIdFirstName      LinkedIdType = 416
	IdentityLinkedIdLastName       LinkedIdType = 417
	IdentityLinkedIdFullName       LinkedIdType = 418
)

// BankAccountType mirrors bank-account-type.ts (string valued).
const (
	BankAccountTypeChecking             = "checking"
	BankAccountTypeSavings              = "savings"
	BankAccountTypeCertificateOfDeposit = "certificateOfDeposit"
	BankAccountTypeLineOfCredit         = "lineOfCredit"
	BankAccountTypeInvestmentBrokerage  = "investmentBrokerage"
	BankAccountTypeMoneyMarket          = "moneyMarket"
	BankAccountTypeOther                = "other"
)

// CollectionType mirrors CollectionTypes in collection.ts.
type CollectionType int

const (
	CollectionTypeShared                CollectionType = 0
	CollectionTypeDefaultUserCollection CollectionType = 1
)

// ImportRecordErrorReason mirrors import-record-error.ts.
type ImportRecordErrorReason string

const (
	ImportRecordErrorReasonError                  ImportRecordErrorReason = "error"
	ImportRecordErrorReasonUnsupportedFeature     ImportRecordErrorReason = "unsupportedFeature"
	ImportRecordErrorReasonUnsupportedType        ImportRecordErrorReason = "unsupportedType"
	ImportRecordErrorReasonFolderDecryptionFailed ImportRecordErrorReason = "folderDecryptionFailed"
	ImportRecordErrorReasonSshKeyParseFailed      ImportRecordErrorReason = "sshKeyParseFailed"
)

// ImportResultErrorKey mirrors import-upgrade-result.ts (only the "upgrade" importers set it).
type ImportResultErrorKey string

const (
	ImportResultErrorKeyInvalidFilePassword ImportResultErrorKey = "invalidFilePassword"
	ImportResultErrorKeyAccountMismatch     ImportResultErrorKey = "importEncKeyError"
)
