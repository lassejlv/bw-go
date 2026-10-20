package onepassword

// Port of types/onepassword-1pux-importer-types.ts. The 1pux importer reads the export through
// the untyped JSON model in js.go (the TS importer is @ts-strict-ignore and relies on JavaScript
// semantics for missing/null/mistyped properties); the interfaces of the TS file describe this
// structure:
//
//	ExportData     { accounts?: AccountsEntity[] }
//	AccountsEntity { attrs: AccountAttributes, vaults?: VaultsEntity[] }
//	AccountAttributes { accountName, name, avatar, email, uuid, domain: string }
//	VaultsEntity   { attrs: VaultAttributes, items?: Item[] }
//	VaultAttributes { uuid, desc, avatar, name, type: string }
//	Item           { uuid: string, favIndex, createdAt, updatedAt: number,
//	                 state: "active" | "archived", categoryUuid: string,
//	                 details: Details, overview: Overview }
//	Details        { loginFields?: LoginFieldsEntity[], notesPlain?: string,
//	                 sections?: SectionsEntity[], passwordHistory?: PasswordHistoryEntity[],
//	                 documentAttributes?: DocumentAttributes, password?: string }
//	LoginFieldsEntity { value, id, name: string, fieldType: LoginFieldType | string, designation?: string }
//	SectionsEntity { title: string, name?: string, fields?: FieldsEntity[], hideAddAnotherField?: boolean }
//	FieldsEntity   { title, id: string, value: Value, guarded, multiline, dontGenerate: boolean,
//	                 placeholder?: string, inputTraits: InputTraits, clipboardFilter?: string }
//	Value          { totp?, string?, concealed?, phone?, menu?, gender?, url?, creditCardType?,
//	                 creditCardNumber?, reference?: string; date?, monthYear?: number;
//	                 email?: Email; address?: Address; sshKey?: SSHKey }
//	Email          { email_address: string, provider: string | null }
//	Address        { street, city, country, zip, state: string }
//	SSHKey         { privateKey: string, metadata: SSHKeyMetadata }
//	SSHKeyMetadata { privateKey, publicKey, fingerprint, keyType: string }
//	InputTraits    { keyboard, correction, capitalization: string }
//	PasswordHistoryEntity { value: string, time: number }
//	DocumentAttributes { fileName, documentId: string, decryptedSize: number }
//	Overview       { subtitle, title, url: string, urls?: UrlsEntity[], ps?, pbe?: number,
//	                 pgrng?: boolean, tags?: string[], icons?, watchtowerExclusions?: string }
//	UrlsEntity     { label, url: string }

// Category is the 1Password item category (Item.categoryUuid).
type Category = string

// Category values.
const (
	CategoryLogin                Category = "001"
	CategoryCreditCard           Category = "002"
	CategorySecureNote           Category = "003"
	CategoryIdentity             Category = "004"
	CategoryPassword             Category = "005"
	CategoryDocument             Category = "006"
	CategorySoftwareLicense      Category = "100"
	CategoryBankAccount          Category = "101"
	CategoryDatabase             Category = "102"
	CategoryDriversLicense       Category = "103"
	CategoryOutdoorLicense       Category = "104"
	CategoryMembership           Category = "105"
	CategoryPassport             Category = "106"
	CategoryRewardsProgram       Category = "107"
	CategorySocialSecurityNumber Category = "108"
	CategoryWirelessRouter       Category = "109"
	CategoryServer               Category = "110"
	CategoryEmailAccount         Category = "111"
	CategoryAPICredential        Category = "112"
	CategoryMedicalRecord        Category = "113"
	CategorySSHKey               Category = "114"
)

// LoginFieldType is LoginFieldsEntity.fieldType.
type LoginFieldType = string

// LoginFieldType values.
const (
	LoginFieldTypeTextOrHtml   LoginFieldType = "T"
	LoginFieldTypeEmailAddress LoginFieldType = "E"
	LoginFieldTypeURL          LoginFieldType = "U"
	LoginFieldTypeNumber       LoginFieldType = "N"
	LoginFieldTypePassword     LoginFieldType = "P"
	LoginFieldTypeTextArea     LoginFieldType = "A"
	LoginFieldTypePhoneNumber  LoginFieldType = "TEL"
	LoginFieldTypeCheckBox     LoginFieldType = "C"
)
