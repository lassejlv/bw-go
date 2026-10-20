package bitwarden

import (
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() {
	importer.Register("bitwardenjson", NewPasswordProtectedImporter)
	importer.Register("bitwardenpasswordprotected", NewPasswordProtectedImporter)
}

// PasswordProtectedImporter is BitwardenPasswordProtectedImporter, the importer upstream uses for
// "bitwardenjson": password-protected exports are decrypted with a key derived from the file
// password; everything else falls through to EncryptedJsonImporter and JsonImporter.
type PasswordProtectedImporter struct {
	EncryptedJsonImporter
	promptPassword func() (string, error)
}

// NewPasswordProtectedImporter is the registered constructor for "bitwardenjson".
func NewPasswordProtectedImporter(opts importer.Options) importer.Importer {
	return newPasswordProtected(opts, false)
}

// NewUpgradePasswordProtectedImporter is UpgradeBitwardenPasswordProtectedImporter (the web
// client's pm-35053 "import upgrade" flow): no KDF bounds check, a stricter file-shape check and
// ImportResult.ErrorKey set on password/account failures. Not registered for the CLI.
func NewUpgradePasswordProtectedImporter(opts importer.Options) importer.Importer {
	return newPasswordProtected(opts, true)
}

func newPasswordProtected(opts importer.Options, upgrade bool) *PasswordProtectedImporter {
	enc := NewEncryptedJson(opts)
	enc.upgrade = upgrade
	return &PasswordProtectedImporter{EncryptedJsonImporter: *enc, promptPassword: opts.PromptPassword}
}

// Parse implements importer.Importer.
func (i *PasswordProtectedImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	parsed, err := parseExportFile(data)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		result.Success = false
		return result, nil
	}
	if !parsed.isPasswordProtected() {
		return i.EncryptedJsonImporter.Parse(data)
	}
	if i.cannotParseFile(parsed) {
		result.Success = false
		return result, nil
	}

	var kdf crypto.KdfConfig
	if i.upgrade {
		kdf = upgradeKdfConfig(parsed)
	} else {
		var ok bool
		kdf, ok = kdfConfigFromPasswordProtectedExport(parsed)
		if !ok {
			result.Success = false
			result.ErrorMessage = importer.MsgImportUnsupportedKdfSettings
			return result, nil
		}
	}

	if i.promptPassword == nil {
		return nil, errNoPasswordPrompt
	}
	password, err := i.promptPassword()
	if err != nil {
		return nil, err
	}
	key, ok := checkPassword(parsed, password, kdf)
	if !ok {
		result.Success = false
		result.ErrorMessage = importer.MsgInvalidFilePassword
		if i.upgrade {
			result.ErrorKey = model.ImportResultErrorKeyInvalidFilePassword
		}
		return result, nil
	}

	clearText, err := crypto.DecryptString(rawString(parsed.Data), key)
	if err != nil {
		return nil, err
	}
	return i.EncryptedJsonImporter.Parse(clearText)
}

type importError string

func (e importError) Error() string { return string(e) }

const errNoPasswordPrompt = importError(importer.MsgImportPasswordRequired)

func checkPassword(f *exportFile, password string, kdf crypto.KdfConfig) (*crypto.SymmetricKey, bool) {
	if importer.IsNullOrWhitespace(password) {
		return nil, false
	}
	key, err := deriveVaultExportKey(password, rawString(f.Salt), kdf)
	if err != nil {
		return nil, false
	}
	if _, err := crypto.DecryptString(rawString(f.EncKeyValidation), key); err != nil {
		return nil, false
	}
	return key, true
}

// cannotParseFile checks the non-KDF fields (the KDF ones are validated by
// kdfConfigFromPasswordProtectedExport); the upgrade variant also checks the KDF type/iterations.
func (i *PasswordProtectedImporter) cannotParseFile(f *exportFile) bool {
	if !truthy(f.Encrypted) || !truthy(f.PasswordProtected) || !truthy(f.Salt) ||
		!truthy(f.EncKeyValidation) || !truthy(f.Data) {
		return true
	}
	if i.upgrade {
		if !f.KdfIterations.IsNumber || f.KdfIterations.Value == 0 {
			return true
		}
		if !f.KdfType.IsNumber || (f.KdfType.Value != float64(crypto.KdfPBKDF2) && f.KdfType.Value != float64(crypto.KdfArgon2id)) {
			return true
		}
	}
	return false
}

func upgradeKdfConfig(f *exportFile) crypto.KdfConfig {
	if f.KdfType.Value == float64(crypto.KdfPBKDF2) {
		return crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: f.KdfIterations.Int()}
	}
	mem, par := f.KdfMemory.Int(), f.KdfParallelism.Int()
	return crypto.KdfConfig{Type: crypto.KdfArgon2id, Iterations: f.KdfIterations.Int(), Memory: &mem, Parallelism: &par}
}
