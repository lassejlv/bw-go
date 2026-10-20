// Package keepasskdbx ports the SDK-backed KeePass importer (format id "keepasskdbx"):
// sdk-internal crates/bitwarden-importers/src/importers/kdbx.rs, the parts of the keepass crate it
// relies on (KDB / KDBX 3.1 / KDBX 4.x reading, key files, AES-KDF, Argon2d/Argon2id, AES-256,
// Twofish and ChaCha20 outer ciphers, Salsa20/ChaCha20 inner streams) and
// libs/importer/src/sdk/importers/kdbx-sdk-importer.ts (error → message mapping).
//
// The importer implements importer.BinaryImporter. The password comes from
// Options.PromptPassword (called once, before parsing, like the CLI collects credentials before
// calling the SDK) and the optional key file from Options.KeyFile.
package keepasskdbx

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("keepasskdbx", New) }

// Error is ImportError's Kdbx* variants. Error() returns the message the CLI prints (the i18n text
// of KdbxSdkImporter.errorMessageKey); SDKMessage is the Rust error's Display text.
type Error struct {
	Variant    string
	SDKMessage string
	message    string
}

func (e *Error) Error() string { return e.message }

// The four ImportError variants the kdbx parser returns.
var (
	ErrInvalidFormat        = &Error{Variant: "KdbxInvalidFormat", SDKMessage: "The file is not a valid KeePass database (.kdbx)", message: importer.MsgKdbxWrongFileType}
	ErrFileTooLarge         = &Error{Variant: "KdbxFileTooLarge", SDKMessage: "The KeePass database exceeds the maximum supported size", message: importer.MsgKdbxFileTooLarge}
	ErrWrongCredentials     = &Error{Variant: "KdbxWrongCredentials", SDKMessage: "Incorrect KeePass password or key file", message: importer.MsgInvalidFilePassword}
	ErrCorruptOrUnsupported = &Error{Variant: "KdbxCorruptOrUnsupported", SDKMessage: "The KeePass database could not be read; it may be corrupted or unsupported", message: importer.MsgKdbxCorruptOrOutdated}
)

// maxGroupDepth is MAX_GROUP_DEPTH.
const maxGroupDepth = 256

// maxKdbxSize is MAX_KDBX_SIZE (10 MiB).
const maxKdbxSize = 10 * 1024 * 1024

// totpFieldKeys is TOTP_FIELD_KEYS.
var totpFieldKeys = []string{
	"otp",
	"TimeOtp-Secret",
	"TimeOtp-Secret-Hex",
	"TimeOtp-Secret-Base32",
	"TimeOtp-Secret-Base64",
	"TimeOtp-Period",
	"TimeOtp-Length",
	"TimeOtp-Algorithm",
}

var standardFieldKeys = []string{"Title", "UserName", "Password", "URL", "Notes"}

// Importer is the kdbx importer.
type Importer struct {
	importer.Base
	promptPassword func() (string, error)
	keyFile        []byte
	now            func() time.Time
}

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{
		Base:           importer.NewBase(opts),
		promptPassword: opts.PromptPassword,
		keyFile:        opts.KeyFile,
		now:            time.Now,
	}
}

// Parse implements importer.Importer for completeness; the CLI must use ParseBytes with the raw
// file contents.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	return i.ParseBytes([]byte(data))
}

// ParseBytes implements importer.BinaryImporter. Failures are returned as one of the *Error values
// above (or the PromptPassword error). For an organization import the groups become collections,
// like the SDK pipeline's build_org_collections without a target.
func (i *Importer) ParseBytes(data []byte) (*model.ImportResult, error) {
	var password *string
	if i.promptPassword != nil {
		pw, err := i.promptPassword()
		if err != nil {
			return nil, err
		}
		password = &pw
	}
	// The CLI passes a key file only when --keyfile is given; an empty file still counts.
	parsed, err := parseKdbx(data, password, i.keyFile, i.keyFile != nil)
	if err != nil {
		return nil, err
	}

	result := model.NewImportResult()
	now := i.now().UTC()
	for _, c := range parsed.ciphers {
		c.CreationDate = &now
		c.RevisionDate = &now
		result.Ciphers = append(result.Ciphers, c)
	}
	for _, name := range parsed.folders {
		result.Folders = append(result.Folders, &model.FolderView{Name: name})
	}
	result.FolderRelationships = append(result.FolderRelationships, parsed.folderRelationships...)
	if i.Organization() {
		i.MoveFoldersToCollections(result)
	}
	result.Success = true
	return result, nil
}

// parsedImport is pipeline::ParsedImport.
type parsedImport struct {
	ciphers             []*model.CipherView
	folders             []string
	folderRelationships []model.Relationship
}

// parseKdbx is kdbx::parse_kdbx.
func parseKdbx(data []byte, password *string, keyFile []byte, haveKeyFile bool) (*parsedImport, error) {
	if len(data) > maxKdbxSize {
		return nil, ErrFileTooLarge
	}
	if len(data) < len(kdbxIdentifier) || string(data[:len(kdbxIdentifier)]) != string(kdbxIdentifier) {
		return nil, ErrInvalidFormat
	}

	key := &databaseKey{password: password, keyFile: keyFile, haveKeyFile: haveKeyFile}
	db, err := openDatabase(data, key)
	if err != nil {
		return nil, mapOpenError(err)
	}

	// Only treat the UUID as the recycle bin when the feature is enabled.
	var recycleBin *[16]byte
	if db.recycleBinEnabled != nil && *db.recycleBinEnabled {
		recycleBin = db.recycleBinUUID
	}
	result := &parsedImport{}
	if err := traverse(db.root, true, "", recycleBin, 0, result); err != nil {
		return nil, err
	}
	return result, nil
}

// mapOpenError is map_open_error.
func mapOpenError(err error) error {
	var oe *openError
	if errors.As(err, &oe) && (oe.kind == openErrKey || oe.kind == openErrCrypto) {
		return ErrWrongCredentials
	}
	return ErrCorruptOrUnsupported
}

func traverse(g *group, isRoot bool, prefix string, recycleBin *[16]byte, depth int, result *parsedImport) error {
	if depth > maxGroupDepth {
		return ErrCorruptOrUnsupported
	}
	if recycleBin != nil && g.uuid == *recycleBin {
		return nil
	}

	folderIndex := len(result.folders)
	groupName := prefix
	if !isRoot {
		if groupName != "" {
			groupName += "/"
		}
		if strings.TrimSpace(g.name) == "" {
			groupName += "-"
		} else {
			groupName += g.name
		}
		result.folders = append(result.folders, groupName)
	}

	for _, e := range g.entries {
		cipherIndex := len(result.ciphers)
		result.ciphers = append(result.ciphers, mapEntry(e))
		if !isRoot {
			result.folderRelationships = append(result.folderRelationships, model.Relationship{cipherIndex, folderIndex})
		}
	}

	for _, sub := range g.groups {
		if err := traverse(sub, false, groupName, recycleBin, depth+1, result); err != nil {
			return err
		}
	}
	return nil
}

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// nonEmpty is non_empty: the value unless it is missing or blank.
func nonEmpty(e *entry, key string) string {
	v, ok := e.get(key)
	if !ok || isBlank(v) {
		return ""
	}
	return v
}

// mapEntry is map_entry.
func mapEntry(e *entry) *model.CipherView {
	cipher := model.NewCipherView()
	cipher.Type = model.CipherTypeLogin
	cipher.Favorite = false
	cipher.Reprompt = model.CipherRepromptNone
	cipher.Login = &model.LoginView{
		Username: nonEmpty(e, "UserName"),
		Password: nonEmpty(e, "Password"),
		Totp:     buildTotp(e),
	}
	if url := nonEmpty(e, "URL"); url != "" {
		cipher.Login.Uris = []*model.LoginUriView{{Uri: sanitizeURI(url)}}
	}

	cipher.Notes = nonEmpty(e, "Notes")

	cipher.Fields = []*model.FieldView{}
	for _, key := range e.keys {
		if contains(totpFieldKeys, key) || contains(standardFieldKeys, key) {
			continue
		}
		v := e.values[key]
		if isBlank(v.value) {
			continue
		}
		t := model.FieldTypeText
		if v.protected {
			t = model.FieldTypeHidden
		}
		cipher.Fields = append(cipher.Fields, &model.FieldView{Name: key, Value: v.value, Type: t})
	}

	cipher.Name = "--"
	if title := nonEmpty(e, "Title"); title != "" {
		cipher.Name = title
	}
	return cipher
}

// buildTotp is build_totp: KeePassXC's `otp` field, or KeePass 2.x's TimeOtp-* fields as a Base32
// secret (default settings) or an otpauth URI.
func buildTotp(e *entry) string {
	if otp := nonEmpty(e, "otp"); otp != "" {
		return strings.TrimPrefix(otp, "key=")
	}
	secret, ok := timeOtpSecretAsBase32(e)
	if !ok {
		return ""
	}
	period, hasPeriod := nonDefault(e, "TimeOtp-Period", "30")
	digits, hasDigits := nonDefault(e, "TimeOtp-Length", "6")
	algorithm, hasAlgorithm := totpAlgorithm(e)
	if !hasPeriod && !hasDigits && !hasAlgorithm {
		return secret
	}
	query := "secret=" + secret
	if hasAlgorithm {
		query += "&algorithm=" + algorithm
	}
	if hasDigits {
		query += "&digits=" + digits
	}
	if hasPeriod {
		query += "&period=" + period
	}
	return "otpauth://totp/Imported?" + query
}

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// timeOtpSecretAsBase32 is time_otp_secret_as_base32. A malformed secret in the first present
// encoding yields no TOTP at all (the Rust `?` returns None).
func timeOtpSecretAsBase32(e *entry) (string, bool) {
	if v := nonEmpty(e, "TimeOtp-Secret-Base32"); v != "" {
		normalized := strings.ToUpper(strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) || r == '=' {
				return -1
			}
			return r
		}, v))
		// data_encoding's BASE32_NOPAD rejects non-canonical input (bad length, non-zero trailing
		// bits); a decode/encode round trip checks the same.
		b, err := base32NoPad.DecodeString(normalized)
		if err != nil {
			return "", false
		}
		encoded := base32NoPad.EncodeToString(b)
		if encoded != normalized {
			return "", false
		}
		return encoded, true
	}
	if v := nonEmpty(e, "TimeOtp-Secret-Base64"); v != "" {
		trimmed := strings.TrimSpace(v)
		if strings.ContainsAny(trimmed, "\r\n") {
			return "", false
		}
		b, err := base64.StdEncoding.Strict().DecodeString(trimmed)
		if err != nil {
			return "", false
		}
		return base32NoPad.EncodeToString(b), true
	}
	if v := nonEmpty(e, "TimeOtp-Secret-Hex"); v != "" {
		b, err := hex.DecodeString(strings.TrimSpace(v))
		if err != nil {
			return "", false
		}
		return base32NoPad.EncodeToString(b), true
	}
	if v := nonEmpty(e, "TimeOtp-Secret"); v != "" {
		return base32NoPad.EncodeToString([]byte(v)), true
	}
	return "", false
}

// totpAlgorithm is totp_algorithm.
func totpAlgorithm(e *entry) (string, bool) {
	v, ok := e.get("TimeOtp-Algorithm")
	if !ok {
		return "", false
	}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "HMAC-SHA-256":
		return "SHA256", true
	case "HMAC-SHA-512":
		return "SHA512", true
	}
	return "", false
}

// nonDefault is non_default: the trimmed value unless missing, blank or equal to the default.
func nonDefault(e *entry, key, def string) (string, bool) {
	v, ok := e.get(key)
	if !ok {
		return "", false
	}
	t := strings.TrimSpace(v)
	if t == "" || t == def {
		return "", false
	}
	return t, true
}
