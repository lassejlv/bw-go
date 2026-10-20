// Package exporter ports libs/tools/export-vault-core (VaultExportService,
// IndividualVaultExportService, OrganizationVaultExportService and BaseVaultExportService): vault
// exports as CSV, JSON, account-encrypted JSON, password-protected JSON and ZIP with attachments.
package exporter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

// Export formats (EXPORT_FORMATS).
const (
	FormatCSV           = "csv"
	FormatJSON          = "json"
	FormatEncryptedJSON = "encrypted_json"
	FormatZip           = "zip"
)

// Formats lists the supported export formats in upstream order.
var Formats = []string{FormatCSV, FormatJSON, FormatEncryptedJSON, FormatZip}

// IsSupportedFormat mirrors ExportCommand.isSupportedExportFormat.
func IsSupportedFormat(f string) bool {
	for _, x := range Formats {
		if x == f {
			return true
		}
	}
	return false
}

// Content types of ExportedVault.
const (
	TypeText = "text/plain"
	TypeZip  = "application/zip"
)

// ExportedVault mirrors ExportedVaultAsString / ExportedVaultAsBlob.
type ExportedVault struct {
	Type     string
	Data     []byte
	FileName string
	// SkippedAttachmentCount is the number of attachments that could not be exported (zip only).
	SkippedAttachmentCount int
}

// Service holds what the export services need from the active account.
type Service struct {
	Vault *vault.Vault
	// Kdf is the account KDF configuration (kdfConfigService.getKdfConfig), used for
	// password-protected exports.
	Kdf crypto.KdfConfig
	// API fetches the organization export and attachments.
	API Client
	// Now returns the current time (file names, zip entry dates). Defaults to time.Now.
	Now func() time.Time
	// LogError reports non-fatal errors (logService.error). Defaults to writing to stderr.
	LogError func(msg string, err error)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logError(msg string, err error) {
	if s.LogError != nil {
		s.LogError(msg, err)
		return
	}
	fmt.Fprintln(os.Stderr, msg, err)
}

// isNullOrWhitespace mirrors Utils.isNullOrWhitespace for strings (JS trim semantics).
func isNullOrWhitespace(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' }) == ""
}

// errEmptySequence is what firstValueFrom rejects with when cipherService.decrypt swallows a
// decryption error (catchError → EMPTY).
var errEmptySequence = errors.New("no elements in sequence")

// GetExport mirrors VaultExportService.getExport: an export of the individual vault (My vault),
// unencrypted, account-encrypted or password-protected.
func (s *Service) GetExport(format, password string) (*ExportedVault, error) {
	if format == "" {
		format = FormatCSV
	}
	if !isNullOrWhitespace(password) {
		if format == FormatCSV {
			return nil, errors.New("CSV does not support password protected export")
		}
		return s.individualPasswordProtectedExport(password)
	}
	return s.individualExport(format)
}

// GetOrganizationExport mirrors VaultExportService.getOrganizationExport.
func (s *Service) GetOrganizationExport(organizationID, format, password string, onlyManagedCollections bool) (*ExportedVault, error) {
	if !isNullOrWhitespace(password) {
		if format == FormatCSV {
			return nil, errors.New("CSV does not support password protected export")
		}
		exp, err := s.organizationExport(organizationID, FormatJSON, onlyManagedCollections)
		if err != nil {
			return nil, err
		}
		data, err := s.buildPasswordExport(exp.Data, password)
		if err != nil {
			return nil, err
		}
		return &ExportedVault{Type: TypeText, Data: data, FileName: GetFileName("org", FormatEncryptedJSON, s.now())}, nil
	}
	return s.organizationExport(organizationID, format, onlyManagedCollections)
}

// GetFileName mirrors ExportHelper.getFileName (local time, yyyyMMddHHmmss).
func GetFileName(prefix, format string, now time.Time) string {
	if format == "" {
		format = FormatCSV
	}
	if format == FormatEncryptedJSON {
		if prefix == "" {
			prefix = "encrypted"
		} else {
			prefix = "encrypted_" + prefix
		}
		format = FormatJSON
	}
	p := ""
	if prefix != "" {
		p = "_" + prefix
	}
	return "bitwarden" + p + "_export_" + now.Format("20060102150405") + "." + format
}

// ---------- JSON documents (field order = JSON.stringify order) ----------

type unencryptedIndividualJSON struct {
	Encrypted bool                        `json:"encrypted"`
	Folders   []vault.FolderWithIDExport  `json:"folders"`
	Items     []*vault.CipherWithIDExport `json:"items"`
}

type encryptedIndividualJSON struct {
	Encrypted        bool                        `json:"encrypted"`
	EncKeyValidation string                      `json:"encKeyValidation_DO_NOT_EDIT"`
	Folders          []vault.FolderWithIDExport  `json:"folders"`
	Items            []*vault.CipherWithIDExport `json:"items"`
}

type unencryptedOrgJSON struct {
	Encrypted   bool                           `json:"encrypted"`
	Collections []vault.CollectionWithIDExport `json:"collections"`
	Items       []*vault.CipherWithIDExport    `json:"items"`
}

type encryptedOrgJSON struct {
	Encrypted        bool                           `json:"encrypted"`
	EncKeyValidation string                         `json:"encKeyValidation_DO_NOT_EDIT"`
	Collections      []vault.CollectionWithIDExport `json:"collections"`
	Items            []*vault.CipherWithIDExport    `json:"items"`
}

// PasswordProtectedJSON mirrors BitwardenPasswordProtectedFileFormat. kdfMemory/kdfParallelism
// are assigned after the object literal upstream, so they serialize last.
type PasswordProtectedJSON struct {
	Encrypted         bool   `json:"encrypted"`
	PasswordProtected bool   `json:"passwordProtected"`
	Salt              string `json:"salt"`
	KdfType           int    `json:"kdfType"`
	KdfIterations     int    `json:"kdfIterations"`
	EncKeyValidation  string `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string `json:"data"`
	KdfMemory         *int   `json:"kdfMemory,omitempty"`
	KdfParallelism    *int   `json:"kdfParallelism,omitempty"`
}

// stringify mirrors JSON.stringify(v, null, "  ").
func stringify(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return unescapeLineSeparators(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// unescapeLineSeparators undoes encoding/json's \u2028 / \u2029 escaping (JSON.stringify keeps
// these characters literally).
func unescapeLineSeparators(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u202`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			out = append(out, b[i])
			continue
		}
		if i+5 < len(b) && b[i+1] == 'u' && b[i+2] == '2' && b[i+3] == '0' && b[i+4] == '2' && (b[i+5] == '8' || b[i+5] == '9') {
			if b[i+5] == '8' {
				out = append(out, "\u2028"...)
			} else {
				out = append(out, "\u2029"...)
			}
			i += 5
			continue
		}
		// any other escape sequence: copy the backslash and the escaped character verbatim
		out = append(out, b[i])
		if i+1 < len(b) {
			out = append(out, b[i+1])
			i++
		}
	}
	return out
}

// ---------- password protection (BaseVaultExportService.buildPasswordExport) ----------

func (s *Service) buildPasswordExport(clearText []byte, password string) ([]byte, error) {
	kdf := s.Kdf
	salt := b64(crypto.RandomBytes(16))
	key, err := DeriveVaultExportKey(password, salt, kdf)
	if err != nil {
		return nil, err
	}
	encKeyValidation, err := crypto.EncryptString(newGUID(), key)
	if err != nil {
		return nil, err
	}
	encText, err := crypto.EncryptString(string(clearText), key)
	if err != nil {
		return nil, err
	}
	doc := PasswordProtectedJSON{
		Encrypted: true, PasswordProtected: true, Salt: salt, KdfType: int(kdf.Type),
		KdfIterations: kdf.Iterations, EncKeyValidation: encKeyValidation, Data: encText,
	}
	if kdf.Type == crypto.KdfArgon2id {
		mem, par := 64, 4
		if kdf.Memory != nil {
			mem = *kdf.Memory
		}
		if kdf.Parallelism != nil {
			par = *kdf.Parallelism
		}
		doc.KdfMemory, doc.KdfParallelism = &mem, &par
	}
	return stringify(doc)
}

// DeriveVaultExportKey mirrors KeyGenerationService.deriveVaultExportKey: the KDF output for
// password/salt, stretched with HKDF into an AES-256-CBC-HMAC key.
func DeriveVaultExportKey(password, salt string, kdf crypto.KdfConfig) (*crypto.SymmetricKey, error) {
	mk, err := crypto.MakeMasterKey(password, salt, kdf)
	if err != nil {
		return nil, err
	}
	return crypto.StretchKey(mk), nil
}
