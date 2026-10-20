// Package importer is the Go port of libs/importer (the `bw import` machinery): the shared
// BaseImporter helpers (Base), the Importer interface, the registry of every upstream format id,
// the ImportService post-processing that does not need the vault, and the CLI's file-reading
// rules. Concrete importers live in internal/importer/formats/<name> and register themselves from
// init(); internal/importer/all blank-imports all of them. See README.md in this directory.
package importer

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Importer is libs/importer/src/importers/importer.ts. The organization id is supplied through
// Options when the importer is constructed.
//
// Parse returns (result, nil) for every outcome the TS importer reports through ImportResult
// (success=false, errorMessage), and a non-nil error only where the TS code throws. Wrap JSON
// syntax errors with NewSyntaxError (or return the *json.SyntaxError) so the service maps them to
// "importFormatError" like it does for a JavaScript SyntaxError.
type Importer interface {
	Parse(data string) (*model.ImportResult, error)
}

// BinaryImporter is implemented by importers whose input is not text (the SDK-backed formats,
// e.g. keepasskdbx). The import command must call ParseBytes with the raw file when
// Format.SDK != nil.
type BinaryImporter interface {
	ParseBytes(data []byte) (*model.ImportResult, error)
}

// Features carries the server feature flags the TS importers read through ConfigService.
type Features struct {
	// NewItemTypes is FeatureFlag.PM32009NewItemTypes (bank account, passport, driver's license
	// item types).
	NewItemTypes bool
}

// Options are the constructor dependencies of every importer (the union of what the TS
// constructors receive).
type Options struct {
	// OrganizationID is importer.organizationId ("" for an individual vault import).
	OrganizationID string
	// PromptPassword is promptForPassword_callback: returns the file password (Bitwarden
	// password-protected JSON, KeePass kdbx, ...). May be nil when no prompt is possible; importers
	// that need it then fail.
	PromptPassword func() (string, error)
	// KeyFile is the optional KeePass key file contents (CredentialKind passwordWithKeyFile).
	KeyFile []byte
	// Decryptor gives the account-encrypted Bitwarden JSON importer access to the account keys and
	// the vault's cipher decryption. Optional for every other importer.
	Decryptor Decryptor
	// Features are the server feature flags.
	Features Features
	// Warn receives BaseImporter's logService.warning messages (CSV row errors). nil means
	// DefaultWarn.
	Warn func(msg string)
}

// AccountKeys exposes the unlocked account's keys.
type AccountKeys interface {
	// UserKey returns the user key, or an error when the vault is locked.
	UserKey() (*crypto.SymmetricKey, error)
	// OrgKey returns the organization key, or (nil, nil) when the account has no key for it.
	OrgKey(organizationID string) (*crypto.SymmetricKey, error)
}

// Decryptor is what the account-encrypted Bitwarden JSON importer needs from the vault layer.
type Decryptor interface {
	AccountKeys
	// DecryptExportCipher decrypts one element of an encrypted export's "items" array (the
	// CipherWithIdExport JSON, after CipherWithIdExport.toDomain: id/collectionIds dropped and
	// organizationId replaced by organizationID) into a view, like CipherService.decrypt. It must
	// handle legacy per-field EncStrings, per-cipher keys and blob ("data") ciphers.
	DecryptExportCipher(item json.RawMessage, organizationID string) (*model.CipherView, error)
}

// Format describes one import format (ImportOption in import-options.ts).
type Format struct {
	ID                string
	Name              string
	Featured          bool
	IsBrowser         bool
	AcceptedFileTypes []string
	PasteFormats      []string
	HasDirectImporter bool
	// SDK is set when upstream parses the format in the Rust SDK; the Go port must implement
	// BinaryImporter for it.
	SDK *SDKInfo
	// Hidden marks ids that are hidden from pickers (keepercsv/keeperjson) but valid for the CLI.
	Hidden bool
	// Source is the upstream file to port.
	Source string
}

// CredentialKind mirrors sdk/credential-kind.ts.
type CredentialKind string

const (
	CredentialNone                CredentialKind = "none"
	CredentialPassword            CredentialKind = "password"
	CredentialPasswordWithKeyFile CredentialKind = "passwordWithKeyFile"
)

// SDKInfo mirrors ImportOption.sdk.
type SDKInfo struct {
	FileTypes      []string
	CredentialKind CredentialKind
}

// SyntaxError marks malformed input (the equivalent of a JavaScript SyntaxError thrown by
// JSON.parse); ImportService turns it into the "importFormatError" message.
type SyntaxError struct{ Err error }

func (e *SyntaxError) Error() string { return e.Err.Error() }
func (e *SyntaxError) Unwrap() error { return e.Err }

// NewSyntaxError wraps err as a SyntaxError.
func NewSyntaxError(err error) error { return &SyntaxError{Err: err} }

// IsSyntaxError reports whether err is a SyntaxError or a JSON syntax error.
func IsSyntaxError(err error) bool {
	var se *SyntaxError
	var js *json.SyntaxError
	return errors.As(err, &se) || errors.As(err, &js)
}

// ErrNotImplemented is returned (wrapped in *NotImplementedError) for a known format whose Go
// importer has not been ported yet.
var ErrNotImplemented = errors.New("import format not implemented")

// NotImplementedError reports a known but unported format.
type NotImplementedError struct{ Format Format }

func (e *NotImplementedError) Error() string {
	return fmt.Sprintf("The %q import format (%s) is not supported by this CLI yet.", e.Format.ID, e.Format.Name)
}

func (e *NotImplementedError) Unwrap() error { return ErrNotImplemented }
