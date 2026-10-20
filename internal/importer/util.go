package importer

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/lassejlv/bw-go/internal/importer/model"
)

// NewGuid is Utils.newGuid: a random (version 4) UUID in lower-case canonical form.
func NewGuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ErrSSHKeyImportUnsupported is returned by the default ImportSSHKey.
var ErrSSHKeyImportUnsupported = errors.New("SSH key import is not available")

// ImportSSHKey is the SDK's import_ssh_key(privateKey, password?) used by the 1Password 1pux and
// Keeper JSON importers: it parses a PEM/OpenSSH private key (decrypting it with password when it
// is encrypted) and returns the OpenSSH private key, public key and SHA256 fingerprint. Importers
// call it and record model.ImportRecordErrorReasonSshKeyParseFailed when it fails.
//
// It is a hook so the implementation (a port of sdk-internal crates/bitwarden-ssh import.rs,
// e.g. on golang.org/x/crypto/ssh) can live in its own package and register itself from init();
// the default reports ErrSSHKeyImportUnsupported.
var ImportSSHKey = func(privateKey, password string) (*model.SshKeyView, error) {
	return nil, ErrSSHKeyImportUnsupported
}
