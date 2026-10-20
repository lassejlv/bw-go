package vault

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

// deriveSSHPublicKeyAndFingerprint mirrors the SDK's derive_public_key_and_fingerprint: the
// OpenSSH public key line and the "SHA256:..." fingerprint, or empty strings when the private
// key cannot be parsed (unencrypted keys only).
func deriveSSHPublicKeyAndFingerprint(privateKey string) (string, string) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return "", ""
	}
	pub := signer.PublicKey()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub)
}
