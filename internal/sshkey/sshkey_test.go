package sshkey

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
)

// Ported from sdk-internal crates/bitwarden-ssh src/import.rs (and the import part of
// src/export.rs). testdata/import and testdata/generator are the crate's resources;
// testdata/extra holds additional keys made with openssl/ssh-keygen. testdata/vectors.json was
// produced by running the SDK's own bitwarden_ssh::import::import_key on every file with the
// passwords None, "", "password" and "wrongpassword".

func readKey(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range []string{"import", "generator", "extra"} {
		if b, err := os.ReadFile(filepath.Join("testdata", dir, name)); err == nil {
			return string(b)
		}
	}
	t.Fatalf("test key %s not found", name)
	return ""
}

func ptr(s string) *string { return &s }

func importOK(t *testing.T, name string, password *string) *KeyData {
	t.Helper()
	d, err := ImportKey(readKey(t, name), password)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}

func expectPublic(t *testing.T, name string, password *string, pubFile string, stripComment bool) {
	t.Helper()
	d := importOK(t, name, password)
	want := readKey(t, pubFile)
	if stripComment {
		want = strings.ReplaceAll(want, "testkey", "")
	}
	want = strings.TrimSpace(want)
	if d.PublicKey != want {
		t.Errorf("%s: public key\n got %q\nwant %q", name, d.PublicKey, want)
	}
}

func expectErr(t *testing.T, key string, password *string, want error) {
	t.Helper()
	_, err := ImportKey(key, password)
	if !errors.Is(err, want) {
		t.Errorf("got %v, want %v", err, want)
	}
}

func TestImportKeyEd25519OpenSSHUnencrypted(t *testing.T) {
	expectPublic(t, "ed25519_openssh_unencrypted", ptr(""), "ed25519_openssh_unencrypted.pub", false)
}

func TestImportKeyEd25519OpenSSHEncrypted(t *testing.T) {
	expectPublic(t, "ed25519_openssh_encrypted", ptr("password"), "ed25519_openssh_encrypted.pub", false)
}

func TestImportKeyRsaOpenSSHUnencrypted(t *testing.T) {
	expectPublic(t, "rsa_openssh_unencrypted", ptr(""), "rsa_openssh_unencrypted.pub", false)
}

func TestImportKeyRsaOpenSSHEncrypted(t *testing.T) {
	expectPublic(t, "rsa_openssh_encrypted", ptr("password"), "rsa_openssh_encrypted.pub", false)
}

func TestImportKeyEd25519PKCS8Unencrypted(t *testing.T) {
	expectPublic(t, "ed25519_pkcs8_unencrypted", ptr(""), "ed25519_pkcs8_unencrypted.pub", true)
}

func TestImportKeyRsaPKCS8Unencrypted(t *testing.T) {
	// for whatever reason pkcs8 + rsa does not include the comment in the public key
	expectPublic(t, "rsa_pkcs8_unencrypted", ptr(""), "rsa_pkcs8_unencrypted.pub", true)
}

func TestImportKeyRsaPKCS8Encrypted(t *testing.T) {
	expectPublic(t, "rsa_pkcs8_encrypted", ptr("password"), "rsa_pkcs8_encrypted.pub", true)
}

func TestImportKeyEd25519OpenSSHEncryptedWrongPassword(t *testing.T) {
	expectErr(t, readKey(t, "ed25519_openssh_encrypted"), ptr("wrongpassword"), ErrWrongPassword)
}

// 1Password's 1PUX export re-encodes Ed25519 keys as PKCS#8 with the whole base64 body on a
// single line (https://github.com/bitwarden/clients/issues/20432).
func TestImportKeyEd25519PKCS8UnencryptedSingleLine(t *testing.T) {
	expectPublic(t, "ed25519_pkcs8_1password_single_line_unencrypted", nil, "ed25519_pkcs8_unencrypted.pub", false)
}

func TestImportNonKeyError(t *testing.T) {
	expectErr(t, "not a key", ptr(""), ErrParsing)
}

func TestImportWrongLabelError(t *testing.T) {
	expectErr(t, readKey(t, "wrong_label"), ptr(""), ErrUnsupportedKeyType)
}

func TestImportEcdsaP256OpenSSHUnencrypted(t *testing.T) {
	expectPublic(t, "ecdsa_openssh_unencrypted", ptr(""), "ecdsa_openssh_unencrypted.pub", false)
}

func TestImportEcdsaP384OpenSSHUnencrypted(t *testing.T) {
	expectPublic(t, "ecdsa_p384_openssh_unencrypted", ptr(""), "ecdsa_p384_openssh_unencrypted.pub", false)
}

func TestImportEcdsaP521OpenSSHUnencrypted(t *testing.T) {
	expectPublic(t, "ecdsa_p521_openssh_unencrypted", ptr(""), "ecdsa_p521_openssh_unencrypted.pub", false)
}

func TestImportKeyEd25519Putty(t *testing.T) {
	expectPublic(t, "ed25519_putty_openssh_unencrypted", ptr(""), "ed25519_putty_openssh_unencrypted.pub", false)
}

func TestImportKeyRsaOpenSSHPutty(t *testing.T) {
	expectPublic(t, "rsa_putty_openssh_unencrypted", ptr(""), "rsa_putty_openssh_unencrypted.pub", false)
}

func TestImportKeyRsaPKCS8Putty(t *testing.T) {
	expectErr(t, readKey(t, "rsa_putty_pkcs1_unencrypted"), ptr(""), ErrUnsupportedKeyType)
}

// https://github.com/bitwarden/clients/issues/17028#issuecomment-3455975763
func TestImportEd25519KeyRegression17028(t *testing.T) {
	expectPublic(t, "ed25519_regression_17028", nil, "ed25519_regression_17028.pub", false)
}

func TestImportSkEd25519OpenSSHUnencryptedIsUnsupported(t *testing.T) {
	expectErr(t, readKey(t, "sk_ed25519_openssh_unencrypted"), nil, ErrUnsupportedKeyType)
}

func TestSupportedAlgorithms(t *testing.T) {
	for _, k := range []keyKind{kindEd25519, kindRSA, kindECDSA} {
		if !isSupportedAlgorithm(k) {
			t.Errorf("%d should be supported", k)
		}
	}
	for _, k := range []keyKind{kindDSA, kindSkEd25519, kindSkECDSA, kindOther} {
		if isSupportedAlgorithm(k) {
			t.Errorf("%d should not be supported", k)
		}
	}
	if a, err := parseAlgorithm("bogus@example.com"); err != nil || a.kind != kindOther {
		t.Errorf("unknown names map to Algorithm::Other: %v %v", a, err)
	}
}

// From export.rs export_ed25519_openssh_unencrypted: the PKCS#8 DER of
// ed25519_openssh_unencrypted re-imports to the same public key (without the comment).
func TestImportPKCS8DERKey(t *testing.T) {
	der := []byte{
		48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 139, 118, 81, 75, 32, 150,
		196, 136, 90, 63, 127, 68, 78, 117, 115, 13, 100, 3, 199, 24, 243, 97, 189, 182, 223,
		181, 163, 236, 81, 145, 35, 104, 129, 33, 0, 50, 66, 141, 182, 77, 117, 205, 170, 241,
		126, 47, 200, 212, 73, 35, 94, 187, 197, 42, 174, 192, 227, 189, 255, 105, 192, 140, 3,
		11, 211, 11, 234,
	}
	orig := importOK(t, "ed25519_openssh_unencrypted", ptr(""))
	d, err := ImportPKCS8DERKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if d.PublicKey != strings.TrimSuffix(orig.PublicKey, " testkey") {
		t.Errorf("got %q, want %q", d.PublicKey, orig.PublicKey)
	}
}

// Round trip: the OpenSSH private key the import produces imports to itself.
func TestImportRoundTrip(t *testing.T) {
	for _, name := range []string{"ecdsa_p256_key", "ecdsa_p384_key", "ecdsa_p521_key", "ed25519_key", "rsa3072_key", "rsa_pkcs8_unencrypted", "ec_P521_pkcs8"} {
		d := importOK(t, name, nil)
		again := importOK(t, name, nil)
		re, err := ImportKey(d.PrivateKey, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if *re != *again {
			t.Errorf("%s: round trip mismatch", name)
		}
	}
}

type vector struct {
	File        string  `json:"file"`
	Password    *string `json:"password"`
	PrivateKey  string  `json:"privateKey"`
	PublicKey   string  `json:"publicKey"`
	Fingerprint string  `json:"fingerprint"`
	Error       string  `json:"error"`
}

// TestSDKVectors compares every result (outputs byte for byte, or the error variant) with the
// output of the Rust SDK.
func TestSDKVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		pw := "None"
		if v.Password != nil {
			pw = "Some(" + *v.Password + ")"
		}
		d, err := ImportKey(readKey(t, v.File), v.Password)
		if v.Error != "" {
			var ie *ImportError
			if !errors.As(err, &ie) || ie.Variant() != v.Error {
				t.Errorf("%s %s: got (%v, %v), want error %s", v.File, pw, d, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %s: unexpected error %v", v.File, pw, err)
			continue
		}
		if d.PrivateKey != v.PrivateKey {
			t.Errorf("%s %s: private key\n got %q\nwant %q", v.File, pw, d.PrivateKey, v.PrivateKey)
		}
		if d.PublicKey != v.PublicKey {
			t.Errorf("%s %s: public key\n got %q\nwant %q", v.File, pw, d.PublicKey, v.PublicKey)
		}
		if d.Fingerprint != v.Fingerprint {
			t.Errorf("%s %s: fingerprint %q, want %q", v.File, pw, d.Fingerprint, v.Fingerprint)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	for err, want := range map[error]string{
		ErrParsing:            "Failed to parse key",
		ErrPasswordRequired:   "Password required",
		ErrWrongPassword:      "Wrong password",
		ErrUnsupportedKeyType: "Unsupported key type",
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err.Error(), want)
		}
	}
}

func TestHook(t *testing.T) {
	v, err := importer.ImportSSHKey(readKey(t, "ed25519_openssh_encrypted"), "password")
	if err != nil {
		t.Fatal(err)
	}
	want := importOK(t, "ed25519_openssh_encrypted", ptr("password"))
	if v.PrivateKey != want.PrivateKey || v.PublicKey != want.PublicKey || v.KeyFingerprint != want.Fingerprint {
		t.Errorf("hook result %+v", v)
	}
	// "" is None: an encrypted key then needs a password.
	if _, err := importer.ImportSSHKey(readKey(t, "ed25519_openssh_encrypted"), ""); !errors.Is(err, ErrPasswordRequired) {
		t.Errorf("got %v", err)
	}
	var withVariant interface{ Variant() string }
	_, err = importer.ImportSSHKey("not a key", "")
	if !errors.As(err, &withVariant) || withVariant.Variant() != "Parsing" {
		t.Errorf("got %v", err)
	}
}
