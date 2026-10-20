package auth

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

func v2AccountKeysJSON(securityState string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"publicKeyEncryptionKeyPair": map[string]any{
			"wrappedPrivateKey": v2WrappedPrivateKey, "publicKey": v2PublicKey, "signedPublicKey": v2SignedPublicKey,
		},
		"signatureKeyPair": map[string]any{"wrappedSigningKey": v2WrappedSigningKey, "verifyingKey": v2VerifyingKey},
		"securityState":    map[string]any{"securityState": securityState, "securityVersion": 2},
	})
	return b
}

func mustKeyB64(t *testing.T, s string) *crypto.SymmetricKey {
	t.Helper()
	k, err := crypto.KeyFromB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUnlockAccountKeysV2(t *testing.T) {
	userKey := mustKeyB64(t, v2UserKey)
	acc, err := UnlockAccountKeys(ParseAccountKeys(v2AccountKeysJSON(v2SecurityState)), "", userKey)
	if err != nil {
		t.Fatalf("v2 unlock: %v", err)
	}
	if !acc.IsV2() || acc.PrivateKey == nil || acc.PublicKey == nil {
		t.Fatalf("unexpected account keys %+v", acc)
	}
	pub, _ := x509.MarshalPKIXPublicKey(acc.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != v2PublicKey {
		t.Error("verified public key does not match the vector")
	}

	// A security state signed by another key must fail verification.
	_, err = UnlockAccountKeys(ParseAccountKeys(v2AccountKeysJSON(v2OtherSecurityState)), "", userKey)
	if err == nil || !strings.HasPrefix(err.Error(), "Unable to unlock the account cryptographic state: ") {
		t.Errorf("tampered security state: %v", err)
	}
	// Wrong (v1) user key.
	if _, err := UnlockAccountKeys(ParseAccountKeys(v2AccountKeysJSON(v2SecurityState)), "", crypto.GenerateKey()); err == nil {
		t.Error("v1 user key accepted for a v2 account")
	}
	// A v2 user key with a v1 state is inconsistent.
	if _, err := UnlockAccountKeys(nil, "2.AAAA|AAAA|AAAA", userKey); err == nil {
		t.Error("v2 user key accepted for a v1 account")
	}
	// Missing v2 fields with a v2 private key.
	if _, err := UnlockAccountKeys(nil, v2WrappedPrivateKey, userKey); err == nil {
		t.Error("v2 private key without signing key accepted")
	}
	// Uninitialized accounts (no keys at all) are accepted.
	if acc, err := UnlockAccountKeys(nil, "", userKey); err != nil || acc != nil {
		t.Errorf("empty state: %v %v", acc, err)
	}
}

func TestUnlockAccountKeysV1(t *testing.T) {
	userKey := crypto.GenerateKey()
	_, encPriv, err := MakeKeyPair(userKey)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := UnlockAccountKeys(nil, encPriv, userKey)
	if err != nil || acc.IsV2() || acc.PrivateKey == nil {
		t.Fatalf("v1 unlock: %+v %v", acc, err)
	}
	// V1 tolerates an undecryptable private key.
	if acc, err := UnlockAccountKeys(nil, encPriv, crypto.GenerateKey()); err != nil || acc.PrivateKey != nil {
		t.Errorf("v1 with foreign private key: %+v %v", acc, err)
	}
}

// The vectors carry no password/KDF, so the master key wrapping is built here around the
// vector user key.
func TestUnlockWithMasterPasswordV2(t *testing.T) {
	userKey := mustKeyB64(t, v2UserKey)
	kdf := crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000}
	mk, err := MakeMasterKey("asdfasdfasdf", "test@bitwarden.com", kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(userKey, crypto.StretchKey(mk))
	if err != nil {
		t.Fatal(err)
	}
	acct := &state.Account{
		UserID: "u", Email: "test@bitwarden.com", Kdf: kdf, KdfSalt: "test@bitwarden.com",
		EncUserKey: wrapped, EncPrivateKey: v2WrappedPrivateKey, HasMasterPassword: true,
		AccountKeys: v2AccountKeysJSON(v2SecurityState),
	}
	uk, gotMk, err := UnlockWithMasterPassword(acct, "asdfasdfasdf")
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !bytes.Equal(uk.Bytes(), userKey.Bytes()) || !bytes.Equal(gotMk, mk) {
		t.Error("unexpected user/master key")
	}
	if _, _, err := UnlockWithMasterPassword(acct, "wrong"); err == nil || err.Error() != "Invalid master password." {
		t.Errorf("wrong password: %v", err)
	}
	acct.AccountKeys = v2AccountKeysJSON(v2OtherSecurityState)
	if _, _, err := UnlockWithMasterPassword(acct, "asdfasdfasdf"); err == nil ||
		!strings.HasPrefix(err.Error(), "Unable to unlock the account cryptographic state: ") {
		t.Errorf("tampered state: %v", err)
	}
	// Without stored AccountKeys the synced profile's accountKeys are used.
	acct.AccountKeys = nil
	acct.Vault.Profile = json.RawMessage(`{"id":"u","accountKeys":` + string(v2AccountKeysJSON(v2SecurityState)) + `}`)
	if _, _, err := UnlockWithMasterPassword(acct, "asdfasdfasdf"); err != nil {
		t.Errorf("profile account keys: %v", err)
	}
}
