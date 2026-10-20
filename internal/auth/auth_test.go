package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/crypto"
)

func TestPasswordTokenForm(t *testing.T) {
	r := &TokenRequest{
		GrantType: GrantPassword, Email: "user@example.com", MasterPasswordHash: "hash",
		TwoFactor: NewTwoFactorRequest(TwoFactorAuthenticator, "123456"),
		Device:    &DeviceRequest{Type: 24, Name: "macos", Identifier: "app-id"},
	}
	f := r.Form()
	want := map[string]string{
		"scope": "api offline_access", "client_id": "cli", "grant_type": "password",
		"username": "user@example.com", "password": "hash", "deviceType": "24",
		"deviceIdentifier": "app-id", "deviceName": "macos", "twoFactorToken": "123456",
		"twoFactorProvider": "0", "twoFactorRemember": "0",
	}
	for k, v := range want {
		if got := f.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if f.Has("newDeviceOtp") {
		t.Error("newDeviceOtp should be absent")
	}
	r.NewDeviceOtp = "999"
	if r.Form().Get("newDeviceOtp") != "999" {
		t.Error("newDeviceOtp missing")
	}
	// A two-factor request without provider is not sent.
	r.TwoFactor = &TwoFactorRequest{Token: "123"}
	if r.Form().Has("twoFactorToken") {
		t.Error("twoFactorToken without provider must not be sent")
	}
}

func TestAPIKeyAndSsoForm(t *testing.T) {
	f := (&TokenRequest{GrantType: GrantClientCredentials, ClientID: "user.abc", ClientSecret: "s"}).Form()
	if f.Get("scope") != "api" || f.Get("client_id") != "user.abc" || f.Get("client_secret") != "s" ||
		f.Get("grant_type") != "client_credentials" {
		t.Errorf("unexpected api key form %v", f)
	}
	f = (&TokenRequest{GrantType: GrantClientCredentials, ClientID: "organization.x"}).Form()
	if f.Get("scope") != "api.organization" {
		t.Errorf("org scope = %q", f.Get("scope"))
	}
	f = (&TokenRequest{GrantType: GrantAuthorizationCode, Code: "c", CodeVerifier: "v", RedirectURI: "http://localhost:8065"}).Form()
	if f.Get("client_id") != "cli" || f.Get("code") != "c" || f.Get("code_verifier") != "v" ||
		f.Get("redirect_uri") != "http://localhost:8065" || f.Get("grant_type") != "authorization_code" ||
		f.Get("scope") != "api offline_access" {
		t.Errorf("unexpected sso form %v", f)
	}
}

func TestPrelogin(t *testing.T) {
	p, err := ParsePasswordPrelogin([]byte(`{"kdfSettings":{"kdfType":1,"iterations":3,"memory":64,"parallelism":4},"salt":"user@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.KdfConfig.Type != crypto.KdfArgon2id || p.KdfConfig.Iterations != 3 || *p.KdfConfig.Memory != 64 ||
		*p.KdfConfig.Parallelism != 4 || p.Salt != "user@example.com" {
		t.Errorf("unexpected prelogin %+v", p)
	}
	p, err = ParsePasswordPrelogin([]byte(`{"KdfSettings":{"KdfType":0,"Iterations":600000},"Salt":"a@b.c"}`))
	if err != nil || p.KdfConfig.Type != crypto.KdfPBKDF2 || p.KdfConfig.Iterations != 600000 {
		t.Fatalf("pascal case prelogin: %+v %v", p, err)
	}
	_, err = ParsePasswordPrelogin([]byte(`{"kdfSettings":{"kdfType":0,"iterations":100},"salt":"x"}`))
	if err == nil || err.Error() != "PBKDF2 iterations must be at least 5000, but was 100; possible pre-login downgrade attack detected." {
		t.Errorf("downgrade not detected: %v", err)
	}
	_, err = ParsePasswordPrelogin([]byte(`{"kdfSettings":{"kdfType":1,"iterations":3},"salt":"x"}`))
	if err == nil || err.Error() != "KDF config response does not contain a valid memory size for Argon2id" {
		t.Errorf("missing memory not detected: %v", err)
	}
	p, err = ParseLegacyPrelogin([]byte(`{"kdf":0,"kdfIterations":100000}`), "a@b.c")
	if err != nil || p.KdfConfig.Iterations != 100000 || p.Salt != "a@b.c" {
		t.Errorf("legacy prelogin: %+v %v", p, err)
	}
}

// Vectors computed independently with Python's hashlib (PBKDF2-SHA256, HKDF-Expand).
func TestMasterKeyDerivation(t *testing.T) {
	mk, err := MakeMasterKey("p@ssw0rd", " User@Example.com ", crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	if got := b64(mk); got != "aSRfRlMTkY/i089mAgOtTpFarcSCdDJVq2Z+xjy29dg=" {
		t.Errorf("master key = %s", got)
	}
	if got := crypto.HashMasterPassword("p@ssw0rd", mk, crypto.HashServerAuthorization); got != "uAP6sl4QKzyzuCc+hBKmT3AiRR1bpii25r9IbEqnoVc=" {
		t.Errorf("master password hash = %s", got)
	}
	s := crypto.StretchKey(mk)
	if b64(s.EncKey) != "VjEu66JoywMXbPKfRT2bsvMCwdUk/AVUz3vXhGrtbpw=" || b64(s.MacKey) != "1xh1++dout5DH3PUL8J6Ucklmi6s8qaW4CFxsoC8y7Q=" {
		t.Errorf("stretched key = %s / %s", b64(s.EncKey), b64(s.MacKey))
	}

	// Round trip: wrap a user key with the stretched master key and unwrap it.
	uk := crypto.GenerateKey()
	enc, err := crypto.Encrypt(uk.Bytes(), s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptUserKeyWithMasterKey(mk, enc.String())
	if err != nil || got.B64() != uk.B64() {
		t.Fatalf("user key round trip failed: %v", err)
	}
	if IsLegacyUserKey(enc.String()) || !IsLegacyUserKey("") || !IsLegacyUserKey("0.AAAA|AAAA") {
		t.Error("IsLegacyUserKey misclassified")
	}
}

func identity(status int, body string) *api.IdentityResult {
	r := &api.IdentityResult{Status: status, Raw: []byte(body)}
	_ = json.Unmarshal(r.Raw, &r.Body)
	return r
}

func TestParseIdentityResult(t *testing.T) {
	r, err := ParseIdentityResult(identity(400, `{"error":"invalid_grant","TwoFactorProviders":["1","0"],"TwoFactorProviders2":{"1":{"Email":"u***@example.com"},"0":null},"SsoEmail2faSessionToken":"tok","Email":"u@example.com"}`))
	if err != nil || r.TwoFactor == nil {
		t.Fatalf("2fa not detected: %v", err)
	}
	if p := r.TwoFactor.Providers(); len(p) != 2 || p[0] != 0 || p[1] != 1 {
		t.Errorf("providers = %v", p)
	}
	if r.TwoFactor.SsoEmail2faSessionToken != "tok" || r.TwoFactor.Email != "u@example.com" {
		t.Errorf("2fa fields: %+v", r.TwoFactor)
	}
	sp := SupportedTwoFactorProviders([]int{TwoFactorEmail, TwoFactorDuo, TwoFactorYubikey, TwoFactorAuthenticator, TwoFactorWebAuthn})
	if len(sp) != 3 || sp[0].Name != "Authenticator App" || sp[1].Name != "Yubico OTP Security Key" || sp[2].Name != "Email" {
		t.Errorf("supported providers = %+v", sp)
	}

	r, err = ParseIdentityResult(identity(400, `{"error":"invalid_grant","ErrorModel":{"Message":"new device verification required","Object":"error"}}`))
	if err != nil || !r.DeviceVerification {
		t.Errorf("device verification not detected: %v", err)
	}
	r, err = ParseIdentityResult(identity(400, `{"error":"invalid_grant","SsoOrganizationIdentifier":"acme"}`))
	if err != nil || r.SsoRequired == nil || r.SsoRequired.SsoOrganizationIdentifier != "acme" {
		t.Errorf("sso required not detected: %v", err)
	}
	_, err = ParseIdentityResult(identity(400, `{"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Username or password is incorrect. Try again.","Object":"error"}}`))
	var apiErr *api.ErrorResponse
	if e, ok := err.(*api.ErrorResponse); !ok || e.SingleMessage() != "Username or password is incorrect. Try again." {
		t.Errorf("error = %v (%T)", err, apiErr)
	}

	r, err = ParseIdentityResult(identity(200, `{"access_token":"a.b.c","token_type":"Bearer","refresh_token":"r","Key":"2.a|b|c",
		"PrivateKey":"2.old|x|y","Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4,"ForcePasswordReset":false,
		"AccountKeys":{"publicKeyEncryptionKeyPair":{"wrappedPrivateKey":"7.priv","publicKey":"pub","signedPublicKey":"spk"},
		"signatureKeyPair":{"wrappedSigningKey":"7.sign","verifyingKey":"vk"},"securityState":{"securityState":"ss","securityVersion":2}},
		"UserDecryptionOptions":{"HasMasterPassword":true,"MasterPasswordUnlock":{"Salt":"salt@x","Kdf":{"KdfType":1,"Iterations":3,"Memory":64,"Parallelism":4},"MasterKeyEncryptedUserKey":"2.k|k|k"}}}`))
	if err != nil || r.Token == nil {
		t.Fatalf("token response: %v", err)
	}
	tok := r.Token
	if tok.KdfConfig.Type != crypto.KdfArgon2id || *tok.KdfConfig.Memory != 64 {
		t.Errorf("kdf = %+v", tok.KdfConfig)
	}
	if !tok.AccountKeys.IsV2Encryption() || tok.WrappedPrivateKey() != "7.priv" {
		t.Errorf("account keys = %+v", tok.AccountKeys)
	}
	if tok.MasterKeyWrappedUserKey() != "2.k|k|k" {
		t.Errorf("wrapped user key = %s", tok.MasterKeyWrappedUserKey())
	}
	if tok.CanUnlockWithKeyConnector() {
		t.Error("master password user cannot unlock with key connector")
	}
	if _, err := ParseIdentityResult(identity(200, `{"access_token":"a","token_type":"Bearer"}`)); err == nil ||
		err.Error() != "kdf is required on IdentityTokenResponse" {
		t.Errorf("missing kdf: %v", err)
	}
}

func TestSsoHelpers(t *testing.T) {
	// RFC 7636 appendix B.
	if got := CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("code challenge = %s", got)
	}
	u := BuildSsoURL("https://vault.bitwarden.com", "cli", "http://localhost:8065", "st", "ch", "", "Acme Org")
	want := "https://vault.bitwarden.com/#/sso?clientId=cli&redirectUri=http%3A%2F%2Flocalhost%3A8065&state=st&codeChallenge=ch&identifier=Acme%20Org"
	if u != want {
		t.Errorf("sso url = %s", u)
	}
	if !CheckState("abc_identifier=acme", "abc") || CheckState("abd", "abc") || CheckState("", "abc") {
		t.Error("CheckState")
	}
	if OrgIdentifierFromState("abc_identifier=acme") != "acme" || OrgIdentifierFromState("abc") != "" {
		t.Error("OrgIdentifierFromState")
	}
	d := MakeSsoPromptData()
	if len(d.State) != 64 || len(d.CodeVerifier) != 64 || d.CodeChallenge != CodeChallenge(d.CodeVerifier) {
		t.Errorf("prompt data = %+v", d)
	}
}

func TestEvaluateMasterPassword(t *testing.T) {
	p := &MasterPasswordPolicyResponse{MinLength: 8, RequireUpper: true, RequireLower: true, RequireNumbers: true, RequireSpecial: true}
	if EvaluateMasterPassword(nil, "Abcdef1!", p) != true {
		t.Error("strong password rejected")
	}
	for _, pw := range []string{"Abcde1!", "abcdef1!", "ABCDEF1!", "Abcdefg!", "Abcdefg1"} {
		if EvaluateMasterPassword(nil, pw, p) {
			t.Errorf("%q accepted", pw)
		}
	}
}
