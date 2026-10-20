package auth

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/syncer"
)

const (
	testEmail    = "user@example.com"
	testPassword = "p@ssw0rd"
	testUserID   = "11111111-2222-3333-4444-555555555555"
)

func makeJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return enc(h) + "." + enc(p) + ".sig"
}

type fakeServer struct {
	*httptest.Server
	mu          sync.Mutex
	tokenForms  []url.Values
	revision    int64
	syncCalls   int
	encUserKey  string
	privateKey  string
	accountKeys string // raw AccountKeys JSON or "null"
	requires2FA bool
	// userKeyID is sync's userDecryption.userKeyId (the id the server knows); "" omits
	// userDecryption like an older server.
	userKeyID   string
	keyIDPosts  []string
	keyIDStatus int // status of POST /accounts/key-management/user-key-id (0: 200)
}

func newFakeServer(t *testing.T, userKey *crypto.SymmetricKey) *fakeServer {
	mk, err := bwauth.MakeMasterKey(testPassword, testEmail, crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.Encrypt(userKey.Bytes(), crypto.StretchKey(mk))
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.HashMasterPassword(testPassword, mk, crypto.HashServerAuthorization)
	_, encPriv, err := bwauth.MakeKeyPair(userKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := bwauth.SymmetricKeyID(userKey)
	fs := &fakeServer{encUserKey: enc.String(), privateKey: encPriv, accountKeys: "null", requires2FA: true, userKeyID: keyID}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.URL.Path {
		case "/identity/accounts/prelogin/password":
			w.WriteHeader(404)
		case "/identity/accounts/prelogin":
			io.WriteString(w, `{"kdf":0,"kdfIterations":5000,"kdfMemory":null,"kdfParallelism":null}`)
		case "/identity/connect/token":
			_ = r.ParseForm()
			fs.tokenForms = append(fs.tokenForms, r.PostForm)
			if r.PostForm.Get("grant_type") == "refresh_token" {
				io.WriteString(w, `{"access_token":"`+makeJWT(map[string]any{"sub": testUserID, "email": testEmail, "exp": time.Now().Add(time.Hour).Unix()})+`","token_type":"Bearer","refresh_token":"r2"}`)
				return
			}
			if r.PostForm.Get("grant_type") != "client_credentials" && r.PostForm.Get("password") != hash {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant","ErrorModel":{"Message":"Username or password is incorrect. Try again.","Object":"error"}}`)
				return
			}
			if fs.requires2FA && r.PostForm.Get("twoFactorToken") != "123456" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant","TwoFactorProviders":["0"],"TwoFactorProviders2":{"0":null}}`)
				return
			}
			tok := makeJWT(map[string]any{"sub": testUserID, "email": testEmail, "name": "Test", "exp": time.Now().Add(time.Hour).Unix(), "amr": []string{"Application"}})
			io.WriteString(w, `{"access_token":"`+tok+`","expires_in":3600,"token_type":"Bearer","refresh_token":"r1",
				"Key":"`+fs.encUserKey+`","PrivateKey":"`+fs.privateKey+`","AccountKeys":`+fs.accountKeys+`,"Kdf":0,"KdfIterations":5000,"ForcePasswordReset":false,
				"UserDecryptionOptions":{"HasMasterPassword":true,"Object":"userDecryptionOptions"}}`)
		case "/api/accounts/revision-date":
			io.WriteString(w, strings.TrimSpace(jsonNum(fs.revision)))
		case "/api/sync":
			if r.URL.RawQuery != "excludeDomains=true" {
				t.Errorf("sync query = %q", r.URL.RawQuery)
			}
			fs.syncCalls++
			userDecryption := ""
			if fs.userKeyID != "" {
				userDecryption = `"userDecryption":{"userKeyId":"` + fs.userKeyID + `"},`
			}
			io.WriteString(w, `{"profile":{"id":"`+testUserID+`","name":"Synced Name","email":"`+testEmail+`","key":"`+fs.encUserKey+`",
				"privateKey":"`+fs.privateKey+`","accountKeys":`+fs.accountKeys+`,"usesKeyConnector":false,"forcePasswordReset":false,"organizations":[]},
				"folders":[{"id":"f1","name":"2.a|b|c"}],"collections":[],"ciphers":[{"id":"c1","type":1},{"Id":"c2","type":2}],
				"policies":[],"sends":[{"id":"s1"}],"domains":null,`+userDecryption+`"object":"sync"}`)
		case "/api/accounts/key-management/user-key-id":
			var body struct {
				UserKeyID string `json:"userKeyId"`
			}
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Errorf("bad user key id request %s", r.Method)
			}
			fs.keyIDPosts = append(fs.keyIDPosts, body.UserKeyID)
			if fs.keyIDStatus != 0 {
				w.WriteHeader(fs.keyIDStatus)
				io.WriteString(w, `{}`)
				return
			}
			fs.userKeyID = body.UserKeyID
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(fs.Close)
	return fs
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }

func newTestApp(t *testing.T, base string) *app.App {
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	if base != "" {
		if err := a.Store.Update(func(d *state.Data) error { d.Environment.Base = base; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func status(t *testing.T, a *app.App) *StatusTemplate {
	r := Status(a)
	if !r.Success {
		t.Fatalf("status failed: %s", r.MessageText())
	}
	return r.Data.(*cli.TemplateResponse).Template.(*StatusTemplate)
}

func TestLoginLockUnlockSyncLogout(t *testing.T) {
	userKey := crypto.GenerateKey()
	fs := newFakeServer(t, userKey)
	a := newTestApp(t, fs.URL)

	if st := status(t, a); st.Status != "unauthenticated" || st.ServerURL == nil || *st.ServerURL != fs.URL || st.UserID != nil {
		t.Fatalf("initial status = %+v", st)
	}

	// Wrong password maps to the host specific message.
	r := Login(a, testEmail, "wrong", LoginOptions{})
	host := strings.TrimPrefix(fs.URL, "http://")
	if r.Success || r.MessageText() != "Invalid master password. Confirm your email is correct and your account was created on "+host+"." {
		t.Fatalf("wrong password: %v %s", r.Success, r.MessageText())
	}

	// Two-factor required and no code in non-interactive mode.
	r = Login(a, testEmail, testPassword, LoginOptions{})
	if r.Success || r.MessageText() != "Code is required." {
		t.Fatalf("2fa without code: %s", r.MessageText())
	}

	r = Login(a, testEmail, testPassword, LoginOptions{Code: "123456"})
	if !r.Success {
		t.Fatalf("login failed: %s", r.MessageText())
	}
	msg := r.Data.(*cli.MessageResponse)
	session := *msg.Raw
	if *msg.Title != "You are logged in!" || !strings.Contains(*msg.Message, `$ export BW_SESSION="`+session+`"`) {
		t.Errorf("login message = %+v", msg)
	}
	last := fs.tokenForms[len(fs.tokenForms)-1]
	if last.Get("twoFactorProvider") != "0" || last.Get("username") != testEmail || last.Get("client_id") != "cli" {
		t.Errorf("token form = %v", last)
	}

	acct := a.ActiveAccount()
	if acct == nil || acct.UserID != testUserID || acct.Name != "Synced Name" || acct.EncUserKey != fs.encUserKey ||
		acct.EncPrivateKey != fs.privateKey || !acct.HasMasterPassword || acct.KdfSalt != testEmail {
		t.Fatalf("account = %+v", acct)
	}
	if len(acct.Vault.Ciphers) != 2 || acct.Vault.Ciphers["c2"] == nil || len(acct.Vault.Folders) != 1 ||
		len(acct.Vault.Sends) != 1 || acct.LastSync == nil || fs.syncCalls != 1 {
		t.Errorf("vault = %+v (sync calls %d)", acct.Vault, fs.syncCalls)
	}
	got, err := a.UserKey()
	if err != nil || got.B64() != userKey.B64() {
		t.Fatalf("user key not available after login: %v", err)
	}
	if st := status(t, a); st.Status != "unlocked" || *st.UserEmail != testEmail || st.LastSync == nil {
		t.Errorf("status after login = %+v", st)
	}
	if r := LoginCheck(a); !r.Success {
		t.Error("login --check failed")
	}

	if r := Lock(a); !r.Success || *r.Data.(*cli.MessageResponse).Title != "Your vault is locked." {
		t.Fatalf("lock: %s", r.MessageText())
	}
	if st := status(t, a); st.Status != "locked" {
		t.Errorf("status after lock = %s", st.Status)
	}
	if r := UnlockCheck(a); r.Success || r.MessageText() != "Vault is locked." {
		t.Error("unlock --check while locked")
	}

	if r := Unlock(a, "nope", UnlockOptions{}); r.Success || r.MessageText() != "Invalid master password." {
		t.Errorf("unlock with wrong password: %s", r.MessageText())
	}
	r = Unlock(a, testPassword, UnlockOptions{})
	if !r.Success || *r.Data.(*cli.MessageResponse).Title != "Your vault is now unlocked!" {
		t.Fatalf("unlock: %s", r.MessageText())
	}
	if got, err := a.UserKey(); err != nil || got.B64() != userKey.B64() {
		t.Fatalf("user key after unlock: %v", err)
	}

	// Not forced and revision older than last sync: no download.
	fs.revision = 1000
	if r := Sync(a, SyncOptions{}); !r.Success || fs.syncCalls != 1 {
		t.Errorf("sync without changes: %s (calls %d)", r.MessageText(), fs.syncCalls)
	}
	fs.revision = time.Now().Add(time.Hour).UnixMilli()
	if r := Sync(a, SyncOptions{}); !r.Success || fs.syncCalls != 2 {
		t.Errorf("sync with changes: %s (calls %d)", r.MessageText(), fs.syncCalls)
	}
	if r := Sync(a, SyncOptions{Force: true}); !r.Success || *r.Data.(*cli.MessageResponse).Title != "Syncing complete." || fs.syncCalls != 3 {
		t.Errorf("forced sync: %s", r.MessageText())
	}
	if r := Sync(a, SyncOptions{Last: true}); !r.Success || r.Data.(*cli.StringResponse).Data == nil {
		t.Error("sync --last")
	}
	if syncer.LastSync(a) == nil {
		t.Error("LastSync nil")
	}

	if r := Config(a, "server", "https://other.example.com", ConfigOptions{}); r.Success || r.MessageText() != "Logout required before server config update." {
		t.Errorf("config while logged in: %s", r.MessageText())
	}

	if r := Logout(a); !r.Success || *r.Data.(*cli.MessageResponse).Title != "You have logged out." {
		t.Fatalf("logout: %s", r.MessageText())
	}
	if a.ActiveAccount() != nil {
		t.Error("account still active after logout")
	}
	if st := status(t, a); st.Status != "unauthenticated" {
		t.Errorf("status after logout = %s", st.Status)
	}
}

func TestLoginValidation(t *testing.T) {
	a := newTestApp(t, "")
	cases := []struct {
		email, password string
		o               LoginOptions
		want            string
	}{
		{"", "", LoginOptions{}, "Email address is required."},
		{"nope", "", LoginOptions{}, "Email address is invalid."},
		{testEmail, "", LoginOptions{}, "Master password is required."},
		{testEmail, "x", LoginOptions{Method: "4"}, "Invalid two-step login method."},
		{testEmail, "x", LoginOptions{Method: "abc"}, "Invalid two-step login method."},
		{"", "", LoginOptions{APIKey: true}, "client_id is required."},
	}
	for _, c := range cases {
		if r := Login(a, c.email, c.password, c.o); r.Success || r.MessageText() != c.want {
			t.Errorf("Login(%q, %q, %+v) = %q, want %q", c.email, c.password, c.o, r.MessageText(), c.want)
		}
	}
	t.Setenv("BW_CLIENTID", "organization.abc")
	t.Setenv("BW_CLIENTSECRET", "secret")
	if r := Login(a, "", "", LoginOptions{APIKey: true}); r.MessageText() != "Invalid API Key; Organization API Key currently not supported" {
		t.Errorf("org api key: %s", r.MessageText())
	}
}

func TestConfigServer(t *testing.T) {
	a := newTestApp(t, "")
	str := func(r *cli.Response) string { return *r.Data.(*cli.StringResponse).Data }
	if r := Config(a, "server", "", ConfigOptions{}); str(r) != "https://bitwarden.com" {
		t.Errorf("default server = %s", str(r))
	}
	if r := Config(a, "SERVER", "bw.company.com/", ConfigOptions{}); !r.Success || *r.Data.(*cli.MessageResponse).Title != "Saved setting `config`." {
		t.Fatalf("set server: %s", r.MessageText())
	}
	if r := Config(a, "server", "", ConfigOptions{}); str(r) != "https://bw.company.com" {
		t.Errorf("server = %s", str(r))
	}
	if u := a.Urls(); u.Api != "https://bw.company.com/api" || u.Identity != "https://bw.company.com/identity" {
		t.Errorf("urls = %+v", u)
	}
	if st := status(t, a); st.ServerURL == nil || *st.ServerURL != "https://bw.company.com" {
		t.Errorf("status server = %v", st.ServerURL)
	}
	if r := Config(a, "server", "", ConfigOptions{API: "http://localhost:4000", Identity: "http://localhost:33656"}); !r.Success {
		t.Fatal(r.MessageText())
	}
	if u := a.Urls(); u.Api != "http://localhost:4000" || u.Identity != "http://localhost:33656" || u.WebVault != "https://vault.bitwarden.com" {
		t.Errorf("urls = %+v", u)
	}
	if r := Config(a, "server", "bitwarden.com", ConfigOptions{}); !r.Success {
		t.Fatal(r.MessageText())
	}
	d, _ := a.Data()
	if d.Environment != (state.Environment{Region: "US"}) {
		t.Errorf("environment = %+v", d.Environment)
	}
	if r := Config(a, "foo", "", ConfigOptions{}); r.MessageText() != "Unknown setting." {
		t.Errorf("unknown setting: %s", r.MessageText())
	}
}

func v2AccountKeysJSON(securityState string) string {
	b, _ := json.Marshal(map[string]any{
		"publicKeyEncryptionKeyPair": map[string]any{
			"wrappedPrivateKey": v2WrappedPrivateKey, "publicKey": v2PublicKey, "signedPublicKey": v2SignedPublicKey,
		},
		"signatureKeyPair": map[string]any{"wrappedSigningKey": v2WrappedSigningKey, "verifyingKey": v2VerifyingKey},
		"securityState":    map[string]any{"securityState": securityState, "securityVersion": 2},
	})
	return string(b)
}

// V2 (COSE user key) account from the SDK test@bitwarden.com vectors: login, lock and unlock
// verify the signed account cryptographic state before storing the user key.
func TestLoginUnlockV2Account(t *testing.T) {
	userKey, err := crypto.KeyFromB64(v2UserKey)
	if err != nil {
		t.Fatal(err)
	}
	fs := newFakeServer(t, userKey)
	fs.requires2FA = false
	fs.privateKey = v2WrappedPrivateKey
	fs.accountKeys = v2AccountKeysJSON(v2SecurityState)
	a := newTestApp(t, fs.URL)

	r := Login(a, testEmail, testPassword, LoginOptions{})
	if !r.Success {
		t.Fatalf("v2 login failed: %s", r.MessageText())
	}
	got, err := a.UserKey()
	if err != nil || got.B64() != userKey.B64() {
		t.Fatalf("v2 user key after login: %v", err)
	}
	acct := a.ActiveAccount()
	if len(acct.AccountKeys) == 0 || acct.EncPrivateKey != v2WrappedPrivateKey {
		t.Errorf("account keys not stored: %+v", acct)
	}

	Lock(a)
	if r := Unlock(a, testPassword, UnlockOptions{}); !r.Success {
		t.Fatalf("v2 unlock: %s", r.MessageText())
	}
	if got, err := a.UserKey(); err != nil || got.B64() != userKey.B64() {
		t.Fatalf("v2 user key after unlock: %v", err)
	}

	// Tampered security state: unlock fails and no user key is stored.
	Lock(a)
	if err := a.UpdateAccount(func(acct *state.Account) error {
		acct.AccountKeys = json.RawMessage(v2AccountKeysJSON(v2OtherSecurityState))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r = Unlock(a, testPassword, UnlockOptions{})
	if r.Success || !strings.HasPrefix(r.MessageText(), "Unable to unlock the account cryptographic state: ") {
		t.Errorf("tampered unlock: %v %s", r.Success, r.MessageText())
	}
	if a.IsUnlocked() {
		t.Error("vault unlocked despite failed verification")
	}
	Logout(a)

	// Tampered state at login: the login fails and the vault stays locked.
	fs.accountKeys = v2AccountKeysJSON(v2OtherSecurityState)
	r = Login(a, testEmail, testPassword, LoginOptions{})
	if r.Success || !strings.HasPrefix(r.MessageText(), "Unable to unlock the account cryptographic state: ") {
		t.Errorf("tampered login: %v %s", r.Success, r.MessageText())
	}
	if a.IsUnlocked() {
		t.Error("vault unlocked after failed v2 verification at login")
	}
}
