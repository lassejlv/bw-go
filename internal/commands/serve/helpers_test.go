package serve

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	bwauth "github.com/lassejlv/bw-go/internal/auth"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	testUserID   = "aaaaaaaa-0000-0000-0000-000000000001"
	testEmail    = "user@example.com"
	testPassword = "p@ssw0rd"
	itemID       = "22222222-0000-0000-0000-000000000001"
	folderID     = "33333333-0000-0000-0000-000000000001"
	serverRev    = "2024-05-01T10:00:00.123Z"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSAKey() *rsa.PrivateKey {
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

func makeJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return enc(h) + "." + enc(p) + ".sig"
}

// ---------- fake Bitwarden API ----------

type captured struct {
	Method, Path string
	Header       http.Header
	Body         []byte
}

type apiHandler func(w http.ResponseWriter, r *http.Request, body []byte)

type fakeAPI struct {
	*httptest.Server
	t      *testing.T
	mu     sync.Mutex
	reqs   []captured
	routes map[string]apiHandler
}

func newFakeAPI(t *testing.T) *fakeAPI {
	fs := &fakeAPI{t: t, routes: map[string]apiHandler{}}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fs.mu.Lock()
		fs.reqs = append(fs.reqs, captured{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
		h := fs.routes[r.Method+" "+r.URL.Path]
		fs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == "GET" && r.URL.Path == "/api/config" {
			io.WriteString(w, `{"featureStates":{}}`)
			return
		}
		if h == nil {
			t.Errorf("unexpected API request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		h(w, r, body)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fakeAPI) on(method, path string, h apiHandler) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.routes[method+" "+path] = h
}

func (fs *fakeAPI) last(method, path string) captured {
	fs.t.Helper()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for i := len(fs.reqs) - 1; i >= 0; i-- {
		if fs.reqs[i].Method == method && fs.reqs[i].Path == path {
			return fs.reqs[i]
		}
	}
	fs.t.Fatalf("no %s %s request captured", method, path)
	return captured{}
}

func writeJSON(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	w.Write(b)
}

// ---------- synthetic logged in vault ----------

type testEnv struct {
	t       *testing.T
	a       *app.App
	api     *fakeAPI
	userKey *crypto.SymmetricKey
	keys    *vault.Keys
	srv     *Server
	stderr  *bytes.Buffer
}

// newEnv creates a logged in, unlocked v1 account (premium) whose user key can also be unlocked
// with testPassword, and a serve handler with origin protection for localhost:8087.
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_SERVE", "true")
	t.Setenv("BW_NOINTERACTION", "true")
	t.Setenv("BW_PRETTY", "")
	t.Setenv("BITWARDENCLI_DEBUG", "")
	api := newFakeAPI(t)
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{t: t, a: a, api: api, userKey: crypto.GenerateKey()}

	kdf := crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000}
	mk, err := bwauth.MakeMasterKey(testPassword, testEmail, kdf)
	if err != nil {
		t.Fatal(err)
	}
	encUserKey, err := crypto.Encrypt(env.userKey.Bytes(), crypto.StretchKey(mk))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(testRSAKey())
	encPriv, err := crypto.WrapPrivateKey(der, env.userKey)
	if err != nil {
		t.Fatal(err)
	}
	profileJSON, _ := json.Marshal(map[string]any{"id": testUserID, "email": testEmail, "premium": true, "organizations": []any{}})
	var p vault.Profile
	_ = json.Unmarshal(profileJSON, &p)
	env.keys = vault.NewKeys(env.userKey, encPriv, nil, &p)

	acct := &state.Account{
		UserID: testUserID, Email: testEmail,
		AccessToken:       makeJWT(map[string]any{"sub": testUserID, "email": testEmail, "exp": time.Now().Add(time.Hour).Unix()}),
		RefreshToken:      "refresh",
		Kdf:               kdf,
		KdfSalt:           testEmail,
		EncUserKey:        encUserKey.String(),
		EncPrivateKey:     encPriv,
		HasMasterPassword: true,
		UserKeyID:         userKeyID(env.userKey), // a current server knows the user key id
		Vault: state.VaultData{
			Profile: profileJSON, Ciphers: map[string]json.RawMessage{}, Folders: map[string]json.RawMessage{},
			Collections: map[string]json.RawMessage{},
		},
	}
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment.Base = api.URL
		if d.Accounts == nil {
			d.Accounts = map[string]*state.Account{}
		}
		d.Accounts[testUserID] = acct
		d.ActiveUserID = testUserID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetUserKey(env.userKey); err != nil {
		t.Fatal(err)
	}
	env.srv = NewHandler(a, HandlerOptions{ProtectOrigin: true, AllowedHosts: BuildAllowedHosts("localhost", "8087")})
	env.stderr = &bytes.Buffer{}
	env.srv.log = &logger{stdout: io.Discard, stderr: env.stderr}
	return env
}

func sp(s string) *string { return &s }

func userKeyID(k *crypto.SymmetricKey) string {
	id, _ := bwauth.SymmetricKeyID(k)
	return id
}

func loginItem(id, name, password string) *vault.CipherView {
	v := vault.NewCipherView()
	v.ID, v.Name = id, name
	v.Login.Username = sp("jdoe")
	v.Login.Password = sp(password)
	return v
}

// addCipher encrypts a view and stores it like a synced cipher with full permissions.
func (env *testEnv) addCipher(view *vault.CipherView) {
	env.t.Helper()
	view.Edit = true
	view.ViewPassword = true
	if view.Permissions == nil {
		view.Permissions = &vault.CipherPermissions{Delete: true, Restore: true}
	}
	if view.RevisionDate.IsZero() {
		view.RevisionDate = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	if view.CreationDate.IsZero() {
		view.CreationDate = view.RevisionDate
	}
	c, _, err := vault.EncryptCipher(view, env.keys)
	if err != nil {
		env.t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		env.t.Fatal(err)
	}
	err = env.a.UpdateAccount(func(acct *state.Account) error {
		if acct.Vault.Ciphers == nil {
			acct.Vault.Ciphers = map[string]json.RawMessage{}
		}
		acct.Vault.Ciphers[c.ID] = raw
		return nil
	})
	if err != nil {
		env.t.Fatal(err)
	}
}

func (env *testEnv) addFolder(id, name string) {
	env.t.Helper()
	enc, _ := crypto.EncryptString(name, env.userKey)
	raw, _ := json.Marshal(map[string]any{"id": id, "name": enc, "revisionDate": serverRev})
	_ = env.a.UpdateAccount(func(acct *state.Account) error {
		if acct.Vault.Folders == nil {
			acct.Vault.Folders = map[string]json.RawMessage{}
		}
		acct.Vault.Folders[id] = raw
		return nil
	})
}

func (env *testEnv) storedView(id string) *vault.CipherView {
	env.t.Helper()
	v, err := vault.Load(env.a)
	if err != nil {
		env.t.Fatal(err)
	}
	view, err := v.Cipher(id)
	if err != nil {
		env.t.Fatalf("cipher %s: %v", id, err)
	}
	return view
}

// serverCipher turns a cipher request body into the server's cipher response.
func serverCipher(body []byte, id string) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if c, ok := m["cipher"].(map[string]any); ok {
		m = c
	}
	for _, k := range []string{"attachments", "attachments2", "encryptedFor", "lastKnownRevisionDate"} {
		delete(m, k)
	}
	m["id"] = id
	m["revisionDate"] = serverRev
	m["creationDate"] = serverRev
	m["edit"] = true
	m["viewPassword"] = true
	m["organizationUseTotp"] = false
	m["permissions"] = map[string]any{"delete": true, "restore": true}
	m["object"] = "cipher"
	return m
}

// ---------- requests against the serve handler ----------

type result struct {
	status int
	header http.Header
	body   string
}

func (r result) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.body), &m); err != nil {
		t.Fatalf("response is not JSON (%d): %q", r.status, r.body)
	}
	return m
}

type reqOpt func(r *http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func host(h string) reqOpt { return func(r *http.Request) { r.Host = h } }

func (env *testEnv) do(method, target string, body io.Reader, opts ...reqOpt) result {
	env.t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.Host = "localhost:8087"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	env.srv.ServeHTTP(rec, req)
	return result{status: rec.Code, header: rec.Header(), body: rec.Body.String()}
}

func (env *testEnv) doJSON(method, target, body string, opts ...reqOpt) result {
	env.t.Helper()
	return env.do(method, target, strings.NewReader(body), opts...)
}

func expect(t *testing.T, r result, status int, body string) {
	t.Helper()
	if r.status != status || r.body != body {
		t.Fatalf("got %d %q, want %d %q", r.status, r.body, status, body)
	}
}
