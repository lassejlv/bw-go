package vaultedit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	testUserID    = "aaaaaaaa-0000-0000-0000-000000000001"
	testOrgID     = "bbbbbbbb-0000-0000-0000-000000000001"
	testOrgUserID = "cccccccc-0000-0000-0000-000000000001"
	testCol1      = "dddddddd-0000-0000-0000-000000000001" // manage
	testCol2      = "dddddddd-0000-0000-0000-000000000002" // read only
	serverRev     = "2024-05-01T10:00:00.123Z"
	serverCreated = "2024-04-01T09:00:00Z"
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

// captured is a request received by the fake server.
type captured struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
}

type handler func(w http.ResponseWriter, r *http.Request, body []byte)

type fakeServer struct {
	*httptest.Server
	t      *testing.T
	mu     sync.Mutex
	reqs   []captured
	routes map[string]handler
}

func newFakeServer(t *testing.T) *fakeServer {
	fs := &fakeServer{t: t, routes: map[string]handler{}}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fs.mu.Lock()
		fs.reqs = append(fs.reqs, captured{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
		h := fs.routes[r.Method+" "+r.URL.Path]
		fs.mu.Unlock()
		if h == nil {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		h(w, r, body)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fakeServer) on(method, path string, h handler) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.routes[method+" "+path] = h
}

// last returns the last captured request for method+path (fails when absent).
func (fs *fakeServer) last(method, path string) captured {
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

func (fs *fakeServer) count(method, path string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for _, r := range fs.reqs {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	w.Write(b)
}

// testEnv is a logged in, unlocked account with a synthetic encrypted vault.
type testEnv struct {
	t       *testing.T
	a       *app.App
	fs      *fakeServer
	userKey *crypto.SymmetricKey
	orgKey  *crypto.SymmetricKey
	keys    *vault.Keys
	v2      bool
}

type envOptions struct {
	v2       bool
	premium  bool
	policies []string // raw policy JSON
}

func newEnv(t *testing.T, o envOptions) *testEnv {
	t.Helper()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	t.Setenv("BW_SERVE", "")
	fs := newFakeServer(t)
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{t: t, a: a, fs: fs, orgKey: crypto.GenerateKey(), v2: o.v2}
	priv := testRSAKey()
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	var accountKeys json.RawMessage
	if o.v2 {
		if env.userKey, err = crypto.GenerateKeyFor(crypto.AlgXChaCha20Poly1305); err != nil {
			t.Fatal(err)
		}
		accountKeys = json.RawMessage(`{"securityState":{"securityVersion":2}}`)
	} else {
		env.userKey = crypto.GenerateKey()
	}
	encPriv, err := crypto.WrapPrivateKey(der, env.userKey)
	if err != nil {
		t.Fatal(err)
	}
	encOrg, err := crypto.RsaEncrypt(env.orgKey.Bytes(), &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{
		"id": testUserID, "email": "user@example.com", "premium": o.premium,
		"organizations": []any{map[string]any{
			"id": testOrgID, "name": "Acme", "key": encOrg, "status": 2, "type": 1, "enabled": true,
			"usePolicies": true, "useTotp": true, "organizationUserId": testOrgUserID,
		}},
	}
	profileJSON, _ := json.Marshal(profile)
	var p vault.Profile
	_ = json.Unmarshal(profileJSON, &p)
	env.keys = vault.NewKeys(env.userKey, encPriv, accountKeys, &p)

	acct := &state.Account{
		UserID: testUserID, Email: "user@example.com",
		AccessToken:   makeJWT(map[string]any{"sub": testUserID, "exp": time.Now().Add(time.Hour).Unix()}),
		RefreshToken:  "refresh",
		EncPrivateKey: encPriv,
		AccountKeys:   accountKeys,
		Vault: state.VaultData{
			Profile: profileJSON, Ciphers: map[string]json.RawMessage{}, Folders: map[string]json.RawMessage{},
			Collections: map[string]json.RawMessage{},
		},
	}
	for _, c := range []struct {
		id, name string
		manage   bool
		readOnly bool
	}{{testCol1, "Engineering", true, false}, {testCol2, "Readers", false, true}} {
		enc, _ := crypto.EncryptString(c.name, env.orgKey)
		raw, _ := json.Marshal(map[string]any{"id": c.id, "organizationId": testOrgID, "name": enc, "externalId": nil,
			"manage": c.manage, "readOnly": c.readOnly, "hidePasswords": false})
		acct.Vault.Collections[c.id] = raw
	}
	for _, pol := range o.policies {
		acct.Vault.Policies = append(acct.Vault.Policies, json.RawMessage(pol))
	}
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment.Base = fs.URL
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
	return env
}

// addCipher encrypts a view and stores it like a synced cipher with full permissions.
func (env *testEnv) addCipher(view *vault.CipherView) *vault.Cipher {
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
	env.storeCipher(c)
	return c
}

func (env *testEnv) storeCipher(c *vault.Cipher) {
	env.t.Helper()
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
	raw, _ := json.Marshal(map[string]any{"id": id, "name": enc, "revisionDate": serverCreated})
	_ = env.a.UpdateAccount(func(acct *state.Account) error {
		if acct.Vault.Folders == nil {
			acct.Vault.Folders = map[string]json.RawMessage{}
		}
		acct.Vault.Folders[id] = raw
		return nil
	})
}

func (env *testEnv) setProfile(mut func(p map[string]any)) {
	env.t.Helper()
	_ = env.a.UpdateAccount(func(acct *state.Account) error {
		var p map[string]any
		_ = json.Unmarshal(acct.Vault.Profile, &p)
		mut(p)
		acct.Vault.Profile, _ = json.Marshal(p)
		return nil
	})
}

func (env *testEnv) vault() *vault.Vault {
	env.t.Helper()
	v, err := vault.Load(env.a)
	if err != nil {
		env.t.Fatal(err)
	}
	return v
}

func (env *testEnv) storedCipher(id string) *vault.Cipher {
	env.t.Helper()
	c, err := env.vault().EncryptedCipher(id)
	if err != nil {
		env.t.Fatalf("cipher %s not stored: %v", id, err)
	}
	return c
}

func (env *testEnv) storedView(id string) *vault.CipherView {
	env.t.Helper()
	view, err := env.vault().Cipher(id)
	if err != nil {
		env.t.Fatalf("cipher %s: %v", id, err)
	}
	return view
}

// serverCipher turns a cipher request body (CipherRequest, or {cipher: ...} for create/share)
// into the server's cipher response.
func serverCipher(body []byte, id string, extra map[string]any) map[string]any {
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
	m["creationDate"] = serverCreated
	m["edit"] = true
	m["viewPassword"] = true
	m["organizationUseTotp"] = false
	m["permissions"] = map[string]any{"delete": true, "restore": true}
	m["object"] = "cipher"
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// decryptRequestCipher decrypts the cipher carried by a request body with the account keys.
func (env *testEnv) decryptRequestCipher(body []byte) (*vault.CipherView, map[string]any) {
	env.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		env.t.Fatal(err)
	}
	inner := m
	if c, ok := m["cipher"].(map[string]any); ok {
		inner = c
	}
	cp := map[string]any{}
	for k, v := range inner {
		if k != "attachments" && k != "attachments2" {
			cp[k] = v
		}
	}
	cp["id"] = "request"
	raw, _ := json.Marshal(cp)
	c, err := vault.ParseCipher(raw)
	if err != nil {
		env.t.Fatal(err)
	}
	view, err := vault.DecryptCipher(c, env.keys)
	if err != nil {
		env.t.Fatalf("request cipher does not decrypt: %v (%s)", err, body)
	}
	return view, m
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sp(s string) *string { return &s }

func mustSucceed(t *testing.T, r *cli.Response) {
	t.Helper()
	if r == nil || !r.Success {
		msg := ""
		if r != nil {
			msg = r.MessageText()
		}
		t.Fatalf("command failed: %s", msg)
	}
}

func mustFail(t *testing.T, r *cli.Response, msg string) {
	t.Helper()
	if r == nil || r.Success {
		t.Fatalf("expected failure %q, got success", msg)
	}
	if r.MessageText() != msg {
		t.Fatalf("message = %q, want %q", r.MessageText(), msg)
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	return cli.MarshalJSON(v, false)
}

func dec(t *testing.T, s string, key *crypto.SymmetricKey) string {
	t.Helper()
	out, err := crypto.DecryptString(s, key)
	if err != nil {
		t.Fatalf("decrypt %q: %v", s, err)
	}
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}
