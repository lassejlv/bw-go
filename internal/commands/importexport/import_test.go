package importexport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	impOrgID     = "11111111-1111-4111-8111-111111111111" // admin: may import
	impUserOrgID = "22222222-2222-4222-8222-222222222222" // user: may not import
	impFolderID  = "f1111111-1111-4111-8111-111111111111"
)

var (
	impRSAOnce sync.Once
	impRSA     *rsa.PrivateKey
)

type impRequest struct {
	Path  string
	Query string
	Body  []byte
}

type impServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	posts    []impRequest
	failBody []byte // when set, import POSTs fail with 400 and this body
}

func (s *impServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/config":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"featureStates":{}}`))
	case r.Method == "POST" && (r.URL.Path == "/api/ciphers/import" || r.URL.Path == "/api/ciphers/import-organization"):
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		s.posts = append(s.posts, impRequest{Path: r.URL.Path, Query: r.URL.RawQuery, Body: b})
		if s.failBody != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = w.Write(s.failBody)
			return
		}
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

type impEnv struct {
	a       *app.App
	srv     *impServer
	userKey *crypto.SymmetricKey
	orgKey  *crypto.SymmetricKey
	keys    *vault.Keys
	dir     string
	v2      bool
}

func setupImport(t *testing.T, v2 bool, policies ...string) *impEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", filepath.Join(dir, "appdata"))
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	for _, k := range []string{"BW_RAW", "BW_RESPONSE", "BW_QUIET", "BW_PRETTY"} {
		t.Setenv(k, "")
	}
	s := &impServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	oldSync := importSync
	importSync = func(*app.App) {}
	t.Cleanup(func() { importSync = oldSync })

	impRSAOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		impRSA = k
	})
	der, _ := x509.MarshalPKCS8PrivateKey(impRSA)
	env := &impEnv{srv: s, orgKey: crypto.GenerateKey(), dir: dir, v2: v2}
	var err error
	var accountKeys json.RawMessage
	if v2 {
		if env.userKey, err = crypto.GenerateKeyFor(crypto.AlgXChaCha20Poly1305); err != nil {
			t.Fatal(err)
		}
		accountKeys = json.RawMessage(`{"signatureKeyPair":{"wrappedSigningKey":"x","verifyingKey":"y"}}`)
	} else {
		env.userKey = crypto.GenerateKey()
	}
	encPriv, err := crypto.Encrypt(der, env.userKey)
	if err != nil {
		t.Fatal(err)
	}
	encOrg, _ := crypto.RsaEncrypt(env.orgKey.Bytes(), &impRSA.PublicKey)
	encOrg2, _ := crypto.RsaEncrypt(crypto.GenerateKey().Bytes(), &impRSA.PublicKey)
	profile, _ := json.Marshal(map[string]any{
		"id": "u1", "email": "u@example.com",
		"organizations": []any{
			map[string]any{"id": impOrgID, "name": "Acme", "key": encOrg, "status": 2, "type": 1, "enabled": true, "usePolicies": true},
			map[string]any{"id": impUserOrgID, "name": "Other", "key": encOrg2, "status": 2, "type": 2, "enabled": true, "usePolicies": true},
		},
	})
	var prof vault.Profile
	_ = json.Unmarshal(profile, &prof)
	env.keys = vault.NewKeys(env.userKey, encPriv.String(), accountKeys, &prof)

	// One existing personal item (exported by the account-encrypted tests).
	existing := vault.NewCipherView()
	existing.ID, existing.Name, existing.FolderID = "a1111111-1111-4111-8111-111111111111", "Existing Login", impStr(impFolderID)
	existing.Login.Username, existing.Login.Password = impStr("old"), impStr("pass")
	existing.Login.URIs = []vault.LoginURIView{{URI: impStr("https://old.example.com")}}
	existing.Fields = []vault.FieldView{{Name: impStr("pin"), Value: impStr("1234"), Type: vault.FieldTypeHidden}}
	c, _, err := vault.EncryptCipher(existing, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	folderName, _ := crypto.EncryptString("Work", env.userKey)
	var pols []json.RawMessage
	for _, p := range policies {
		pols = append(pols, json.RawMessage(p))
	}

	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment = state.Environment{Base: s.srv.URL}
		d.ActiveUserID = "u1"
		d.Accounts = map[string]*state.Account{"u1": {UserID: "u1", Email: "u@example.com", AccessToken: "token",
			EncPrivateKey: encPriv.String(), AccountKeys: accountKeys,
			Kdf: crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000},
			Vault: state.VaultData{Profile: profile, Policies: pols,
				Ciphers: map[string]json.RawMessage{existing.ID: raw},
				Folders: map[string]json.RawMessage{impFolderID: json.RawMessage(`{"id":"` + impFolderID + `","name":"` + folderName + `"}`)}}}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetUserKey(env.userKey); err != nil {
		t.Fatal(err)
	}
	env.a = a
	return env
}

func impStr(s string) *string { return &s }

func (e *impEnv) write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// impPosted is the decoded body of an import POST.
type impPosted struct {
	Ciphers                 []json.RawMessage `json:"ciphers"`
	Folders                 []map[string]any  `json:"folders"`
	FolderRelationships     []map[string]int  `json:"folderRelationships"`
	Collections             []map[string]any  `json:"collections"`
	CollectionRelationships []map[string]int  `json:"collectionRelationships"`
}

func (e *impEnv) lastPost(t *testing.T) (impRequest, impPosted) {
	t.Helper()
	e.srv.mu.Lock()
	defer e.srv.mu.Unlock()
	if len(e.srv.posts) == 0 {
		t.Fatal("no import request was posted")
	}
	r := e.srv.posts[len(e.srv.posts)-1]
	var p impPosted
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatalf("%v: %s", err, r.Body)
	}
	return r, p
}

// decryptPosted decrypts the posted CipherRequests back into views with the account keys.
func (e *impEnv) decryptPosted(t *testing.T, p impPosted) []*vault.CipherView {
	t.Helper()
	var out []*vault.CipherView
	for _, raw := range p.Ciphers {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m["encryptedFor"] != "u1" {
			t.Fatalf("encryptedFor = %v", m["encryptedFor"])
		}
		c, err := vault.ParseCipher(raw)
		if err != nil {
			t.Fatal(err)
		}
		if c.Key == nil {
			t.Fatalf("cipher without a per-cipher key: %s", raw)
		}
		blob := c.Data.Val != nil && vault.IsBlobData(c.Data.Val)
		if wantBlob := e.v2 && c.OrganizationID == nil; blob != wantBlob {
			t.Fatalf("blob=%v, want %v: %s", blob, wantBlob, raw)
		}
		if !blob && (c.Name == nil || !crypto.IsEncString(*c.Name)) {
			t.Fatalf("name not encrypted: %s", raw)
		}
		v, err := vault.DecryptCipher(c, e.keys)
		if err != nil {
			t.Fatalf("decrypt %s: %v", raw, err)
		}
		out = append(out, v)
	}
	return out
}

func (e *impEnv) folderName(t *testing.T, f map[string]any) string {
	t.Helper()
	s, err := crypto.DecryptString(f["name"].(string), e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func impSuccess(t *testing.T, r *cli.Response, title string) *cli.MessageResponse {
	t.Helper()
	if !r.Success {
		t.Fatalf("import failed: %s", r.MessageText())
	}
	m, ok := r.Data.(*cli.MessageResponse)
	if !ok || m.Title == nil || *m.Title != title {
		t.Fatalf("unexpected response %+v", r.Data)
	}
	return m
}

func impFail(t *testing.T, r *cli.Response, msg string) {
	t.Helper()
	if r.Success || r.MessageText() != msg {
		t.Fatalf("got success=%v %q, want %q", r.Success, r.MessageText(), msg)
	}
}

func TestImportFormatsList(t *testing.T) {
	env := setupImport(t, false)
	r := Import(env.a, "", "", ImportOptions{Formats: true})
	m := impSuccess(t, r, "Supported input formats:")
	want := strings.Join(importer.CLIFormatIDs(), "\n")
	if m.Message == nil || *m.Message != want || m.Raw == nil || *m.Raw != want {
		t.Fatalf("formats %+v", m)
	}
	for _, id := range []string{"bitwardencsv", "bitwardenjson", "keepass2xml", "lastpasscsv"} {
		if !strings.Contains("\n"+want+"\n", "\n"+id+"\n") {
			t.Fatalf("%s missing from %q", id, want)
		}
	}
	// the organization check runs before --formats
	bad := "00000000-0000-4000-8000-000000000000"
	impFail(t, Import(env.a, "", "", ImportOptions{Formats: true, OrganizationID: &bad}),
		"You do not belong to an organization with the ID of "+bad+". Check the organization ID and sync your vault.")
}

func TestImportErrors(t *testing.T) {
	env := setupImport(t, false)
	impFail(t, Import(env.a, "", "", ImportOptions{}), "`format` was not provided.")
	impFail(t, Import(env.a, "bitwardencsv", "", ImportOptions{}), "`filepath` was not provided.")
	other := impUserOrgID
	impFail(t, Import(env.a, "bitwardencsv", "x.csv", ImportOptions{OrganizationID: &other}),
		"You are not authorized to import into the provided organization.")
	impFail(t, Import(env.a, "nosuchformat", env.write(t, "a.csv", "x"), ImportOptions{}), "Proper importer type required.")
	impFail(t, Import(env.a, "bitwardencsv", env.write(t, "empty.csv", ""), ImportOptions{}), "Import file was empty.")
	missing := filepath.Join(env.dir, "missing.csv")
	impFail(t, Import(env.a, "bitwardencsv", missing, ImportOptions{}), "ENOENT: no such file or directory, open '"+missing+"'")
	impFail(t, Import(env.a, "keeper", "x.txt", ImportOptions{}), "Cannot determine Keeper file type. Use a .csv or .json file.")
	if len(env.srv.posts) != 0 {
		t.Fatal("nothing should have been posted")
	}
}

const impCSV = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
	"Work,1,login,Mail,a note,PIN: 1234,0,https://mail.example.com,me,secret,\n" +
	",,note,Memo,hello,,1,,,,\n"

func TestImportBitwardenCSV(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupImport(t, v2)
		path := env.write(t, "source.csv", impCSV)
		impSuccess(t, Import(env.a, "bitwardencsv", path, ImportOptions{}), "Imported "+path)

		req, p := env.lastPost(t)
		if req.Path != "/api/ciphers/import" || req.Query != "" {
			t.Fatalf("posted to %s?%s", req.Path, req.Query)
		}
		views := env.decryptPosted(t, p)
		if len(views) != 2 {
			t.Fatalf("%d ciphers", len(views))
		}
		l := views[0]
		if l.Name != "Mail" || *l.Notes != "a note" || !l.Favorite || *l.Login.Username != "me" || *l.Login.Password != "secret" ||
			len(l.Login.URIs) != 1 || *l.Login.URIs[0].URI != "https://mail.example.com" || l.Login.Totp != nil {
			t.Fatalf("login %+v %+v", l, l.Login)
		}
		if len(l.Fields) != 1 || *l.Fields[0].Name != "PIN" || *l.Fields[0].Value != "1234" {
			t.Fatalf("fields %+v", l.Fields)
		}
		n := views[1]
		if n.Name != "Memo" || *n.Notes != "hello" || n.Type != vault.CipherTypeSecureNote || n.Reprompt != vault.RepromptPassword {
			t.Fatalf("note %+v", n)
		}
		if len(p.Folders) != 1 || env.folderName(t, p.Folders[0]) != "Work" || p.Folders[0]["id"] != nil {
			t.Fatalf("folders %+v", p.Folders)
		}
		if len(p.FolderRelationships) != 1 || p.FolderRelationships[0]["key"] != 0 || p.FolderRelationships[0]["value"] != 0 {
			t.Fatalf("folderRelationships %+v", p.FolderRelationships)
		}
		if strings.Contains(string(req.Body), `"collections"`) {
			t.Fatalf("individual import must not send collections: %s", req.Body)
		}
	}
}

const impPlainJSON = `{
  "encrypted": false,
  "folders": [{"id": "f1", "name": "Personal"}],
  "items": [
    {"id": "i1", "type": 1, "name": "Mail", "folderId": "f1", "favorite": false, "reprompt": 0,
     "notes": null, "collectionIds": null,
     "fields": [{"name": "secret", "value": "v", "type": 1, "linkedId": null}],
     "login": {"username": "me", "password": "pw", "totp": null,
               "uris": [{"uri": "https://a.example.com", "match": 3}]},
     "passwordHistory": [{"password": "older", "lastUsedDate": "2023-01-01T00:00:00.000Z"}]},
    {"id": "i2", "type": 3, "name": "Visa", "folderId": null, "favorite": true, "reprompt": 0,
     "card": {"cardholderName": "Me", "brand": "Visa", "number": "4111111111111111",
              "expMonth": "1", "expYear": "2030", "code": "123"}}
  ]
}`

func TestImportBitwardenJSONPlain(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupImport(t, v2)
		path := env.write(t, "export.json", impPlainJSON)
		impSuccess(t, Import(env.a, "bitwardenjson", path, ImportOptions{}), "Imported "+path)
		_, p := env.lastPost(t)
		views := env.decryptPosted(t, p)
		if len(views) != 2 {
			t.Fatalf("%d ciphers", len(views))
		}
		l, c := views[0], views[1]
		if l.Name != "Mail" || *l.Login.Password != "pw" || *l.Login.URIs[0].Match != vault.UriMatchExact ||
			len(l.PasswordHistory) != 1 || *l.PasswordHistory[0].Password != "older" ||
			l.Fields[0].Type != vault.FieldTypeHidden || *l.Fields[0].Value != "v" {
			t.Fatalf("login %+v %+v", l, l.Login)
		}
		if c.Name != "Visa" || !c.Favorite || *c.Card.Number != "4111111111111111" || *c.Card.Code != "123" {
			t.Fatalf("card %+v %+v", c, c.Card)
		}
		if len(p.Folders) != 1 || env.folderName(t, p.Folders[0]) != "Personal" || p.Folders[0]["id"] != "f1" {
			t.Fatalf("folders %+v", p.Folders)
		}
		if len(p.FolderRelationships) != 1 || p.FolderRelationships[0]["key"] != 0 || p.FolderRelationships[0]["value"] != 0 {
			t.Fatalf("folderRelationships %+v", p.FolderRelationships)
		}
	}
}

func TestImportRestrictedItemTypes(t *testing.T) {
	policy := `{"id":"p1","organizationId":"` + impUserOrgID + `","type":15,"data":[3],"enabled":true}`
	env := setupImport(t, false, policy)
	path := env.write(t, "export.json", impPlainJSON)
	impSuccess(t, Import(env.a, "bitwardenjson", path, ImportOptions{}), "Imported "+path)
	_, p := env.lastPost(t)
	views := env.decryptPosted(t, p)
	if len(views) != 1 || views[0].Name != "Mail" {
		t.Fatalf("restricted card was not filtered: %d ciphers", len(views))
	}
}

// impExport writes an export of the synthetic vault (encrypted_json, optionally password protected).
func (e *impEnv) impExport(t *testing.T, password string) (string, string) {
	t.Helper()
	v, err := vault.Load(e.a)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := exportNewService(e.a, v).GetExport("encrypted_json", password)
	if err != nil {
		t.Fatal(err)
	}
	return e.write(t, "bw_export.json", string(exp.Data)), string(exp.Data)
}

func checkImportedExisting(t *testing.T, env *impEnv) {
	t.Helper()
	_, p := env.lastPost(t)
	views := env.decryptPosted(t, p)
	if len(views) != 1 {
		t.Fatalf("%d ciphers", len(views))
	}
	v := views[0]
	if v.Name != "Existing Login" || *v.Login.Username != "old" || *v.Login.Password != "pass" ||
		len(v.Login.URIs) != 1 || *v.Login.URIs[0].URI != "https://old.example.com" ||
		len(v.Fields) != 1 || *v.Fields[0].Value != "1234" {
		t.Fatalf("imported %+v %+v", v, v.Login)
	}
	if len(p.Folders) != 1 || env.folderName(t, p.Folders[0]) != "Work" || p.Folders[0]["id"] != impFolderID {
		t.Fatalf("folders %+v", p.Folders)
	}
	if len(p.FolderRelationships) != 1 {
		t.Fatalf("folderRelationships %+v", p.FolderRelationships)
	}
}

func TestImportBitwardenJSONAccountEncrypted(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupImport(t, v2)
		path, data := env.impExport(t, "")
		if v2 != strings.Contains(data, `"data"`) {
			t.Fatalf("v2=%v but export blob presence differs: %s", v2, data)
		}
		impSuccess(t, Import(env.a, "bitwardenjson", path, ImportOptions{}), "Imported "+path)
		checkImportedExisting(t, env)

		// An export from another account fails the encKeyValidation check.
		other := setupImport(t, v2)
		impFail(t, Import(other.a, "bitwardenjson", path, ImportOptions{}), importer.MsgImportEncKeyError)
	}
}

func TestImportBitwardenJSONPasswordProtected(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupImport(t, v2)
		path, data := env.impExport(t, "hunter2")
		if !strings.Contains(data, `"passwordProtected": true`) {
			t.Fatalf("not password protected: %s", data)
		}
		// BW_NOINTERACTION and no password source
		impFail(t, Import(env.a, "bitwardenjson", path, ImportOptions{}), importer.MsgImportPasswordRequired)

		t.Setenv("IMPORT_TEST_PW", "wrong")
		impFail(t, Import(env.a, "bitwardenjson", path, ImportOptions{PasswordEnv: "IMPORT_TEST_PW"}), importer.MsgInvalidFilePassword)

		pwFile := env.write(t, "pw.txt", "hunter2\nignored")
		impSuccess(t, Import(env.a, "bitwardenjson", path, ImportOptions{PasswordFile: pwFile}), "Imported "+path)
		checkImportedExisting(t, env)

		// interactive prompt uses the import prompt text
		var prompt string
		old := importGetPassword
		importGetPassword = func(pw, file, envName, msg string) (string, *cli.Response) { prompt = msg; return "hunter2", nil }
		impSuccess(t, Import(env.a, "bitwardenjson", path, ImportOptions{}), "Imported "+path)
		importGetPassword = old
		if prompt != "Import file password:" {
			t.Fatalf("prompt %q", prompt)
		}
	}
}

const impOrgCSV = "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
	"Engineering,login,Shared Login,,,0,https://x.example.com,team,pw,\n" +
	"\"Engineering,Ops\",note,Runbook,steps,,0,,,,\n"

func TestImportOrganization(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupImport(t, v2)
		org := impOrgID
		path := env.write(t, "org.csv", impOrgCSV)
		impSuccess(t, Import(env.a, "bitwardencsv", path, ImportOptions{OrganizationID: &org}), "Imported "+path)

		req, p := env.lastPost(t)
		if req.Path != "/api/ciphers/import-organization" || req.Query != "organizationId="+impOrgID {
			t.Fatalf("posted to %s?%s", req.Path, req.Query)
		}
		views := env.decryptPosted(t, p)
		if len(views) != 2 || views[0].Name != "Shared Login" || *views[0].Login.Username != "team" ||
			views[1].Name != "Runbook" || *views[1].Notes != "steps" {
			t.Fatalf("ciphers %+v", views)
		}
		for i, v := range views {
			if v.OrganizationID == nil || *v.OrganizationID != impOrgID {
				t.Fatalf("cipher %d organizationId %v", i, v.OrganizationID)
			}
		}
		// the org key, not the user key, encrypts org ciphers
		var c0 map[string]any
		_ = json.Unmarshal(p.Ciphers[0], &c0)
		if _, err := crypto.DecryptToKey(c0["key"].(string), env.orgKey); err != nil {
			t.Fatalf("cipher key not wrapped by the org key: %v", err)
		}
		var names []string
		for _, c := range p.Collections {
			n, err := crypto.DecryptString(c["name"].(string), env.orgKey)
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, n)
			if _, ok := c["id"]; !ok || c["id"] != nil {
				t.Fatalf("collection id %+v", c)
			}
			if g, ok := c["groups"].([]any); !ok || len(g) != 0 {
				t.Fatalf("collection groups %+v", c)
			}
		}
		if strings.Join(names, "|") != "Engineering|Ops" {
			t.Fatalf("collections %v", names)
		}
		rels, _ := json.Marshal(p.CollectionRelationships)
		if string(rels) != `[{"key":0,"value":0},{"key":1,"value":0},{"key":1,"value":1}]` {
			t.Fatalf("collectionRelationships %s", rels)
		}
		if !strings.Contains(string(req.Body), `"folders":[]`) || !strings.Contains(string(req.Body), `"folderRelationships":[]`) {
			t.Fatalf("folders %s", req.Body)
		}

		// every item must be assigned to a collection
		// (upstream compares the relationship count with the cipher count)
		path = env.write(t, "unassigned.csv", "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"+
			"Engineering,login,Assigned,,,0,,u,p,\n,login,Loose,,,0,,u,p,\n")
		impFail(t, Import(env.a, "bitwardencsv", path, ImportOptions{OrganizationID: &org}), "File contains unassigned items.")
	}
}

func TestImportServerValidationError(t *testing.T) {
	env := setupImport(t, false)
	env.srv.failBody = []byte(`{"message":"The model state is invalid.","validationErrors":{` +
		`"Folders[0].Name":["The field Name must be a string with a maximum length of 1000."],` +
		`"Ciphers[1].Notes":["The field Notes exceeds the maximum encrypted value length of 10000 characters."]}}`)
	path := env.write(t, "source.csv", impCSV)
	// Messages follow the server's key order (JS for..in), as upstream.
	impFail(t, Import(env.a, "bitwardencsv", path, ImportOptions{}),
		`[Folder] "Work": The field Name must be a string with a maximum length of 1000.`+
			"\n\n"+`[2] [SecureNote] "Memo": The field Notes exceeds the maximum encrypted value length of 10000 characters.`)

	env.srv.failBody = []byte(`{"message":"Something broke."}`)
	impFail(t, Import(env.a, "bitwardencsv", path, ImportOptions{}), "Something broke.")
}

func TestImportOptionsFromQuery(t *testing.T) {
	q := map[string][]string{"organizationid": {impOrgID}, "passwordenv": {"X"}, "formats": {""}}
	o := ImportOptionsFromQuery(q)
	if o.OrganizationID == nil || *o.OrganizationID != impOrgID || o.PasswordEnv != "X" || !o.Formats {
		t.Fatalf("%+v", o)
	}
}
