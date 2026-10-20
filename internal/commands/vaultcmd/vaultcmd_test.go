package vaultcmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	userID   = "aaaaaaaa-0000-0000-0000-000000000001"
	org1     = "0b000000-0000-0000-0000-000000000001" // member (User), restricts cards
	org2     = "0b000000-0000-0000-0000-000000000002" // Admin: can view all collections
	folder1  = "0f000000-0000-0000-0000-000000000001"
	col1     = "0c000000-0000-0000-0000-000000000001"
	col2     = "0c000000-0000-0000-0000-000000000002"
	cGoogle  = "c0000000-0000-0000-0000-000000000001"
	cGitHub  = "c0000000-0000-0000-0000-000000000002"
	cNote    = "c0000000-0000-0000-0000-000000000003"
	cCard    = "c0000000-0000-0000-0000-000000000004"
	cArchive = "c0000000-0000-0000-0000-000000000005"
	cHidden  = "c0000000-0000-0000-0000-000000000006"
	attID    = "att1abcdefgh"
	otherID  = "dddddddd-0000-0000-0000-000000000009"
)

var (
	rsaOnce sync.Once
	rsaPriv *rsa.PrivateKey
	rsaPub2 *rsa.PrivateKey
)

func testRSA() (*rsa.PrivateKey, *rsa.PrivateKey) {
	rsaOnce.Do(func() {
		rsaPriv, _ = rsa.GenerateKey(rand.Reader, 2048)
		rsaPub2, _ = rsa.GenerateKey(rand.Reader, 2048)
	})
	return rsaPriv, rsaPub2
}

type env struct {
	a          *app.App
	srv        *httptest.Server
	userKey    *crypto.SymmetricKey
	orgKeys    map[string]*crypto.SymmetricKey
	attContent []byte
	attBlob    []byte
	requests   []string
	mu         sync.Mutex
}

func tm(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func sp(s string) *string { return &s }

func mustEnc(t *testing.T, s string, k *crypto.SymmetricKey) string {
	t.Helper()
	e, err := crypto.EncryptString(s, k)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func profileJSON(t *testing.T, premium bool, encOrg1, encOrg2 string) json.RawMessage {
	t.Helper()
	p := map[string]any{
		"id": userID, "email": "user@example.com", "premium": premium,
		"organizations": []any{
			map[string]any{"id": org1, "name": "Acme", "key": encOrg1, "status": 2, "type": 2, "enabled": true,
				"usePolicies": true, "useTotp": true},
			map[string]any{"id": org2, "name": "Beta Org", "key": encOrg2, "status": 2, "type": 1, "enabled": true,
				"usePolicies": true, "useTotp": true},
		},
	}
	b, _ := json.Marshal(p)
	return b
}

func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	t.Setenv("BW_SERVE", "")
	t.Setenv("BW_RAW", "")
	t.Setenv("BW_RESPONSE", "")
	t.Setenv("BW_PRETTY", "")
	t.Setenv("BW_QUIET", "")

	priv, other := testRSA()
	e := &env{userKey: crypto.GenerateKey(), orgKeys: map[string]*crypto.SymmetricKey{
		org1: crypto.GenerateKey(), org2: crypto.GenerateKey()}}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.handle(t, w, r, other) }))
	t.Cleanup(e.srv.Close)
	oldHIBP := PwnedPasswordsAPI
	PwnedPasswordsAPI = e.srv.URL + "/range/"
	t.Cleanup(func() { PwnedPasswordsAPI = oldHIBP })

	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	e.a = a

	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	encPriv, err := crypto.Encrypt(der, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	encOrg1, _ := crypto.RsaEncrypt(e.orgKeys[org1].Bytes(), &priv.PublicKey)
	encOrg2, _ := crypto.RsaEncrypt(e.orgKeys[org2].Bytes(), &priv.PublicKey)
	profile := profileJSON(t, true, encOrg1, encOrg2)

	acct := &state.Account{UserID: userID, Email: "user@example.com", AccessToken: "token",
		EncPrivateKey: encPriv.String(),
		Vault: state.VaultData{
			Profile:     profile,
			Ciphers:     map[string]json.RawMessage{},
			Folders:     map[string]json.RawMessage{},
			Collections: map[string]json.RawMessage{},
			Policies: []json.RawMessage{json.RawMessage(`{"id":"p1","organizationId":"` + org1 +
				`","type":15,"data":null,"enabled":true}`)},
		}}

	// Ciphers are encrypted through the vault package with the account keys.
	var p vault.Profile
	_ = json.Unmarshal(profile, &p)
	keys := vault.NewKeys(e.userKey, acct.EncPrivateKey, nil, &p)

	e.attContent = []byte("hello attachment")
	attKey := crypto.GenerateKey()
	if e.attBlob, err = crypto.EncryptBytes(e.attContent, attKey); err != nil {
		t.Fatal(err)
	}

	add := func(v *vault.CipherView) {
		c, _, err := vault.EncryptCipher(v, keys)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(c)
		acct.Vault.Ciphers[v.ID] = raw
	}
	base := func(id, name string, typ vault.CipherType) *vault.CipherView {
		v := vault.NewCipherView()
		v.ID, v.Name, v.Type = id, name, typ
		v.CreationDate = tm("2024-01-02T03:04:05Z")
		v.RevisionDate = tm("2024-02-03T04:05:06Z")
		v.Fields, v.Attachments, v.PasswordHistory = nil, nil, nil
		return v
	}

	g := base(cGoogle, "Google", vault.CipherTypeLogin)
	g.FolderID = sp(folder1)
	g.Notes = sp("my notes")
	g.Login.Username, g.Login.Password, g.Login.Totp = sp("user@gmail.com"), sp("pw-google"), sp("JBSWY3DPEHPK3PXP")
	g.Login.URIs = []vault.LoginURIView{{URI: sp("https://google.com")}}
	g.Attachments = []vault.AttachmentView{{ID: sp(attID), URL: sp(e.srv.URL + "/stale"), FileName: sp("photo.jpg"),
		Size: sp("16"), SizeName: sp("16 Bytes"), Key: attKey}}
	add(g)

	gh := base(cGitHub, "GitHub", vault.CipherTypeLogin)
	gh.OrganizationID = sp(org1)
	gh.CollectionIDs = []string{col1}
	gh.OrganizationUseTotp = true
	gh.Login.Username, gh.Login.Password, gh.Login.Totp = sp("octo"), sp("pw2"), sp("JBSWY3DPEHPK3PXP")
	gh.Login.URIs = []vault.LoginURIView{{URI: sp("https://github.com")}}
	add(gh)

	n := base(cNote, "Trashed note", vault.CipherTypeSecureNote)
	n.DeletedDate = &[]time.Time{tm("2024-03-01T00:00:00Z")}[0]
	add(n)

	card := base(cCard, "Visa", vault.CipherTypeCard)
	card.Card.Number = sp("4111111111111111")
	add(card)

	ar := base(cArchive, "Old account", vault.CipherTypeLogin)
	ar.ArchivedDate = &[]time.Time{tm("2024-04-01T00:00:00Z")}[0]
	ar.Login.Username = sp("old")
	add(ar)

	h := base(cHidden, "Hidden pw", vault.CipherTypeLogin)
	h.OrganizationID = sp(org2)
	h.ViewPassword = false
	h.Login.Username, h.Login.Password = sp("hid"), sp("secret")
	add(h)

	acct.Vault.Folders[folder1] = json.RawMessage(`{"id":"` + folder1 + `","name":"` + mustEnc(t, "Social", e.userKey) +
		`","revisionDate":"2024-01-01T00:00:00Z"}`)
	acct.Vault.Collections[col1] = json.RawMessage(`{"id":"` + col1 + `","organizationId":"` + org1 + `","name":"` +
		mustEnc(t, "Engineering", e.orgKeys[org1]) + `","externalId":null}`)
	acct.Vault.Collections[col2] = json.RawMessage(`{"id":"` + col2 + `","organizationId":"` + org2 + `","name":"` +
		mustEnc(t, "Beta Shared", e.orgKeys[org2]) + `","externalId":"ext-2"}`)

	if err := a.Store.Update(func(d *state.Data) error {
		d.Environment = state.Environment{Base: e.srv.URL}
		d.ActiveUserID = userID
		d.Accounts = map[string]*state.Account{userID: acct}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetUserKey(e.userKey); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) setPremium(t *testing.T, premium bool) {
	t.Helper()
	err := e.a.UpdateAccount(func(acct *state.Account) error {
		var m map[string]any
		_ = json.Unmarshal(acct.Vault.Profile, &m)
		m["premium"] = premium
		acct.Vault.Profile, _ = json.Marshal(m)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) handle(t *testing.T, w http.ResponseWriter, r *http.Request, other *rsa.PrivateKey) {
	e.mu.Lock()
	e.requests = append(e.requests, r.Method+" "+r.URL.RequestURI())
	e.mu.Unlock()
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	p := r.URL.Path
	switch {
	case p == "/api/organizations/"+org1+"/users":
		writeJSON(map[string]any{"data": []any{
			map[string]any{"id": "ou1", "email": "a@example.com", "name": "Alice", "status": 2, "type": 0, "twoFactorEnabled": true},
			map[string]any{"id": "ou2", "email": "b@example.com", "name": nil, "status": 0, "type": 2, "twoFactorEnabled": false},
		}, "object": "list"})
	case p == "/api/collections":
		writeJSON(map[string]any{"data": []any{
			map[string]any{"id": col1, "organizationId": org1, "name": mustEnc(t, "Zeta", e.orgKeys[org1]), "externalId": nil},
			map[string]any{"id": "0c000000-0000-0000-0000-0000000000a1", "organizationId": org1, "name": mustEnc(t, "Alpha", e.orgKeys[org1]), "externalId": "x1"},
			map[string]any{"id": col2, "organizationId": org2, "name": mustEnc(t, "Other", e.orgKeys[org2]), "externalId": nil},
		}})
	case p == "/api/organizations/"+org2+"/collections":
		writeJSON(map[string]any{"data": []any{
			map[string]any{"id": col2, "organizationId": org2, "name": mustEnc(t, "Beta Shared", e.orgKeys[org2]), "externalId": nil},
		}})
	case p == "/api/organizations/"+org2+"/collections/"+col2+"/details":
		writeJSON(map[string]any{"id": col2, "organizationId": org2, "name": mustEnc(t, "Beta Shared", e.orgKeys[org2]),
			"externalId": nil, "assigned": false,
			"groups": []any{map[string]any{"id": "g1", "readOnly": true, "hidePasswords": false, "manage": false}},
			"users":  []any{map[string]any{"id": "u1", "readOnly": false, "hidePasswords": true, "manage": true}}})
	case p == "/api/ciphers/"+cGoogle+"/attachment/"+attID:
		writeJSON(map[string]any{"id": attID, "url": e.srv.URL + "/blob/" + attID})
	case p == "/blob/"+attID:
		_, _ = w.Write(e.attBlob)
	case p == "/api/users/"+otherID+"/public-key":
		der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
		writeJSON(map[string]any{"userId": otherID, "publicKey": base64.StdEncoding.EncodeToString(der)})
	case strings.HasPrefix(p, "/range/"):
		if r.Header.Get("Add-Padding") != "true" {
			w.WriteHeader(400)
			return
		}
		sum := sha1.Sum([]byte("pw-google"))
		h := strings.ToUpper(hex.EncodeToString(sum[:]))
		if strings.TrimPrefix(p, "/range/") != h[:5] {
			_, _ = io.WriteString(w, "0000000000000000000000000000000000A:0\r\n")
			return
		}
		_, _ = io.WriteString(w, "0000000000000000000000000000000000A:0\r\n"+h[5:]+":42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3")
	default:
		w.WriteHeader(404)
	}
}

func listJSON(t *testing.T, r *cli.Response) string {
	t.Helper()
	if !r.Success {
		t.Fatalf("unexpected failure: %s", r.MessageText())
	}
	return cli.MarshalJSON(r.Data.(*cli.ListResponse).Data, false)
}

func listIDs(t *testing.T, r *cli.Response) []string {
	t.Helper()
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(listJSON(t, r)), &items); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	return ids
}

func str(t *testing.T, r *cli.Response) string {
	t.Helper()
	if !r.Success {
		t.Fatalf("unexpected failure: %s", r.MessageText())
	}
	s := r.Data.(*cli.StringResponse)
	if s.Data == nil {
		return "<nil>"
	}
	return *s.Data
}

func expectErr(t *testing.T, r *cli.Response, msg string) {
	t.Helper()
	if r.Success || r.MessageText() != msg {
		t.Fatalf("expected error %q, got success=%v %q", msg, r.Success, r.MessageText())
	}
}

func TestListItemsFilters(t *testing.T) {
	e := newEnv(t)
	a := e.a
	cases := []struct {
		name string
		opts ListOptions
		want []string
	}{
		// GitHub, Google sorted; trashed and archived items excluded; the personal card is restricted.
		{"all", ListOptions{}, []string{cGitHub, cGoogle, cHidden}},
		{"folder null", ListOptions{FolderID: "null"}, []string{cGitHub, cHidden}},
		{"folder id", ListOptions{FolderID: folder1}, []string{cGoogle}},
		{"folder OR org", ListOptions{FolderID: folder1, OrganizationID: "notnull"}, []string{cGitHub, cGoogle, cHidden}},
		{"org null", ListOptions{OrganizationID: "null"}, []string{cGoogle}},
		{"org id", ListOptions{OrganizationID: org2}, []string{cHidden}},
		{"collection null", ListOptions{CollectionID: "null"}, []string{cGoogle, cHidden}},
		{"collection notnull", ListOptions{CollectionID: "notnull"}, []string{cGitHub}},
		{"collection id", ListOptions{CollectionID: col1}, []string{cGitHub}},
		{"search", ListOptions{Search: "goo"}, []string{cGoogle}},
		{"search AND filter", ListOptions{Search: "git", FolderID: folder1}, []string{}},
		{"trash", ListOptions{Trash: true}, []string{cNote}},
		{"archived", ListOptions{Archived: true}, []string{cArchive}},
		{"url", ListOptions{URL: "https://accounts.google.com/login"}, []string{cGoogle}},
		{"url + trash", ListOptions{URL: "https://google.com", Trash: true}, []string{}},
	}
	for _, c := range cases {
		if got := listIDs(t, List(a, "items", c.opts)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}

	// Without premium, --archived is ignored (and archived items stay hidden).
	e.setPremium(t, false)
	if got := listIDs(t, List(a, "items", ListOptions{Archived: true})); !reflect.DeepEqual(got, []string{cGitHub, cGoogle, cHidden}) {
		t.Errorf("archived without premium: %v", got)
	}
	expectErr(t, List(a, "nope", ListOptions{}), "Unknown object.")
}

func TestListItemsURLMatchPolicy(t *testing.T) {
	e := newEnv(t)
	err := e.a.UpdateAccount(func(acct *state.Account) error {
		acct.Vault.Policies = append(acct.Vault.Policies, json.RawMessage(`{"id":"p2","organizationId":"`+org1+
			`","type":16,"data":{"uriMatchDetection":3},"enabled":true}`))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The UriMatchDefaults policy (Exact) replaces the Domain default.
	if got := listIDs(t, List(e.a, "items", ListOptions{URL: "https://accounts.google.com/login"})); len(got) != 0 {
		t.Errorf("exact policy, other url: %v", got)
	}
	if got := listIDs(t, List(e.a, "items", ListOptions{URL: "https://google.com"})); !reflect.DeepEqual(got, []string{cGoogle}) {
		t.Errorf("exact policy, same url: %v", got)
	}
}

func TestListItemJSON(t *testing.T) {
	e := newEnv(t)
	got := listJSON(t, List(e.a, "items", ListOptions{OrganizationID: org2}))
	want := `[{"type":1,"favorite":false,"reprompt":0,"id":"` + cHidden + `","collectionIds":[],"object":"item",` +
		`"organizationId":"` + org2 + `","name":"Hidden pw","fields":[],` +
		`"login":{"uris":[],"fido2Credentials":[],"username":"hid","password":null,"totp":null,"passwordRevisionDate":null},` +
		`"creationDate":"2024-01-02T03:04:05.000Z","revisionDate":"2024-02-03T04:05:06.000Z","attachments":[]}]`
	if got != want {
		t.Fatalf("list items json:\n got %s\nwant %s", got, want)
	}
}

func TestListFoldersCollectionsOrgs(t *testing.T) {
	e := newEnv(t)
	a := e.a
	if got := listJSON(t, List(a, "folders", ListOptions{})); got !=
		`[{"name":"Social","object":"folder","id":"`+folder1+`"},{"name":"No Folder","object":"folder","id":""}]` {
		t.Errorf("folders: %s", got)
	}
	if got := listJSON(t, List(a, "folders", ListOptions{Search: "SOC"})); got !=
		`[{"name":"Social","object":"folder","id":"`+folder1+`"}]` {
		t.Errorf("folders search: %s", got)
	}
	want := `[{"object":"collection","id":"` + col2 + `","organizationId":"` + org2 + `","name":"Beta Shared","externalId":"ext-2"},` +
		`{"object":"collection","id":"` + col1 + `","organizationId":"` + org1 + `","name":"Engineering","externalId":null}]`
	if got := listJSON(t, List(a, "collections", ListOptions{})); got != want {
		t.Errorf("collections:\n got %s\nwant %s", got, want)
	}
	if got := listIDs(t, List(a, "collections", ListOptions{OrganizationID: org1})); !reflect.DeepEqual(got, []string{col1}) {
		t.Errorf("collections by org: %v", got)
	}
	want = `[{"object":"organization","id":"` + org1 + `","name":"Acme","status":2,"type":2,"enabled":true},` +
		`{"object":"organization","id":"` + org2 + `","name":"Beta Org","status":2,"type":1,"enabled":true}]`
	if got := listJSON(t, List(a, "organizations", ListOptions{})); got != want {
		t.Errorf("organizations:\n got %s\nwant %s", got, want)
	}
	if got := listIDs(t, List(a, "organizations", ListOptions{Search: "beta"})); !reflect.DeepEqual(got, []string{org2}) {
		t.Errorf("organizations search: %v", got)
	}
}

func TestListOrgCollectionsAndMembers(t *testing.T) {
	e := newEnv(t)
	a := e.a
	expectErr(t, List(a, "org-collections", ListOptions{}), "`organizationid` option is required.")
	expectErr(t, List(a, "org-members", ListOptions{OrganizationID: "abc"}), "`abc` is not a GUID.")
	expectErr(t, List(a, "org-members", ListOptions{OrganizationID: otherID}), "Organization not found.")

	// org1: plain member -> GET /collections, filtered by org, decrypted and sorted by name.
	want := `[{"object":"collection","id":"0c000000-0000-0000-0000-0000000000a1","organizationId":"` + org1 + `","name":"Alpha","externalId":"x1"},` +
		`{"object":"collection","id":"` + col1 + `","organizationId":"` + org1 + `","name":"Zeta","externalId":null}]`
	if got := listJSON(t, List(a, "org-collections", ListOptions{OrganizationID: org1})); got != want {
		t.Errorf("org-collections:\n got %s\nwant %s", got, want)
	}
	// org2: admin -> GET /organizations/{id}/collections.
	if got := listIDs(t, List(a, "org-collections", ListOptions{OrganizationID: org2, Search: "beta"})); !reflect.DeepEqual(got, []string{col2}) {
		t.Errorf("org-collections admin: %v", got)
	}

	want = `[{"object":"org-member","id":"ou1","email":"a@example.com","name":"Alice","status":2,"type":0,"twoFactorEnabled":true},` +
		`{"object":"org-member","id":"ou2","email":"b@example.com","name":null,"status":0,"type":2,"twoFactorEnabled":false}]`
	if got := listJSON(t, List(a, "org-members", ListOptions{OrganizationID: org1})); got != want {
		t.Errorf("org-members:\n got %s\nwant %s", got, want)
	}
	found := false
	for _, r := range e.requests {
		if r == "GET /api/organizations/"+org1+"/users?" {
			found = true
		}
	}
	if !found {
		t.Errorf("org-members request path: %v", e.requests)
	}
}

func TestGetItem(t *testing.T) {
	e := newEnv(t)
	a := e.a
	r := Get(a, "item", strings.ToUpper(cGoogle), GetOptions{})
	if !r.Success {
		t.Fatal(r.MessageText())
	}
	got := cli.MarshalJSON(r.Data, false)
	want := `{"type":1,"favorite":false,"reprompt":0,"id":"` + cGoogle + `","collectionIds":[],"object":"item",` +
		`"folderId":"` + folder1 + `","name":"Google","notes":"my notes","fields":[],` +
		`"login":{"uris":[{"uri":"https://google.com"}],"fido2Credentials":[],"username":"user@gmail.com",` +
		`"password":"pw-google","totp":"JBSWY3DPEHPK3PXP","passwordRevisionDate":null},"passwordHistory":[],` +
		`"creationDate":"2024-01-02T03:04:05.000Z","revisionDate":"2024-02-03T04:05:06.000Z",` +
		`"attachments":[{"id":"` + attID + `","fileName":"photo.jpg","size":"16","sizeName":"16 Bytes","url":"` + e.srv.URL + `/stale"}]}`
	if got != want {
		t.Fatalf("get item:\n got %s\nwant %s", got, want)
	}

	// Search by name; multiple results; not found; restricted.
	if r := Get(a, "item", "github", GetOptions{}); !r.Success || r.Data.(*vault.CipherResponse).ID != cGitHub {
		t.Fatalf("get item by search: %v", r.MessageText())
	}
	r = Get(a, "item", "g", GetOptions{})
	expectErr(t, r, "More than one result was found. Try getting a specific object by `id` instead. "+
		"The following objects were found:\n"+cGitHub+"\n"+cGoogle)
	if ids := r.Data.([]string); len(ids) != 2 {
		t.Fatalf("multiple results data: %v", r.Data)
	}
	expectErr(t, Get(a, "item", "nothing-like-this", GetOptions{}), "Not found.")
	expectErr(t, Get(a, "item", cCard, GetOptions{}), "Access to this item type is restricted by organizational policy.")
	expectErr(t, Get(a, "item", "visa", GetOptions{}), "Access to this item type is restricted by organizational policy.")
	// Trashed items are found by id but not by search.
	if r := Get(a, "item", cNote, GetOptions{}); !r.Success {
		t.Fatalf("trashed by id: %s", r.MessageText())
	}
	expectErr(t, Get(a, "item", "trashed", GetOptions{}), "Not found.")
	expectErr(t, Get(a, "nope", "x", GetOptions{}), "Unknown object.")
}

func TestGetFields(t *testing.T) {
	e := newEnv(t)
	a := e.a
	if s := str(t, Get(a, "username", "google", GetOptions{})); s != "user@gmail.com" {
		t.Errorf("username %q", s)
	}
	if s := str(t, Get(a, "password", cGoogle, GetOptions{})); s != "pw-google" {
		t.Errorf("password %q", s)
	}
	if s := str(t, Get(a, "uri", "google", GetOptions{})); s != "https://google.com" {
		t.Errorf("uri %q", s)
	}
	if s := str(t, Get(a, "notes", "google", GetOptions{})); s != "my notes" {
		t.Errorf("notes %q", s)
	}
	expectErr(t, Get(a, "notes", "github", GetOptions{}), "Not found.")
	// The response redacts the password of items the user may not view.
	expectErr(t, Get(a, "password", cHidden, GetOptions{}), "No password available for this login.")
	expectErr(t, Get(a, "password", cNote, GetOptions{}), "Not found.")
	if s := str(t, Get(a, "username", "hid", GetOptions{})); s != "hid" {
		t.Errorf("username hidden %q", s)
	}
}

func TestGetTotp(t *testing.T) {
	e := newEnv(t)
	a := e.a
	before, _ := vault.GenerateTotp("JBSWY3DPEHPK3PXP", time.Time{})
	code := str(t, Get(a, "totp", "google", GetOptions{}))
	after, _ := vault.GenerateTotp("JBSWY3DPEHPK3PXP", time.Time{})
	if code != before.Code && code != after.Code {
		t.Fatalf("totp %q", code)
	}
	e.setPremium(t, false)
	expectErr(t, Get(a, "totp", "google", GetOptions{}), "Premium status is required to use this feature.")
	// Organization items with organizationUseTotp work without premium.
	if code := str(t, Get(a, "totp", cGitHub, GetOptions{})); len(code) != 6 {
		t.Fatalf("org totp %q", code)
	}
}

func TestGetExposed(t *testing.T) {
	e := newEnv(t)
	if s := str(t, Get(e.a, "exposed", "google", GetOptions{})); s != "42" {
		t.Fatalf("exposed %q", s)
	}
	if s := str(t, Get(e.a, "exposed", "github", GetOptions{})); s != "0" {
		t.Fatalf("exposed github %q", s)
	}
}

func TestGetAttachment(t *testing.T) {
	e := newEnv(t)
	a := e.a
	expectErr(t, Get(a, "attachment", "photo", GetOptions{}), "--itemid <itemid> required.")
	expectErr(t, Get(a, "attachment", "photo", GetOptions{ItemID: cGitHub}), "No attachments available for this item.")
	expectErr(t, Get(a, "attachment", "nope", GetOptions{ItemID: cGoogle}), "Attachment `nope` was not found.")

	out := filepath.Join(t.TempDir(), "sub", "out.jpg")
	r := Get(a, "attachment", "PHOTO", GetOptions{ItemID: strings.ToUpper(cGoogle), Output: out})
	if !r.Success {
		t.Fatal(r.MessageText())
	}
	msg := r.Data.(*cli.MessageResponse)
	if *msg.Title != "Saved "+out || *msg.Raw != out {
		t.Fatalf("message %+v", msg)
	}
	if b, _ := os.ReadFile(out); string(b) != string(e.attContent) {
		t.Fatalf("content %q", b)
	}

	t.Setenv("BW_SERVE", "true")
	r = Get(a, "attachment", attID, GetOptions{ItemID: "google"})
	if f, ok := r.Data.(*cli.FileResponse); !ok || string(f.Data) != string(e.attContent) || f.FileName != "photo.jpg" {
		t.Fatalf("serve file response: %v %v", r.MessageText(), r.Data)
	}

	e.setPremium(t, false)
	expectErr(t, Get(a, "attachment", "photo", GetOptions{ItemID: cGoogle}), "Premium status is required to use this feature.")
}

func TestGetFolderCollectionOrganization(t *testing.T) {
	e := newEnv(t)
	a := e.a
	if got := cli.MarshalJSON(Get(a, "folder", "soc", GetOptions{}).Data, false); got != `{"name":"Social","object":"folder","id":"`+folder1+`"}` {
		t.Errorf("folder: %s", got)
	}
	expectErr(t, Get(a, "folder", "o", GetOptions{}), "More than one result was found. Try getting a specific object by `id` instead. "+
		"The following objects were found:\n"+folder1+"\n")
	expectErr(t, Get(a, "folder", otherID, GetOptions{}), "Not found.")
	if got := cli.MarshalJSON(Get(a, "collection", col1, GetOptions{}).Data, false); got !=
		`{"object":"collection","id":"`+col1+`","organizationId":"`+org1+`","name":"Engineering","externalId":null}` {
		t.Errorf("collection: %s", got)
	}
	if got := cli.MarshalJSON(Get(a, "collection", "beta", GetOptions{}).Data, false); !strings.Contains(got, `"name":"Beta Shared"`) {
		t.Errorf("collection search: %s", got)
	}
	if got := cli.MarshalJSON(Get(a, "organization", "acme", GetOptions{}).Data, false); got !=
		`{"object":"organization","id":"`+org1+`","name":"Acme","status":2,"type":2,"enabled":true}` {
		t.Errorf("organization: %s", got)
	}

	expectErr(t, Get(a, "org-collection", col2, GetOptions{}), "`organizationid` option is required.")
	expectErr(t, Get(a, "org-collection", "x", GetOptions{OrganizationID: org2}), "`x` is not a GUID.")
	expectErr(t, Get(a, "org-collection", col2, GetOptions{OrganizationID: otherID}), "Error: No encryption key for this organization.")
	r := Get(a, "org-collection", col2, GetOptions{OrganizationID: org2})
	want := `{"object":"org-collection","id":"` + col2 + `","organizationId":"` + org2 + `","name":"Beta Shared","externalId":null,` +
		`"groups":[{"id":"g1","readOnly":true,"hidePasswords":false,"manage":false}],` +
		`"users":[{"id":"u1","readOnly":false,"hidePasswords":true,"manage":true}]}`
	if got := cli.MarshalJSON(r.Data, false); got != want {
		t.Errorf("org-collection:\n got %s\nwant %s", got, want)
	}
}

func TestGetTemplate(t *testing.T) {
	e := newEnv(t)
	a := e.a
	if got := cli.MarshalJSON(Get(a, "template", "FOLDER", GetOptions{}).Data, false); got != `{"object":"template","template":{"name":"Folder name"}}` {
		t.Errorf("template folder: %s", got)
	}
	if got := cli.MarshalJSON(Get(a, "template", "item-collections", GetOptions{}).Data, false); got != `{"object":"template","template":["collection-id1","collection-id2"]}` {
		t.Errorf("template item-collections: %s", got)
	}
	expectErr(t, Get(a, "template", "item.passport", GetOptions{}), "Passport item type is not available.")
	expectErr(t, Get(a, "template", "item.bankaccount", GetOptions{}), "Bank account item type is not available.")
	expectErr(t, Get(a, "template", "item.driverslicense", GetOptions{}), "Driver's license item type is not available.")
	expectErr(t, Get(a, "template", "item.sshkey", GetOptions{}), "Unknown template object.")
	r := Get(a, "template", "send.text", GetOptions{})
	if got := cli.MarshalJSON(r.Data, false); !r.Success || got !=
		"{\"object\":\"template\",\"template\":{\"success\":false,\"message\":\"Invalid template object. Use `bw send template send.text` instead.\"}}" {
		t.Errorf("template send.text: %s", got)
	}
	old := NewItemTypesEnabled
	NewItemTypesEnabled = func(*app.App) bool { return true }
	defer func() { NewItemTypesEnabled = old }()
	if r := Get(a, "template", "item.passport", GetOptions{}); !r.Success {
		t.Errorf("template passport with flag: %s", r.MessageText())
	}
}

func TestFingerprint(t *testing.T) {
	// LegacyCompatKeyService.spec: hashPhrase of the HKDF output.
	user, _ := base64.StdEncoding.DecodeString("V5AQSk83YXd6kZqCncC6d9J72R7UZ60Xl1eIoDoWgTc=")
	phrase, err := hashPhrase(user, 64)
	if err != nil || strings.Join(phrase, "-") != "predefine-hunting-pastime-enrich-unhearing" {
		t.Fatalf("hashPhrase: %v %v", phrase, err)
	}
	if _, err := hashPhrase(make([]byte, 3), 64); err == nil || err.Error() != "Output entropy of hash function is too small" {
		t.Fatalf("entropy error: %v", err)
	}

	e := newEnv(t)
	priv, other := testRSA()
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	exp, _ := Fingerprint(userID, der)
	if s := str(t, Get(e.a, "fingerprint", "ME", GetOptions{})); s != strings.Join(exp, "-") || len(exp) != 5 {
		t.Fatalf("fingerprint me: %q want %v", s, exp)
	}
	der2, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	exp2, _ := Fingerprint(otherID, der2)
	if s := str(t, Get(e.a, "fingerprint", otherID, GetOptions{})); s != strings.Join(exp2, "-") {
		t.Fatalf("fingerprint other: %q", s)
	}
	expectErr(t, Get(e.a, "fingerprint", "eeeeeeee-0000-0000-0000-000000000000", GetOptions{}), "Not found.")
	expectErr(t, Get(e.a, "fingerprint", "someone", GetOptions{}), "Not found.")
}

func TestFingerprintSDKVector(t *testing.T) {
	// bitwarden-crypto fingerprint.rs test vector. The SDK keys HKDF-Expand with the SPKI bytes
	// directly; HMAC hashes keys longer than its block size, so this equals the TS
	// SHA-256-then-expand construction.
	key, _ := base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB")
	phrase, err := Fingerprint("a09726a0-9590-49d1-a5f5-afe300b6a515", key)
	if err != nil || strings.Join(phrase, "-") != "turban-deftly-anime-chatroom-unselfish" {
		t.Fatalf("fingerprint: %v %v", phrase, err)
	}
}

func TestOptionsFromQuery(t *testing.T) {
	q, _ := url.ParseQuery("organizationId=o&folderid=f&collectionid=&collectionId=c&search=s&url=u&trash&archived=TRUE")
	got := ListOptionsFromQuery(q)
	want := ListOptions{OrganizationID: "o", CollectionID: "c", FolderID: "f", Search: "s", URL: "u", Trash: true, Archived: true}
	if got != want {
		t.Fatalf("list options %+v", got)
	}
	q, _ = url.ParseQuery("trash=false")
	if ListOptionsFromQuery(q).Trash {
		t.Fatal("trash=false")
	}
	q, _ = url.ParseQuery("itemId=i&organizationid=o&output=x")
	if g := GetOptionsFromQuery(q); g != (GetOptions{ItemID: "i", OrganizationID: "o", Output: "x"}) {
		t.Fatalf("get options %+v", g)
	}
}

func TestCommandValidation(t *testing.T) {
	newEnv(t)
	t.Setenv("BW_RESPONSE", "true")
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		rd, wr, _ := os.Pipe()
		old := os.Stdout
		os.Stdout = wr
		root.Execute(a, args)
		os.Stdout = old
		wr.Close()
		b, _ := io.ReadAll(rd)
		return string(b)
	}
	if out := run("list", "Items"); out != `{"success":false,"message":"Unknown object \"Items\". Allowed objects are: items, folders, collections, org-collections, org-members, organizations."}` {
		t.Errorf("list validation: %s", out)
	}
	if out := run("get", "bogus", "x"); !strings.Contains(out, `Unknown object \"bogus\". Allowed objects are: item, username, password, uri, totp, notes, exposed, attachment, folder, collection, org-collection, organization, template, fingerprint, send.`) {
		t.Errorf("get validation: %s", out)
	}
	if out := run("get", "send", "x"); out != `{"success":false,"message":"Unknown object."}` {
		t.Errorf("get send: %s", out)
	}
	if out := run("list", "folders", "--search", "soc"); !strings.Contains(out, `"data":{"object":"list","data":[{"name":"Social","object":"folder","id":"`+folder1+`"}]}`) {
		t.Errorf("list folders cli: %s", out)
	}
}
