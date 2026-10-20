package importexport

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/exporter"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	xOrgID    = "7063feab-4b10-472e-b64c-785e2b870b92"
	xFolderID = "f0000000-0000-4000-8000-000000000001"
	xColID    = "c0000000-0000-4000-8000-000000000001"
)

var (
	xRSAOnce sync.Once
	xRSA     *rsa.PrivateKey
)

func xsp(s string) *string { return &s }

type exportServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	orgExport []byte
	files     map[string][]byte // attachment id -> encrypted content
	events    []map[string]any
	requests  []string
}

func (s *exportServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/organizations/"+xOrgID+"/export":
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.orgExport)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/ciphers/") && strings.Contains(r.URL.Path, "/attachment/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "url": s.srv.URL + "/blob/" + id})
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/blob/"):
		if r.Header.Get("Authorization") != "" {
			w.WriteHeader(400) // attachment downloads are unauthenticated
			return
		}
		b, ok := s.files[strings.TrimPrefix(r.URL.Path, "/blob/")]
		if !ok {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write(b)
	case r.Method == "POST" && r.URL.Path == "/events/collect":
		var ev []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		s.events = append(s.events, ev...)
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

type exportEnv struct {
	a       *app.App
	srv     *exportServer
	userKey *crypto.SymmetricKey
	orgKey  *crypto.SymmetricKey
	keys    *vault.Keys
	dir     string
}

func setupExport(t *testing.T, v2 bool, policies ...string) *exportEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", filepath.Join(dir, "appdata"))
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	t.Setenv("BW_RAW", "")
	t.Setenv("BW_RESPONSE", "")
	t.Setenv("BW_QUIET", "")
	t.Setenv("BW_PRETTY", "")
	es := &exportServer{files: map[string][]byte{}}
	es.srv = httptest.NewServer(http.HandlerFunc(es.handle))
	t.Cleanup(es.srv.Close)

	xRSAOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		xRSA = k
	})
	der, _ := x509.MarshalPKCS8PrivateKey(xRSA)
	env := &exportEnv{srv: es, orgKey: crypto.GenerateKey(), dir: dir}
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
	encOrg, _ := crypto.RsaEncrypt(env.orgKey.Bytes(), &xRSA.PublicKey)
	profile, _ := json.Marshal(map[string]any{
		"id": "u1", "email": "u@example.com",
		"organizations": []any{map[string]any{"id": xOrgID, "name": "Acme", "key": encOrg, "status": 2,
			"type": 2, "enabled": true, "usePolicies": true, "useEvents": true}},
	})
	var prof vault.Profile
	_ = json.Unmarshal(profile, &prof)
	env.keys = vault.NewKeys(env.userKey, encPriv.String(), accountKeys, &prof)

	ciphers := map[string]json.RawMessage{}
	created := time.Date(2024, 1, 2, 3, 4, 5, 678e6, time.UTC)
	add := func(v *vault.CipherView) (*crypto.SymmetricKey, json.RawMessage) {
		v.CreationDate, v.RevisionDate = created, created
		c, ck, err := vault.EncryptCipher(v, env.keys)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(c)
		return ck, raw
	}
	login := vault.NewCipherView()
	login.ID, login.Name, login.FolderID = "a0000000-0000-4000-8000-000000000001", "Mail, Inc", xsp(xFolderID)
	login.Login.Username, login.Login.Password = xsp("me"), xsp("secret")
	login.Attachments = []vault.AttachmentView{{ID: xsp("att1"), FileName: xsp("doc.txt"), Key: crypto.GenerateKey(), Size: xsp("4")}}
	_, raw := add(login)
	ciphers[login.ID] = raw
	enc, _ := crypto.EncryptBytes([]byte("DATA"), login.Attachments[0].Key)
	es.files["att1"] = enc

	orgItem := vault.NewCipherView()
	org := xOrgID
	orgItem.ID, orgItem.Name, orgItem.OrganizationID = "b0000000-0000-4000-8000-000000000001", "Shared", &org
	orgItem.CollectionIDs = []string{xColID}
	orgItem.Login.Username = xsp("team")
	_, orgRaw := add(orgItem)
	ciphers[orgItem.ID] = orgRaw
	colName, _ := crypto.EncryptString("Engineering", env.orgKey)
	colRaw, _ := json.Marshal(map[string]any{"id": xColID, "organizationId": xOrgID, "name": colName, "externalId": nil})
	es.orgExport, _ = json.Marshal(map[string]any{"collections": []json.RawMessage{colRaw}, "ciphers": []json.RawMessage{orgRaw}})

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
		d.Environment = state.Environment{Base: es.srv.URL}
		d.ActiveUserID = "u1"
		d.Accounts = map[string]*state.Account{"u1": {UserID: "u1", Email: "u@example.com", AccessToken: "token",
			EncPrivateKey: encPriv.String(), AccountKeys: accountKeys,
			Kdf: crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000},
			Vault: state.VaultData{Profile: profile, Ciphers: ciphers, Policies: pols,
				Folders:     map[string]json.RawMessage{xFolderID: json.RawMessage(`{"id":"` + xFolderID + `","name":"` + folderName + `"}`)},
				Collections: map[string]json.RawMessage{xColID: colRaw}}}}
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

func savedPath(t *testing.T, r *cli.Response) string {
	t.Helper()
	if !r.Success {
		t.Fatalf("export failed: %s", r.MessageText())
	}
	m, ok := r.Data.(*cli.MessageResponse)
	if !ok || m.Raw == nil || !strings.HasPrefix(*m.Title, "Saved ") {
		t.Fatalf("unexpected response %+v", r.Data)
	}
	return *m.Raw
}

func readSaved(t *testing.T, r *cli.Response) (string, []byte) {
	t.Helper()
	p := savedPath(t, r)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Base(p), b
}

func fileNameLike(t *testing.T, name, prefix, ext string) {
	t.Helper()
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) || len(name) != len(prefix)+14+len(ext) {
		t.Fatalf("file name %q, want %s<yyyyMMddHHmmss>%s", name, prefix, ext)
	}
}

const xWantCSV = "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
	"Work,,login,\"Mail, Inc\",,,0,,,me,secret,"

func TestExportFormats(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupExport(t, v2)
		out := env.dir + string(os.PathSeparator)

		name, data := readSaved(t, Export(env.a, ExportOptions{Output: out}))
		fileNameLike(t, name, "bitwarden_export_", ".csv")
		if string(data) != xWantCSV {
			t.Fatalf("csv %q", data)
		}

		jsonFmt := "json"
		name, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &jsonFmt}))
		fileNameLike(t, name, "bitwarden_export_", ".json")
		var doc struct {
			Encrypted bool
			Folders   []map[string]string
			Items     []map[string]any
		}
		if err := json.Unmarshal(data, &doc); err != nil || doc.Encrypted || len(doc.Items) != 1 || doc.Items[0]["name"] != "Mail, Inc" || doc.Folders[0]["name"] != "Work" {
			t.Fatalf("json %s", data)
		}

		encFmt := "encrypted_json"
		name, data = readSaved(t, Export(env.a, ExportOptions{Output: filepath.Join(env.dir, "sub", "enc.json"), Format: &encFmt}))
		if name != "enc.json" {
			t.Fatal(name)
		}
		var edoc struct {
			EncKeyValidation string `json:"encKeyValidation_DO_NOT_EDIT"`
		}
		_ = json.Unmarshal(data, &edoc)
		if _, err := crypto.DecryptString(edoc.EncKeyValidation, env.userKey); err != nil {
			t.Fatalf("account encrypted export: %v", err)
		}

		// --password <value> with json => encrypted_json, password protected.
		pw := "hunter2"
		name, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &jsonFmt, Password: &pw}))
		fileNameLike(t, name, "bitwarden_encrypted_export_", ".json")
		checkPasswordProtected(t, data, pw, "Mail, Inc")

		// --password without a value prompts for encrypted_json ...
		prompted := 0
		old := exportPromptPassword
		exportPromptPassword = func() (string, error) { prompted++; return "prompted", nil }
		_, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &jsonFmt, PromptPassword: true}))
		checkPasswordProtected(t, data, "prompted", "Mail, Inc")
		// ... but is ignored for csv and zip
		_, data = readSaved(t, Export(env.a, ExportOptions{Output: out, PromptPassword: true}))
		if string(data) != xWantCSV || prompted != 1 {
			t.Fatalf("prompted=%d csv %q", prompted, data)
		}
		// an empty prompted password falls back to the account-encrypted export
		exportPromptPassword = func() (string, error) { return "", nil }
		name, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &encFmt, PromptPassword: true}))
		exportPromptPassword = old
		if !strings.Contains(string(data), "encKeyValidation_DO_NOT_EDIT") || strings.Contains(string(data), "passwordProtected") {
			t.Fatalf("empty prompt: %s", data)
		}

		// zip with attachments downloaded from the server
		zipFmt := "zip"
		name, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &zipFmt}))
		fileNameLike(t, name, "bitwarden_export_", ".zip")
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range zr.File {
			names = append(names, f.Name)
			if f.Name == "attachments/Mail, Inc/doc.txt" {
				rc, _ := f.Open()
				b, _ := io.ReadAll(rc)
				rc.Close()
				if string(b) != "DATA" {
					t.Fatalf("attachment %q", b)
				}
			}
		}
		if strings.Join(names, "|") != "data.json|attachments/|attachments/Mail, Inc/|attachments/Mail, Inc/doc.txt" {
			t.Fatalf("zip entries %v", names)
		}
		// zip + password => password-protected json
		_, data = readSaved(t, Export(env.a, ExportOptions{Output: out, Format: &zipFmt, Password: &pw}))
		checkPasswordProtected(t, data, pw, "Mail, Inc")

		// csv + password is rejected by the export service
		r := Export(env.a, ExportOptions{Output: out, Password: &pw})
		if r.Success || r.MessageText() != "CSV does not support password protected export" {
			t.Fatalf("csv+password: %+v", r.MessageText())
		}
	}
}

func checkPasswordProtected(t *testing.T, data []byte, password, wantName string) {
	t.Helper()
	var doc exporter.PasswordProtectedJSON
	if err := json.Unmarshal(data, &doc); err != nil || !doc.PasswordProtected || doc.KdfIterations != 5000 {
		t.Fatalf("password protected doc %s", data)
	}
	key, err := exporter.DeriveVaultExportKey(password, doc.Salt, crypto.KdfConfig{Type: crypto.KdfType(doc.KdfType), Iterations: doc.KdfIterations})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.DecryptString(doc.Data, key)
	if err != nil {
		t.Fatalf("decrypt with password: %v", err)
	}
	if !strings.Contains(plain, `"name": "`+wantName+`"`) {
		t.Fatalf("payload %s", plain)
	}
}

func TestExportValidation(t *testing.T) {
	env := setupExport(t, false)
	bad := "xml"
	r := Export(env.a, ExportOptions{Format: &bad})
	if r.Success || r.MessageText() != "'xml' is not a supported export format. Supported formats: csv, json, encrypted_json, zip." {
		t.Fatal(r.MessageText())
	}
	empty := ""
	if r := Export(env.a, ExportOptions{Format: &empty}); r.MessageText() != "'' is not a supported export format. Supported formats: csv, json, encrypted_json, zip." {
		t.Fatal(r.MessageText())
	}
	notGUID := "acme"
	if r := Export(env.a, ExportOptions{OrganizationID: &notGUID}); r.Success || r.MessageText() != "`acme` is not a GUID." {
		t.Fatal(r.MessageText())
	}
	if r := Export(env.a, ExportOptions{OrganizationID: &empty}); r.MessageText() != "`` is not a GUID." {
		t.Fatal(r.MessageText())
	}
	zipFmt := "zip"
	org := xOrgID
	if r := Export(env.a, ExportOptions{OrganizationID: &org, Format: &zipFmt}); r.MessageText() != "Zip export not supported for organization" {
		t.Fatal(r.MessageText())
	}
	// locked vault
	t.Setenv("BW_SESSION", "")
	_ = env.a.Lock()
	if r := Export(env.a, ExportOptions{}); r.Success || r.MessageText() != "Vault is locked." {
		t.Fatal(r.MessageText())
	}
}

func TestExportPersonalVaultPolicy(t *testing.T) {
	policy := `{"id":"p1","organizationId":"` + xOrgID + `","type":10,"enabled":true}`
	env := setupExport(t, false, policy)
	r := Export(env.a, ExportOptions{Output: env.dir + "/"})
	if r.Success || r.MessageText() != "One or more organization policies prevents you from exporting your personal vault." {
		t.Fatal(r.MessageText())
	}
	// organization exports are not affected
	org := xOrgID
	name, data := readSaved(t, Export(env.a, ExportOptions{Output: env.dir + "/", OrganizationID: &org}))
	fileNameLike(t, name, "bitwarden_org_export_", ".csv")
	want := "collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
		"Engineering,login,Shared,,,0,,,team,,"
	if string(data) != want {
		t.Fatalf("org csv %q", data)
	}
}

func TestOrganizationExportAndEvents(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := setupExport(t, v2)
		org := xOrgID
		encFmt := "encrypted_json"
		name, data := readSaved(t, Export(env.a, ExportOptions{Output: env.dir + "/", OrganizationID: &org, Format: &encFmt}))
		fileNameLike(t, name, "bitwarden_encrypted_org_export_", ".json")
		var doc struct {
			EncKeyValidation string `json:"encKeyValidation_DO_NOT_EDIT"`
			Collections      []map[string]any
			Items            []json.RawMessage
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.DecryptString(doc.EncKeyValidation, env.orgKey); err != nil {
			t.Fatal("org export must be validated with the organization key")
		}
		if len(doc.Collections) != 1 || len(doc.Items) != 1 {
			t.Fatalf("org export %s", data)
		}

		_, _ = readSaved(t, Export(env.a, ExportOptions{Output: env.dir + "/"}))
		env.srv.mu.Lock()
		events := env.srv.events
		env.srv.mu.Unlock()
		if len(events) != 2 {
			t.Fatalf("events %v", events)
		}
		if events[0]["type"] != float64(1602) || events[0]["organizationId"] != xOrgID || events[0]["cipherId"] != nil {
			t.Fatalf("org event %v", events[0])
		}
		if events[1]["type"] != float64(1007) || events[1]["organizationId"] != nil {
			t.Fatalf("user event %v", events[1])
		}
		if _, err := time.Parse(cli.JSDateLayout, events[1]["date"].(string)); err != nil {
			t.Fatalf("event date %v", events[1]["date"])
		}
	}
}

func TestExportRawToStdout(t *testing.T) {
	env := setupExport(t, false)
	t.Setenv("BW_RAW", "true")
	rd, wr, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = wr
	r := Export(env.a, ExportOptions{})
	os.Stdout = old
	wr.Close()
	b, _ := io.ReadAll(rd)
	if !r.Success || r.Data != nil || string(b) != xWantCSV {
		t.Fatalf("raw %+v %q", r, b)
	}
}

func TestExportOptionsFromQuery(t *testing.T) {
	q, _ := url.ParseQuery("format=json&password=pw&organizationid=" + xOrgID + "&output=/tmp/x")
	o := ExportOptionsFromQuery(q)
	if *o.Format != "json" || *o.Password != "pw" || *o.OrganizationID != xOrgID || o.Output != "/tmp/x" || o.PromptPassword {
		t.Fatalf("%+v", o)
	}
	o = ExportOptionsFromQuery(url.Values{})
	if o.Format != nil || o.Password != nil || o.OrganizationID != nil {
		t.Fatalf("%+v", o)
	}
}

func TestExportTakePasswordValue(t *testing.T) {
	cases := []struct {
		raw, args []string
		value     string
		rest      []string
		ok        bool
	}{
		{[]string{"export", "--password", "pw", "--format", "json"}, []string{"pw"}, "pw", []string{}, true},
		{[]string{"export", "--password", "--format", "json"}, nil, "", nil, false},
		{[]string{"export", "--password"}, nil, "", nil, false},
		{[]string{"export", "extra", "--password"}, []string{"extra"}, "", []string{"extra"}, false},
		{[]string{"export", "--password", "-"}, []string{"-"}, "-", []string{}, true},
		{[]string{"export", "--password", "a", "--password"}, []string{"a"}, "", []string{"a"}, false},
	}
	for _, c := range cases {
		v, rest, ok := exportTakePasswordValue(c.raw, c.args)
		if ok != c.ok || v != c.value || (ok && strings.Join(rest, ",") != strings.Join(c.rest, ",")) {
			t.Errorf("%v: got %q %v %v", c.raw, v, rest, ok)
		}
	}
}

func TestExportCommandLine(t *testing.T) {
	env := setupExport(t, false)
	t.Setenv("BW_NOINTERACTION", "true")
	run := func(args ...string) int {
		old := exportRawArgs
		exportRawArgs = func() []string { return args }
		defer func() { exportRawArgs = old }()
		oldOut := os.Stdout
		devnull, _ := os.Open(os.DevNull)
		os.Stdout = devnull
		defer func() { os.Stdout = oldOut; devnull.Close() }()
		return root.Execute(env.a, args)
	}
	target := filepath.Join(env.dir, "cmd.json")
	if code := run("export", "--password", "s3cret", "--format", "json", "--output", target); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	checkPasswordProtected(t, data, "s3cret", "Mail, Inc")

	target = filepath.Join(env.dir, "eq.json")
	if code := run("export", "--format=json", "--password=pw2", "--output="+target); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, _ = os.ReadFile(target)
	checkPasswordProtected(t, data, "pw2", "Mail, Inc")

	// --password without value and csv => plain csv, no prompt
	target = filepath.Join(env.dir, "plain.csv")
	if code := run("export", "--output", target, "--password"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if data, _ = os.ReadFile(target); string(data) != xWantCSV {
		t.Fatalf("csv %q", data)
	}

	if code := run("export", "myPassword321"); code != 1 {
		t.Fatalf("excess argument exit %d", code)
	}
}
