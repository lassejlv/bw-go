package serve

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

func TestBuildAllowedHosts(t *testing.T) {
	got := BuildAllowedHosts("MyHost", "8087")
	for _, h := range []string{"localhost:8087", "127.0.0.1:8087", "[::1]:8087", "myhost:8087"} {
		if !got[h] {
			t.Errorf("%s missing", h)
		}
	}
	if len(got) != 4 || got["localhost"] {
		t.Errorf("unexpected entries %v", got)
	}
	got = BuildAllowedHosts("bwapi.example.com", "443")
	for _, h := range []string{"localhost", "127.0.0.1", "[::1]", "bwapi.example.com", "bwapi.example.com:443"} {
		if !got[h] {
			t.Errorf("443: %s missing", h)
		}
	}
}

func TestHostAndOriginProtection(t *testing.T) {
	env := newEnv(t)

	r := env.do("GET", "/status", nil, host("evil.example:8087"))
	expect(t, r, 403, "Forbidden")
	if r.header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("content type %q", r.header.Get("Content-Type"))
	}
	if env.stderr.String() != "Blocking request with disallowed Host \"evil.example:8087\"\n" {
		t.Errorf("log %q", env.stderr.String())
	}
	expect(t, env.do("GET", "/status", nil, host("localhost")), 403, "Forbidden") // port required unless 80/443
	env.stderr.Reset()
	expect(t, env.do("GET", "/status", nil, host("")), 403, "Forbidden")
	if env.stderr.String() != "Blocking request with disallowed Host \"(missing)\"\n" {
		t.Errorf("log %q", env.stderr.String())
	}
	for _, h := range []string{"LOCALHOST:8087", "127.0.0.1:8087", "[::1]:8087"} {
		if r := env.do("GET", "/status", nil, host(h)); r.status != 200 {
			t.Errorf("host %s: %d %s", h, r.status, r.body)
		}
	}

	env.stderr.Reset()
	expect(t, env.do("GET", "/status", nil, header("Origin", "https://evil.example")), 403, "Forbidden")
	if env.stderr.String() != "Blocking request from \"https://evil.example\"\n" {
		t.Errorf("log %q", env.stderr.String())
	}
	env.stderr.Reset()
	expect(t, env.do("GET", "/status", nil, func(r *http.Request) { r.Header["Origin"] = []string{""} }), 403, "Forbidden")
	if env.stderr.String() != "Blocking request from \"(Origin header value missing)\"\n" {
		t.Errorf("log %q", env.stderr.String())
	}

	// --disable-origin-protection turns both guards off
	env.srv.protectOrigin = false
	if r := env.do("GET", "/status", nil, host("evil.example"), header("Origin", "https://evil.example")); r.status != 200 {
		t.Errorf("unprotected: %d %s", r.status, r.body)
	}
	// --hostname all: no Host allow-list, Origin still rejected
	env.srv.protectOrigin, env.srv.allowedHosts = true, nil
	if r := env.do("GET", "/status", nil, host("192.168.1.10:8087")); r.status != 200 {
		t.Errorf("hostname all: %d %s", r.status, r.body)
	}
	expect(t, env.do("GET", "/status", nil, host("192.168.1.10:8087"), header("Origin", "x")), 403, "Forbidden")
}

func TestStatus(t *testing.T) {
	env := newEnv(t)
	r := env.do("GET", "/status", nil)
	want := `{"success":true,"data":{"object":"template","template":{"serverUrl":"` + env.api.URL +
		`","lastSync":null,"userEmail":"user@example.com","userId":"` + testUserID + `","status":"unlocked"}}}`
	expect(t, r, 200, want)
	if r.header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("content type %q", r.header.Get("Content-Type"))
	}
	// ?pretty (any value) indents with two spaces
	r = env.do("GET", "/status?pretty", nil)
	if !strings.HasPrefix(r.body, "{\n  \"success\": true,\n  \"data\": {\n    \"object\": \"template\",") {
		t.Errorf("pretty body %q", r.body)
	}
}

func TestLockUnlock(t *testing.T) {
	env := newEnv(t)
	env.addCipher(loginItem(itemID, "Google", "secret"))

	expect(t, env.do("POST", "/lock", nil), 200,
		`{"success":true,"data":{"object":"message","title":"Your vault is locked.","message":null,"noColor":false}}`)
	if os.Getenv("BW_SESSION") != "" {
		t.Error("BW_SESSION not cleared")
	}
	locked := `{"success":false,"message":"Vault is locked."}`
	expect(t, env.do("GET", "/list/object/items", nil), 400, locked)
	expect(t, env.do("GET", "/object/item/"+itemID, nil), 400, locked)
	expect(t, env.doJSON("POST", "/object/folder", `{"name":"x"}`), 400, locked)
	if st := env.do("GET", "/status", nil).json(t); st["data"].(map[string]any)["template"].(map[string]any)["status"] != "locked" {
		t.Errorf("status %v", st)
	}

	expect(t, env.do("POST", "/unlock", nil), 400,
		`{"success":false,"message":"Master password is required. Try again in interactive mode or provide a password file or environment variable."}`)
	// the password file/env options are never honoured through serve
	t.Setenv("SERVE_TEST_PW", testPassword)
	for _, q := range []string{"passwordEnv", "passwordenv"} {
		if r := env.do("POST", "/unlock?"+q+"=SERVE_TEST_PW", nil); r.status != 400 {
			t.Errorf("%s: %d %s", q, r.status, r.body)
		}
	}
	expect(t, env.doJSON("POST", "/unlock", `{"password":"wrong"}`), 400, `{"success":false,"message":"Invalid master password."}`)

	r := env.doJSON("POST", "/unlock", `{"password":"`+testPassword+`"}`)
	if r.status != 200 {
		t.Fatalf("unlock: %d %s", r.status, r.body)
	}
	msg := r.json(t)["data"].(map[string]any)
	session := os.Getenv("BW_SESSION")
	if session == "" || msg["raw"] != session || msg["title"] != "Your vault is now unlocked!" ||
		!strings.Contains(msg["message"].(string), `$ export BW_SESSION="`+session+`"`) {
		t.Fatalf("unlock message %v (session %q)", msg, session)
	}

	// the session is kept for subsequent requests
	r = env.do("GET", "/list/object/items", nil)
	if r.status != 200 || !strings.Contains(r.body, `"name":"Google"`) {
		t.Fatalf("list after unlock: %d %s", r.status, r.body)
	}
	// a failed unlock does not lock an unlocked vault
	expect(t, env.doJSON("POST", "/unlock", `{"password":"wrong"}`), 400, `{"success":false,"message":"Invalid master password."}`)
	if os.Getenv("BW_SESSION") != session || !env.a.IsUnlocked() {
		t.Error("failed unlock locked the vault")
	}

	// urlencoded bodies are parsed too (koa-bodyparser form support)
	env.do("POST", "/lock", nil)
	r = env.do("POST", "/unlock", strings.NewReader("password="+testPassword), header("Content-Type", "application/x-www-form-urlencoded"))
	if r.status != 200 || !env.a.IsUnlocked() {
		t.Fatalf("form unlock: %d %s", r.status, r.body)
	}
}

func TestNotLoggedIn(t *testing.T) {
	env := newEnv(t)
	if err := env.a.Logout(); err != nil {
		t.Fatal(err)
	}
	expect(t, env.do("GET", "/list/object/items", nil), 400, `{"success":false,"message":"You are not logged in."}`)
	expect(t, env.do("POST", "/unlock", strings.NewReader(`{"password":"x"}`)), 400, `{"success":false,"message":"No active account found"}`)
}

func TestListAndGet(t *testing.T) {
	env := newEnv(t)
	env.addCipher(loginItem(itemID, "Google", "secret"))
	other := loginItem("22222222-0000-0000-0000-000000000002", "GitHub", "gh")
	env.addCipher(other)
	env.addFolder(folderID, "Work")

	r := env.do("GET", "/list/object/items?search=goo", nil)
	m := r.json(t)
	items := m["data"].(map[string]any)["data"].([]any)
	if r.status != 200 || m["data"].(map[string]any)["object"] != "list" || len(items) != 1 ||
		items[0].(map[string]any)["name"] != "Google" {
		t.Fatalf("list items: %d %s", r.status, r.body)
	}
	r = env.do("GET", "/list/object/folders", nil)
	if r.status != 200 || !strings.Contains(r.body, `{"name":"Work","object":"folder","id":"`+folderID+`"}`) {
		t.Errorf("list folders: %s", r.body)
	}
	expect(t, env.do("GET", "/list/object/things", nil), 400, `{"success":false,"message":"Unknown object."}`)
	expect(t, env.do("GET", "/list/object/send", nil), 200, `{"success":true,"data":{"object":"list","data":[]}}`)
	expect(t, env.do("GET", "/send/list", nil), 200, `{"success":true,"data":{"object":"list","data":[]}}`)

	r = env.do("GET", "/object/item/"+strings.ToUpper(itemID), nil)
	m = r.json(t)
	if r.status != 200 || m["data"].(map[string]any)["id"] != itemID || m["data"].(map[string]any)["object"] != "item" {
		t.Fatalf("get item: %d %s", r.status, r.body)
	}
	expect(t, env.do("GET", "/object/password/"+itemID, nil), 200, `{"success":true,"data":{"object":"string","data":"secret"}}`)
	expect(t, env.do("GET", "/object/item/nope", nil), 400, `{"success":false,"message":"Not found."}`)
	expect(t, env.do("GET", "/object/send/nope", nil), 400, "{\"success\":false,\"message\":\"`nope` is not a GUID.\"}")

	// koa-router: case-insensitive paths, optional trailing slash, decoded parameters
	if r := env.do("GET", "/OBJECT/Password/"+itemID+"/", nil); r.status != 200 {
		t.Errorf("router normalisation: %d %s", r.status, r.body)
	}
	if r := env.do("GET", "/list/object/item%73", nil); r.status != 200 {
		t.Errorf("decoded param: %d %s", r.status, r.body)
	}
}

func TestCreateEditDeleteItem(t *testing.T) {
	env := newEnv(t)
	const newID = "44444444-0000-0000-0000-000000000001"
	env.api.on("POST", "/api/ciphers", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, serverCipher(body, newID))
	})
	req := `{"type":1,"name":"Google","notes":"n","favorite":true,"fields":[],` +
		`"login":{"uris":[{"uri":"https://google.com","match":null}],"username":"jdoe","password":"secret","totp":null}}`
	r := env.doJSON("POST", "/object/item", req)
	m := r.json(t)
	data, _ := m["data"].(map[string]any)
	if r.status != 200 || data["id"] != newID || data["name"] != "Google" {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	if sv := env.storedView(newID); sv.Name != "Google" || *sv.Login.Password != "secret" {
		t.Errorf("stored %+v", sv)
	}

	env.api.on("PUT", "/api/ciphers/"+newID, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, serverCipher(body, newID))
	})
	edit := strings.Replace(req, `"name":"Google"`, `"name":"Renamed"`, 1)
	r = env.doJSON("PUT", "/object/item/"+newID, edit)
	if r.status != 200 || r.json(t)["data"].(map[string]any)["name"] != "Renamed" {
		t.Fatalf("edit: %d %s", r.status, r.body)
	}
	if sv := env.storedView(newID); sv.Name != "Renamed" {
		t.Errorf("stored after edit %+v", sv)
	}

	env.api.on("PUT", "/api/ciphers/"+newID+"/delete", func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	expect(t, env.do("DELETE", "/object/item/"+newID, nil), 200, `{"success":true}`)
	if !env.storedView(newID).IsDeleted() {
		t.Error("item not soft deleted")
	}
	env.api.on("PUT", "/api/ciphers/"+newID+"/restore", func(w http.ResponseWriter, r *http.Request, body []byte) {
		io.WriteString(w, `{"revisionDate":"`+serverRev+`"}`)
	})
	expect(t, env.do("POST", "/restore/item/"+newID, nil), 200, `{"success":true}`)
	if env.storedView(newID).IsDeleted() {
		t.Error("item not restored")
	}
	env.api.on("DELETE", "/api/ciphers/"+newID, func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	expect(t, env.do("DELETE", "/object/item/"+newID+"?permanent", nil), 200, `{"success":true}`)
	expect(t, env.do("DELETE", "/object/item/"+newID, nil), 400, `{"success":false,"message":"Not found."}`)
}

func TestFolderAndSendBodies(t *testing.T) {
	env := newEnv(t)
	env.api.on("POST", "/api/folders", func(w http.ResponseWriter, r *http.Request, body []byte) {
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		writeJSON(w, map[string]any{"id": folderID, "name": m["name"], "revisionDate": serverRev})
	})
	expect(t, env.doJSON("POST", "/object/folder", `{"name":"Work"}`), 200,
		`{"success":true,"data":{"name":"Work","object":"folder","id":"`+folderID+`"}}`)

	// sends: the body is the request object; file sends are refused through serve
	expect(t, env.doJSON("POST", "/object/send", `{}`), 400,
		`{"success":false,"message":"Must specify a valid deletion date after the current time"}`)
	expect(t, env.doJSON("POST", "/object/send", `{"type":1,"deletionDate":"2999-01-01T00:00:00Z","file":{"fileName":"/etc/passwd"}}`), 400,
		"{\"success\":false,\"message\":\"Creating a file-based Send is unsupported through the `serve` command at this time.\"}")

	// POST /object/attachment never reads a local file
	expect(t, env.do("POST", "/object/attachment", nil), 400, "{\"success\":false,\"message\":\"`itemid` option is required.\"}")
	expect(t, env.do("POST", "/object/attachment?itemid="+itemID+"&file=/etc/passwd", nil), 500, "Internal Server Error")
}

func TestGenerate(t *testing.T) {
	env := newEnv(t)
	r := env.do("GET", "/generate?length=20&uppercase&number", nil)
	m := r.json(t)
	pw, _ := m["data"].(map[string]any)["data"].(string)
	if r.status != 200 || len(pw) != 20 || strings.ToUpper(pw) != pw {
		t.Fatalf("generate: %d %s", r.status, r.body)
	}
	r = env.do("GET", "/generate?passphrase&words=4&separator=_", nil)
	pp, _ := r.json(t)["data"].(map[string]any)["data"].(string)
	if r.status != 200 || len(strings.Split(pp, "_")) != 4 {
		t.Fatalf("passphrase: %d %s", r.status, r.body)
	}
	// generate does not require an unlocked vault
	env.do("POST", "/lock", nil)
	if r := env.do("GET", "/generate", nil); r.status != 200 {
		t.Errorf("generate while locked: %d %s", r.status, r.body)
	}
}

func multipartBody(t *testing.T, field, fileName string, data []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("note", "ignored")
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="`+field+`"; filename="`+fileName+`"`)
	h.Set("Content-Type", "text/plain")
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	pw.Write(data)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestAttachmentUpload(t *testing.T) {
	env := newEnv(t)
	env.addCipher(loginItem(itemID, "With file", "x"))

	var uploaded []byte
	var meta map[string]any
	env.api.on("POST", "/api/ciphers/"+itemID+"/attachment/v2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		_ = json.Unmarshal(body, &meta)
		var c map[string]any
		_ = json.Unmarshal(env.cipherJSON(itemID), &c)
		c["revisionDate"] = serverRev
		c["attachments"] = []any{map[string]any{"id": "att1", "fileName": meta["fileName"], "key": meta["key"],
			"size": "5", "sizeName": "5 Bytes", "url": "https://files/att1"}}
		writeJSON(w, map[string]any{"attachmentId": "att1", "fileUploadType": 0, "cipherResponse": c, "cipherMiniResponse": nil})
	})
	env.api.on("POST", "/api/ciphers/"+itemID+"/attachment/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		part, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).NextPart()
		if err != nil {
			t.Fatal(err)
		}
		uploaded, _ = io.ReadAll(part)
		w.WriteHeader(200)
	})

	body, ct := multipartBody(t, "file", "/docs/notes.txt", []byte("hello"))
	r := env.do("POST", "/attachment?itemid="+itemID, body, header("Content-Type", ct))
	if r.status != 200 {
		t.Fatalf("upload: %d %s", r.status, r.body)
	}
	out := r.json(t)["data"].(map[string]any)
	atts, _ := out["attachments"].([]any)
	if len(atts) != 1 || atts[0].(map[string]any)["fileName"] != "notes.txt" {
		t.Errorf("response %s", r.body)
	}
	v, err := vault.Load(env.a)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := v.EncryptedCipher(itemID)
	cipherKey, err := env.keys.CipherKey(c)
	if err != nil {
		t.Fatal(err)
	}
	attKey, err := crypto.DecryptToKey(meta["key"].(string), cipherKey)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := crypto.DecryptBytes(uploaded, attKey); err != nil || string(plain) != "hello" {
		t.Fatalf("uploaded file decrypts to %q (%v)", plain, err)
	}
	if name, _ := crypto.DecryptString(meta["fileName"].(string), cipherKey); name != "notes.txt" {
		t.Errorf("file name %q", name)
	}

	// option errors come from the create command
	body, ct = multipartBody(t, "file", "a.txt", []byte("x"))
	expect(t, env.do("POST", "/attachment", body, header("Content-Type", ct)), 400,
		"{\"success\":false,\"message\":\"`itemid` option is required.\"}")
	// no file / unexpected file field: koa answers 500 like upstream (TypeError / MulterError)
	expect(t, env.do("POST", "/attachment?itemid="+itemID, nil), 500, "Internal Server Error")
	body, ct = multipartBody(t, "upload", "a.txt", []byte("x"))
	expect(t, env.do("POST", "/attachment?itemid="+itemID, body, header("Content-Type", ct)), 500, "Internal Server Error")
	// locked vault
	env.do("POST", "/lock", nil)
	body, ct = multipartBody(t, "file", "a.txt", []byte("x"))
	expect(t, env.do("POST", "/attachment?itemid="+itemID, body, header("Content-Type", ct)), 400,
		`{"success":false,"message":"Vault is locked."}`)
}

func (env *testEnv) cipherJSON(id string) []byte {
	d, err := env.a.Data()
	if err != nil {
		env.t.Fatal(err)
	}
	return d.Active().Vault.Ciphers[id]
}

func TestRoutingAndBodyErrors(t *testing.T) {
	env := newEnv(t)
	expect(t, env.do("GET", "/nope", nil), 404, "Not Found")

	r := env.do("DELETE", "/status", nil)
	expect(t, r, 405, "Method Not Allowed")
	if r.header.Get("Allow") != "HEAD, GET" {
		t.Errorf("Allow %q", r.header.Get("Allow"))
	}
	r = env.do("OPTIONS", "/object/item/x", nil)
	expect(t, r, 200, "")
	if r.header.Get("Allow") != "PUT, HEAD, GET, DELETE" {
		t.Errorf("Allow %q", r.header.Get("Allow"))
	}
	expect(t, env.do("PROPFIND", "/status", nil), 501, "Not Implemented")

	expect(t, env.doJSON("POST", "/object/item", `"string"`), 400, "invalid JSON, only supports object and array")
	if r := env.doJSON("POST", "/object/item", `{"name":`); r.status != 400 || r.header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("invalid JSON: %d %q", r.status, r.body)
	}
	big := `{"name":"` + strings.Repeat("a", jsonLimit) + `"}`
	expect(t, env.doJSON("POST", "/object/item", big), 413, "request entity too large")
	// non JSON content types leave the body empty ({}), like koa-bodyparser
	r = env.do("POST", "/move/"+itemID+"/"+itemID, strings.NewReader(`["x"]`), header("Content-Type", "text/plain"))
	if r.status != 400 || !strings.Contains(r.body, `"success":false`) {
		t.Errorf("text body: %d %s", r.status, r.body)
	}
}

func TestProcessResponseFile(t *testing.T) {
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/object/attachment/x", nil)
	processResponse(rec, req, cli.Success(cli.NewFile([]byte("abc"), "résumé \"v1\".pdf")))
	if rec.Code != 200 || rec.Body.String() != "abc" || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		rec.Header().Get("Content-Length") != "3" {
		t.Fatalf("file response %d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	want := `attachment; filename="résumé \"v1\".pdf"`
	if got := rec.Header().Get("Content-Disposition"); got != want {
		t.Errorf("disposition %q, want %q", got, want)
	}
	for name, want := range map[string]string{
		"plain.txt":    `attachment; filename="plain.txt"`,
		"dir/€uro.txt": `attachment; filename="?uro.txt"; filename*=UTF-8''%E2%82%ACuro.txt`,
		"100%25.txt":   `attachment; filename="100%25.txt"; filename*=UTF-8''100%2525.txt`,
		"":             `attachment; filename*=UTF-8''`,
	} {
		if got := contentDisposition(name); got != want {
			t.Errorf("contentDisposition(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestOptionParsing(t *testing.T) {
	if jsNumber("0x50") != 80 || jsNumber(" 8080 ") != 8080 || jsNumber("") != 0 || jsNumber("80a") == jsNumber("80a") {
		t.Error("jsNumber")
	}
	if n, ok := parseIntJS("3abc"); !ok || n != 3 {
		t.Error("parseIntJS 3abc")
	}
	if _, ok := parseIntJS("abc"); ok {
		t.Error("parseIntJS abc")
	}
	cmd := newServeCommand(nil)
	for _, f := range []string{"hostname", "port", "disable-origin-protection"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("flag %s missing", f)
		}
	}
}
