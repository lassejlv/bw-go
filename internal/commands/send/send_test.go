package send

import (
	"bytes"
	"encoding/base64"
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
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/sendcore"
	"github.com/lassejlv/bw-go/internal/state"
)

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }

func TestSendResponseJSONShape(t *testing.T) {
	rev := time.Date(2024, 1, 7, 23, 56, 48, 207363000, time.UTC)
	del := time.Date(2024, 1, 14, 23, 56, 48, 0, time.UTC)
	f := false
	v := &sendcore.View{
		ID: "3d80dd72-2d14-4f26-812c-b0f0018aa144", AccessID: "ct2APRQtJk-BLLDwAYqhRA",
		Name: sp("Test"), Key: mustURLB64(t, "Pgui0FK85cNhBGWHAlBHBw"), Type: sendcore.TypeText,
		Text: &sendcore.TextView{Text: sp("This is a test")}, RevisionDate: &rev, DeletionDate: &del,
		Disabled: &f, HideEmail: &f, AuthType: ip(2), Emails: []string{},
	}
	got := cli.MarshalJSON(NewSendResponse(v, "https://send.bitwarden.com/#"), false)
	want := `{"object":"send","id":"3d80dd72-2d14-4f26-812c-b0f0018aa144","accessId":"ct2APRQtJk-BLLDwAYqhRA",` +
		`"accessUrl":"https://send.bitwarden.com/#ct2APRQtJk-BLLDwAYqhRA/Pgui0FK85cNhBGWHAlBHBw","name":"Test",` +
		`"notes":null,"key":"Pgui0FK85cNhBGWHAlBHBw==","type":0,"maxAccessCount":null,"accessCount":0,` +
		`"revisionDate":"2024-01-07T23:56:48.207Z","deletionDate":"2024-01-14T23:56:48.000Z","expirationDate":null,` +
		`"passwordSet":false,"emails":[],"disabled":false,"hideEmail":false,"authType":2,` +
		`"text":{"text":"This is a test","hidden":false}}`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}

	fv := &sendcore.View{ID: "i", AccessID: "a", Key: []byte{1}, Type: sendcore.TypeFile, Password: sp("hash"),
		File: &sendcore.FileView{ID: sp("f"), Size: json.RawMessage(`"10"`), SizeName: sp("10 Bytes"), FileName: sp("x.txt")},
		Text: &sendcore.TextView{}}
	got = cli.MarshalJSON(NewSendResponse(fv, "https://vault.example.com/#/send/"), false)
	if !strings.Contains(got, `"passwordSet":true`) || strings.Contains(got, `"text"`) ||
		!strings.HasSuffix(got, `"file":{"id":"f","size":"10","sizeName":"10 Bytes","fileName":"x.txt"}}`) ||
		strings.Contains(got, `"authType"`) || !strings.Contains(got, `"accessUrl":"https://vault.example.com/#/send/a/AQ"`) {
		t.Fatalf("file send json: %s", got)
	}

	av := &sendcore.AccessView{ID: "acc", Name: sp("n"), Type: sendcore.TypeText, Text: &sendcore.TextView{Text: sp("t"), Hidden: true}}
	if got := cli.MarshalJSON(NewSendAccessResponse(av), false); got != `{"object":"send-access","id":"acc","name":"n","type":0,"text":{"text":"t","hidden":true}}` {
		t.Fatalf("access json: %s", got)
	}
}

func mustURLB64(t *testing.T, s string) []byte {
	b, err := sendcore.FromURLB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTemplate(t *testing.T) {
	r := Template("file")
	got := cli.MarshalJSON(r.Data.(*cli.TemplateResponse).Template, false)
	if !strings.HasPrefix(got, `{"object":"send","name":"Send name","notes":"Some notes about this send.","type":1,"text":null,"file":{"fileName":"file attachment location"},"maxAccessCount":null,"deletionDate":"`) ||
		!strings.HasSuffix(got, `","expirationDate":null,"password":null,"emails":null,"disabled":false,"hideEmail":false}`) {
		t.Fatalf("template: %s", got)
	}
	if r := Template("nope"); r.Success || r.MessageText() != "Unknown template object." {
		t.Fatal("expected bad request")
	}
}

func TestParseEmail(t *testing.T) {
	ok := []struct {
		in   string
		want []string
	}{
		{"user@example.com", []string{"user@example.com"}},
		{`["a@b.com","c@d.com"]`, []string{"a@b.com", "c@d.com"}},
		{"a@b.com, c@d.com", []string{"a@b.com", "c@d.com"}},
		{"a@b.com c@d.com", []string{"a@b.com", "c@d.com"}},
	}
	for _, c := range ok {
		got, err := ParseEmail(c.in, nil)
		if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: %v %v", c.in, got, err)
		}
	}
	prev, _ := ParseEmail("x@y.z", nil)
	if got, _ := ParseEmail("a@b.c", prev); len(got) != 2 {
		t.Error("previous input must be kept")
	}
	bad := map[string]string{
		"[bad":         "Invalid JSON format for email list",
		`["a@b.com"`:   "Invalid JSON format for email list",
		"a@b.com, bad": "Invalid email address: bad",
		"nope":         "`input` must be a single address, a comma-separated list, or a JSON array",
	}
	for in, msg := range bad {
		if _, err := ParseEmail(in, nil); err == nil || err.Error() != msg {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestMakeSendJSON(t *testing.T) {
	enc, r := MakeSendJSON("hello", QuickOptions{DeleteInDays: "7", Hidden: true})
	if r != nil {
		t.Fatal(r.MessageText())
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["notes"]; ok {
		t.Error("notes must be omitted when not given")
	}
	if _, ok := m["emails"]; ok {
		t.Error("emails must be omitted when not given")
	}
	if m["text"].(map[string]any)["hidden"] != true || m["file"] != nil || !IsGUID(m["name"].(string)) {
		t.Errorf("unexpected template: %s", raw)
	}
	enc, _ = MakeSendJSON("hello", QuickOptions{DeleteInDays: "abc", Name: sp("n"), Emails: []string{"a@b.c"}})
	raw, _ = base64.StdEncoding.DecodeString(enc)
	_ = json.Unmarshal(raw, &m)
	if m["deletionDate"] != nil || m["name"] != "n" {
		t.Errorf("unexpected template: %s", raw)
	}
	if _, r := MakeSendJSON("/does/not/exist", QuickOptions{File: true}); r == nil || r.MessageText() != "data path does not exist" {
		t.Error("expected missing path error")
	}
}

// ---------- end to end against a fake server ----------

type fakeServer struct {
	mu      sync.Mutex
	sends   map[string]map[string]any
	seq     int
	srv     *httptest.Server
	lastReq map[string]any
	upload  []byte
}

func (f *fakeServer) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	toSend := func(id string, req map[string]any) map[string]any {
		s := map[string]any{"object": "send", "id": id, "accessId": "acc-" + id, "accessCount": 0,
			"revisionDate": "2026-01-01T00:00:00Z"}
		for k, v := range req {
			s[k] = v
		}
		if f, ok := s["file"].(map[string]any); ok {
			f["id"] = "file-" + id
			f["size"] = "5"
			f["sizeName"] = "5 Bytes"
		}
		delete(s, "fileLength")
		return s
	}
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/api/sends":
		f.lastReq = nil
		_ = json.Unmarshal(body, &f.lastReq)
		f.seq++
		id := "0a0a0a0a-0000-0000-0000-00000000000" + string(rune('0'+f.seq))
		f.sends[id] = toSend(id, f.lastReq)
		writeJSON(f.sends[id])
	case r.Method == "POST" && p == "/api/sends/file/v2":
		f.lastReq = nil
		_ = json.Unmarshal(body, &f.lastReq)
		f.seq++
		id := "0b0b0b0b-0000-0000-0000-00000000000" + string(rune('0'+f.seq))
		f.sends[id] = toSend(id, f.lastReq)
		writeJSON(map[string]any{"fileUploadType": 0, "sendResponse": f.sends[id], "url": ""})
	case r.Method == "POST" && strings.HasPrefix(p, "/api/sends/") && strings.Contains(p, "/file/") && !strings.HasPrefix(p, "/api/sends/access/"):
		mr, err := r.MultipartReader()
		if err != nil {
			w.WriteHeader(400)
			return
		}
		part, _ := mr.NextPart()
		f.upload, _ = io.ReadAll(part)
	case r.Method == "PUT" && strings.HasSuffix(p, "/remove-password"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/sends/"), "/remove-password")
		f.sends[id]["password"] = nil
		writeJSON(f.sends[id])
	case r.Method == "PUT" && strings.HasPrefix(p, "/api/sends/"):
		id := strings.TrimPrefix(p, "/api/sends/")
		f.lastReq = nil
		_ = json.Unmarshal(body, &f.lastReq)
		s := toSend(id, f.lastReq)
		f.sends[id] = s
		writeJSON(s)
	case r.Method == "DELETE" && strings.HasPrefix(p, "/api/sends/"):
		delete(f.sends, strings.TrimPrefix(p, "/api/sends/"))
	case r.Method == "POST" && p == "/identity/connect/token":
		r.Form, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") != "send_access" || r.Form.Get("scope") != "api.send.access" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		for _, s := range f.sends {
			if s["accessId"] == r.Form.Get("send_id") {
				if pw, _ := s["password"].(string); pw != "" && r.Form.Get("password_hash_b64") != pw {
					w.WriteHeader(400)
					errType := "password_hash_b64_required"
					code := "invalid_request"
					if r.Form.Get("password_hash_b64") != "" {
						errType, code = "password_hash_b64_invalid", "invalid_grant"
					}
					_, _ = w.Write([]byte(`{"error":"` + code + `","send_access_error_type":"` + errType + `"}`))
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"tok-` + s["accessId"].(string) + `","expires_in":300}`))
				return
			}
		}
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","send_access_error_type":"send_id_invalid"}`))
	case r.Method == "POST" && p == "/api/sends/access":
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
		for _, s := range f.sends {
			if s["accessId"] == tok {
				writeJSON(map[string]any{"id": s["accessId"], "type": s["type"], "name": s["name"], "text": s["text"], "file": s["file"]})
				return
			}
		}
		w.WriteHeader(404)
	case r.Method == "POST" && strings.HasPrefix(p, "/api/sends/access/file/"):
		writeJSON(map[string]any{"id": "x", "url": f.srv.URL + "/download"})
	case r.Method == "GET" && p == "/download":
		_, _ = w.Write(f.upload)
	default:
		w.WriteHeader(404)
	}
}

func setupApp(t *testing.T) (*app.App, *fakeServer, *crypto.SymmetricKey) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", dir)
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_NOINTERACTION", "true")
	t.Setenv("BW_SERVE", "")
	fs := &fakeServer{sends: map[string]map[string]any{}}
	fs.srv = httptest.NewServer(http.HandlerFunc(fs.handler))
	t.Cleanup(fs.srv.Close)
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	userKey := crypto.GenerateKey()
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment = state.Environment{Base: fs.srv.URL}
		d.ActiveUserID = "u1"
		d.Accounts = map[string]*state.Account{"u1": {UserID: "u1", Email: "u@example.com", AccessToken: "token",
			Vault: state.VaultData{Profile: json.RawMessage(`{"premium":true}`)}}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetUserKey(userKey); err != nil {
		t.Fatal(err)
	}
	return a, fs, userKey
}

func encode(v any) string {
	b, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(b)
}

func captureStdout(fn func()) string {
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	defer func() { stdout = old }()
	fn()
	return buf.String()
}

func TestEndToEnd(t *testing.T) {
	a, fs, _ := setupApp(t)

	// bw send "secret" --password pw
	enc, r := MakeSendJSON("secret text", QuickOptions{DeleteInDays: "7"})
	if r != nil {
		t.Fatal(r.MessageText())
	}
	r = Create(a, enc, CreateOptions{Password: sp("pw"), MaxAccessCount: sp("3")})
	if !r.Success {
		t.Fatal(r.MessageText())
	}
	created := r.Data.(*SendResponse)
	if created.Text == nil || *created.Text.Text != "secret text" || !created.PasswordSet ||
		*created.MaxAccessCount != 3 || *created.AuthType != sendcore.AuthPassword {
		t.Fatalf("created: %s", cli.MarshalJSON(created, false))
	}
	if fs.lastReq["password"] == nil || fs.lastReq["fileLength"] != nil {
		t.Fatalf("request: %v", fs.lastReq)
	}
	if !strings.HasPrefix(created.AccessURL, fs.srv.URL+"/#/send/"+created.AccessID+"/") {
		t.Fatalf("access url %s", created.AccessURL)
	}
	if acct := a.ActiveAccount(); len(acct.Vault.Sends) != 1 {
		t.Fatal("send not stored in state")
	}

	// list / get
	r = List(a, "")
	if list := r.Data.(*cli.ListResponse).Data.([]*SendResponse); len(list) != 1 || list[0].ID != created.ID {
		t.Fatal("list mismatch")
	}
	out := captureStdout(func() { r = Get(a, "secret", GetOptions{Text: true}) })
	if !r.Success || out != "secret text" {
		t.Fatalf("get --text: %q %v", out, r.MessageText())
	}
	if r = Get(a, "nothing-matches", GetOptions{}); r.MessageText() != "Not found." {
		t.Fatal("expected not found")
	}

	// receive: password required, wrong password, right password
	r = Receive(a, created.AccessURL, ReceiveOptions{})
	if r.MessageText() != "Password required" {
		t.Fatalf("receive without password: %q", r.MessageText())
	}
	if r = Receive(a, created.AccessURL, ReceiveOptions{Password: "wrong"}); r.MessageText() != "Invalid password" {
		t.Fatalf("receive wrong password: %q", r.MessageText())
	}
	out = captureStdout(func() { r = Receive(a, created.AccessURL, ReceiveOptions{Password: "pw"}) })
	if !r.Success || out != "secret text" {
		t.Fatalf("receive: %q %q", out, r.MessageText())
	}
	r = Receive(a, created.AccessURL, ReceiveOptions{Password: "pw", Obj: true})
	if got := cli.MarshalJSON(r.Data, false); !strings.Contains(got, `"object":"send-access"`) || !strings.Contains(got, `"text":{"text":"secret text","hidden":false}`) {
		t.Fatalf("receive --obj: %s", got)
	}

	// edit name via JSON from get
	get := Get(a, created.ID, GetOptions{}).Data.(*SendResponse)
	var m map[string]any
	_ = json.Unmarshal([]byte(cli.MarshalJSON(get, false)), &m)
	m["name"] = "renamed"
	r = Edit(a, encode(m), EditOptions{})
	if !r.Success || *r.Data.(*SendResponse).Name != "renamed" || r.Data.(*SendResponse).Key != get.Key {
		t.Fatalf("edit: %s %v", r.MessageText(), r.Data)
	}
	m["type"] = 1
	if r = Edit(a, encode(m), EditOptions{}); r.MessageText() != "Cannot change a Send's type" {
		t.Fatalf("edit type: %q", r.MessageText())
	}

	// remove-password, then receive without password
	if r = RemovePassword(a, created.ID); !r.Success || r.Data.(*SendResponse).PasswordSet {
		t.Fatalf("remove-password: %q", r.MessageText())
	}
	out = captureStdout(func() { r = Receive(a, created.AccessURL, ReceiveOptions{}) })
	if out != "secret text" {
		t.Fatalf("receive after remove-password: %q %q", out, r.MessageText())
	}

	// file send + receive to a file
	dir := t.TempDir()
	src := filepath.Join(dir, "hello.txt")
	_ = os.WriteFile(src, []byte("hello"), 0o600)
	enc, _ = MakeSendJSON(src, QuickOptions{File: true, DeleteInDays: "1"})
	r = Create(a, enc, CreateOptions{})
	if !r.Success {
		t.Fatal(r.MessageText())
	}
	fileSend := r.Data.(*SendResponse)
	if fileSend.File == nil || *fileSend.File.FileName != "hello.txt" || len(fs.upload) == 0 {
		t.Fatalf("file send: %s", cli.MarshalJSON(fileSend, false))
	}
	outPath := filepath.Join(dir, "out", "recv.txt")
	r = Receive(a, fileSend.AccessURL, ReceiveOptions{Output: outPath})
	if !r.Success {
		t.Fatal(r.MessageText())
	}
	if b, _ := os.ReadFile(outPath); string(b) != "hello" {
		t.Fatalf("received file content %q", b)
	}

	// delete
	if r = Delete(a, created.ID); !r.Success {
		t.Fatal(r.MessageText())
	}
	if r = Delete(a, created.ID); r.MessageText() != "Not found." {
		t.Fatal("expected not found after delete")
	}
	if r = Receive(a, created.AccessURL, ReceiveOptions{}); r.MessageText() != "Not found." {
		t.Fatalf("receive deleted: %q", r.MessageText())
	}
}

func TestCreateValidation(t *testing.T) {
	a, _, _ := setupApp(t)
	past := map[string]any{"type": 0, "text": map[string]any{"text": "x"}, "deletionDate": "2000-01-01T00:00:00Z"}
	if r := Create(a, encode(past), CreateOptions{}); r.MessageText() != "Must specify a valid deletion date after the current time" {
		t.Fatal(r.MessageText())
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	bad := map[string]any{"type": 0, "text": map[string]any{"text": "x"}, "deletionDate": future, "expirationDate": "garbage"}
	if r := Create(a, encode(bad), CreateOptions{}); r.MessageText() != "Unable to parse expirationDate: Invalid Date" {
		t.Fatal(r.MessageText())
	}
	both := map[string]any{"type": 0, "text": map[string]any{"text": "x"}, "deletionDate": future}
	if r := Create(a, encode(both), CreateOptions{Password: sp("p"), Emails: []string{"a@b.c"}}); r.MessageText() != "--password and --emails are mutually exclusive." {
		t.Fatal(r.MessageText())
	}
	noType := map[string]any{"deletionDate": future}
	if r := Create(a, encode(noType), CreateOptions{}); r.MessageText() != "Unknown Send type undefined. Valid types are: file, text" {
		t.Fatal(r.MessageText())
	}
	noText := map[string]any{"type": 0, "deletionDate": future}
	if r := Create(a, encode(noText), CreateOptions{}); r.MessageText() != "Must specify text content to Send either with the --text option or in the request JSON." {
		t.Fatal(r.MessageText())
	}
	if r := Create(a, "!!!", CreateOptions{}); r.MessageText() != "Error parsing the encoded request data." {
		t.Fatal(r.MessageText())
	}
}
