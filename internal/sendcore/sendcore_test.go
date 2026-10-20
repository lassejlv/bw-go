package sendcore

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

func mustKey(t *testing.T, b64 string) *crypto.SymmetricKey {
	t.Helper()
	k, err := crypto.KeyFromB64(b64)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func strp(s string) *string { return &s }

// Vector from bitwarden-send send.rs test_get_send_key.
func TestSendKeyDerivation(t *testing.T) {
	userKey := mustKey(t, "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==")
	seed, err := UnwrapSeed("2.+1KUfOX8A83Xkwk1bumo/w==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=", userKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := MakeSendKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := k.B64(), "IR9ImHGm6rRuIjiN7csj94bcZR5WYTJj5GtNfx33zm6tJCHUl+QZlpNPba8g2yn70KnOHsAODLcR0um6E3MAlg=="; got != want {
		t.Fatalf("send key = %s, want %s", got, want)
	}
}

// Vector from bitwarden-send send.rs test_create_password.
func TestHashPassword(t *testing.T) {
	seed, err := FromURLB64("Pgui0FK85cNhBGWHAlBHBw")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := HashPassword("abc123", seed), "vTIDfdj3FTDbejmMf+mJWpYdMXsxfeSd1Sma3sjCtiQ="; got != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
}

const decryptUserKey = "bYCsk857hl8QJJtxyRK65tjUrbxKC4aDifJpsml+NIv4W9cVgFvi3qVD+yJTUU2T4UwNKWYtt9pqWf7Q+2WCCg=="

// Vector from bitwarden-send send.rs test_decrypt, as camelCase server JSON.
const vectorSendJSON = `{
  "id": "3d80dd72-2d14-4f26-812c-b0f0018aa144",
  "accessId": "ct2APRQtJk-BLLDwAYqhRA",
  "type": 0,
  "name": "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=",
  "notes": null,
  "file": null,
  "text": {"text": "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=", "hidden": false},
  "key": "2.KLv/j0V4Ebs0dwyPdtt4vw==|jcrFuNYN1Qb3onBlwvtxUV/KpdnR1LPRL4EsCoXNAt4=|gHSywGy4Rj/RsCIZFwze4s2AACYKBtqDXTrQXjkgtIE=",
  "maxAccessCount": null,
  "accessCount": 0,
  "password": null,
  "disabled": false,
  "revisionDate": "2024-01-07T23:56:48.207363Z",
  "expirationDate": null,
  "deletionDate": "2024-01-14T23:56:48Z",
  "hideEmail": false,
  "emails": null,
  "authType": 2,
  "object": "send"
}`

func TestDecryptVector(t *testing.T) {
	var d Data
	if err := json.Unmarshal([]byte(vectorSendJSON), &d); err != nil {
		t.Fatal(err)
	}
	v, err := Decrypt(&d, mustKey(t, decryptUserKey))
	if err != nil {
		t.Fatal(err)
	}
	if v.Name == nil || *v.Name != "Test" {
		t.Fatalf("name = %v", v.Name)
	}
	if v.Text == nil || v.Text.Text == nil || *v.Text.Text != "This is a test" {
		t.Fatalf("text = %+v", v.Text)
	}
	if v.URLB64Key() != "Pgui0FK85cNhBGWHAlBHBw" {
		t.Fatalf("url key = %s", v.URLB64Key())
	}
	if len(v.Emails) != 0 || v.Emails == nil {
		t.Fatalf("emails = %#v", v.Emails)
	}
	if v.DeletionDate == nil || v.DeletionDate.UTC().Format("2006-01-02T15:04:05Z") != "2024-01-14T23:56:48Z" {
		t.Fatalf("deletion = %v", v.DeletionDate)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	userKey := crypto.GenerateKey()
	name, notes, text := "My send", "some notes", "secret text"
	v := &View{Type: TypeText, Name: &name, Notes: &notes, Text: &TextView{Text: &text, Hidden: true},
		Emails: []string{" A@Example.com", "b@example.com "}}
	pw := "hunter2"
	req, encFile, err := Encrypt(v, nil, &pw, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if encFile != nil || req.FileLength != nil {
		t.Fatal("unexpected file data for a text send")
	}
	if len(v.Key) != SeedLength {
		t.Fatalf("seed length %d", len(v.Key))
	}
	if req.Emails == nil || *req.Emails != "a@example.com,b@example.com" || req.Password != nil {
		t.Fatalf("emails/password = %v / %v", req.Emails, req.Password)
	}
	// Server echoes the request back as a Send.
	d := &Data{ID: "id", AccessID: "acc", Type: req.Type, Name: req.Name, Notes: req.Notes, Key: req.Key,
		Text: &TextData{Text: req.Text.Text, Hidden: req.Text.Hidden}, Emails: req.Emails}
	got, err := Decrypt(d, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if *got.Name != name || *got.Notes != notes || *got.Text.Text != text || !got.Text.Hidden {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if string(got.Key) != string(v.Key) || got.CryptoKey.B64() != v.CryptoKey.B64() {
		t.Fatal("seed/key mismatch")
	}
	if len(got.Emails) != 2 || got.Emails[0] != "a@example.com" {
		t.Fatalf("emails = %v", got.Emails)
	}

	// Password without emails is hashed with the seed.
	v2 := &View{Type: TypeText, Name: &name, Text: &TextView{Text: &text}}
	req2, _, err := Encrypt(v2, nil, &pw, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if req2.Password == nil || *req2.Password != HashPassword(pw, v2.Key) || req2.Emails != nil {
		t.Fatalf("password = %v", req2.Password)
	}
}

func TestEncryptFileAndAccessDecrypt(t *testing.T) {
	userKey := crypto.GenerateKey()
	name, fname := "file send", "photo.jpg"
	content := []byte("binary\x00content")
	v := &View{Type: TypeFile, Name: &name, File: &FileView{FileName: &fname}}
	req, encFile, err := Encrypt(v, content, nil, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if req.FileLength == nil || *req.FileLength != len(encFile) || req.Password != nil {
		t.Fatalf("fileLength = %v", req.FileLength)
	}
	b, _ := json.Marshal(req)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["password"]; ok {
		t.Fatal("password must be omitted when unset")
	}
	if _, ok := m["text"]; ok {
		t.Fatal("text must be omitted for file sends")
	}

	// Recipient side: only the seed from the link is known.
	fid := "fileid"
	ad := &AccessData{ID: "acc", Type: TypeFile, Name: req.Name, File: &FileData{ID: &fid, FileName: req.File.FileName}}
	av, key, err := DecryptAccess(ad, v.Key)
	if err != nil {
		t.Fatal(err)
	}
	if *av.Name != name || *av.File.FileName != fname {
		t.Fatalf("access view = %+v", av)
	}
	plain, err := crypto.DecryptBytes(encFile, key)
	if err != nil || string(plain) != string(content) {
		t.Fatalf("file decrypt: %v %q", err, plain)
	}

	// Wrong seed: fields become the decrypt error placeholder.
	av2, _, err := DecryptAccess(ad, NewSeed())
	if err != nil || *av2.Name != DecryptError {
		t.Fatalf("lenient decrypt: %v %v", err, av2.Name)
	}
}

func TestItemSendsAreIsolated(t *testing.T) {
	d := &Data{ID: "x", Type: TypeItem, Key: strp("")}
	if _, err := Decrypt(d, crypto.GenerateKey()); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := DecryptAccess(&AccessData{Type: TypeItem}, NewSeed()); err != ErrItemSendUnsupported {
		t.Fatalf("err = %v", err)
	}
}

func TestURLParsing(t *testing.T) {
	cases := []struct{ url, id, key, origin string }{
		{"https://vault.bitwarden.com/#/send/rg3iuoS_Akm2gqy6ADRHmg/Ht7dYjsqjmgqUM3rjzZDSQ", "rg3iuoS_Akm2gqy6ADRHmg", "Ht7dYjsqjmgqUM3rjzZDSQ", "https://vault.bitwarden.com"},
		{"https://send.bitwarden.com/#ct2APRQtJk-BLLDwAYqhRA/Pgui0FK85cNhBGWHAlBHBw", "ct2APRQtJk-BLLDwAYqhRA", "Pgui0FK85cNhBGWHAlBHBw", "https://send.bitwarden.com"},
		{"https://Example.COM:443/vault/#/send/a/b", "a", "b", "https://example.com"},
		{"http://localhost:8080/#/send/a", "send", "a", "http://localhost:8080"}, // last two segments, like upstream
		{"https://send.bitwarden.com/#onlyid", "onlyid", "", "https://send.bitwarden.com"},
		{"https://example.com/", "", "", "https://example.com"},
	}
	for _, c := range cases {
		u, err := ParseURL(c.url)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		id, key := IDAndKey(u)
		if id != c.id || key != c.key {
			t.Fatalf("%s: got %q %q", c.url, id, key)
		}
		if o := Origin(u); o != c.origin {
			t.Fatalf("%s: origin %q", c.url, o)
		}
	}
	if _, err := ParseURL("not a url"); err == nil {
		t.Fatal("expected parse failure")
	}
	if _, err := FromURLB64("abcde"); err == nil {
		t.Fatal("expected illegal base64url error")
	}
	seed := []byte{0xfb, 0xff, 0xfe, 1, 2}
	if got := AccessURL("https://send.bitwarden.com/#", "acc", seed); got != "https://send.bitwarden.com/#acc/-__-AQI" {
		t.Fatalf("access url = %s", got)
	}
	back, err := FromURLB64("-__-AQI")
	if err != nil || string(back) != string(seed) {
		t.Fatal("url b64 round trip failed")
	}
}

func TestResolveServer(t *testing.T) {
	us := state.Environment{}
	urls := api.Resolve(us)
	parse := func(s string) Server {
		u, err := ParseURL(s)
		if err != nil {
			t.Fatal(err)
		}
		return ResolveServer(u, us, urls)
	}
	s := parse("https://send.bitwarden.com/#a/b")
	if !s.Trusted || !s.IsConfiguredServer || s.APIURL != "https://api.bitwarden.com" {
		t.Fatalf("us: %+v", s)
	}
	s = parse("https://vault.bitwarden.eu/#/send/a/b")
	if !s.Trusted || s.IsConfiguredServer || s.IdentityURL != "https://identity.bitwarden.eu" {
		t.Fatalf("eu: %+v", s)
	}
	s = parse("https://send.bitwarden.com.example.test/#a/b")
	if s.Trusted || s.APIURL != "https://send.bitwarden.com.example.test/api" {
		t.Fatalf("lookalike: %+v", s)
	}
	self := state.Environment{Base: "https://bw.example.com"}
	u, _ := ParseURL("https://bw.example.com/#/send/a/b")
	s = ResolveServer(u, self, api.Resolve(self))
	if !s.Trusted || !s.IsConfiguredServer || s.APIURL != "https://bw.example.com/api" {
		t.Fatalf("self-hosted: %+v", s)
	}
}

func TestUnsafeURL(t *testing.T) {
	cases := map[string]string{
		"https://bitwarden-send.blob.core.windows.net/x?sig=1": "",
		"http://example.com/x":                                 "scheme",
		"https://127.0.0.1/x":                                  "host",
		"https://169.254.169.254/latest":                       "host",
		"https://[::1]/x":                                      "host",
		"https://[::ffff:10.0.0.1]/x":                          "host",
		"https://foo.localhost/x":                              "host",
		"https://api.bitwarden.com/sends/x":                    "",
		"https://[fe80::1]/x":                                  "host",
		"https://172.32.0.1/x":                                 "",
	}
	for u, want := range cases {
		r := UnsafeURL(u, "")
		got := ""
		if r != nil {
			got = r.Code
		}
		if got != want {
			t.Errorf("%s: got %q want %q", u, got, want)
		}
	}
	if UnsafeURL("http://192.168.1.2:8080/attachments/x", "http://192.168.1.2:8080/api") != nil {
		t.Error("trusted origin must be exempt")
	}
}

func TestDataDecodesPascalCase(t *testing.T) {
	raw := `{"Id":"x","AccessId":"y","Type":1,"File":{"Id":"f","FileName":"2.a|b|c","Size":"1234","SizeName":"1.2 KB"},"AccessCount":3,"Disabled":true}`
	var d Data
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	if d.ID != "x" || d.File == nil || string(d.File.Size) != `"1234"` || !d.Disabled || d.AccessCount != 3 {
		t.Fatalf("%+v", d)
	}
	_ = base64.StdEncoding
}
