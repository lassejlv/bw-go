package exporter

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

func TestUnparse(t *testing.T) {
	rows := []csvRow{
		{"plain", nil, 1, csvArray{sp("a"), nil, sp("b")}},
		{"with,comma", `q"uote`, " lead", "trail "},
		{"multi\nline", "cr\rx", "\uFEFFbom", csvArray{}},
		{sp("ptr"), (*string)(nil), 0, ""},
	}
	got := Unparse([]string{"h1", "h 2", "h,3", "h4"}, rows)
	want := "h1,h 2,\"h,3\",h4\r\n" +
		"plain,,1,\"a,,b\"\r\n" +
		"\"with,comma\",\"q\"\"uote\",\" lead\",\"trail \"\r\n" +
		"\"multi\nline\",\"cr\rx\",\"\uFEFFbom\",\r\n" +
		"ptr,,0,"
	if got != want {
		t.Fatalf("unparse\n got %q\nwant %q", got, want)
	}
	if Unparse(IndividualCSVFields, nil) != "" {
		t.Fatal("empty unparse must be empty")
	}
}

func TestGetFileName(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.Local)
	cases := map[[2]string]string{
		{"", "csv"}:               "bitwarden_export_20240102030405.csv",
		{"", "json"}:              "bitwarden_export_20240102030405.json",
		{"", "zip"}:               "bitwarden_export_20240102030405.zip",
		{"", "encrypted_json"}:    "bitwarden_encrypted_export_20240102030405.json",
		{"org", "csv"}:            "bitwarden_org_export_20240102030405.csv",
		{"org", "encrypted_json"}: "bitwarden_encrypted_org_export_20240102030405.json",
	}
	for in, want := range cases {
		if got := GetFileName(in[0], in[1], now); got != want {
			t.Errorf("%v: got %s want %s", in, got, want)
		}
	}
}

func TestStringifyLineSeparators(t *testing.T) {
	b, err := stringify(map[string]string{"a": "x\u2028y\u2029z\\u2028<&>"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n  \"a\": \"x\u2028y\u2029z\\\\u2028<&>\"\n}"; string(b) != want {
		t.Fatalf("got %q want %q", b, want)
	}
}

const wantIndividualCSV = "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
	",,login,Files/Docs,,,0,,,a,,\r\n" +
	",,login,Files/Docs,,,0,,,b,,\r\n" +
	"Work,1,login,GitHub,\"line1\nline2\",\"PIN: 1234\nflag: true\",1,2024-03-04T05:06:07.890Z,\"https://github.com,https://gh.io\",octo,\"p@ss,\"\"word\"\"\",JBSWY3DPEHPK3PXP\r\n" +
	",,note,\"Note \",\" leading\",,0,,,,,"

const wantGitHubJSON = `    {
      "type": 1,
      "favorite": true,
      "reprompt": 1,
      "id": "a0000000-0000-4000-8000-000000000001",
      "collectionIds": null,
      "folderId": "f0000000-0000-4000-8000-000000000001",
      "name": "GitHub",
      "notes": "line1\nline2",
      "fields": [
        {
          "type": 0,
          "name": "PIN",
          "value": "1234"
        },
        {
          "type": 2,
          "name": "flag",
          "value": "true"
        }
      ],
      "login": {
        "uris": [
          {
            "uri": "https://github.com"
          },
          {
            "uri": "https://gh.io"
          }
        ],
        "fido2Credentials": [],
        "username": "octo",
        "password": "p@ss,\"word\"",
        "totp": "JBSWY3DPEHPK3PXP"
      },
      "passwordHistory": [
        {
          "password": "old",
          "lastUsedDate": "2023-12-31T23:59:59.000Z"
        }
      ],
      "creationDate": "2024-01-02T03:04:05.678Z",
      "revisionDate": "2024-02-03T04:05:06.789Z",
      "archivedDate": "2024-03-04T05:06:07.890Z"
    },`

func itemIDs(t *testing.T, data []byte) []string {
	t.Helper()
	var doc struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, it := range doc.Items {
		ids = append(ids, it.ID)
	}
	return ids
}

func TestIndividualDecryptedExports(t *testing.T) {
	var jsons [][]byte
	for _, v2 := range []bool{false, true} {
		f := newFixture(t, fixtureOpts{v2: v2})
		s := f.service()

		e, err := s.GetExport("csv", "")
		if err != nil {
			t.Fatal(err)
		}
		if e.Type != TypeText || e.FileName != "bitwarden_export_20240708091011.csv" || string(e.Data) != wantIndividualCSV {
			t.Fatalf("v2=%v csv %s\n%q", v2, e.FileName, e.Data)
		}
		// default format is csv
		if d, _ := s.GetExport("", ""); string(d.Data) != wantIndividualCSV {
			t.Fatal("default format")
		}

		e, err = s.GetExport("json", "   ")
		if err != nil {
			t.Fatal(err)
		}
		if e.FileName != "bitwarden_export_20240708091011.json" {
			t.Fatal(e.FileName)
		}
		out := string(e.Data)
		if !strings.HasPrefix(out, "{\n  \"encrypted\": false,\n  \"folders\": [\n    {\n      \"name\": \"Work\",\n      \"id\": \""+tFolder+"\"\n    }\n  ],\n  \"items\": [\n") {
			t.Fatalf("json prefix\n%s", out)
		}
		if !strings.Contains(out, wantGitHubJSON) {
			t.Fatalf("v2=%v GitHub item\n%s", v2, out)
		}
		if strings.Contains(out, `"key"`) {
			t.Fatal("cipher key must be deleted from the unencrypted export")
		}
		// deleted and organization items are excluded; cards are included in JSON only
		ids := itemIDs(t, e.Data)
		want := []string{"a0000000-0000-4000-8000-000000000005", "a0000000-0000-4000-8000-000000000006",
			"a0000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000002",
			"a0000000-0000-4000-8000-000000000003"}
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Fatalf("items %v", ids)
		}
		jsons = append(jsons, e.Data)
	}
	if !bytes.Equal(jsons[0], jsons[1]) {
		t.Fatalf("v1 and v2 decrypted exports differ\n%s\n%s", jsons[0], jsons[1])
	}
}

func TestRestrictedItemTypes(t *testing.T) {
	policy := `{"id":"p1","organizationId":"` + tOrgID + `","type":15,"enabled":true,"data":null}`
	f := newFixture(t, fixtureOpts{policies: []string{policy}})
	s := f.service()
	for _, format := range []string{"json", "encrypted_json"} {
		e, err := s.GetExport(format, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range itemIDs(t, e.Data) {
			if id == "a0000000-0000-4000-8000-000000000003" {
				t.Fatalf("%s: restricted card exported", format)
			}
		}
		if len(itemIDs(t, e.Data)) != 4 {
			t.Fatalf("%s: %v", format, itemIDs(t, e.Data))
		}
		o, err := s.GetOrganizationExport(tOrgID, format, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if ids := itemIDs(t, o.Data); len(ids) != 2 {
			t.Fatalf("org %s: %v", format, ids)
		}
	}
}

type encDoc struct {
	Encrypted        bool              `json:"encrypted"`
	EncKeyValidation string            `json:"encKeyValidation_DO_NOT_EDIT"`
	Folders          []json.RawMessage `json:"folders"`
	Collections      []json.RawMessage `json:"collections"`
	Items            []json.RawMessage `json:"items"`
}

func TestIndividualEncryptedExport(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		f := newFixture(t, fixtureOpts{v2: v2})
		e, err := f.service().GetExport("encrypted_json", "")
		if err != nil {
			t.Fatal(err)
		}
		if e.FileName != "bitwarden_encrypted_export_20240708091011.json" {
			t.Fatal(e.FileName)
		}
		if !strings.HasPrefix(string(e.Data), "{\n  \"encrypted\": true,\n  \"encKeyValidation_DO_NOT_EDIT\": \"") ||
			!strings.Contains(string(e.Data), "\",\n  \"folders\": [\n    {\n      \"name\": \"") {
			t.Fatalf("shape\n%s", e.Data)
		}
		var doc encDoc
		if err := json.Unmarshal(e.Data, &doc); err != nil {
			t.Fatal(err)
		}
		g, err := crypto.DecryptString(doc.EncKeyValidation, f.userKey)
		if err != nil || !guidRe.MatchString(g) {
			t.Fatalf("validation %q %v", g, err)
		}
		if v2 != strings.HasPrefix(doc.EncKeyValidation, "7.") {
			t.Fatalf("v2=%v validation type %s", v2, doc.EncKeyValidation[:2])
		}
		var folder vault.Folder
		_ = json.Unmarshal(doc.Folders[0], &folder)
		if fv, err := vault.DecryptFolder(&folder, f.userKey); err != nil || fv.Name != "Work" || fv.ID != tFolder {
			t.Fatalf("folder %+v %v", fv, err)
		}
		if len(doc.Items) != 5 {
			t.Fatalf("items %d", len(doc.Items))
		}
		names := map[string]string{}
		for _, raw := range doc.Items {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			if v, ok := m["collectionIds"]; !ok || v != nil {
				t.Fatalf("collectionIds must be null: %s", raw)
			}
			if _, ok := m["key"]; !ok {
				t.Fatalf("encrypted export keeps the cipher key: %s", raw)
			}
			if _, ok := m["data"]; ok != v2 {
				t.Fatalf("v2=%v blob data presence: %s", v2, raw)
			}
			c, err := vault.ParseCipher(raw)
			if err != nil {
				t.Fatal(err)
			}
			view, err := vault.DecryptCipher(c, f.keys)
			if err != nil {
				t.Fatalf("decrypt exported item: %v\n%s", err, raw)
			}
			names[view.ID] = view.Name
		}
		if names["a0000000-0000-4000-8000-000000000001"] != "GitHub" || names["a0000000-0000-4000-8000-000000000003"] != "Visa" {
			t.Fatalf("names %v", names)
		}
	}
}

func decryptPasswordExport(t *testing.T, data []byte, password string) (PasswordProtectedJSON, string) {
	t.Helper()
	var doc PasswordProtectedJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Encrypted || !doc.PasswordProtected {
		t.Fatal("flags")
	}
	key, err := DeriveVaultExportKey(password, doc.Salt, crypto.KdfConfig{Type: crypto.KdfType(doc.KdfType),
		Iterations: doc.KdfIterations, Memory: doc.KdfMemory, Parallelism: doc.KdfParallelism})
	if err != nil {
		t.Fatal(err)
	}
	g, err := crypto.DecryptString(doc.EncKeyValidation, key)
	if err != nil || !guidRe.MatchString(g) {
		t.Fatalf("validation %q %v", g, err)
	}
	if !strings.HasPrefix(doc.Data, "2.") {
		t.Fatal("password-protected data must be AES-CBC-HMAC")
	}
	plain, err := crypto.DecryptString(doc.Data, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveVaultExportKey("wrong", doc.Salt, crypto.KdfConfig{Type: crypto.KdfType(doc.KdfType),
		Iterations: doc.KdfIterations, Memory: doc.KdfMemory, Parallelism: doc.KdfParallelism}); err == nil {
		wk, _ := DeriveVaultExportKey("wrong", doc.Salt, crypto.KdfConfig{Type: crypto.KdfType(doc.KdfType),
			Iterations: doc.KdfIterations, Memory: doc.KdfMemory, Parallelism: doc.KdfParallelism})
		if _, err := crypto.DecryptString(doc.Data, wk); err == nil {
			t.Fatal("wrong password decrypted the export")
		}
	}
	return doc, plain
}

func TestPasswordProtectedExport(t *testing.T) {
	f := newFixture(t, fixtureOpts{v2: true})
	s := f.service()
	plainJSON, _ := s.GetExport("json", "")

	if _, err := s.GetExport("csv", "pw"); err == nil || err.Error() != "CSV does not support password protected export" {
		t.Fatalf("csv with password: %v", err)
	}
	for _, format := range []string{"json", "encrypted_json", "zip"} {
		e, err := s.GetExport(format, "s3cret")
		if err != nil {
			t.Fatal(err)
		}
		if e.Type != TypeText || e.FileName != "bitwarden_encrypted_export_20240708091011.json" {
			t.Fatalf("%s: %s %s", format, e.Type, e.FileName)
		}
		re := regexp.MustCompile(`^\{\n  "encrypted": true,\n  "passwordProtected": true,\n  "salt": "[A-Za-z0-9+/=]{24}",\n  "kdfType": 0,\n  "kdfIterations": 5000,\n  "encKeyValidation_DO_NOT_EDIT": "2\.[^"]+",\n  "data": "2\.[^"]+"\n\}$`)
		if !re.Match(e.Data) {
			t.Fatalf("shape\n%s", e.Data)
		}
		_, plain := decryptPasswordExport(t, e.Data, "s3cret")
		if plain != string(plainJSON.Data) {
			t.Fatalf("decrypted payload differs\n%s", plain)
		}
	}

	// Argon2id: memory and parallelism are appended after data.
	mem, par := 16, 1
	f = newFixture(t, fixtureOpts{kdf: &crypto.KdfConfig{Type: crypto.KdfArgon2id, Iterations: 2, Memory: &mem, Parallelism: &par}})
	e, err := f.service().GetOrganizationExport(tOrgID, "json", "pw", false)
	if err != nil {
		t.Fatal(err)
	}
	if e.FileName != "bitwarden_encrypted_org_export_20240708091011.json" {
		t.Fatal(e.FileName)
	}
	if !strings.Contains(string(e.Data), "\"kdfType\": 1,\n  \"kdfIterations\": 2,\n") ||
		!strings.HasSuffix(string(e.Data), "\",\n  \"kdfMemory\": 16,\n  \"kdfParallelism\": 1\n}") {
		t.Fatalf("argon2 shape\n%s", e.Data)
	}
	_, plain := decryptPasswordExport(t, e.Data, "pw")
	orgJSON, _ := f.service().GetOrganizationExport(tOrgID, "json", "", false)
	if plain != string(orgJSON.Data) {
		t.Fatal("org payload differs")
	}
}

func TestZipExport(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		f := newFixture(t, fixtureOpts{v2: v2})
		s := f.service()
		var logged []string
		s.LogError = func(msg string, err error) { logged = append(logged, msg) }
		e, err := s.GetExport("zip", "")
		if err != nil {
			t.Fatal(err)
		}
		if e.Type != TypeZip || e.FileName != "bitwarden_export_20240708091011.zip" || e.SkippedAttachmentCount != 1 {
			t.Fatalf("%s %s %d", e.Type, e.FileName, e.SkippedAttachmentCount)
		}
		if len(logged) != 1 || logged[0] != "Failed to export attachment: Cipher Id: a0000000-0000-4000-8000-000000000006" {
			t.Fatalf("log %v", logged)
		}
		r, err := zip.NewReader(bytes.NewReader(e.Data), int64(len(e.Data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		contents := map[string]string{}
		for _, zf := range r.File {
			names = append(names, zf.Name)
			if zf.Method != zip.Store {
				t.Fatalf("%s not stored", zf.Name)
			}
			if strings.HasSuffix(zf.Name, "/") {
				if !zf.FileInfo().IsDir() {
					t.Fatalf("%s should be a directory", zf.Name)
				}
				continue
			}
			rc, _ := zf.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			contents[zf.Name] = string(b)
		}
		want := []string{"data.json", "attachments/", "attachments/Files_Docs/",
			"attachments/Files_Docs/reportfinal.pdf", "attachments/Files_Docs/a_b.txt",
			"attachments/Files_Docs/reportfinal_1.pdf", "attachments/Files_Docs_1/",
			"attachments/Files_Docs_1/noext"}
		if strings.Join(names, "|") != strings.Join(want, "|") {
			t.Fatalf("entries\n got %v\nwant %v", names, want)
		}
		plain, _ := s.GetExport("json", "")
		if contents["data.json"] != string(plain.Data) {
			t.Fatal("data.json differs from the json export")
		}
		if contents["attachments/Files_Docs/reportfinal.pdf"] != "hello" || contents["attachments/Files_Docs/a_b.txt"] != "hi" ||
			contents["attachments/Files_Docs/reportfinal_1.pdf"] != "two" || contents["attachments/Files_Docs_1/noext"] != "x" {
			t.Fatalf("contents %v", contents)
		}
	}
}

func TestZipBuilderJSZipSemantics(t *testing.T) {
	z := newZipBuilder()
	z.file("data.json", []byte("1"))
	root := z.folder("attachments")
	same := z.folder(root + "") // folder("") returns the same folder
	if same != "attachments/" {
		t.Fatal(same)
	}
	z.file(root+"x/a.b/c", []byte("nested")) // parent folders are created
	z.file("data.json", []byte("2"))         // replaced in place
	if strings.Join(z.names, "|") != "data.json|attachments/|attachments/x/|attachments/x/a.b/|attachments/x/a.b/c" {
		t.Fatal(z.names)
	}
	if string(z.files["data.json"]) != "2" {
		t.Fatal("replace")
	}
}

const wantOrgCSV = "collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
	"\"Engineering,Ops, Team\",login,Shared,,,0,,https://team.example.com,team,pw,\r\n" +
	"\"Ops, Team\",note,Team note,note,,0,,,,,"

const wantOrgJSONPrefix = `{
  "encrypted": false,
  "collections": [
    {
      "id": "c0000000-0000-4000-8000-000000000001",
      "organizationId": "11111111-1111-4111-8111-111111111111",
      "name": "Engineering",
      "externalId": null
    },
    {
      "id": "c0000000-0000-4000-8000-000000000002",
      "organizationId": "11111111-1111-4111-8111-111111111111",
      "name": "Ops, Team",
      "externalId": null
    }
  ],
  "items": [
    {
      "type": 1,
      "favorite": false,
      "reprompt": 0,
      "id": "b0000000-0000-4000-8000-000000000001",
      "collectionIds": [
        "c0000000-0000-4000-8000-000000000001",
        "c0000000-0000-4000-8000-000000000002"
      ],
      "organizationId": "11111111-1111-4111-8111-111111111111",
      "name": "Shared",
      "fields": [],
      "login": {
        "uris": [
          {
            "uri": "https://team.example.com"
          }
        ],
        "fido2Credentials": [],
        "username": "team",
        "password": "pw"
      },
      "passwordHistory": [],
      "creationDate": "2024-01-02T03:04:05.678Z",
      "revisionDate": "2024-02-03T04:05:06.789Z"
    },
`

func TestOrganizationExport(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		f := newFixture(t, fixtureOpts{v2: v2})
		s := f.service()

		e, err := s.GetOrganizationExport(tOrgID, "csv", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if e.FileName != "bitwarden_org_export_20240708091011.csv" || string(e.Data) != wantOrgCSV {
			t.Fatalf("csv %s\n%q", e.FileName, e.Data)
		}
		e, err = s.GetOrganizationExport(tOrgID, "json", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if e.FileName != "bitwarden_org_export_20240708091011.json" || !strings.HasPrefix(string(e.Data), wantOrgJSONPrefix) {
			t.Fatalf("json\n%s", e.Data)
		}
		if ids := itemIDs(t, e.Data); len(ids) != 3 || strings.Contains(string(e.Data), `"key"`) {
			t.Fatalf("items %v", ids)
		}

		e, err = s.GetOrganizationExport(tOrgID, "encrypted_json", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if e.FileName != "bitwarden_encrypted_org_export_20240708091011.json" ||
			!strings.HasPrefix(string(e.Data), "{\n  \"encrypted\": true,\n  \"encKeyValidation_DO_NOT_EDIT\": \"2.") {
			t.Fatalf("encrypted %s\n%s", e.FileName, e.Data)
		}
		var doc encDoc
		if err := json.Unmarshal(e.Data, &doc); err != nil {
			t.Fatal(err)
		}
		if g, err := crypto.DecryptString(doc.EncKeyValidation, f.orgKey); err != nil || !guidRe.MatchString(g) {
			t.Fatalf("org validation %v", err)
		}
		if len(doc.Collections) != 2 || len(doc.Items) != 3 {
			t.Fatalf("encrypted org counts %d %d", len(doc.Collections), len(doc.Items))
		}
		var col struct {
			ID, OrganizationID, Name string
			ExternalID               *string `json:"externalId"`
		}
		_ = json.Unmarshal(doc.Collections[1], &col)
		if n, err := crypto.DecryptString(col.Name, f.orgKey); err != nil || n != "Ops, Team" || col.ID != tCol2 {
			t.Fatalf("collection %+v %v", col, err)
		}
		if !strings.Contains(string(doc.Collections[0]), `"externalId": null`) {
			t.Fatalf("externalId null: %s", doc.Collections[0])
		}
		for _, raw := range doc.Items {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			if _, ok := m["collectionIds"].([]any); !ok {
				t.Fatalf("org export keeps collectionIds: %s", raw)
			}
			c, _ := vault.ParseCipher(raw)
			if _, err := vault.DecryptCipher(c, f.keys); err != nil {
				t.Fatal(err)
			}
		}

		if _, err := s.GetOrganizationExport(tOrgID, "zip", "", false); err == nil || err.Error() != "Zip export not supported for organization" {
			t.Fatalf("zip: %v", err)
		}
		if _, err := s.GetOrganizationExport(tOrgID, "csv", "pw", false); err == nil || err.Error() != "CSV does not support password protected export" {
			t.Fatalf("csv pw: %v", err)
		}
		if _, err := s.GetOrganizationExport(" ", "json", "", false); err == nil || err.Error() != "OrganizationId must be set" {
			t.Fatalf("org id: %v", err)
		}
		if _, err := s.GetOrganizationExport("99999999-9999-4999-8999-999999999999", "json", "", false); err == nil || err.Error() != "Resource not found." {
			t.Fatalf("api error: %v", err)
		}
	}
}

func TestOrganizationExportDecryptFailure(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	other := vault.NewKeys(f.userKey, f.acct.EncPrivateKey, nil, nil)
	other.SetOrgKey(tOrgID, crypto.GenerateKey())
	v := baseView("b0000000-0000-4000-8000-0000000000ff", "Bad", vault.CipherTypeLogin)
	org := tOrgID
	v.OrganizationID = &org
	c, _, err := vault.EncryptCipher(v, other)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	f.client.org.Ciphers = append(f.client.org.Ciphers, raw)
	if _, err := f.service().GetOrganizationExport(tOrgID, "json", "", false); err == nil || err.Error() != "no elements in sequence" {
		t.Fatalf("got %v", err)
	}
	// the encrypted export does not decrypt items
	if _, err := f.service().GetOrganizationExport(tOrgID, "encrypted_json", "", false); err != nil {
		t.Fatal(err)
	}
}

func TestManagedCollectionsExport(t *testing.T) {
	f := newFixture(t, fixtureOpts{manage: true})
	s := f.service()
	e, err := s.GetOrganizationExport(tOrgID, "csv", "", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
		"Engineering,login,Shared,,,0,,https://team.example.com,team,pw,"
	if string(e.Data) != want {
		t.Fatalf("managed csv %q", e.Data)
	}
	e, err = s.GetOrganizationExport(tOrgID, "encrypted_json", "", true)
	if err != nil {
		t.Fatal(err)
	}
	var doc encDoc
	_ = json.Unmarshal(e.Data, &doc)
	if len(doc.Collections) != 1 || len(doc.Items) != 1 || f.client.orgCalls != 0 {
		t.Fatalf("managed encrypted %d %d calls=%d", len(doc.Collections), len(doc.Items), f.client.orgCalls)
	}
}
