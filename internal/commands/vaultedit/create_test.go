package vaultedit

import (
	"bytes"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

const newItemID = "eeeeeeee-0000-0000-0000-000000000001"

func TestCreateItem(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		name := "v1"
		if v2 {
			name = "v2"
		}
		t.Run(name, func(t *testing.T) {
			env := newEnv(t, envOptions{v2: v2})
			env.fs.on("POST", "/api/ciphers", func(w http.ResponseWriter, r *http.Request, body []byte) {
				writeJSON(w, serverCipher(body, newItemID, nil))
			})
			req := `{"type":1,"name":"Google","notes":"n","favorite":true,"fields":[{"type":1,"name":"pin","value":"1234"}],` +
				`"login":{"uris":[{"uri":"https://google.com","match":null}],"username":"jdoe","password":"secret","totp":null}}`
			r := CreateEncoded(env.a, "item", b64(req), CreateOptions{})
			mustSucceed(t, r)

			got := env.fs.last("POST", "/api/ciphers")
			view, body := env.decryptRequestCipher(got.Body)
			if str(body, "encryptedFor") != testUserID {
				t.Errorf("encryptedFor = %v", body["encryptedFor"])
			}
			if view.Name != "Google" || *view.Notes != "n" || !view.Favorite || *view.Login.Username != "jdoe" ||
				*view.Login.Password != "secret" || *view.Login.URIs[0].URI != "https://google.com" ||
				len(view.Fields) != 1 || *view.Fields[0].Value != "1234" {
				t.Errorf("request decrypts to %+v", view)
			}
			if body["key"] == nil {
				t.Error("cipher key missing")
			}
			if v2 {
				if body["data"] == nil || body["name"] != nil {
					t.Errorf("v2 personal items must be blob ciphers: %s", got.Body)
				}
			} else if body["data"] != nil {
				t.Errorf("v1 item must not use the blob format: %s", got.Body)
			}

			// Same shape as `bw get item` (vault.NewCipherResponse of the decrypted server cipher).
			want := `{"type":1,"favorite":true,"reprompt":0,"id":"` + newItemID + `","collectionIds":[],"object":"item",` +
				`"name":"Google","notes":"n","fields":[{"type":1,"name":"pin","value":"1234"}],` +
				`"login":{"uris":[{"uri":"https://google.com"}],"fido2Credentials":[],"username":"jdoe","password":"secret","passwordRevisionDate":null},` +
				`"passwordHistory":[],"creationDate":"2024-04-01T09:00:00.000Z","revisionDate":"2024-05-01T10:00:00.123Z","attachments":[]}`
			if out := toJSON(t, r.Data); out != want {
				t.Errorf("output\n got %s\nwant %s", out, want)
			}
			// local state was updated (cipherService.upsert)
			if sv := env.storedView(newItemID); sv.Name != "Google" {
				t.Errorf("stored view %+v", sv)
			}
		})
	}
}

func TestCreateOrgItemWithCollections(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.fs.on("POST", "/api/ciphers/create", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, serverCipher(body, newItemID, nil))
	})
	req := `{"type":2,"name":"Shared note","notes":"secret note","secureNote":{"type":0},"organizationId":"` + testOrgID +
		`","collectionIds":["` + testCol1 + `"]}`
	r := Create(env.a, "item", json.RawMessage(req), CreateOptions{})
	mustSucceed(t, r)
	got := env.fs.last("POST", "/api/ciphers/create")
	view, body := env.decryptRequestCipher(got.Body)
	if view.Name != "Shared note" || *view.Notes != "secret note" {
		t.Errorf("request %+v", view)
	}
	if ids, _ := body["collectionIds"].([]any); len(ids) != 1 || ids[0] != testCol1 {
		t.Errorf("collectionIds = %v", body["collectionIds"])
	}
	inner := body["cipher"].(map[string]any)
	if inner["organizationId"] != testOrgID || inner["data"] != nil {
		t.Errorf("org item request %v", inner)
	}
	// the cipher key is wrapped by the organization key
	if _, err := crypto.DecryptToKey(inner["key"].(string), env.orgKey); err != nil {
		t.Errorf("cipher key not wrapped by org key: %v", err)
	}
	stored := env.storedCipher(newItemID)
	if len(stored.CollectionIDs) != 1 || stored.CollectionIDs[0] != testCol1 {
		t.Errorf("stored collection ids %v", stored.CollectionIDs)
	}
}

func TestCreateItemChecks(t *testing.T) {
	env := newEnv(t, envOptions{policies: []string{
		`{"id":"p1","organizationId":"` + testOrgID + `","type":15,"enabled":true,"data":null}`,
	}})
	// the user is an admin of the org, but RestrictedItemTypes has no exempt roles
	mustFail(t, Create(env.a, "item", json.RawMessage(`{"type":3,"name":"Visa","card":{"number":"4111"}}`), CreateOptions{}),
		"Creating this item type is restricted by organizational policy.")
	mustFail(t, Create(env.a, "item", json.RawMessage(`{"type":6,"name":"Bank","bankAccount":{}}`), CreateOptions{}),
		"Item type 6 is not available.")
	mustFail(t, Create(env.a, "item", nil, CreateOptions{}), "`requestJson` was not provided.")
	mustFail(t, Create(env.a, "nope", json.RawMessage(`{}`), CreateOptions{}), "Unknown object.")
	mustFail(t, CreateEncoded(env.a, "item", "!!!", CreateOptions{}), "Error parsing the encoded request data.")
	mustFail(t, CreateEncoded(env.a, "item", b64(`{"name":`), CreateOptions{}), "Error parsing the encoded request data.")
	// SSH keys must carry public key and fingerprint unless key derivation is enabled
	r := Create(env.a, "item", json.RawMessage(`{"type":5,"name":"ssh","sshKey":{"privateKey":"x"}}`), CreateOptions{})
	if r.Success {
		t.Error("ssh key without public key should fail")
	}
	if n := len(env.fs.reqs); n != 0 {
		t.Errorf("no request expected, got %d", n)
	}
}

func TestCreateFolder(t *testing.T) {
	env := newEnv(t, envOptions{v2: true})
	env.fs.on("POST", "/api/folders", func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		writeJSON(w, map[string]any{"id": "f1", "name": req["name"], "revisionDate": serverRev, "object": "folder"})
	})
	r := CreateEncoded(env.a, "folder", "eyJuYW1lIjoiTXkgRm9sZGVyIn0K", CreateOptions{})
	mustSucceed(t, r)
	var req map[string]string
	_ = json.Unmarshal(env.fs.last("POST", "/api/folders").Body, &req)
	if dec(t, req["name"], env.userKey) != "My Folder" || len(req) != 1 {
		t.Errorf("folder request %v", req)
	}
	if out := toJSON(t, r.Data); out != `{"name":"My Folder","object":"folder","id":"f1"}` {
		t.Errorf("output %s", out)
	}
	if f, err := env.vault().Folder("f1"); err != nil || f.Name != "My Folder" {
		t.Errorf("stored folder %+v %v", f, err)
	}
}

func TestCreateOrgCollection(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.fs.on("POST", "/api/organizations/"+testOrgID+"/collections", func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		writeJSON(w, map[string]any{"id": "ffffffff-0000-0000-0000-000000000001", "organizationId": testOrgID, "name": req["name"],
			"Groups": req["groups"], "Users": req["users"], "object": "collectionAccessDetails"})
	})
	r := Create(env.a, "org-collection", json.RawMessage(`{"organizationId":"`+testOrgID+`","name":"Ops","externalId":null}`), CreateOptions{})
	mustSucceed(t, r)
	got := env.fs.last("POST", "/api/organizations/"+testOrgID+"/collections")
	var req map[string]any
	_ = json.Unmarshal(got.Body, &req)
	if dec(t, req["name"].(string), env.orgKey) != "Ops" {
		t.Errorf("name %v", req["name"])
	}
	wantBody := `{"groups":[],"users":[{"id":"` + testOrgUserID + `","readOnly":false,"hidePasswords":false,"manage":true}],"name":"` + req["name"].(string) + `"}`
	if string(got.Body) != wantBody {
		t.Errorf("body\n got %s\nwant %s", got.Body, wantBody)
	}
	want := `{"object":"org-collection","id":"ffffffff-0000-0000-0000-000000000001","organizationId":"` + testOrgID +
		`","name":"Ops","externalId":null,"groups":[],"users":[{"id":"` + testOrgUserID + `","readOnly":false,"hidePasswords":false,"manage":true}]}`
	if out := toJSON(t, r.Data); out != want {
		t.Errorf("output\n got %s\nwant %s", out, want)
	}

	// explicit groups/users and the --organizationid option
	r = Create(env.a, "org-collection", json.RawMessage(`{"name":"Ops2","externalId":"ext","groups":[{"id":"g1","readOnly":true,"hidePasswords":false,"manage":false}],"users":[]}`),
		CreateOptions{OrganizationID: testOrgID})
	mustSucceed(t, r)
	got = env.fs.last("POST", "/api/organizations/"+testOrgID+"/collections")
	_ = json.Unmarshal(got.Body, &req)
	if req["externalId"] != "ext" || len(req["groups"].([]any)) != 1 || len(req["users"].([]any)) != 0 {
		t.Errorf("body %s", got.Body)
	}

	mustFail(t, Create(env.a, "org-collection", json.RawMessage(`{"name":"x"}`), CreateOptions{}),
		"An organization id is required, either via the `--organizationid` option (or `organizationId` query parameter when using `bwgo serve`), or the request's `organizationId` property.")
	mustFail(t, Create(env.a, "org-collection", json.RawMessage(`{"name":"x","organizationId":"abc"}`), CreateOptions{}), "`abc` is not a GUID.")
	mustFail(t, Create(env.a, "org-collection", json.RawMessage(`{"name":"x","organizationId":"`+testOrgID+`"}`),
		CreateOptions{OrganizationID: "bbbbbbbb-0000-0000-0000-000000000002"}),
		"The `--organizationid` option (or `organizationId` query parameter) does not match the request's `organizationId` property.")
	mustFail(t, Create(env.a, "org-collection", json.RawMessage(`{"name":"  ","organizationId":"`+testOrgID+`"}`), CreateOptions{}), "Collection name is required.")
	mustFail(t, Create(env.a, "org-collection", json.RawMessage(`{"name":"x","organizationId":"bbbbbbbb-0000-0000-0000-000000000009"}`), CreateOptions{}),
		"No encryption key for this organization.")
}

func attachmentServer(t *testing.T, env *testEnv, itemID string, uploadType int, uploaded *[]byte) {
	env.fs.on("POST", "/api/ciphers/"+itemID+"/attachment/v2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		stored := env.storedCipher(itemID)
		raw, _ := json.Marshal(stored)
		var resp map[string]any
		_ = json.Unmarshal(raw, &resp)
		resp["revisionDate"] = serverRev
		resp["attachments"] = []any{map[string]any{"id": "att1", "fileName": req["fileName"], "key": req["key"],
			"size": "5", "sizeName": "5 Bytes", "url": "https://files/att1"}}
		out := map[string]any{"attachmentId": "att1", "fileUploadType": uploadType, "cipherResponse": resp, "cipherMiniResponse": nil}
		if uploadType == fileUploadAzure {
			out["url"] = env.fs.URL + "/azure/att1?sv=2020-04-08&se=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		}
		writeJSON(w, out)
	})
	env.fs.on("POST", "/api/ciphers/"+itemID+"/attachment/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		// (Part.FileName() would strip the "/" characters of the encrypted name)
		if cd := part.Header.Get("Content-Disposition"); part.FormName() != "data" || !strings.Contains(cd, `filename="2.`) ||
			part.Header.Get("Content-Type") != "application/octet-stream" {
			t.Errorf("multipart part %v", part.Header)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(part)
		*uploaded = buf.Bytes()
		w.WriteHeader(200)
	})
	env.fs.on("PUT", "/azure/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("x-ms-blob-type") != "BlockBlob" || r.Header.Get("x-ms-version") != "2020-04-08" {
			t.Errorf("azure headers %v", r.Header)
		}
		*uploaded = body
		w.WriteHeader(201)
	})
}

func TestCreateAttachment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		v2         bool
		uploadType int
		org        bool
	}{{"direct-v1", false, fileUploadDirect, false}, {"azure-v2", true, fileUploadAzure, false}, {"org-direct-v2", true, fileUploadDirect, true}} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t, envOptions{v2: tc.v2, premium: true})
			item := vault.NewCipherView()
			item.ID, item.Name = "11111111-0000-0000-0000-00000000000a", "With file"
			item.RevisionDate = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
			if tc.org {
				org := testOrgID
				item.OrganizationID = &org
				item.CollectionIDs = []string{testCol1}
			}
			env.addCipher(item)
			var uploaded []byte
			attachmentServer(t, env, item.ID, tc.uploadType, &uploaded)

			file := filepath.Join(t.TempDir(), "notes.txt")
			_ = os.WriteFile(file, []byte("hello"), 0o600)
			r := Create(env.a, "attachment", nil, CreateOptions{ItemID: strings.ToUpper(item.ID), File: file})
			mustSucceed(t, r)

			var meta map[string]any
			_ = json.Unmarshal(env.fs.last("POST", "/api/ciphers/"+item.ID+"/attachment/v2").Body, &meta)
			stored := env.storedCipher(item.ID)
			cipherKey, err := env.keys.CipherKey(stored)
			if err != nil {
				t.Fatal(err)
			}
			if dec(t, meta["fileName"].(string), cipherKey) != "notes.txt" {
				t.Error("file name not encrypted with the cipher key")
			}
			attKey, err := crypto.DecryptToKey(meta["key"].(string), cipherKey)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := crypto.DecryptBytes(uploaded, attKey)
			if err != nil || string(plain) != "hello" {
				t.Fatalf("uploaded file decrypts to %q (%v)", plain, err)
			}
			if int(meta["fileSize"].(float64)) != len(uploaded) || meta["adminRequest"] != false ||
				meta["lastKnownRevisionDate"] != "2024-01-02T03:04:05.000Z" {
				t.Errorf("metadata %v", meta)
			}
			out := r.Data.(*vault.CipherResponse)
			if len(out.Attachments) != 1 || out.Attachments[0].FileName.Get() != "notes.txt" || out.RevisionDate.Format(time.RFC3339Nano) != "2024-05-01T10:00:00.123Z" {
				t.Errorf("response %s", toJSON(t, out))
			}
			if sv := env.storedView(item.ID); len(sv.Attachments) != 1 || sv.CollectionIDs == nil || (tc.org && sv.CollectionIDs[0] != testCol1) {
				t.Errorf("stored %+v", sv)
			}
		})
	}
}

func TestCreateAttachmentErrors(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := vault.NewCipherView()
	item.ID, item.Name = "11111111-0000-0000-0000-00000000000a", "With file"
	env.addCipher(item)
	file := filepath.Join(t.TempDir(), "f.bin")
	_ = os.WriteFile(file, []byte("x"), 0o600)

	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{File: file}), "`itemid` option is required.")
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID}), "`file` option is required.")
	missing := filepath.Join(t.TempDir(), "missing")
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID, File: missing}), "Cannot find file at "+missing)
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID, Upload: &FileUpload{FileName: "x"}}), "File not provided.")
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID, Upload: &FileUpload{Data: []byte("x"), FileName: " "}}), "File name not provided.")
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: "nope", File: file}), "Not found.")
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID, File: file}), "Premium status is required to use this feature.")

	// upload failure rolls the attachment back
	env.setProfile(func(p map[string]any) { p["premium"] = true })
	var uploaded []byte
	attachmentServer(t, env, item.ID, fileUploadDirect, &uploaded)
	env.fs.on("POST", "/api/ciphers/"+item.ID+"/attachment/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(400)
		writeJSON(w, map[string]any{"message": "The model state is invalid.", "validationErrors": map[string]any{"": []string{"Upload failed."}}})
	})
	env.fs.on("DELETE", "/api/ciphers/"+item.ID+"/attachment/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"cipher": map[string]any{"id": item.ID}})
	})
	mustFail(t, Create(env.a, "attachment", nil, CreateOptions{ItemID: item.ID, Upload: &FileUpload{Data: []byte("x"), FileName: "x.txt"}}), "Upload failed.")
	if env.fs.count("DELETE", "/api/ciphers/"+item.ID+"/attachment/att1") != 1 {
		t.Error("attachment was not rolled back")
	}
}
