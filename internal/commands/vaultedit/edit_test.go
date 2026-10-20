package vaultedit

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/vault"
)

const itemID = "22222222-0000-0000-0000-000000000001"

func loginItem(name, password string) *vault.CipherView {
	v := vault.NewCipherView()
	v.ID, v.Name = itemID, name
	v.Permissions = &vault.CipherPermissions{Delete: true, Restore: true}
	v.Login.Username = sp("jdoe")
	v.Login.Password = sp(password)
	v.Login.Totp = sp("JBSWY3DPEHPK3PXP")
	v.Fields = []vault.FieldView{
		{Type: vault.FieldTypeHidden, Name: sp("pin"), Value: sp("1111")},
		{Type: vault.FieldTypeText, Name: sp("note"), Value: sp("visible")},
		{Type: vault.FieldTypeHidden, Name: sp("pin"), Value: sp("2222")},
	}
	v.RevisionDate = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return v
}

func echoCipherPut(env *testEnv, id string) {
	env.fs.on("PUT", "/api/ciphers/"+id, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, serverCipher(body, id, nil))
	})
}

func TestEditItem(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := newEnv(t, envOptions{v2: v2})
		env.addCipher(loginItem("Old", "old-pass"))
		echoCipherPut(env, itemID)

		req := `{"type":1,"name":"New","notes":null,"favorite":false,"revisionDate":"2024-01-02T03:04:05.000Z",` +
			`"login":{"uris":[],"username":"jdoe","password":"new-pass","totp":"JBSWY3DPEHPK3PXP"},` +
			`"fields":[{"type":1,"name":"pin","value":"1111"},{"type":0,"name":"note","value":"visible"}]}`
		r := EditEncoded(env.a, "item", itemID, b64(req), EditOptions{})
		mustSucceed(t, r)
		got := env.fs.last("PUT", "/api/ciphers/"+itemID)
		view, body := env.decryptRequestCipher(got.Body)
		if view.Name != "New" || *view.Login.Password != "new-pass" {
			t.Fatalf("request %+v", view)
		}
		if body["lastKnownRevisionDate"] != "2024-01-02T03:04:05.000Z" || body["encryptedFor"] != testUserID {
			t.Errorf("request meta %v %v", body["lastKnownRevisionDate"], body["encryptedFor"])
		}
		// password history: changed password and the removed hidden field "pin: 2222"
		if len(view.PasswordHistory) != 2 || *view.PasswordHistory[0].Password != "pin: 2222" || *view.PasswordHistory[1].Password != "old-pass" {
			for _, p := range view.PasswordHistory {
				t.Logf("history %s", *p.Password)
			}
			t.Errorf("password history %d entries", len(view.PasswordHistory))
		}
		if view.Login.PasswordRevisionDate == nil {
			t.Error("passwordRevisionDate not set")
		}
		out := r.Data.(*vault.CipherResponse)
		if out.Name != "New" || out.Login.Password.Get() != "new-pass" || len(out.PasswordHistory) != 2 {
			t.Errorf("output %s", toJSON(t, out))
		}
		if sv := env.storedView(itemID); sv.Name != "New" {
			t.Errorf("stored %+v", sv)
		}
	}
}

func TestEditItemKeepsRedactedValues(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := loginItem("Item", "real-pass")
	c, _, err := vault.EncryptCipher(item, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	f := false
	c.Edit, c.ViewPassword = true, &f
	env.storeCipher(c)
	echoCipherPut(env, itemID)
	// `bw get item` output of a user without viewPassword: password/totp/hidden values are null.
	req := `{"type":1,"name":"Renamed","login":{"username":"jdoe","password":null,"totp":null},` +
		`"fields":[{"type":0,"name":"note","value":"visible"},{"type":1,"name":"pin","value":null},{"type":1,"name":"pin","value":"9999"}]}`
	mustSucceed(t, Edit(env.a, "item", itemID, json.RawMessage(req), EditOptions{}))
	view, _ := env.decryptRequestCipher(env.fs.last("PUT", "/api/ciphers/"+itemID).Body)
	if *view.Login.Password != "real-pass" || *view.Login.Totp != "JBSWY3DPEHPK3PXP" || view.Name != "Renamed" {
		t.Errorf("login %+v", view.Login)
	}
	if *view.Fields[1].Value != "1111" || *view.Fields[2].Value != "9999" {
		t.Errorf("fields %s %s", *view.Fields[1].Value, *view.Fields[2].Value)
	}
}

func TestEditItemChecks(t *testing.T) {
	env := newEnv(t, envOptions{policies: []string{
		`{"id":"p1","organizationId":"` + testOrgID + `","type":5,"enabled":true,"data":null}`,
	}})
	mustFail(t, Edit(env.a, "item", "nope", json.RawMessage(`{"type":1}`), EditOptions{}), "Not found.")

	ro := loginItem("ro", "x")
	ro.ID = "22222222-0000-0000-0000-000000000002"
	c, _, _ := vault.EncryptCipher(ro, env.keys)
	c.Edit = false
	env.storeCipher(c)
	mustFail(t, Edit(env.a, "item", ro.ID, json.RawMessage(`{"type":1}`), EditOptions{}), "You do not have permission to edit this item")

	del := loginItem("deleted", "x")
	del.ID = "22222222-0000-0000-0000-000000000003"
	now := time.Now()
	del.DeletedDate = &now
	env.addCipher(del)
	mustFail(t, Edit(env.a, "item", del.ID, json.RawMessage(`{"type":1}`), EditOptions{}),
		"You may not edit a deleted item. Use the restore command first.")

	// personal item + organization data ownership policy (the user is an admin, but the
	// policy exempts only owners/admins: use a plain user)
	env.setProfile(func(p map[string]any) {
		p["organizations"].([]any)[0].(map[string]any)["type"] = 2
	})
	env.addCipher(loginItem("personal", "x"))
	mustFail(t, Edit(env.a, "item", itemID, json.RawMessage(`{"type":1,"name":"x"}`), EditOptions{}),
		"An organization policy restricts editing this cipher. Please use the share command first before modifying it.")
	mustFail(t, EditEncoded(env.a, "item", itemID, "", EditOptions{}), "`requestJson` was not provided.")
}

func TestEditArchivedWithoutPremium(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := loginItem("arch", "x")
	at := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	item.ArchivedDate = &at
	env.addCipher(item)
	echoCipherPut(env, itemID)
	mustSucceed(t, Edit(env.a, "item", itemID, json.RawMessage(`{"type":1,"name":"arch2","archivedDate":"2024-02-01T00:00:00.000Z"}`), EditOptions{}))
	_, body := env.decryptRequestCipher(env.fs.last("PUT", "/api/ciphers/"+itemID).Body)
	if v, ok := body["archivedDate"]; !ok || v != nil {
		t.Errorf("archivedDate should be cleared, got %v", body["archivedDate"])
	}

	// interactive: cancelling aborts the edit
	t.Setenv("BW_NOINTERACTION", "")
	oldPrompt, oldTTY := promptArchiveEdit, stdinIsTTY
	promptArchiveEdit = func() (int, error) { return 1, nil }
	stdinIsTTY = func() bool { return true }
	defer func() { promptArchiveEdit, stdinIsTTY = oldPrompt, oldTTY }()
	puts := env.fs.count("PUT", "/api/ciphers/"+itemID)
	mustFail(t, Edit(env.a, "item", itemID, json.RawMessage(`{"type":1,"name":"x","archivedDate":"2024-02-01T00:00:00.000Z"}`), EditOptions{}), "Edit cancelled.")
	if env.fs.count("PUT", "/api/ciphers/"+itemID) != puts {
		t.Error("cancelled edit must not be saved")
	}
}

func TestEditItemCollections(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := loginItem("org", "x")
	org := testOrgID
	item.OrganizationID = &org
	item.CollectionIDs = []string{testCol1}
	stored := env.addCipher(item)
	env.fs.on("PUT", "/api/ciphers/"+itemID+"/collections_v2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		raw, _ := json.Marshal(stored)
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		c["collectionIds"] = req["collectionIds"]
		c["revisionDate"] = serverRev
		writeJSON(w, map[string]any{"object": "optionalCipherDetails", "unavailable": false, "cipher": c})
	})
	r := EditEncoded(env.a, "item-collections", itemID, b64(`["`+testCol1+`","`+testCol2+`"]`), EditOptions{})
	mustSucceed(t, r)
	if body := string(env.fs.last("PUT", "/api/ciphers/"+itemID+"/collections_v2").Body); body != `{"collectionIds":["`+testCol1+`","`+testCol2+`"]}` {
		t.Errorf("body %s", body)
	}
	if out := r.Data.(*vault.CipherResponse); len(out.CollectionIDs) != 2 {
		t.Errorf("output %s", toJSON(t, out))
	}
	if sc := env.storedCipher(itemID); len(sc.CollectionIDs) != 2 {
		t.Errorf("stored %v", sc.CollectionIDs)
	}

	// access lost: the item is removed locally
	env.fs.on("PUT", "/api/ciphers/"+itemID+"/collections_v2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"object": "optionalCipherDetails", "unavailable": true, "cipher": nil})
	})
	mustFail(t, Edit(env.a, "item-collections", itemID, json.RawMessage(`[]`), EditOptions{}), "no elements in sequence")
	if _, err := env.vault().EncryptedCipher(itemID); err == nil {
		t.Error("cipher should have been removed")
	}

	personal := loginItem("p", "x")
	personal.ID = "22222222-0000-0000-0000-000000000009"
	env.addCipher(personal)
	mustFail(t, Edit(env.a, "item-collections", personal.ID, json.RawMessage(`[]`), EditOptions{}),
		"Item does not belong to an organization. Consider moving it first.")
}

func TestEditFolder(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.addFolder("f1", "Old")
	env.fs.on("PUT", "/api/folders/f1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		writeJSON(w, map[string]any{"id": "f1", "name": req["name"], "revisionDate": serverRev})
	})
	r := EditEncoded(env.a, "folder", "F1", "eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==", EditOptions{})
	mustSucceed(t, r)
	var req map[string]string
	_ = json.Unmarshal(env.fs.last("PUT", "/api/folders/f1").Body, &req)
	if dec(t, req["name"], env.userKey) != "My Folder2" {
		t.Errorf("request %v", req)
	}
	if out := toJSON(t, r.Data); out != `{"name":"My Folder2","object":"folder","id":"f1"}` {
		t.Errorf("output %s", out)
	}
	mustFail(t, Edit(env.a, "folder", "f2", json.RawMessage(`{"name":"x"}`), EditOptions{}), "Not found.")
}

func TestEditOrgCollection(t *testing.T) {
	env := newEnv(t, envOptions{})
	path := "/api/organizations/" + testOrgID + "/collections/" + testCol1
	env.fs.on("PUT", path, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"id": testCol1, "organizationId": testOrgID, "groups": nil, "users": []any{
			map[string]any{"id": "u1", "readOnly": false, "hidePasswords": true, "manage": false},
		}})
	})
	r := Edit(env.a, "org-collection", testCol1, json.RawMessage(`{"name":"Renamed"}`), EditOptions{OrganizationID: testOrgID})
	mustSucceed(t, r)
	got := env.fs.last("PUT", path)
	var req map[string]any
	_ = json.Unmarshal(got.Body, &req)
	if dec(t, req["name"].(string), env.orgKey) != "Renamed" {
		t.Error("name")
	}
	if string(got.Body) != `{"groups":[],"users":[],"name":"`+req["name"].(string)+`"}` {
		t.Errorf("body %s", got.Body)
	}
	want := `{"object":"org-collection","id":"` + testCol1 + `","organizationId":"` + testOrgID + `","name":"Renamed","groups":[],` +
		`"users":[{"id":"u1","readOnly":false,"hidePasswords":true,"manage":false}]}`
	if out := toJSON(t, r.Data); out != want {
		t.Errorf("output\n got %s\nwant %s", out, want)
	}
	mustFail(t, Edit(env.a, "org-collection", "not-a-guid", json.RawMessage(`{"name":"x"}`), EditOptions{OrganizationID: testOrgID}),
		"`not-a-guid` is not a GUID.")
}
