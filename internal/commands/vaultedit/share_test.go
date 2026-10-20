package vaultedit

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

func TestMove(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		env := newEnv(t, envOptions{v2: v2})
		attKey := crypto.GenerateKey()
		item := loginItem("Personal", "pw")
		item.Attachments = []vault.AttachmentView{{ID: sp("att1"), FileName: sp("a.txt"), Size: sp("3"), SizeName: sp("3 Bytes"), URL: sp("u"), Key: attKey}}
		env.addCipher(item)
		env.fs.on("PUT", "/api/ciphers/"+itemID+"/share", func(w http.ResponseWriter, r *http.Request, body []byte) {
			var req struct {
				Cipher struct {
					Attachments2 map[string]map[string]any `json:"attachments2"`
				} `json:"cipher"`
			}
			_ = json.Unmarshal(body, &req)
			var atts []any
			for id, a := range req.Cipher.Attachments2 {
				atts = append(atts, map[string]any{"id": id, "fileName": a["fileName"], "key": a["key"], "size": "3", "sizeName": "3 Bytes", "url": "u"})
			}
			writeJSON(w, serverCipher(body, itemID, map[string]any{"attachments": atts}))
		})

		r := MoveEncoded(env.a, itemID, testOrgID, b64(`["`+testCol1+`"]`))
		mustSucceed(t, r)
		got := env.fs.last("PUT", "/api/ciphers/"+itemID+"/share")
		view, body := env.decryptRequestCipher(got.Body)
		if *view.OrganizationID != testOrgID || view.Name != "Personal" || *view.Login.Password != "pw" {
			t.Errorf("request %+v", view)
		}
		if ids, _ := body["collectionIds"].([]any); len(ids) != 1 || ids[0] != testCol1 {
			t.Errorf("collectionIds %v", body["collectionIds"])
		}
		inner := body["cipher"].(map[string]any)
		if inner["data"] != nil || inner["attachments"] != nil || inner["id"] != nil {
			t.Errorf("share cipher request %s", got.Body)
		}
		cipherKey, err := crypto.DecryptToKey(inner["key"].(string), env.orgKey)
		if err != nil {
			t.Fatalf("cipher key not wrapped by the org key: %v", err)
		}
		a2 := inner["attachments2"].(map[string]any)["att1"].(map[string]any)
		if k, err := crypto.DecryptToKey(a2["key"].(string), cipherKey); err != nil || k.B64() != attKey.B64() {
			t.Errorf("attachment key not re-wrapped: %v", err)
		}
		if dec(t, a2["fileName"].(string), cipherKey) != "a.txt" {
			t.Error("attachment file name")
		}
		out := r.Data.(*vault.CipherResponse)
		if out.OrganizationID.Get() != testOrgID || len(out.CollectionIDs) != 1 || out.CollectionIDs[0] != testCol1 ||
			len(out.Attachments) != 1 || out.Attachments[0].FileName.Get() != "a.txt" {
			t.Errorf("output %s", toJSON(t, out))
		}
		if sc := env.storedCipher(itemID); sc.OrganizationID == nil || len(sc.CollectionIDs) != 1 {
			t.Errorf("stored %+v", sc)
		}

		mustFail(t, MoveEncoded(env.a, itemID, testOrgID, b64(`["`+testCol1+`"]`)), "This item already belongs to an organization.")
	}
}

func TestMoveChecks(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.addCipher(loginItem("Personal", "pw"))
	mustFail(t, MoveEncoded(env.a, itemID, testOrgID, b64(`[]`)), "You must provide at least one collection id for this item.")
	mustFail(t, MoveEncoded(env.a, itemID, testOrgID, b64(`null`)), "You must provide at least one collection id for this item.")
	mustFail(t, MoveEncoded(env.a, itemID, testOrgID, "%%%"), "Error parsing the encoded request data.")
	mustFail(t, MoveEncoded(env.a, itemID, testOrgID, ""), "`requestJson` was not provided.")
	mustFail(t, Move(env.a, "missing", testOrgID, json.RawMessage(`["x"]`)), "Not found.")
	mustFail(t, Move(env.a, itemID, "bbbbbbbb-0000-0000-0000-000000000009", json.RawMessage(`["x"]`)), "Organization not found.")
	mustFail(t, Move(env.a, itemID, testOrgID, json.RawMessage(`["`+testCol2+`"]`)), "You do not have permission to add items to this collection.")
	mustFail(t, Move(env.a, itemID, testOrgID, json.RawMessage(`["unknown"]`)), "You do not have permission to add items to this collection.")

	legacy := loginItem("legacy", "pw")
	legacy.ID = "22222222-0000-0000-0000-0000000000aa"
	legacy.Attachments = []vault.AttachmentView{{ID: sp("old"), FileName: sp("old.txt")}}
	env.addCipher(legacy)
	mustFail(t, Move(env.a, legacy.ID, testOrgID, json.RawMessage(`["`+testCol1+`"]`)),
		"This cipher contains attachments without keys. Those attachments will need to be reuploaded to complete the operation")
}

func TestConfirm(t *testing.T) {
	env := newEnv(t, envOptions{})
	member := "99999999-0000-0000-0000-000000000001"
	memberUser := "99999999-0000-0000-0000-0000000000aa"
	status := 1
	env.fs.on("GET", "/api/organizations/"+testOrgID+"/users/"+member, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"id": member, "userId": memberUser, "status": status, "type": 2, "email": "m@example.com"})
	})
	pub, _ := x509.MarshalPKIXPublicKey(&testRSAKey().PublicKey)
	env.fs.on("GET", "/api/users/"+memberUser+"/public-key", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"userId": memberUser, "publicKey": base64.StdEncoding.EncodeToString(pub)})
	})
	env.fs.on("POST", "/api/organizations/"+testOrgID+"/users/"+member+"/confirm", func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(200)
	})
	r := Confirm(env.a, "org-member", member, ConfirmOptions{OrganizationID: testOrgID})
	mustSucceed(t, r)
	if r.Data != nil {
		t.Errorf("data %v", r.Data)
	}
	var req map[string]string
	_ = json.Unmarshal(env.fs.last("POST", "/api/organizations/"+testOrgID+"/users/"+member+"/confirm").Body, &req)
	key, err := crypto.RsaDecrypt(req["key"], testRSAKey())
	if err != nil || base64.StdEncoding.EncodeToString(key) != env.orgKey.B64() {
		t.Errorf("key does not decapsulate to the org key: %v", err)
	}
	if dec(t, req["defaultUserCollectionName"], env.orgKey) != "My Items" || len(req) != 2 {
		t.Errorf("request %v", req)
	}
	if q := env.fs.last("GET", "/api/organizations/"+testOrgID+"/users/"+member).Query; q != "" {
		t.Errorf("query %q", q)
	}

	for s, msg := range map[int]string{
		0:  "User must accept the invitation before they can be confirmed.",
		2:  "User is already confirmed.",
		-1: "User is revoked and cannot be confirmed.",
		7:  "User is not in a valid state to be confirmed.",
	} {
		status = s
		mustFail(t, Confirm(env.a, "org-member", member, ConfirmOptions{OrganizationID: testOrgID}), msg)
	}
	mustFail(t, Confirm(env.a, "org-member", member, ConfirmOptions{}), "--organizationid <organizationid> required.")
	mustFail(t, Confirm(env.a, "org-member", "x", ConfirmOptions{OrganizationID: testOrgID}), "`x` is not a GUID.")
	mustFail(t, Confirm(env.a, "org-member", member, ConfirmOptions{OrganizationID: "y"}), "`y` is not a GUID.")
	mustFail(t, Confirm(env.a, "org-member", member, ConfirmOptions{OrganizationID: "bbbbbbbb-0000-0000-0000-000000000009"}),
		"No encryption key for this organization.")
	mustFail(t, Confirm(env.a, "user", member, ConfirmOptions{OrganizationID: testOrgID}), "Unknown object.")
}
