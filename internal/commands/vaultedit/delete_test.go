package vaultedit

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

func TestDeleteItem(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.addCipher(loginItem("x", "y"))
	env.fs.on("PUT", "/api/ciphers/"+itemID+"/delete", func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	env.fs.on("DELETE", "/api/ciphers/"+itemID, func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })

	r := Delete(env.a, "item", itemID, DeleteOptions{})
	mustSucceed(t, r)
	if r.Data != nil {
		t.Errorf("data %v", r.Data)
	}
	if !env.storedCipher(itemID).IsDeleted() {
		t.Error("soft delete should set deletedDate")
	}
	mustSucceed(t, Delete(env.a, "ITEM", itemID, DeleteOptions{Permanent: true}))
	if _, err := env.vault().EncryptedCipher(itemID); err == nil {
		t.Error("permanent delete should remove the cipher")
	}
	mustFail(t, Delete(env.a, "item", itemID, DeleteOptions{}), "Not found.")

	noPerm := loginItem("np", "y")
	noPerm.ID = "22222222-0000-0000-0000-00000000000f"
	noPerm.Permissions = &vault.CipherPermissions{}
	env.addCipher(noPerm)
	mustFail(t, Delete(env.a, "item", noPerm.ID, DeleteOptions{}), "You do not have permission to delete this item.")
	mustFail(t, Delete(env.a, "thing", noPerm.ID, DeleteOptions{}), "Unknown object.")
}

func TestDeleteRestrictedItem(t *testing.T) {
	env := newEnv(t, envOptions{policies: []string{
		`{"id":"p1","organizationId":"` + testOrgID + `","type":15,"enabled":true,"data":[3]}`,
	}})
	card := vault.NewCipherView()
	card.ID, card.Name, card.Type = itemID, "Visa", vault.CipherTypeCard
	card.Permissions = &vault.CipherPermissions{Delete: true, Restore: true}
	env.addCipher(card)
	mustFail(t, Delete(env.a, "item", itemID, DeleteOptions{}), "Deleting this item type is restricted by organizational policy.")
}

func TestDeleteAttachment(t *testing.T) {
	env := newEnv(t, envOptions{premium: true})
	item := loginItem("x", "y")
	item.Attachments = []vault.AttachmentView{
		{ID: sp("att1"), FileName: sp("a.txt"), Size: sp("1"), SizeName: sp("1 Bytes"), URL: sp("u1"), Key: crypto.GenerateKey()},
		{ID: sp("att2"), FileName: sp("b.txt"), Size: sp("2"), SizeName: sp("2 Bytes"), URL: sp("u2"), Key: crypto.GenerateKey()},
	}
	env.addCipher(item)
	env.fs.on("DELETE", "/api/ciphers/"+itemID+"/attachment/att1", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"cipher": map[string]any{"id": itemID, "revisionDate": serverRev}})
	})
	mustSucceed(t, Delete(env.a, "attachment", "ATT1", DeleteOptions{ItemID: itemID}))
	sv := env.storedView(itemID)
	if len(sv.Attachments) != 1 || *sv.Attachments[0].ID != "att2" || *sv.Attachments[0].FileName != "b.txt" {
		t.Errorf("attachments %+v", sv.Attachments)
	}
	if sv.RevisionDate.Format(time.RFC3339Nano) != "2024-05-01T10:00:00.123Z" {
		t.Errorf("revision date %v", sv.RevisionDate)
	}

	mustFail(t, Delete(env.a, "attachment", "att1", DeleteOptions{}), "`itemid` option is required.")
	mustFail(t, Delete(env.a, "attachment", "att9", DeleteOptions{ItemID: itemID}), "Attachment `att9` was not found.")
	plain := loginItem("plain", "y")
	plain.ID = "22222222-0000-0000-0000-00000000000e"
	env.addCipher(plain)
	mustFail(t, Delete(env.a, "attachment", "att1", DeleteOptions{ItemID: plain.ID}), "No attachments available for this item.")

	env.setProfile(func(p map[string]any) { p["premium"] = false })
	mustFail(t, Delete(env.a, "attachment", "att2", DeleteOptions{ItemID: itemID}), "Premium status is required to use this feature.")

	// server errors are reported with their single message
	env.setProfile(func(p map[string]any) { p["premium"] = true })
	env.fs.on("DELETE", "/api/ciphers/"+itemID+"/attachment/att2", func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(400)
		writeJSON(w, map[string]any{"message": "Nope."})
	})
	mustFail(t, Delete(env.a, "attachment", "att2", DeleteOptions{ItemID: itemID}), "Nope.")
}

func TestDeleteFolder(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.addFolder("f1", "Work")
	item := loginItem("x", "y")
	item.FolderID = sp("f1")
	env.addCipher(item)
	env.fs.on("DELETE", "/api/folders/f1", func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	mustSucceed(t, Delete(env.a, "folder", "F1", DeleteOptions{}))
	if _, err := env.vault().Folder("f1"); err == nil {
		t.Error("folder not removed")
	}
	if env.storedCipher(itemID).FolderID != nil {
		t.Error("folderId not cleared")
	}
	mustFail(t, Delete(env.a, "folder", "f1", DeleteOptions{}), "Not found.")
}

func TestDeleteOrgCollection(t *testing.T) {
	env := newEnv(t, envOptions{})
	env.fs.on("DELETE", "/api/organizations/"+testOrgID+"/collections/"+testCol1, func(w http.ResponseWriter, r *http.Request, body []byte) {
		w.WriteHeader(200)
	})
	mustSucceed(t, Delete(env.a, "org-collection", testCol1, DeleteOptions{OrganizationID: testOrgID}))
	mustFail(t, Delete(env.a, "org-collection", testCol1, DeleteOptions{}), "`organizationid` options is required.")
	mustFail(t, Delete(env.a, "org-collection", "x", DeleteOptions{OrganizationID: testOrgID}), "`x` is not a GUID.")
	mustFail(t, Delete(env.a, "org-collection", testCol1, DeleteOptions{OrganizationID: "y"}), "`y` is not a GUID.")
}

func TestRestore(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := loginItem("x", "y")
	deleted := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	item.DeletedDate = &deleted
	env.addCipher(item)
	env.fs.on("PUT", "/api/ciphers/"+itemID+"/restore", func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, map[string]any{"id": itemID, "revisionDate": serverRev})
	})
	mustSucceed(t, Restore(env.a, "item", itemID))
	sv := env.storedView(itemID)
	if sv.IsDeleted() || sv.RevisionDate.Format(time.RFC3339Nano) != "2024-05-01T10:00:00.123Z" {
		t.Errorf("restored %+v", sv)
	}
	mustFail(t, Restore(env.a, "item", itemID), "Cipher is not in trash.")
	mustFail(t, Restore(env.a, "folder", itemID), "Unknown object.")
	mustFail(t, Restore(env.a, "item", "missing"), "Not found.")

	// no restore permission
	np := loginItem("np", "y")
	np.ID = "22222222-0000-0000-0000-00000000000d"
	np.DeletedDate = &deleted
	np.Permissions = &vault.CipherPermissions{Delete: true}
	env.addCipher(np)
	mustFail(t, Restore(env.a, "item", np.ID), "You do not have permission to restore this item")
}

func TestRestoreArchived(t *testing.T) {
	env := newEnv(t, envOptions{})
	item := loginItem("x", "y")
	org := testOrgID
	item.OrganizationID = &org
	item.CollectionIDs = []string{testCol1}
	archived := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	item.ArchivedDate = &archived
	stored := env.addCipher(item)
	env.fs.on("PUT", "/api/ciphers/unarchive", func(w http.ResponseWriter, r *http.Request, body []byte) {
		raw, _ := json.Marshal(stored)
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		c["archivedDate"] = nil
		c["revisionDate"] = serverRev
		delete(c, "collectionIds")
		writeJSON(w, map[string]any{"data": []any{c}, "object": "list", "continuationToken": nil})
	})
	mustSucceed(t, Restore(env.a, "item", itemID))
	if body := string(env.fs.last("PUT", "/api/ciphers/unarchive").Body); body != `{"ids":["`+itemID+`"]}` {
		t.Errorf("body %s", body)
	}
	sc := env.storedCipher(itemID)
	if sc.IsArchived() || len(sc.CollectionIDs) != 1 || sc.CollectionIDs[0] != testCol1 {
		t.Errorf("stored %+v", sc)
	}
}

func TestArchive(t *testing.T) {
	env := newEnv(t, envOptions{})
	stored := env.addCipher(loginItem("x", "y"))
	mustFail(t, Archive(env.a, "item", itemID), "Premium status is required to use this feature.")
	env.setProfile(func(p map[string]any) { p["premium"] = true })
	env.fs.on("PUT", "/api/ciphers/archive", func(w http.ResponseWriter, r *http.Request, body []byte) {
		raw, _ := json.Marshal(stored)
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		c["archivedDate"] = serverRev
		writeJSON(w, map[string]any{"data": []any{c}})
	})
	mustSucceed(t, Archive(env.a, "Item", itemID))
	if body := string(env.fs.last("PUT", "/api/ciphers/archive").Body); body != `{"ids":["`+itemID+`"]}` {
		t.Errorf("body %s", body)
	}
	if !env.storedCipher(itemID).IsArchived() {
		t.Error("not archived locally")
	}
	mustFail(t, Archive(env.a, "item", itemID), "Item is already archived.")
	mustFail(t, Archive(env.a, "folder", itemID), "Unknown object.")

	del := loginItem("d", "y")
	del.ID = "22222222-0000-0000-0000-00000000000c"
	now := time.Now()
	del.DeletedDate = &now
	env.addCipher(del)
	mustFail(t, Archive(env.a, "item", del.ID), "Item is in the trash, the item must be restored before archiving.")
}
