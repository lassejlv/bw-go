package vault

import (
	"encoding/json"
	"testing"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

func encryptedRaw(t *testing.T, env *testEnv, v *CipherView) json.RawMessage {
	t.Helper()
	c, _, err := EncryptCipher(v, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestVault(t *testing.T) (*Vault, *testEnv, *state.Account) {
	t.Helper()
	env := newTestEnv(t)
	profile, _ := json.Marshal(env.profile)
	acct := &state.Account{UserID: testUserID, EncPrivateKey: env.encPriv, Vault: state.VaultData{
		Profile: profile, Ciphers: map[string]json.RawMessage{}, Folders: map[string]json.RawMessage{},
		Collections: map[string]json.RawMessage{},
	}}
	mk := func(id, name string, org *string) {
		v := NewCipherView()
		v.ID, v.Name, v.OrganizationID = id, name, org
		v.Login.Username = sp("user-" + name)
		v.Login.URIs = []LoginURIView{{URI: sp("https://" + name + ".example.com")}}
		acct.Vault.Ciphers[id] = encryptedRaw(t, env, v)
	}
	org := testOrgID
	missing := "99999999-9999-9999-9999-999999999999"
	env.keys.SetOrgKey(missing, crypto.GenerateKey()) // only the test encryptor knows this key
	mk("c2", "zeta", nil)
	mk("c1", "alpha", &org)
	mk("c3", "missing-org", &missing)
	// an undecryptable personal cipher
	bad := NewCipherView()
	bad.ID, bad.Name = "c4", "bad"
	other := &Keys{userKey: crypto.GenerateKey(), orgKeys: map[string]*crypto.SymmetricKey{}, orgErrs: map[string]error{}}
	c, _, _ := EncryptCipher(bad, other)
	b, _ := json.Marshal(c)
	acct.Vault.Ciphers["c4"] = b
	fname, _ := crypto.EncryptString("Work", env.userKey)
	acct.Vault.Folders["f1"] = json.RawMessage(`{"Id":"f1","Name":"` + fname + `","RevisionDate":"2024-01-01T00:00:00Z"}`)
	cname, _ := crypto.EncryptString("Engineering", env.orgKey)
	acct.Vault.Collections["col1"] = json.RawMessage(`{"id":"col1","organizationId":"` + testOrgID + `","name":"` + cname + `","externalId":null}`)
	acct.Vault.Policies = []json.RawMessage{json.RawMessage(`{"id":"p1","organizationId":"` + testOrgID + `","type":15,"enabled":true,"data":null}`)}
	acct.Vault.Domains = json.RawMessage(`{"equivalentDomains":[["alpha.example.com","zeta.example.com"]],"globalEquivalentDomains":[]}`)

	var persisted []string
	v, err := New(acct, env.userKey, func(fn func(a *state.Account) error) error {
		persisted = append(persisted, "x")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, env, acct
}

func TestVaultService(t *testing.T) {
	v, env, _ := newTestVault(t)
	cs := v.Ciphers()
	if len(cs) != 2 || cs[0].Name != "alpha" || cs[1].Name != "zeta" {
		t.Fatalf("ciphers %+v", cs)
	}
	if f := v.FailedCiphers(); len(f) != 1 || f[0].ID != "c4" || f[0].Name != DecryptError {
		t.Fatalf("failed %+v", f)
	}
	if _, err := v.Cipher("nope"); err != ErrNotFound {
		t.Fatal("not found")
	}
	if c, err := v.Cipher("c2"); err != nil || c.Name != "zeta" {
		t.Fatal("cipher by id")
	}
	folders := v.Folders()
	if len(folders) != 2 || folders[0].Name != "Work" || folders[1].ID != "" || folders[1].Name != NoFolderName {
		t.Fatalf("folders %+v", folders)
	}
	cols := v.Collections()
	if len(cols) != 1 || cols[0].Name != "Engineering" {
		t.Fatalf("collections %+v", cols)
	}
	if len(v.MemberOrganizations()) != 1 || len(v.Organizations()) != 2 {
		t.Fatal("organizations")
	}
	// URL matching uses equivalent domains (exact registrable domain lists).
	if got := v.CiphersForURL("https://alpha.example.com", nil); len(got) != 2 {
		t.Fatalf("url match %d", len(got))
	}
	// Restricted item types: cards restricted by the user's org policy.
	card := NewCipherView()
	card.Type = CipherTypeCard
	if !v.IsCipherRestricted(card) {
		t.Fatal("card should be restricted")
	}

	// Upsert a server response with collectionIds override.
	nv := NewCipherView()
	nv.ID, nv.Name = "c9", "new"
	raw := encryptedRaw(t, env, nv)
	view, err := v.UpsertCipher(raw, []string{"col1"})
	if err != nil || view == nil || view.Name != "new" || len(view.CollectionIDs) != 1 {
		t.Fatalf("upsert %+v %v", view, err)
	}
	if len(v.Ciphers()) != 3 {
		t.Fatal("cache not invalidated")
	}
	if err := v.SoftDeleteCiphers("c9"); err != nil {
		t.Fatal(err)
	}
	c9, _ := v.Cipher("c9")
	if !c9.IsDeleted() {
		t.Fatal("soft delete")
	}
	if err := v.RestoreCipher("c9", "2025-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	c9, _ = v.Cipher("c9")
	if c9.IsDeleted() || c9.RevisionDate.Year() != 2025 {
		t.Fatal("restore")
	}
	if err := v.DeleteCiphers("c9"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Cipher("c9"); err != ErrNotFound {
		t.Fatal("delete")
	}
	// Folder upsert/delete clears folderId on ciphers.
	fname, _ := crypto.EncryptString("Home", env.userKey)
	if f, err := v.UpsertFolder(json.RawMessage(`{"id":"f2","name":"` + fname + `"}`)); err != nil || f.Name != "Home" {
		t.Fatal("folder upsert")
	}
	_ = v.PatchCipher("c2", map[string]any{"folderId": "f2"})
	if c, _ := v.Cipher("c2"); c.FolderID == nil || *c.FolderID != "f2" {
		t.Fatal("patch")
	}
	_ = v.DeleteFolder("f2")
	if c, _ := v.Cipher("c2"); c.FolderID != nil {
		t.Fatal("folder delete should clear folderId")
	}
}
