package exporter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	tOrgID  = "11111111-1111-4111-8111-111111111111"
	tUserID = "44444444-4444-4444-4444-444444444444"
	tFolder = "f0000000-0000-4000-8000-000000000001"
	tCol1   = "c0000000-0000-4000-8000-000000000001"
	tCol2   = "c0000000-0000-4000-8000-000000000002"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSA() *rsa.PrivateKey {
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

func sp(s string) *string { return &s }

func tp(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return &t
}

var (
	created = *tp("2024-01-02T03:04:05.678Z")
	revised = *tp("2024-02-03T04:05:06.789Z")
)

type fixture struct {
	v2          bool
	userKey     *crypto.SymmetricKey
	orgKey      *crypto.SymmetricKey
	keys        *vault.Keys
	acct        *state.Account
	vault       *vault.Vault
	client      *fakeClient
	attachments map[string][]byte // plain attachment content by attachment id
}

type fakeClient struct {
	org       *OrganizationExportResponse
	orgCalls  int
	urls      map[string]string // cipherId/attachmentId -> url
	downloads map[string][]byte // url -> encrypted content
}

func (f *fakeClient) GetOrganizationExport(id string) (*OrganizationExportResponse, error) {
	f.orgCalls++
	if id != tOrgID {
		return nil, errors.New("Resource not found.")
	}
	return f.org, nil
}

func (f *fakeClient) GetAttachmentData(cipherID, attachmentID string) (string, error) {
	u, ok := f.urls[cipherID+"/"+attachmentID]
	if !ok {
		return "", errors.New("Resource not found.")
	}
	return u, nil
}

func (f *fakeClient) DownloadAttachment(url string) ([]byte, error) {
	b, ok := f.downloads[url]
	if !ok {
		return nil, errors.New("Error downloading attachment")
	}
	return b, nil
}

type cipherSpec struct {
	view        *vault.CipherView
	attachments map[string]string // attachment id -> plain content
}

// baseView returns a cipher view with fixed dates.
func baseView(id, name string, typ vault.CipherType) *vault.CipherView {
	v := vault.NewCipherView()
	v.ID, v.Name, v.Type = id, name, typ
	v.CreationDate, v.RevisionDate = created, revised
	return v
}

func personalCiphers() []cipherSpec {
	gh := baseView("a0000000-0000-4000-8000-000000000001", "GitHub", vault.CipherTypeLogin)
	gh.FolderID = sp(tFolder)
	gh.Favorite = true
	gh.Notes = sp("line1\nline2")
	gh.Reprompt = vault.RepromptPassword
	gh.ArchivedDate = tp("2024-03-04T05:06:07.890Z")
	gh.Login.Username = sp("octo")
	gh.Login.Password = sp(`p@ss,"word"`)
	gh.Login.Totp = sp("JBSWY3DPEHPK3PXP")
	gh.Login.URIs = []vault.LoginURIView{{URI: sp("https://github.com")}, {URI: sp("https://gh.io")}}
	gh.Fields = []vault.FieldView{
		{Name: sp("PIN"), Value: sp("1234"), Type: vault.FieldTypeText},
		{Name: sp("flag"), Value: sp("true"), Type: vault.FieldTypeBoolean},
	}
	gh.PasswordHistory = []vault.PasswordHistoryView{{Password: sp("old"), LastUsedDate: tp("2023-12-31T23:59:59.000Z")}}

	note := baseView("a0000000-0000-4000-8000-000000000002", "Note ", vault.CipherTypeSecureNote)
	note.Notes = sp(" leading")

	card := baseView("a0000000-0000-4000-8000-000000000003", "Visa", vault.CipherTypeCard)
	card.Card.CardholderName = sp("Jane Doe")
	card.Card.Number = sp("4242424242424242")

	deleted := baseView("a0000000-0000-4000-8000-000000000004", "Old", vault.CipherTypeLogin)
	deleted.DeletedDate = tp("2024-05-01T00:00:00.000Z")

	// Same names: logins with different usernames so the vault's name sort is deterministic.
	files := baseView("a0000000-0000-4000-8000-000000000005", "Files/Docs", vault.CipherTypeLogin)
	files.Login.Username = sp("a")
	files.Attachments = []vault.AttachmentView{
		{ID: sp("att1"), FileName: sp("report.final.pdf"), Key: crypto.GenerateKey(), Size: sp("5"), SizeName: sp("5 Bytes")},
		{ID: sp("att2"), FileName: sp("a:b.txt"), Key: crypto.GenerateKey(), Size: sp("2"), SizeName: sp("2 Bytes")},
		{ID: sp("att3"), FileName: sp("report.final.pdf"), Key: crypto.GenerateKey(), Size: sp("3"), SizeName: sp("3 Bytes")},
	}
	files2 := baseView("a0000000-0000-4000-8000-000000000006", "Files/Docs", vault.CipherTypeLogin)
	files2.Login.Username = sp("b")
	files2.Attachments = []vault.AttachmentView{
		{ID: sp("att4"), FileName: sp("noext"), Size: sp("1"), SizeName: sp("1 Bytes")}, // legacy: no attachment key
		{ID: sp("att5"), FileName: sp("missing.bin"), Key: crypto.GenerateKey(), Size: sp("1"), SizeName: sp("1 Bytes")},
	}
	return []cipherSpec{
		{view: gh}, {view: note}, {view: card}, {view: deleted},
		{view: files, attachments: map[string]string{"att1": "hello", "att2": "hi", "att3": "two"}},
		{view: files2, attachments: map[string]string{"att4": "x"}}, // att5 cannot be downloaded
	}
}

func orgCiphers() []*vault.CipherView {
	org := tOrgID
	shared := baseView("b0000000-0000-4000-8000-000000000001", "Shared", vault.CipherTypeLogin)
	shared.OrganizationID = &org
	shared.CollectionIDs = []string{tCol1, tCol2}
	shared.Login.Username = sp("team")
	shared.Login.Password = sp("pw")
	shared.Login.URIs = []vault.LoginURIView{{URI: sp("https://team.example.com")}}

	onlyOne := baseView("b0000000-0000-4000-8000-000000000002", "Team note", vault.CipherTypeSecureNote)
	onlyOne.OrganizationID = &org
	onlyOne.CollectionIDs = []string{tCol2}
	onlyOne.Notes = sp("note")

	card := baseView("b0000000-0000-4000-8000-000000000003", "Corp card", vault.CipherTypeCard)
	card.OrganizationID = &org
	card.CollectionIDs = []string{tCol1}

	gone := baseView("b0000000-0000-4000-8000-000000000004", "Gone", vault.CipherTypeLogin)
	gone.OrganizationID = &org
	gone.DeletedDate = tp("2024-05-01T00:00:00.000Z")
	return []*vault.CipherView{shared, onlyOne, card, gone}
}

type fixtureOpts struct {
	v2       bool
	policies []string
	kdf      *crypto.KdfConfig
	manage   bool
}

func newFixture(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()
	priv := testRSA()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{v2: o.v2, orgKey: crypto.GenerateKey(), attachments: map[string][]byte{},
		client: &fakeClient{urls: map[string]string{}, downloads: map[string][]byte{}}}
	if o.v2 {
		if f.userKey, err = crypto.GenerateKeyFor(crypto.AlgXChaCha20Poly1305); err != nil {
			t.Fatal(err)
		}
	} else {
		f.userKey = crypto.GenerateKey()
	}
	encPriv, err := crypto.Encrypt(der, f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	encOrg, err := crypto.RsaEncrypt(f.orgKey.Bytes(), &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]any{
		"id": tUserID, "email": "user@example.com",
		"organizations": []any{map[string]any{
			"id": tOrgID, "name": "Acme", "key": encOrg, "status": 2, "type": 2, "enabled": true,
			"usePolicies": true, "useEvents": true,
		}},
	})
	var accountKeys json.RawMessage
	if o.v2 {
		accountKeys = json.RawMessage(`{"signatureKeyPair":{"wrappedSigningKey":"x","verifyingKey":"y"}}`)
	}
	kdf := crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000}
	if o.kdf != nil {
		kdf = *o.kdf
	}
	f.acct = &state.Account{UserID: tUserID, Email: "user@example.com", EncPrivateKey: encPriv.String(),
		AccountKeys: accountKeys, Kdf: kdf, Vault: state.VaultData{Profile: profile,
			Ciphers: map[string]json.RawMessage{}, Folders: map[string]json.RawMessage{}, Collections: map[string]json.RawMessage{}}}
	for _, p := range o.policies {
		f.acct.Vault.Policies = append(f.acct.Vault.Policies, json.RawMessage(p))
	}
	var prof vault.Profile
	if err := json.Unmarshal(profile, &prof); err != nil {
		t.Fatal(err)
	}
	f.keys = vault.NewKeys(f.userKey, f.acct.EncPrivateKey, accountKeys, &prof)
	if !f.keys.HasOrgKey(tOrgID) {
		t.Fatal("org key not decrypted")
	}

	encrypt := func(v *vault.CipherView) (json.RawMessage, *vault.Cipher, *crypto.SymmetricKey) {
		c, ck, err := vault.EncryptCipher(v, f.keys)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw, c, ck
	}
	for _, spec := range personalCiphers() {
		raw, _, ck := encrypt(spec.view)
		f.acct.Vault.Ciphers[spec.view.ID] = raw
		for _, a := range spec.view.Attachments {
			content, ok := spec.attachments[*a.ID]
			if !ok {
				continue
			}
			key := a.Key
			if key == nil {
				key = ck
			}
			enc, err := crypto.EncryptBytes([]byte(content), key)
			if err != nil {
				t.Fatal(err)
			}
			url := "https://files.example/" + *a.ID
			f.client.urls[spec.view.ID+"/"+*a.ID] = url
			f.client.downloads[url] = enc
			f.attachments[*a.ID] = []byte(content)
		}
	}
	org := &OrganizationExportResponse{}
	for _, v := range orgCiphers() {
		raw, _, _ := encrypt(v)
		org.Ciphers = append(org.Ciphers, raw)
		if v.DeletedDate == nil && v.Type != vault.CipherTypeCard {
			f.acct.Vault.Ciphers[v.ID] = raw
		}
	}
	for i, c := range []struct{ id, name string }{{tCol1, "Engineering"}, {tCol2, "Ops, Team"}} {
		enc, err := crypto.EncryptString(c.name, f.orgKey)
		if err != nil {
			t.Fatal(err)
		}
		manage := o.manage && i == 0
		raw, _ := json.Marshal(map[string]any{"id": c.id, "organizationId": tOrgID, "name": enc,
			"externalId": nil, "readOnly": false, "manage": manage, "hidePasswords": false, "type": 0})
		org.Collections = append(org.Collections, raw)
		f.acct.Vault.Collections[c.id] = raw
	}
	f.client.org = org

	fname, err := crypto.EncryptString("Work", f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	f.acct.Vault.Folders[tFolder] = json.RawMessage(`{"id":"` + tFolder + `","name":"` + fname + `","revisionDate":"2024-01-01T00:00:00.000Z"}`)

	if f.vault, err = vault.New(f.acct, f.userKey, nil); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) service() *Service {
	return &Service{Vault: f.vault, Kdf: f.acct.Kdf, API: f.client,
		Now:      func() time.Time { return time.Date(2024, 7, 8, 9, 10, 11, 0, time.Local) },
		LogError: func(string, error) {}}
}
