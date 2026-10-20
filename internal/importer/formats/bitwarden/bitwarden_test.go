package bitwarden

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// ---------- bitwarden-csv-importer.spec.ts ----------

func orgCsv() importer.Importer { return NewCsv(importertest.OrgOptions("orgId")) }
func indCsv() importer.Importer { return NewCsv(importertest.Options()) }

func TestCsvEmpty(t *testing.T) {
	r := importertest.Parse(t, orgCsv(), "")
	if r.Success || len(r.Ciphers) != 0 {
		t.Fatal("expected failure")
	}
}

func TestCsvParse(t *testing.T) {
	data := "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp" +
		"\ncollection1/collection2,login,testlogin,testnotes,,0,https://example.com,testusername,testpassword,"
	r := importertest.Parse(t, orgCsv(), data)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "testlogin" || c.Type != model.CipherTypeLogin || c.Notes != "testnotes" || c.Reprompt != model.CipherRepromptNone ||
		c.Login.Username != "testusername" || c.Login.Password != "testpassword" || c.Login.Uris[0].Uri != "https://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Collections) != 2 || r.Collections[0].Name != "collection1/collection2" || r.Collections[1].Name != "collection1" {
		t.Fatalf("%s", importertest.Dump(r.Collections))
	}
}

func TestCsvSecureNote(t *testing.T) {
	r := importertest.Parse(t, orgCsv(), "name,type,notes\nTest Note,note,Some secure notes")
	c := r.Ciphers[0]
	if c.Name != "Test Note" || c.Type != model.CipherTypeSecureNote || c.Notes != "Some secure notes" ||
		c.SecureNote == nil || c.SecureNote.Type != model.SecureNoteTypeGeneric {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestCsvMissingFields(t *testing.T) {
	r := importertest.Parse(t, orgCsv(), "name,login_username,login_password,login_uri\nTest Login,username,password,http://example.com")
	c := r.Ciphers[0]
	if c.Name != "Test Login" || c.Type != model.CipherTypeLogin || c.Login.Username != "username" ||
		c.Login.Password != "password" || c.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestCsvCollections(t *testing.T) {
	r := importertest.Parse(t, orgCsv(), "name,collections\nTest Login,collection1/collection2")
	if len(r.Ciphers) != 1 || len(r.Collections) != 2 || r.Collections[0].Name != "collection1/collection2" || r.Collections[1].Name != "collection1" {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestCsvArchived(t *testing.T) {
	archivedDate := "2025-01-15T10:30:00.000Z"
	r := importertest.Parse(t, indCsv(), "name,type,archivedDate,login_uri,login_username,login_password\nArchived Login,login,"+archivedDate+",https://example.com,user,pass")
	c := r.Ciphers[0]
	if c.Name != "Archived Login" || c.ArchivedDate == nil || c.ArchivedDate.UTC().Format("2006-01-02T15:04:05.000Z") != archivedDate {
		t.Fatalf("%s", importertest.Dump(c))
	}
	r = importertest.Parse(t, indCsv(), "name,type,login_uri\nTest Login,login,https://example.com")
	if r.Ciphers[0].ArchivedDate != nil {
		t.Fatal("archivedDate should be unset")
	}
}

func TestCsvFolders(t *testing.T) {
	header := "folder,favorite,type,name,login_uri,login_username,login_password"
	r := importertest.Parse(t, indCsv(), header+"\nSocial,0,login,Facebook,https://facebook.com,user@example.com,password")
	if len(r.Folders) != 1 || r.Folders[0].Name != "Social" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	r = importertest.Parse(t, indCsv(), header+"\nSocial,0,login,Facebook,https://facebook.com,user1,pass1\nSocial,0,login,Twitter,https://twitter.com,user2,pass2")
	if len(r.Ciphers) != 2 || len(r.Folders) != 1 || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {1, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	r = importertest.Parse(t, indCsv(), header+"\nWork/Email,0,login,Gmail,https://gmail.com,user@work.com,pass")
	if len(r.Folders) != 2 || r.Folders[0].Name != "Work/Email" || r.Folders[1].Name != "Work" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	r = importertest.Parse(t, indCsv(), header+"\n,0,login,No Folder Item,https://example.com,user,pass")
	if len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestCsvOrgCollectionRelationships(t *testing.T) {
	header := "collections,type,name,login_uri,login_username,login_password"
	r := importertest.Parse(t, orgCsv(), header+"\ncol1,login,Item1,https://example.com,user1,pass1\ncol2,login,Item2,https://example.com,user2,pass2")
	if len(r.Collections) != 2 || !reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}, {1, 1}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	r = importertest.Parse(t, orgCsv(), header+"\nShared,login,Item1,https://example.com,user1,pass1\nShared,login,Item2,https://example.com,user2,pass2")
	if len(r.Collections) != 1 || r.Collections[0].Name != "Shared" || !reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}, {1, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestCsvFieldsAndUris(t *testing.T) {
	data := "name,type,fields,login_uri,favorite,reprompt\n" +
		`x,login,"a: 1` + "\n" + `b: c: 2` + "\n" + `nodelim` + "\n" + `empty: ",` + `"https://a.com,https://b.com",1,1`
	r := importertest.Parse(t, indCsv(), data)
	c := r.Ciphers[0]
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("a", "1"), importertest.F("b: c", "2"), importertest.F("empty", ""))
	if !reflect.DeepEqual(importertest.URIs(c), []string{"https://a.com", "https://b.com"}) || !c.Favorite || c.Reprompt != model.CipherRepromptPassword {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

// ---------- bitwarden JSON ----------

type fakeKeys struct {
	user *crypto.SymmetricKey
	orgs map[string]*crypto.SymmetricKey
}

func (k fakeKeys) UserKey() (*crypto.SymmetricKey, error) {
	if k.user == nil {
		return nil, errors.New("locked")
	}
	return k.user, nil
}
func (k fakeKeys) OrgKey(id string) (*crypto.SymmetricKey, error) { return k.orgs[id], nil }

func jsonImporter(t *testing.T, opts importer.Options) importer.Importer {
	t.Helper()
	imp, err := importer.New("bitwardenjson", opts)
	if err != nil {
		t.Fatal(err)
	}
	return imp
}

func TestJsonUnencrypted(t *testing.T) {
	imp := jsonImporter(t, importertest.Options())
	if r := importertest.Parse(t, imp, importertest.ReadFile(t, "emptyUnencryptedExport.txt")); !r.Success {
		t.Fatal("empty export should succeed")
	}
	// drops the per-cipher key so key-bearing exports import successfully
	r := importertest.Parse(t, imp, importertest.ReadFile(t, "unencryptedExportWithCipherKey.txt"))
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.ID != "" || c.Name != "login" || c.Notes != "note" || c.Login.Username != "username" || c.Login.Uris[0].Uri != "github.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestJsonCollections(t *testing.T) {
	data := importertest.ReadFile(t, "cipherWithCollections.txt")
	r := importertest.Parse(t, jsonImporter(t, importertest.OrgOptions("c6181652-66eb-4cd9-a7f2-b02a00e12352")), data)
	if len(r.Collections) != 1 || r.Collections[0].Name != "asdf" || r.Collections[0].OrganizationID != "" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}}) || r.Ciphers[0].Name != "asdf123" {
		t.Fatalf("%s", importertest.Dump(r))
	}
	// Individual import of an org export: no folder relationships.
	r = importertest.Parse(t, jsonImporter(t, importertest.Options()), data)
	if len(r.FolderRelationships) != 0 || len(r.CollectionRelationships) != 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestJsonFoldersAndHistory(t *testing.T) {
	var history []string
	for i := 0; i < 7; i++ {
		history = append(history, fmt.Sprintf(`{"password":"p%d","lastUsedDate":"2024-01-0%dT00:00:00.000Z"}`, i, i+1))
	}
	data := `{"encrypted":false,"folders":[{"id":"f1","name":"Folder"}],"items":[` +
		`{"id":"x","type":1,"name":"a","folderId":"f1","login":{"username":"u"},"passwordHistory":[` + strings.Join(history, ",") + `]},` +
		`{"id":"y","type":2,"name":"","secureNote":{"type":0},"folderId":"missing","notes":"  "}]}`
	r := importertest.Parse(t, jsonImporter(t, importertest.Options()), data)
	if len(r.Folders) != 1 || r.Folders[0].ID != "f1" || !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if len(r.Ciphers[0].PasswordHistory) != 5 || r.Ciphers[0].PasswordHistory[4].Password != "p4" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers[0].PasswordHistory))
	}
	note := r.Ciphers[1]
	if note.Name != "--" || note.Notes != "" || note.Login != nil || note.Type != model.CipherTypeSecureNote {
		t.Fatalf("%s", importertest.Dump(note))
	}
}

func TestJsonErrors(t *testing.T) {
	imp := jsonImporter(t, importertest.Options())
	if _, err := imp.Parse("{not json"); !importer.IsSyntaxError(err) {
		t.Fatalf("%v", err)
	}
	if r := importertest.Parse(t, imp, "null"); r.Success {
		t.Fatal("null should fail")
	}
	if r := importertest.Parse(t, imp, `{"encrypted":false}`); r.Success {
		t.Fatal("missing items should fail")
	}
	_, err := imp.Parse(`{"encrypted":false,"items":[{"type":5,"name":"k","sshKey":{"privateKey":"x"}}]}`)
	if err == nil || err.Error() != "SSH key public key is required." {
		t.Fatalf("%v", err)
	}
	_, err = NewJson(importertest.Options()).Parse(`{"encrypted":true,"items":[]}`)
	if err == nil || err.Error() != "Data is encrypted. Use BitwardenEncryptedJsonImporter instead." {
		t.Fatalf("%v", err)
	}
	_, err = NewEncryptedJson(importertest.Options()).Parse(`{"encrypted":true,"passwordProtected":true,"items":[]}`)
	if err == nil || err.Error() != "Data is password-protected. Use BitwardenPasswordProtectedImporter instead." {
		t.Fatalf("%v", err)
	}
}

// ---------- account encrypted (V1 vector from bitwarden-encrypted-json-importer.vectors.spec.ts) ----------

type vector struct {
	Account struct {
		Email  string `json:"email"`
		Method struct {
			MasterPasswordUnlock struct {
				Password string `json:"password"`
				Unlock   struct {
					Kdf struct {
						PBKDF2 struct {
							Iterations int `json:"iterations"`
						} `json:"pBKDF2"`
					} `json:"kdf"`
					MasterKeyWrappedUserKey string `json:"masterKeyWrappedUserKey"`
					Salt                    string `json:"salt"`
				} `json:"master_password_unlock"`
			} `json:"masterPasswordUnlock"`
		} `json:"method"`
	} `json:"account"`
	ExportJSON string `json:"exportJson"`
	Expected   struct {
		Folders []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"folders"`
		Ciphers []json.RawMessage `json:"ciphers"`
	} `json:"expected"`
}

func loadV1(t *testing.T) (vector, *crypto.SymmetricKey) {
	t.Helper()
	var v vector
	if err := json.Unmarshal([]byte(importertest.ReadFile(t, "account-encrypted-v1.json")), &v); err != nil {
		t.Fatal(err)
	}
	u := v.Account.Method.MasterPasswordUnlock
	mk, err := crypto.MakeMasterKey(u.Password, u.Unlock.Salt, crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: u.Unlock.Kdf.PBKDF2.Iterations})
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := crypto.DecryptToKey(u.Unlock.MasterKeyWrappedUserKey, crypto.StretchKey(mk))
	if err != nil {
		t.Fatal(err)
	}
	return v, userKey
}

func TestAccountEncryptedV1(t *testing.T) {
	v, userKey := loadV1(t)
	keys := fakeKeys{user: userKey}
	opts := importertest.Options()
	opts.Decryptor = LegacyDecryptor{AccountKeys: keys}
	r := importertest.Parse(t, jsonImporter(t, opts), v.ExportJSON)
	if !r.Success {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != v.Expected.Folders[0].Name || r.Folders[0].ID != v.Expected.Folders[0].ID {
		t.Fatalf("folders %s", importertest.Dump(r.Folders))
	}
	if len(r.Ciphers) != len(v.Expected.Ciphers) {
		t.Fatalf("ciphers %d", len(r.Ciphers))
	}
	var b JsonImporter
	for i, raw := range v.Expected.Ciphers {
		c, err := parseCipherExport(raw)
		if err != nil {
			t.Fatal(err)
		}
		want, err := c.toView(plain)
		if err != nil {
			t.Fatal(err)
		}
		want.ID, want.CollectionIDs = "", nil
		b.CleanupCipher(want)
		importertest.AssertEqualJSON(t, r.Ciphers[i], want)
	}
	// cipher 0 is in the folder and 3 (identity) too
	if !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {3, 0}}) {
		t.Fatalf("%v", r.FolderRelationships)
	}
	if got := r.Ciphers[0]; got.Login.Fido2Credentials[0].Counter != 0 || !got.Login.Fido2Credentials[0].Discoverable || got.Fields[4].LinkedID == nil {
		t.Fatalf("%s", importertest.Dump(got))
	}
}

func TestAccountEncryptedFailures(t *testing.T) {
	v, userKey := loadV1(t)
	opts := importertest.Options()

	// No decryptor (vault locked / not supplied).
	if _, err := jsonImporter(t, opts).Parse(v.ExportJSON); !errors.Is(err, ErrNoDecryptor) {
		t.Fatalf("%v", err)
	}

	// Wrong key → importEncKeyError.
	opts.Decryptor = LegacyDecryptor{AccountKeys: fakeKeys{user: crypto.GenerateKey()}}
	r := importertest.Parse(t, jsonImporter(t, opts), v.ExportJSON)
	if r.Success || r.ErrorMessage != importer.MsgImportEncKeyError || r.ErrorKey != "" {
		t.Fatalf("%s", importertest.Dump(r))
	}
	up := NewUpgradePasswordProtectedImporter(opts)
	if r := importertest.Parse(t, up, v.ExportJSON); r.ErrorKey != model.ImportResultErrorKeyAccountMismatch {
		t.Fatalf("upgrade errorKey %q", r.ErrorKey)
	}

	// Empty validation string (emptyAccountEncrypted).
	opts.Decryptor = LegacyDecryptor{AccountKeys: fakeKeys{user: userKey}}
	r = importertest.Parse(t, jsonImporter(t, opts), importertest.ReadFile(t, "emptyAccountEncrypted.txt"))
	if r.Success || r.ErrorMessage != importer.MsgImportEncKeyError {
		t.Fatalf("%s", importertest.Dump(r))
	}

	// Org import uses the org key when the account has it.
	orgKey := crypto.GenerateKey()
	validation, _ := crypto.EncryptString("x", orgKey)
	name, _ := crypto.EncryptString("Item", orgKey)
	colName, _ := crypto.EncryptString("Col", orgKey)
	orgExport := fmt.Sprintf(`{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":%q,"collections":[{"id":"c1","organizationId":"org","name":%q}],"items":[{"id":"i","type":2,"name":%q,"secureNote":{"type":0},"collectionIds":["c1"]}]}`, validation, colName, name)
	o := importertest.OrgOptions("org")
	o.Decryptor = LegacyDecryptor{AccountKeys: fakeKeys{user: userKey, orgs: map[string]*crypto.SymmetricKey{"org": orgKey}}}
	r = importertest.Parse(t, jsonImporter(t, o), orgExport)
	if !r.Success || r.Ciphers[0].Name != "Item" || r.Ciphers[0].OrganizationID != "org" || r.Collections[0].Name != "Col" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}

	// Blob ciphers need the vault decryptor.
	blob := fmt.Sprintf(`{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":%q,"folders":[],"items":[{"id":"i","type":1,"data":"{}"}]}`, validation)
	o.Decryptor = LegacyDecryptor{AccountKeys: fakeKeys{user: orgKey}}
	o.OrganizationID = ""
	if _, err := jsonImporter(t, o).Parse(blob); !errors.Is(err, ErrBlobCipher) {
		t.Fatalf("%v", err)
	}
}

// ---------- password protected (bitwarden-password-protected-importer.spec.ts) ----------

type ppDoc map[string]any

func makeProtected(t *testing.T, password string, kdf crypto.KdfConfig, payload string) ppDoc {
	t.Helper()
	salt := "c2FsdA=="
	key, err := deriveVaultExportKey(password, salt, kdf)
	if err != nil {
		t.Fatal(err)
	}
	validation, _ := crypto.EncryptString("8a1e9c0e-1d1b-4f5e-9d38-2bfa3c1e7b55", key)
	data, _ := crypto.EncryptString(payload, key)
	doc := ppDoc{"encrypted": true, "passwordProtected": true, "salt": salt, "kdfType": int(kdf.Type),
		"kdfIterations": kdf.Iterations, "encKeyValidation_DO_NOT_EDIT": validation, "data": data}
	if kdf.Memory != nil {
		doc["kdfMemory"] = *kdf.Memory
		doc["kdfParallelism"] = *kdf.Parallelism
	}
	return doc
}

func (d ppDoc) with(k string, v any) string {
	c := ppDoc{}
	for kk, vv := range d {
		c[kk] = vv
	}
	if v == "<delete>" {
		delete(c, k)
	} else {
		c[k] = v
	}
	b, _ := json.Marshal(c)
	return string(b)
}

const payload = `{"encrypted":false,"folders":[],"items":[{"type":1,"name":"inner","login":{"password":"pw"}}]}`

func protectedImporter(password string, prompted *int, upgrade bool) importer.Importer {
	o := importertest.Options()
	o.PromptPassword = func() (string, error) { *prompted++; return password, nil }
	if upgrade {
		return NewUpgradePasswordProtectedImporter(o)
	}
	return NewPasswordProtectedImporter(o)
}

func TestPasswordProtected(t *testing.T) {
	pbkdf2 := crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000}
	doc := makeProtected(t, "secret", pbkdf2, payload)
	prompted := 0

	r := importertest.Parse(t, protectedImporter("secret", &prompted, false), doc.with("x", nil))
	if !r.Success || len(r.Ciphers) != 1 || r.Ciphers[0].Name != "inner" || prompted != 1 {
		t.Fatalf("succeeds with default jdoc: %s", importertest.Dump(r))
	}

	for field, value := range map[string]any{
		"salt": nil, "kdfIterations": nil, "kdfType": nil, "encKeyValidation_DO_NOT_EDIT": nil, "data": nil,
	} {
		r := importertest.Parse(t, protectedImporter("secret", &prompted, false), doc.with(field, value))
		if r.Success {
			t.Errorf("fails if %s === null", field)
		}
	}
	for name, kdfType := range map[string]any{"not a string": "not a valid kdf type", "unknown": -1} {
		if r := importertest.Parse(t, protectedImporter("secret", &prompted, false), doc.with("kdfType", kdfType)); r.Success {
			t.Errorf("kdfType %s", name)
		}
	}
	if r := importertest.Parse(t, protectedImporter("secret", &prompted, false), doc.with("kdfIterations", "not a number")); r.Success {
		t.Error("kdfIterations not a number")
	}

	// Wrong / blank password.
	r = importertest.Parse(t, protectedImporter("wrong", &prompted, false), doc.with("x", nil))
	if r.Success || r.ErrorMessage != importer.MsgInvalidFilePassword || r.ErrorKey != "" {
		t.Fatalf("%s", importertest.Dump(r))
	}
	r = importertest.Parse(t, protectedImporter(" ", &prompted, true), doc.with("x", nil))
	if r.Success || r.ErrorKey != model.ImportResultErrorKeyInvalidFilePassword {
		t.Fatalf("%s", importertest.Dump(r))
	}

	// No prompt available (BW_NOINTERACTION without --passwordfile/--passwordenv).
	if _, err := NewPasswordProtectedImporter(importertest.Options()).Parse(doc.with("x", nil)); err == nil || err.Error() != importer.MsgImportPasswordRequired {
		t.Fatalf("%v", err)
	}
}

func TestPasswordProtectedKdfBounds(t *testing.T) {
	mem, par := 16, 1
	argon := crypto.KdfConfig{Type: crypto.KdfArgon2id, Iterations: 2, Memory: &mem, Parallelism: &par}
	doc := makeProtected(t, "secret", argon, payload)
	prompted := 0
	if r := importertest.Parse(t, protectedImporter("secret", &prompted, false), doc.with("x", nil)); !r.Success {
		t.Fatalf("in-range Argon2id: %s", importertest.Dump(r))
	}

	prompted = 0
	for name, mutate := range map[string][2]any{
		"kdfMemory out of bounds":   {"kdfMemory", 999999},
		"argon params missing":      {"kdfParallelism", "<delete>"},
		"PBKDF2 iterations too big": {"kdfIterations", 999999999},
	} {
		d := doc
		if name == "PBKDF2 iterations too big" {
			d = makeProtected(t, "secret", crypto.KdfConfig{Type: crypto.KdfPBKDF2, Iterations: 5000}, payload)
		}
		r := importertest.Parse(t, protectedImporter("secret", &prompted, false), d.with(mutate[0].(string), mutate[1]))
		if r.Success || r.ErrorMessage != importer.MsgImportUnsupportedKdfSettings {
			t.Errorf("%s: %s", name, importertest.Dump(r))
		}
	}
	if prompted != 0 {
		t.Fatal("must not prompt for a password when the KDF settings are rejected")
	}
}

func TestKdfConfigFromPasswordProtectedExport(t *testing.T) {
	file := func(kdf map[string]any) *exportFile {
		base := map[string]any{"encrypted": true, "passwordProtected": true, "salt": "c2FsdA==", "kdfType": 0,
			"kdfIterations": 600000, "encKeyValidation_DO_NOT_EDIT": "v", "data": "d"}
		for k, v := range kdf {
			if v == "<delete>" {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		b, _ := json.Marshal(base)
		// json.Marshal cannot express NaN/Infinity; JSON exports cannot contain them either.
		f, err := parseExportFile(string(b))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	accept := []map[string]any{
		{"kdfIterations": 600000}, {"kdfIterations": 5000}, {"kdfIterations": 100000}, {"kdfIterations": 2000000},
		{"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4},
		{"kdfType": 1, "kdfIterations": 10, "kdfMemory": 1024, "kdfParallelism": 16},
	}
	for _, a := range accept {
		if _, ok := kdfConfigFromPasswordProtectedExport(file(a)); !ok {
			t.Errorf("should accept %v", a)
		}
	}
	argon := func(k string, v any) map[string]any {
		m := map[string]any{"kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4}
		m[k] = v
		return m
	}
	reject := []map[string]any{
		{"kdfIterations": 2000001}, {"kdfIterations": 999999999}, {"kdfIterations": 4999}, {"kdfIterations": 0},
		{"kdfIterations": -1}, {"kdfIterations": 600000.5}, {"kdfIterations": nil}, {"kdfIterations": "<delete>"},
		{"kdfIterations": "600000"},
		argon("kdfMemory", 999999), argon("kdfMemory", 1025), argon("kdfMemory", 15), argon("kdfMemory", 64.5),
		argon("kdfMemory", nil), argon("kdfMemory", "<delete>"),
		argon("kdfParallelism", 17), argon("kdfParallelism", 0), argon("kdfParallelism", 4.5), argon("kdfParallelism", nil),
		argon("kdfIterations", 11), argon("kdfIterations", 999999999), argon("kdfIterations", 1), argon("kdfIterations", 3.5),
		argon("kdfIterations", nil),
		{"kdfType": -1}, {"kdfType": 2}, {"kdfType": nil}, {"kdfType": "<delete>"}, {"kdfType": "PBKDF2"},
	}
	for _, r := range reject {
		if _, ok := kdfConfigFromPasswordProtectedExport(file(r)); ok {
			t.Errorf("should reject %v", r)
		}
	}
}

func TestPasswordProtectedFallsThrough(t *testing.T) {
	prompted := 0
	r := importertest.Parse(t, protectedImporter("x", &prompted, false), importertest.ReadFile(t, "emptyUnencryptedExport.txt"))
	if !r.Success || prompted != 0 {
		t.Fatal("unencrypted export should parse without prompting")
	}
	if r := importertest.Parse(t, protectedImporter("x", &prompted, false), "null"); r.Success {
		t.Fatal("null")
	}
}
