package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
)

func TestKeys(t *testing.T) {
	env := newTestEnv(t)
	if _, err := env.keys.PrivateKey(); err != nil {
		t.Fatal(err)
	}
	k, err := env.keys.OrgKey(testOrgID)
	if err != nil || !reflect.DeepEqual(k.Bytes(), env.orgKey.Bytes()) {
		t.Fatalf("org key mismatch: %v", err)
	}
	if _, err := env.keys.ProviderKey(testProviderID); err != nil {
		t.Fatal(err)
	}
	if !env.keys.HasOrgKey(testProvOrgID) {
		t.Fatal("provider org key not decrypted")
	}
	if _, err := env.keys.OrgKey("nope"); err == nil {
		t.Fatal("expected error for unknown org")
	}
	if env.keys.SecurityVersion != 1 {
		t.Fatalf("security version %d", env.keys.SecurityVersion)
	}
	orgs := BuildOrganizations(env.profile)
	if len(orgs) != 2 || !orgs[0].IsMember || orgs[1].IsMember || !orgs[1].IsProviderUser {
		t.Fatalf("unexpected orgs %+v", orgs)
	}
}

func fullLoginView() *CipherView {
	v := NewCipherView()
	v.ID = "aaaaaaaa-0000-0000-0000-000000000001"
	v.Name = "My <Login> & co"
	v.Notes = sp("some notes")
	v.Favorite = true
	v.Reprompt = RepromptPassword
	v.CollectionIDs = []string{}
	v.CreationDate = tm("2024-01-01T10:00:00Z")
	v.RevisionDate = tm("2024-01-02T10:00:00.123Z")
	m := UriMatchHost
	linked := LinkedID(100)
	v.Login = &LoginView{
		Username:             sp("alice"),
		Password:             sp("secret"),
		PasswordRevisionDate: tp("2024-01-01T11:00:00Z"),
		Totp:                 sp("JBSWY3DPEHPK3PXP"),
		URIs:                 []LoginURIView{{URI: sp("https://example.com/login")}, {URI: sp("https://other.org"), Match: &m}},
		Fido2Credentials: []Fido2CredentialView{{
			CredentialID: "cred", KeyType: "public-key", KeyAlgorithm: "ECDSA", KeyCurve: "P-256", KeyValue: "kv",
			RpID: "example.com", UserName: sp("alice"), Counter: "7", Discoverable: true,
			CreationDate: tp("2024-01-01T09:00:00Z"),
		}},
	}
	v.Fields = []FieldView{
		{Name: sp("text"), Value: sp("v1"), Type: FieldTypeText},
		{Name: sp("hidden"), Value: sp("h1"), Type: FieldTypeHidden},
		{Name: sp("linked"), Type: FieldTypeLinked, LinkedID: &linked},
	}
	v.PasswordHistory = []PasswordHistoryView{{Password: sp("old"), LastUsedDate: tp("2023-12-31T00:00:00Z")}}
	return v
}

func TestCipherRoundTripLogin(t *testing.T) {
	env := newTestEnv(t)
	v := fullLoginView()
	enc, out := roundTrip(t, env, v)
	if enc.Key == nil {
		t.Fatal("a cipher key must be generated")
	}
	if enc.Login.URIs[0].URIChecksum == nil {
		t.Fatal("uri checksum missing")
	}
	if out.Name != v.Name || *out.Notes != *v.Notes || !out.Favorite || out.Reprompt != RepromptPassword {
		t.Fatalf("metadata mismatch: %+v", out)
	}
	if out.Key == nil {
		t.Fatal("decrypted view should carry the cipher key")
	}
	l := out.Login
	if *l.Username != "alice" || *l.Password != "secret" || *l.Totp != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("login mismatch %+v", l)
	}
	if len(l.URIs) != 2 || *l.URIs[1].Match != UriMatchHost || l.URIs[0].Match != nil {
		t.Fatalf("uris mismatch %+v", l.URIs)
	}
	if len(l.Fido2Credentials) != 1 || l.Fido2Credentials[0].Counter != "7" || !l.Fido2Credentials[0].Discoverable {
		t.Fatalf("fido2 mismatch %+v", l.Fido2Credentials)
	}
	if len(out.Fields) != 3 || *out.Fields[1].Value != "h1" || *out.Fields[2].LinkedID != 100 || out.Fields[2].Value != nil {
		t.Fatalf("fields mismatch %+v", out.Fields)
	}
	if len(out.PasswordHistory) != 1 || *out.PasswordHistory[0].Password != "old" {
		t.Fatalf("history mismatch")
	}
	// Re-encrypting keeps the existing cipher key.
	enc2, _, err := EncryptCipher(out, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := crypto.DecryptToKey(*enc.Key, env.userKey)
	k2, _ := crypto.DecryptToKey(*enc2.Key, env.userKey)
	if k1.B64() != k2.B64() {
		t.Fatal("existing cipher key was not kept")
	}
}

func TestCipherRoundTripOtherTypes(t *testing.T) {
	env := newTestEnv(t)
	org := testOrgID
	cases := []*CipherView{}
	card := NewCipherView()
	card.Type, card.Name = CipherTypeCard, "card"
	card.Card = &CardView{CardholderName: sp("John"), Number: sp("4242424242424242"), Brand: sp("Visa"), Code: sp("")}
	cases = append(cases, card)
	ident := NewCipherView()
	ident.Type, ident.Name, ident.OrganizationID = CipherTypeIdentity, "ident", &org
	ident.Identity = &IdentityView{FirstName: sp("Jane"), LastName: sp("Doe"), SSN: sp("123"), Email: sp("")}
	cases = append(cases, ident)
	note := NewCipherView()
	note.Type, note.Name = CipherTypeSecureNote, "note"
	cases = append(cases, note)
	ssh := NewCipherView()
	ssh.Type, ssh.Name = CipherTypeSshKey, "ssh"
	ssh.SshKey = &SshKeyView{PrivateKey: "priv", PublicKey: "pub", KeyFingerprint: "fp"}
	cases = append(cases, ssh)
	bank := NewCipherView()
	bank.Type, bank.Name = CipherTypeBankAccount, "bank"
	bank.BankAccount = &BankAccountView{BankName: sp("Acme"), Iban: sp("GB00")}
	cases = append(cases, bank)
	dl := NewCipherView()
	dl.Type, dl.Name = CipherTypeDriversLicense, "dl"
	dl.DriversLicense = &DriversLicenseView{FirstName: sp("Jane"), IssuingState: sp("CA")}
	cases = append(cases, dl)
	pp := NewCipherView()
	pp.Type, pp.Name = CipherTypePassport, "pp"
	pp.Passport = &PassportView{GivenName: sp("Jane"), Surname: sp("Smith"), IssuingCountry: sp("US")}
	cases = append(cases, pp)

	for _, v := range cases {
		enc, out := roundTrip(t, env, v)
		switch v.Type {
		case CipherTypeCard:
			if *out.Card.Number != "4242424242424242" || *out.Card.Code != "" || out.Card.ExpMonth != nil {
				t.Fatalf("card %+v", out.Card)
			}
			if got := *out.Subtitle(); got != "Visa, *4242" {
				t.Fatalf("card subtitle %q", got)
			}
		case CipherTypeIdentity:
			if out.OrganizationID == nil || *out.OrganizationID != org {
				t.Fatal("org id lost")
			}
			// Empty identity strings become undefined (toSdkIdentityView).
			if enc.Identity.Email != nil || out.Identity.Email != nil || *out.Identity.SSN != "123" {
				t.Fatalf("identity %+v", out.Identity)
			}
			if *out.Subtitle() != "Jane Doe" {
				t.Fatal("identity subtitle")
			}
			// the cipher key is wrapped with the org key
			if _, err := crypto.DecryptToKey(*enc.Key, env.orgKey); err != nil {
				t.Fatal("cipher key not wrapped by org key")
			}
		case CipherTypeSecureNote:
			if out.SecureNote == nil || out.SecureNote.Type != SecureNoteTypeGeneric {
				t.Fatal("note")
			}
		case CipherTypeSshKey:
			if out.SshKey.PrivateKey != "priv" || out.SshKey.KeyFingerprint != "fp" || *out.Subtitle() != "fp" {
				t.Fatalf("ssh %+v", out.SshKey)
			}
		case CipherTypeBankAccount:
			if *out.BankAccount.Iban != "GB00" || *out.Subtitle() != "Acme" {
				t.Fatal("bank")
			}
		case CipherTypeDriversLicense:
			if *out.Subtitle() != "Jane, CA" {
				t.Fatalf("dl subtitle %q", *out.Subtitle())
			}
		case CipherTypePassport:
			if *out.Subtitle() != "Jane Smith, US" {
				t.Fatalf("passport subtitle %q", *out.Subtitle())
			}
		}
	}
}

func TestDecryptLegacyCipherWithoutKey(t *testing.T) {
	env := newTestEnv(t)
	e := func(s string) string { x, _ := crypto.EncryptString(s, env.userKey); return x }
	h := sha256.Sum256([]byte("https://bad.example"))
	raw := `{"Id":"c1","Type":1,"Name":"` + e("legacy") + `","Notes":null,"FolderId":"","OrganizationId":null,
	"Login":{"Username":"` + e("bob") + `","Password":"not-an-encstring","Uris":[{"Uri":"` + e("https://bad.example") +
		`","UriChecksum":"` + e(base64.StdEncoding.EncodeToString(h[:])) + `","Match":null},{"Uri":"` + e("https://nochecksum.example") + `","Match":null}]},
	"Fields":[{"Type":0,"Name":"` + e("f") + `","Value":"garbage"}],
	"RevisionDate":"2024-05-01T12:00:00.1234567Z","CreationDate":"2024-05-01T12:00:00Z","DeletedDate":null,
	"Edit":true,"ViewPassword":null,"Reprompt":0,"Attachments":[{"Id":"a1","FileName":"` + e("file.txt") + `","Size":"10","SizeName":"10 Bytes","Url":"https://x"},{"Id":"a2","FileName":"broken","Size":"1"}]}`
	c, err := ParseCipher(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.FolderID != nil {
		t.Fatal("empty folderId should be null")
	}
	v, err := DecryptCipher(c, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "legacy" || *v.Login.Username != "bob" || v.Login.Password != nil {
		t.Fatalf("lenient decryption failed: %+v", v.Login)
	}
	// Without a cipher key (and v1 account) checksums are not enforced.
	if len(v.Login.URIs) != 2 {
		t.Fatalf("uris: %d", len(v.Login.URIs))
	}
	if *v.Fields[0].Name != "f" || v.Fields[0].Value != nil {
		t.Fatal("field lenient decryption")
	}
	if !v.ViewPassword || !v.Edit || v.Key != nil {
		t.Fatal("metadata")
	}
	if len(v.Attachments) != 2 || *v.Attachments[0].FileName != "file.txt" || !v.Attachments[1].HasDecryptionError || v.Attachments[1].FileName != nil {
		t.Fatalf("attachments %+v", v.Attachments)
	}
	// With v2 security state, URIs without a valid checksum are removed.
	env.keys.SecurityVersion = 2
	v, _ = DecryptCipher(c, env.keys)
	if len(v.Login.URIs) != 1 || *v.Login.URIs[0].URI != "https://bad.example" {
		t.Fatalf("checksum enforcement: %+v", v.Login.URIs)
	}
}

func TestDecryptFailureWrongKey(t *testing.T) {
	env := newTestEnv(t)
	other := newTestEnv(t)
	other.userKey = crypto.GenerateKey()
	other.keys = NewKeys(other.userKey, "", nil, nil)
	v := fullLoginView()
	c, _, err := EncryptCipher(v, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptCipher(c, other.keys); err == nil {
		t.Fatal("expected cipher key failure")
	}
	f := failedCipherView(c)
	if f.Name != DecryptError || !f.DecryptionFailure {
		t.Fatal("failed view")
	}
}

func TestAttachmentKeysRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	v := NewCipherView()
	v.Type, v.Name = CipherTypeSecureNote, "n"
	ak := crypto.GenerateKey()
	v.Attachments = []AttachmentView{{ID: sp("a"), FileName: sp("doc.pdf"), Size: sp("2048"), SizeName: sp("2 KB"), Key: ak}}
	enc, out := roundTrip(t, env, v)
	if enc.Attachments[0].Key == nil || out.Attachments[0].Key.B64() != ak.B64() || *out.Attachments[0].FileName != "doc.pdf" {
		t.Fatal("attachment key round trip")
	}
	req := NewCipherRequest(enc, testUserID)
	b := mustJSON(t, req)
	if !strings.Contains(b, `"attachments2":{"a":{"fileName":"`) || !strings.Contains(b, `"encryptedFor":"`+testUserID+`"`) {
		t.Fatalf("request: %s", b)
	}
}

func TestBlobRoundTripV2(t *testing.T) {
	env := newTestEnv(t)
	env.keys.SecurityVersion = 2
	v := fullLoginView()
	enc, out := roundTrip(t, env, v)
	if enc.Data.Val == nil || !IsBlobData(enc.Data.Val) || enc.Name != nil || enc.Login != nil {
		t.Fatalf("expected blob cipher, got data=%v name=%v", enc.Data.Val, enc.Name)
	}
	if out.Name != v.Name || *out.Login.Password != "secret" || len(out.Login.URIs) != 2 ||
		out.Login.Fido2Credentials[0].Counter != "7" || *out.Fields[2].LinkedID != 100 ||
		len(out.PasswordHistory) != 1 || !out.Login.PasswordRevisionDate.Equal(*v.Login.PasswordRevisionDate) {
		t.Fatalf("blob round trip mismatch %+v", out)
	}
	// Organization items stay field-encrypted.
	org := testOrgID
	v.OrganizationID = &org
	enc, _ = roundTrip(t, env, v)
	if enc.Data.Val != nil || enc.Name == nil {
		t.Fatal("org cipher must use legacy field encryption")
	}
	// Domain export of a blob cipher carries only data.
	env.keys.SecurityVersion = 2
	v.OrganizationID = nil
	enc, _ = roundTrip(t, env, v)
	got := mustJSON(t, BuildCipherExportFromDomain(enc))
	if !strings.Contains(got, `"data":"{\"format_version\":1`) || strings.Contains(got, `"name"`) || strings.Contains(got, `"login"`) {
		t.Fatalf("blob export: %s", got)
	}
}

// SDK test vectors (bitwarden-vault cipher/blob/v1.rs).
const (
	sdkLoginCEK      = "pQEEAlClJ9tO9x8fN2JVe5N8uzAaAzoAARFvBIEEIFggZwJXkLK7A6Sy5Y9+dacJrzCg9bo4RMRxXaRGDWYfbTYB"
	sdkLoginEnvelope = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFClJ9tO9x8fN2JVe5N8uzAaOgABOIECOgABOIABoQVYGNYP1rgAT3D2T6q2lGTRjIPHR2IELUDWE1kC2erlZM4Dqyeew1VlDkdXnZIE+t2g4SJh8IFSHo9WuzmyY+qC+V9cuGW3QHt+sg7pfZ5kQBh40U9uxUcxOHdVF3jQhcAmgB9abShR68u41NMDwwLSafG8PLzsUfhhxpCG0+ZuOda3tFVM1y5TyiDPJBBoJECuYK/K/1RLNAWAy5AU98yI0RgdK0MHxpoOqdSC8dXXu6fGgON7XLQWkkceFWILp0o51/c7OvdJ3B1nCiCIZjwAyS96+oWOzLrsPaGkBjqedBCi5iwelzLOttXk6nrzE/FfC0PkeeSsPSr9UdXBbeuUSK7wKtir9Lx/gtJ4sMPFidtTNdXCcDT9RA7y21h+3+wHQgGSlOGRigXFgXWi5ajSPCs9zLn7ERoG4BZ4IHa6EMSJbGH1pANW+Ibg4aadBF7LzOi/BZx2oZ/6z54XfAfqb44FR3/XXdNFHosPH9IH7CkKbNvLTuGrOTk9S998qFDNkWeGthrDYclaYSFktSHULvmHhSPadRL4uM6254HTmSjTAG6FDhhqdJU3SvoifrvBeHqjEP7F5R+zjVQol+JUcs/ExwmlrxXETOTzGyC/++FflZyPIUnH9U7ZqXhiYGd0ZvcyrnrnieehYToWFdwFR9ho+6h9hB/SCjhGudP5CRPZDL9GkNAUS5+pAd4ZC19fDjWpwMnEbgPTuthXKl6YRHxxCV+xpc9jncVQt9zF31e0bSIP7kVcdmlgjXaV6Nmd3aZ+PqeJnj27gCxG2tZkMimdJmEgxkL/cfvNHENg43+rpnV2mCTrCAO/X+RDGKdi7SIzsLesPVXVHEZCM4UBv2v+S/vpDFC3ie09cz525PCgt/7Je68k8S5WsTwKVeL0+T/ysqDo7wJvFSToY2G/LOGnBYMUYcCLfJGQbD8g2xI3oC+go8kcyVDJv+936/MkAYSxnvZDrMr30zEZaNm5YBh8cRqKr4MxOjJBk1XWjwDNsSQrDw=="
	sdkCardCEK       = "pQEEAlBqeNyImi1f1pMtJVlvDuV1AzoAARFvBIEEIFggyyOmMlDBj/oRic4qPjXnnKXGf4QGYMq7KvztZO3it+cB"
	sdkCardEnvelope  = "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFBqeNyImi1f1pMtJVlvDuV1OgABOIECOgABOIABoQVYGHZO47yxMBN7r8jgWNJ8c+1bfUld0uzdNli2xQgFm6X0chG+qNdkiROVAUxi75+cN4jiTOzt41pG7bXyo7U4D8R38zR+l7jePi39w3YV4tnmxIenwBPK/0qdO8pLKUMwi8PMIBqJ2UxanLqRhP6Ru2i43rpVZMgAmasGgzGG8hhJttii1CidG8ntNP/zRvRl38F/7bphlN1a08/FeycdIAfQUf7tgzoaj1JegSwEs1M7/+ONHlPtlkmovN/zJTP0ZHL7U7NAt/JBIWbeScbGP6E="
)

func openSDKVector(t *testing.T, cekB64, envelope string) *CipherBlobV1 {
	t.Helper()
	cek, err := crypto.KeyFromB64(cekB64)
	if err != nil {
		t.Fatal(err)
	}
	content, err := crypto.OpenDataEnvelope(envelope, crypto.DataEnvelopeNamespaceVaultItem, cek)
	if err != nil {
		t.Fatal(err)
	}
	j, err := crypto.CBORToJSON(content)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := decodeBlobJSON(j)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestSDKBlobVectors(t *testing.T) {
	blob := openSDKVector(t, sdkLoginCEK, sdkLoginEnvelope)
	v := NewCipherView()
	v.Type = CipherTypeLogin
	applyBlob(v, blob)
	l := v.Login
	if v.Name != "Test Login" || *v.Notes != "Login notes" || *l.Username != "testuser@example.com" ||
		*l.Password != "p@ssw0rd123" || *l.Totp != "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP" ||
		!l.PasswordRevisionDate.Equal(tm("2024-01-15T12:00:00Z")) || !*l.AutofillOnPageLoad {
		t.Fatalf("login blob %+v / %+v", v, l)
	}
	if len(l.URIs) != 1 || *l.URIs[0].URI != "https://example.com/login" || *l.URIs[0].Match != UriMatchDomain {
		t.Fatalf("uris %+v", l.URIs)
	}
	f := l.Fido2Credentials[0]
	if f.CredentialID != "credential-id-123" || f.Counter != "42" || !f.Discoverable || *f.UserDisplayName != "Test User" ||
		!f.CreationDate.Equal(tm("2024-06-01T10:30:00Z")) {
		t.Fatalf("fido2 %+v", f)
	}
	if *v.Fields[0].Name != "Custom Field" || v.Fields[0].Type != FieldTypeLinked || *v.Fields[0].LinkedID != 100 {
		t.Fatalf("fields %+v", v.Fields)
	}
	if *v.PasswordHistory[0].Password != "old-password-1" || !v.PasswordHistory[0].LastUsedDate.Equal(tm("2023-12-01T08:00:00Z")) {
		t.Fatal("history")
	}
	// Re-encoding produces the same logical content.
	again, err := blobFromView(v)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := blobVersionedJSON(blob)
	j2, _ := blobVersionedJSON(again)
	if string(j1) != string(j2) {
		t.Fatalf("blob re-encode mismatch\n%s\n%s", j1, j2)
	}

	card := openSDKVector(t, sdkCardCEK, sdkCardEnvelope)
	cv := NewCipherView()
	cv.Type = CipherTypeCard
	applyBlob(cv, card)
	if cv.Name != "Test Card" || *cv.Card.Number != "4111111111111111" || *cv.Card.Brand != "Visa" || *cv.Card.ExpYear != "2028" {
		t.Fatalf("card %+v", cv.Card)
	}
}

func TestAdjustCipherHistory(t *testing.T) {
	existing := fullLoginView()
	model := fullLoginView()
	model.Login.Password = sp("new-secret")
	model.Fields = []FieldView{{Name: sp("hidden"), Value: sp("changed"), Type: FieldTypeHidden}}
	AdjustCipherHistory(model, existing)
	if len(model.PasswordHistory) != 3 {
		t.Fatalf("history %d", len(model.PasswordHistory))
	}
	if *model.PasswordHistory[0].Password != "hidden: h1" || *model.PasswordHistory[1].Password != "secret" || *model.PasswordHistory[2].Password != "old" {
		t.Fatalf("order %+v", model.PasswordHistory)
	}
	if model.Login.PasswordRevisionDate.Equal(*existing.Login.PasswordRevisionDate) {
		t.Fatal("revision date not updated")
	}
	// Unchanged password keeps the revision date; empty history becomes nil.
	m2 := fullLoginView()
	e2 := fullLoginView()
	e2.PasswordHistory = []PasswordHistoryView{}
	AdjustCipherHistory(m2, e2)
	if m2.PasswordHistory != nil || !m2.Login.PasswordRevisionDate.Equal(*e2.Login.PasswordRevisionDate) {
		t.Fatal("unchanged history handling")
	}
}

func TestCipherRequestShape(t *testing.T) {
	env := newTestEnv(t)
	v := NewCipherView()
	v.Name = "x"
	v.CollectionIDs = []string{"c1"}
	v.RevisionDate = tm("2024-01-01T00:00:00Z")
	c, _, err := EncryptCipher(v, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	r := NewCipherCreateRequest(c, "")
	var m map[string]any
	_ = json.Unmarshal([]byte(mustJSON(t, r)), &m)
	cr := m["cipher"].(map[string]any)
	if cr["type"].(float64) != 1 || cr["folderId"] != nil || cr["lastKnownRevisionDate"] != "2024-01-01T00:00:00.000Z" ||
		cr["login"] == nil || m["collectionIds"].([]any)[0] != "c1" {
		t.Fatalf("create request %v", m)
	}
	share := NewCipherShareRequest(c, []string{"c2"}, testUserID)
	if !strings.Contains(mustJSON(t, share), `"collectionIds":["c2"]`) {
		t.Fatal("share request")
	}
	_ = cli.Date{}
}
