package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCipherResponseLoginShape(t *testing.T) {
	v := fullLoginView()
	got := mustJSON(t, NewCipherResponse(v))
	want := `{"type":1,"favorite":true,"reprompt":1,"id":"aaaaaaaa-0000-0000-0000-000000000001","collectionIds":[],"object":"item",` +
		`"name":"My <Login> & co","notes":"some notes",` +
		`"fields":[{"type":0,"name":"text","value":"v1"},{"type":1,"name":"hidden","value":"h1"},{"type":3,"name":"linked","linkedId":100}],` +
		`"login":{"uris":[{"uri":"https://example.com/login"},{"uri":"https://other.org","match":1}],` +
		`"fido2Credentials":[{"credentialId":"cred","keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256","keyValue":"kv","rpId":"example.com","counter":"7","discoverable":"true","creationDate":"2024-01-01T09:00:00.000Z","userName":"alice"}],` +
		`"username":"alice","password":"secret","totp":"JBSWY3DPEHPK3PXP","passwordRevisionDate":"2024-01-01T11:00:00.000Z"},` +
		`"passwordHistory":[{"lastUsedDate":"2023-12-31T00:00:00.000Z","password":"old"}],` +
		`"creationDate":"2024-01-01T10:00:00.000Z","revisionDate":"2024-01-02T10:00:00.123Z","attachments":[]}`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestCipherResponseRedaction(t *testing.T) {
	v := fullLoginView()
	v.ViewPassword = false
	org, folder := testOrgID, "ffffffff-0000-0000-0000-000000000000"
	v.OrganizationID, v.FolderID = &org, &folder
	v.Login.PasswordRevisionDate = nil
	v.Login.Fido2Credentials = []Fido2CredentialView{}
	v.DeletedDate = tp("2024-02-01T00:00:00Z")
	v.Attachments = []AttachmentView{{ID: sp("att"), FileName: sp("a.txt"), Size: sp("12"), SizeName: sp("12 Bytes"), URL: sp("https://cdn/att")}}
	got := mustJSON(t, NewCipherResponse(v))
	want := `{"type":1,"favorite":true,"reprompt":1,"id":"aaaaaaaa-0000-0000-0000-000000000001","collectionIds":[],"object":"item",` +
		`"organizationId":"` + org + `","folderId":"` + folder + `","name":"My <Login> & co","notes":"some notes",` +
		`"fields":[{"type":0,"name":"text","value":"v1"},{"type":1,"name":"hidden","value":null},{"type":3,"name":"linked","linkedId":100}],` +
		`"login":{"uris":[{"uri":"https://example.com/login"},{"uri":"https://other.org","match":1}],"fido2Credentials":[],` +
		`"username":"alice","password":null,"totp":null,"passwordRevisionDate":null},` +
		`"creationDate":"2024-01-01T10:00:00.000Z","revisionDate":"2024-01-02T10:00:00.123Z","deletedDate":"2024-02-01T00:00:00.000Z",` +
		`"attachments":[{"id":"att","fileName":"a.txt","size":"12","sizeName":"12 Bytes","url":"https://cdn/att"}]}`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestCipherResponseOtherTypes(t *testing.T) {
	v := NewCipherView()
	v.ID, v.Name, v.Type = "id1", "Card", CipherTypeCard
	v.CreationDate, v.RevisionDate = tm("2024-01-01T00:00:00Z"), tm("2024-01-01T00:00:00Z")
	v.Card = &CardView{CardholderName: sp("John"), Number: sp("4111"), Code: sp("")}
	got := mustJSON(t, NewCipherResponse(v))
	want := `{"type":3,"favorite":false,"reprompt":0,"id":"id1","collectionIds":[],"object":"item","name":"Card","fields":[],` +
		`"card":{"cardholderName":"John","number":"4111","code":""},"passwordHistory":[],` +
		`"creationDate":"2024-01-01T00:00:00.000Z","revisionDate":"2024-01-01T00:00:00.000Z","attachments":[]}`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}

	v.Type = CipherTypeSecureNote
	if !strings.Contains(mustJSON(t, NewCipherResponse(v)), `"fields":[],"secureNote":{"type":0},"passwordHistory":[]`) {
		t.Fatal("secure note shape")
	}
	v.Type = CipherTypeSshKey
	v.SshKey = &SshKeyView{PrivateKey: "p", PublicKey: "k", KeyFingerprint: "f"}
	if !strings.Contains(mustJSON(t, NewCipherResponse(v)), `"sshKey":{"privateKey":"p","publicKey":"k","keyFingerprint":"f"}`) {
		t.Fatal("ssh shape")
	}
	v.Type = CipherTypeIdentity
	v.Identity = &IdentityView{Title: sp("Mr"), LastName: sp("Doe"), LicenseNumber: sp("L")}
	if !strings.Contains(mustJSON(t, NewCipherResponse(v)), `"identity":{"title":"Mr","lastName":"Doe","licenseNumber":"L"}`) {
		t.Fatal("identity shape")
	}
}

func TestOtherResponses(t *testing.T) {
	f := NewFolderResponse(&FolderView{ID: "f1", Name: "Work"})
	if got := mustJSON(t, f); got != `{"name":"Work","object":"folder","id":"f1"}` {
		t.Fatal(got)
	}
	if got := mustJSON(t, BuildFolderExport(&FolderView{ID: "f1", Name: "Work"})); got != `{"name":"Work","id":"f1"}` {
		t.Fatal(got)
	}
	c := &CollectionView{ID: "c1", OrganizationID: "o1", Name: "Col", Assigned: true}
	if got := mustJSON(t, NewCollectionResponse(c)); got != `{"object":"collection","id":"c1","organizationId":"o1","name":"Col","externalId":null}` {
		t.Fatal(got)
	}
	email := "user@x"
	c.DefaultUserCollectionEmail = &email
	c.ExternalID = sp("ext")
	sel := []SelectionReadOnly{{ID: "g1", ReadOnly: true}}
	if got := mustJSON(t, NewOrganizationCollectionResponse(c, sel, []SelectionReadOnly{})); got !=
		`{"object":"org-collection","id":"c1","organizationId":"o1","name":"user@x","externalId":"ext","groups":[{"id":"g1","readOnly":true,"hidePasswords":false,"manage":false}],"users":[]}` {
		t.Fatal(got)
	}
	// views from user input (toView) leave externalId undefined
	in := &CollectionExport{}
	_ = json.Unmarshal([]byte(`{"organizationId":"o1","name":"N"}`), in)
	if got := mustJSON(t, NewCollectionResponse(in.ToView("new"))); got != `{"object":"collection","id":"new","organizationId":"o1","name":"N"}` {
		t.Fatal(got)
	}
	o := &Organization{ProfileOrganization: ProfileOrganization{ID: "o1", Name: "Acme", Status: OrgUserStatusConfirmed, Type: OrgUserAdmin, Enabled: true}}
	if got := mustJSON(t, NewOrganizationResponse(o)); got != `{"object":"organization","id":"o1","name":"Acme","status":2,"type":1,"enabled":true}` {
		t.Fatal(got)
	}
	u := NewOrganizationUserResponse("u1", "a@b", nil, OrgUserStatusInvited, OrgUserUser, false)
	if got := mustJSON(t, u); got != `{"object":"org-member","id":"u1","email":"a@b","name":null,"status":0,"type":2,"twoFactorEnabled":false}` {
		t.Fatal(got)
	}
}

func TestTemplates(t *testing.T) {
	cases := map[string]string{
		"item":             `{"type":1,"favorite":false,"reprompt":0,"name":"Item name","notes":"Some notes about this item.","fields":[],"passwordHistory":[]}`,
		"item.field":       `{"type":0,"name":"Field name","value":"Some value"}`,
		"item.login":       `{"uris":[],"username":"jdoe","password":"myp@ssword123","totp":"JBSWY3DPEHPK3PXP","fido2Credentials":[]}`,
		"item.login.uri":   `{"uri":"https://google.com"}`,
		"item.card":        `{"cardholderName":"John Doe","brand":"visa","number":"4242424242424242","expMonth":"04","expYear":"2023","code":"123"}`,
		"item.securenote":  `{"type":0}`,
		"folder":           `{"name":"Folder name"}`,
		"collection":       `{"organizationId":"00000000-0000-0000-0000-000000000000","name":"Collection name","externalId":null}`,
		"item-collections": `["collection-id1","collection-id2"]`,
		"org-collection": `{"organizationId":"00000000-0000-0000-0000-000000000000","name":"Collection name","externalId":null,` +
			`"groups":[{"id":"00000000-0000-0000-0000-000000000000","readOnly":false,"hidePasswords":false,"manage":false},{"id":"00000000-0000-0000-0000-000000000000","readOnly":false,"hidePasswords":false,"manage":false}],` +
			`"users":[{"id":"00000000-0000-0000-0000-000000000000","readOnly":false,"hidePasswords":false,"manage":false},{"id":"00000000-0000-0000-0000-000000000000","readOnly":false,"hidePasswords":false,"manage":false}]}`,
		"ITEM.IDENTITY": `{"title":"Mr","firstName":"John","middleName":"William","lastName":"Doe","address1":"123 Any St","address2":"Apt #123","city":"New York","state":"NY","postalCode":"10001","country":"US","company":"Acme Inc.","email":"john@company.com","phone":"5555551234","ssn":"000-123-4567","username":"jdoe","passportNumber":"US-123456789","licenseNumber":"D123-12-123-12333"}`,
	}
	for name, want := range cases {
		tpl, ok := Template(name)
		if !ok {
			t.Fatalf("missing template %s", name)
		}
		if got := mustJSON(t, tpl); got != want {
			t.Fatalf("%s:\ngot  %s\nwant %s", name, got, want)
		}
	}
	if _, ok := Template("nope"); ok {
		t.Fatal("unknown template")
	}
	for _, n := range TemplateNames {
		if _, ok := Template(n); !ok {
			t.Fatalf("listed template %s missing", n)
		}
	}
}

func TestToViewCreate(t *testing.T) {
	in := `{"type":1,"name":"New","notes":null,"favorite":true,"folderId":null,"collectionIds":["c1"],
	"fields":[{"name":"f","value":"v","type":1}],
	"login":{"uris":[{"uri":"https://a.com","match":null}],"username":"u","password":"p","totp":null,
	"fido2Credentials":[{"credentialId":"c","keyType":"public-key","keyAlgorithm":"ECDSA","keyCurve":"P-256","keyValue":"k","rpId":"a.com","counter":"5","discoverable":"true","creationDate":"2024-01-01T00:00:00.000Z"}]},
	"reprompt":null,"passwordHistory":[{"password":"old"}]}`
	req := &CipherExport{}
	if err := json.Unmarshal([]byte(in), req); err != nil {
		t.Fatal(err)
	}
	v, err := req.ToView(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "New" || !v.Favorite || v.Notes != nil || v.FolderID != nil || v.Reprompt != RepromptNone ||
		len(v.CollectionIDs) != 1 || *v.Login.Username != "u" || v.Login.Totp != nil ||
		v.Login.URIs[0].Match != nil || v.Login.Fido2Credentials[0].Counter != "5" || !v.Login.Fido2Credentials[0].Discoverable ||
		v.Fields[0].Type != FieldTypeHidden || v.PasswordHistory[0].LastUsedDate == nil {
		t.Fatalf("toView %+v", v)
	}
	// ssh key validation
	ssh := &CipherExport{}
	_ = json.Unmarshal([]byte(`{"type":5,"name":"s","sshKey":{"privateKey":"x","publicKey":"","keyFingerprint":""}}`), ssh)
	if _, err := ssh.ToView(nil, false); err == nil || err.Error() != "SSH key public key is required." {
		t.Fatalf("ssh validation: %v", err)
	}
	if _, err := ssh.ToView(nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestToViewEdit(t *testing.T) {
	existing := fullLoginView()
	existing.CollectionIDs = []string{"c1"}
	org := testOrgID
	existing.OrganizationID = &org
	key := existing.Key
	req := &CipherExport{}
	_ = json.Unmarshal([]byte(`{"type":1,"name":"Edited","organizationId":"other","collectionIds":["c2","c1"],"login":{"username":"x"}}`), req)
	v, err := req.ToView(existing, false)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "Edited" || *v.OrganizationID != org || len(v.CollectionIDs) != 2 || v.FolderID != nil ||
		v.Login.Password != nil || len(v.Fields) != 3 || v.Key != key {
		t.Fatalf("edit toView %+v", v)
	}
}

func TestBuildCipherExport(t *testing.T) {
	v := fullLoginView()
	e := BuildCipherExport(v)
	e.CollectionIDs = Null[[]string]()
	got := mustJSON(t, e)
	if !strings.HasPrefix(got, `{"type":1,"favorite":true,"reprompt":1,"id":"aaaaaaaa-0000-0000-0000-000000000001","collectionIds":null,"name":"My <Login> & co","notes":"some notes","fields":[`) ||
		!strings.Contains(got, `"passwordHistory":[{"password":"old","lastUsedDate":"2023-12-31T00:00:00.000Z"}],"creationDate":`) ||
		strings.Contains(got, `passwordRevisionDate`) {
		t.Fatal(got)
	}
}
