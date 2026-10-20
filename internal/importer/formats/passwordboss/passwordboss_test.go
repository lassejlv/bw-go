package passwordboss

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/passwordboss-json-importer.spec.ts.

// Current "Password Boss JSON - Not Encrypted" export: a flat array of items, card/login fields
// directly on the item, and no separate `folders` list.
const flatExport = `[
  {"id":"b0e7dbdb-71d5-4449-87a7-91b2b185dc4a","itemType":2,"folder":"Personal","logoColor":"#E92763",
   "username":"usernameTest","password":"passwordTest","name":"testPW","notes":"","url":"test.com",
   "totp":"JBSWY3DPEHPK3PXP","accountType":"personal",
   "customFields":[{"name":"Security Question","value":"Answer"}],"tags":[],"itemTypeName":"Website"},
  {"id":"b9e905d5-709e-4d7d-95e6-384255df426d","itemType":11,"folder":null,"logoColor":"#2196F3",
   "username":"","password":"","name":"Personal Card","notes":"","cardNumber":"4111111111111111",
   "nameOnCard":"Jane Doe","expirationDate":"2030-01-31T23:59:59.000Z","cardType":"visa","issuingBank":"",
   "securityCode":"","issueDate":"","pin":"","tags":[],"itemTypeName":"CreditCard"},
  {"id":"c1e905d5-709e-4d7d-95e6-384255df4270","itemType":5,"folder":null,"logoColor":"#000000",
   "username":"","password":"","name":"Wifi note","notes":"Home wifi: ABC123","url":"","customFields":[],
   "tags":[],"itemTypeName":"SecureNote"}
]`

// Older export shape from before Password Boss changed its export format.
const legacyExport = `{"folders":[{"id":"f1","name":"Personal"}],"items":[{"name":"Amazon","type":"Website",
  "login_url":"https://amazon.com","folder":"f1","identifiers":{"username":"jdoe@example.com",
  "password":"Sup3rSecret!","notes":"line one\\r\\nline two"}}]}`

func parse(t *testing.T, data string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.Options()), data)
}

func fieldPairs(c *model.CipherView) [][2]string {
	var out [][2]string
	for _, f := range c.Fields {
		out = append(out, [2]string{f.Name, f.Value})
	}
	return out
}

func containsPairs(t *testing.T, c *model.CipherView, want ...[2]string) {
	t.Helper()
	got := fieldPairs(c)
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("field %v not in %v", w, got)
		}
	}
}

func findField(c *model.CipherView, name string) *model.FieldView {
	for _, f := range c.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func TestFlatExport(t *testing.T) {
	r := parse(t, flatExport)
	if !r.Success || len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r))
	}

	login := r.Ciphers[0]
	if login.Name != "testPW" || login.Type != model.CipherTypeLogin || login.Login.Username != "usernameTest" ||
		login.Login.Password != "passwordTest" || login.Login.Uris[0].Uri != "http://test.com" ||
		login.Login.Totp != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%s", importertest.Dump(login))
	}
	containsPairs(t, login, [2]string{"Security Question", "Answer"}, [2]string{"accountType", "personal"})

	card := r.Ciphers[1]
	if card.Name != "Personal Card" || card.Type != model.CipherTypeCard || card.Card.Number != "4111111111111111" ||
		card.Card.CardholderName != "Jane Doe" || card.Card.ExpYear != "2030" || card.Card.ExpMonth != "1" ||
		findField(card, "cardType") != nil {
		t.Fatalf("%s", importertest.Dump(card))
	}

	note := r.Ciphers[2]
	if note.Name != "Wifi note" || note.Type != model.CipherTypeSecureNote || note.Notes != "Home wifi: ABC123" {
		t.Fatalf("%s", importertest.Dump(note))
	}

	if len(r.Folders) != 1 || r.Folders[0].Name != "Personal" ||
		!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestEmailKeptWhenUsernamePresent(t *testing.T) {
	r := parse(t, `[{"id":"d2","itemType":2,"folder":null,"logoColor":"#E92763","username":"usernameTest",
	  "password":"passwordTest","name":"testPW","notes":"","url":"test.com","totp":"","email":"jdoe@example.com",
	  "customFields":[],"tags":[],"itemTypeName":"Website"}]`)
	login := r.Ciphers[0]
	if login.Login.Username != "usernameTest" {
		t.Fatal(login.Login.Username)
	}
	containsPairs(t, login, [2]string{"email", "jdoe@example.com"})
}

func TestCardKeepsLoginStyleFields(t *testing.T) {
	r := parse(t, `[{"id":"e2","itemType":11,"folder":null,"logoColor":"#2196F3","username":"cardUsername",
	  "password":"cardPassword","url":"issuer.example.com","totp":"JBSWY3DPEHPK3PXP","name":"Personal Card",
	  "notes":"","cardNumber":"4111111111111111","nameOnCard":"Jane Doe","expirationDate":"2030-01-31T23:59:59.000Z",
	  "cardType":"visa","issuingBank":"","securityCode":"","issueDate":"","pin":"","tags":[],"itemTypeName":"CreditCard"}]`)
	card := r.Ciphers[0]
	if card.Type != model.CipherTypeCard {
		t.Fatal(card.Type)
	}
	containsPairs(t, card, [2]string{"username", "cardUsername"}, [2]string{"password", "cardPassword"},
		[2]string{"url", "issuer.example.com"}, [2]string{"totp", "JBSWY3DPEHPK3PXP"})
	if f := findField(card, "password"); f == nil || f.Type != model.FieldTypeHidden {
		t.Fatalf("%s", importertest.Dump(f))
	}
}

func TestStraySensitiveFieldMasked(t *testing.T) {
	r := parse(t, `[{"id":"a3","itemType":2,"folder":null,"logoColor":"#E92763","username":"usernameTest",
	  "password":"passwordTest","name":"testPW","notes":"","url":"test.com","totp":"","pin":"9999","tags":[],
	  "itemTypeName":"Website"}]`)
	if f := findField(r.Ciphers[0], "pin"); f == nil || f.Value != "9999" || f.Type != model.FieldTypeHidden {
		t.Fatalf("%s", importertest.Dump(f))
	}
}

func TestCardPinHidden(t *testing.T) {
	r := parse(t, `[{"id":"f2","itemType":11,"folder":null,"logoColor":"#2196F3","username":"","password":"",
	  "name":"Personal Card","notes":"","cardNumber":"4111111111111111","nameOnCard":"Jane Doe",
	  "expirationDate":"2030-01-31T23:59:59.000Z","cardType":"visa","issuingBank":"","securityCode":"",
	  "issueDate":"","pin":"1234","tags":[],"itemTypeName":"CreditCard"}]`)
	if f := findField(r.Ciphers[0], "PIN"); f == nil || f.Value != "1234" || f.Type != model.FieldTypeHidden {
		t.Fatalf("%s", importertest.Dump(f))
	}
}

func TestCardExpirationUTC(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip(err)
	}
	old := time.Local
	time.Local = loc
	defer func() { time.Local = old }()
	card := parse(t, flatExport).Ciphers[1]
	if card.Card.ExpYear != "2030" || card.Card.ExpMonth != "1" {
		t.Fatalf("%s", importertest.Dump(card.Card))
	}
}

func TestLegacyExport(t *testing.T) {
	r := parse(t, legacyExport)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Amazon" || c.Login.Username != "jdoe@example.com" || c.Login.Password != "Sup3rSecret!" ||
		c.Notes != "line one\nline two" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != "Personal" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
}

func TestLegacyMissingItems(t *testing.T) {
	if r := parse(t, `{"folders":[]}`); r.Success {
		t.Fatal("expected failure")
	}
}

func TestLegacyCardAndQuirks(t *testing.T) {
	r := parse(t, `{"folders":[{"id":1,"name":"Num"},{"id":"1","name":"Str"},{"id":1,"name":"Num2"}],"items":[
	  {"name":"NoIdentifiers","folder":1},
	  {"name":"Card","type":"CreditCard","folder":"1","identifiers":{"cardNumber":"4111111111111111",
	    "nameOnCard":"Jane","security_code":123,"expires":"not a date","cardType":"visa","extra":[1,2],
	    "custom_fields":[{"name":"cf","value":"v"}],"ignoreItemInSecurityScore":true}},
	  {"name":"Web","identifiers":{"email":"e@x.com","username":"u","url":"x.com","website":"y.com","totp":"t"}}]}`)
	if len(r.Folders) != 2 || r.Folders[0].Name != "Num2" || r.Folders[1].Name != "Str" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
	// The item without identifiers still adds a relationship (index 0) but no cipher.
	if !reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}, {0, 1}}) || len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	card := r.Ciphers[0]
	if card.Type != model.CipherTypeCard || card.Card.Brand != "Visa" || card.Card.Code != "123" ||
		card.Card.ExpYear != "NaN" || card.Card.ExpMonth != "NaN" || card.Card.CardholderName != "Jane" {
		t.Fatalf("%s", importertest.Dump(card))
	}
	importertest.AssertCustomFieldsStructure(t, card.Fields, importertest.F("extra", "1,2"), importertest.F("cf", "v"))
	web := r.Ciphers[1]
	if web.Login.Username != "e@x.com" || web.Login.Totp != "t" ||
		!reflect.DeepEqual(importertest.URIs(web), []string{"http://x.com"}) {
		t.Fatalf("%s", importertest.Dump(web))
	}
	importertest.AssertCustomFieldsStructure(t, web.Fields, importertest.F("username", "u"), importertest.F("website", "y.com"))
}

func TestTypeErrors(t *testing.T) {
	for _, data := range []string{`[null]`, `{"items":[]}`, `{"folders":[],"items":[null]}`} {
		if _, err := New(importertest.Options()).Parse(data); err == nil || !strings.Contains(err.Error(), "Cannot read properties") {
			t.Errorf("%s: %v", data, err)
		}
	}
}
