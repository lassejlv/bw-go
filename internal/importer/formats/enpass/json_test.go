package enpass

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/enpass/enpass-json-importer.spec.ts.

func parseJsonFixture(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, NewJson(importertest.Options()), importertest.ReadFile(t, name))
	if !r.Success || len(r.Ciphers) == 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	return r
}

func TestJsonFolders(t *testing.T) {
	r := parseJsonFixture(t, "folders.json")
	if len(r.Folders) != 2 {
		t.Fatalf("folders = %s", importertest.Dump(r.Folders))
	}
	eq(t, "folder 0", r.Folders[0].Name, "Social")
	// Created 2 folders and Twitter is child of Social
	eq(t, "folder 1", r.Folders[1].Name, "Social/Twitter")
	// The single cipher item is assigned to sub-folder "Social/Twitter"
	if len(r.FolderRelationships) == 0 || r.FolderRelationships[0] != (model.Relationship{0, 1}) {
		t.Errorf("relationships = %v", r.FolderRelationships)
	}
}

func TestJsonLogin(t *testing.T) {
	r := parseJsonFixture(t, "login.json")
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "name", c.Name, "Amazon")
	// cipher.subTitle is the login username for login ciphers.
	eq(t, "favorite", c.Favorite, true)
	eq(t, "notes", c.Notes, "some notes on the login item")

	eq(t, "username", c.Login.Username, "emily@enpass.io")
	eq(t, "password", c.Login.Password, `$&W:v@}4\iRpUXVbjPdPKDGbD<xK>`)
	eq(t, "totp", c.Login.Totp, "TOTP_SEED_VALUE")
	if u := importertest.URIs(c); len(u) != 1 || u[0] != "https://www.amazon.com" {
		t.Errorf("uris = %v", u)
	}

	if len(c.Fields) != 3 {
		t.Fatalf("fields = %s", importertest.Dump(c.Fields))
	}
	importertest.AssertCustomFieldsExist(t, c.Fields,
		importertest.F("Phone number", "12345678"),
		importertest.F("Security question", "SECURITY_QUESTION"),
		importertest.F("Security answer", "SECURITY_ANSWER"),
	)
}

func TestJsonLoginAndroidUrl(t *testing.T) {
	r := parseJsonFixture(t, "loginAndroidUrl.json")
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeLogin)
	eq(t, "name", c.Name, "Amazon")
	want := []string{
		"https://www.amazon.com",
		"androidapp://com.amazon.0",
		"androidapp://com.amazon.1",
		"androidapp://com.amazon.2",
		"androidapp://com.amazon.3",
	}
	if u := importertest.URIs(c); strings.Join(u, "|") != strings.Join(want, "|") {
		t.Errorf("uris = %v", u)
	}
}

func TestJsonCreditCard(t *testing.T) {
	r := parseJsonFixture(t, "creditCard.json")
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeCard)
	eq(t, "name", c.Name, "Emily Sample Credit Card")
	// cipher.subTitle ("Amex, *10005") is derived from brand + the number's last digits.
	eq(t, "favorite", c.Favorite, true)
	eq(t, "notes", c.Notes, "some notes on the credit card")
	eq(t, "card", *c.Card, model.CardView{
		CardholderName: "Emily Sample", Number: "3782 822463 10005", Brand: "Amex", Code: "1234", ExpMonth: "3", ExpYear: "2023",
	})

	if len(c.Fields) != 9 {
		t.Fatalf("fields = %s", importertest.Dump(c.Fields))
	}
	importertest.AssertCustomFieldsExist(t, c.Fields,
		importertest.F("PIN", "9874"),
		importertest.F("Username", "Emily_ENP"),
		importertest.F("Login password", "nnn tug shoot selfish bon liars convent dusty minnow uncheck"),
		importertest.F("Website", "http://global.americanexpress.com/"),
		importertest.F("Issuing bank", "American Express"),
		importertest.F("Credit limit", "100000"),
		importertest.F("Withdrawal limit", "50000"),
		importertest.F("Interest rate", "1.5"),
		importertest.F("If lost, call", "12345678"),
	)
}

func TestJsonAndroidUrlNoBacktracking(t *testing.T) {
	adversarialUrl := strings.Repeat("androidapp://", 76)
	data := map[string]any{
		"folders": []any{},
		"items": []any{map[string]any{
			"archived": 0, "auto_submit": 1, "category": "login", "createdAt": 0, "favorite": 0,
			"subtitle": "", "trashed": 0,
			"fields": []any{map[string]any{
				"deleted": 0, "label": "Android", "order": 1, "sensitive": 0, "type": ".Android#",
				"uid": 1, "updated_at": 0, "value": adversarialUrl, "value_updated_at": 0,
			}},
			"icon":          map[string]any{"fav": "", "image": map[string]any{"file": ""}, "type": 0, "uuid": ""},
			"note":          "",
			"template_type": "login.default",
			"title":         "Test",
			"updated_at":    0,
			"uuid":          "test-uuid",
		}},
	}
	b, _ := json.Marshal(data)
	r := importertest.Parse(t, NewJson(importertest.Options()), string(b))
	if !r.Success {
		t.Fatal("success = false")
	}
	// No ==@ present, so the URL passes through unchanged
	eq(t, "uri", r.Ciphers[0].Login.Uri(), adversarialUrl)
}

func TestJsonNote(t *testing.T) {
	r := parseJsonFixture(t, "note.json")
	c := r.Ciphers[0]
	eq(t, "type", c.Type, model.CipherTypeSecureNote)
	eq(t, "name", c.Name, "some secure note title")
	eq(t, "favorite", c.Favorite, false)
	eq(t, "notes", c.Notes, "some secure note content")
}
