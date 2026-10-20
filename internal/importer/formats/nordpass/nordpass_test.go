package nordpass

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/nordpass-csv-importer.spec.ts (spec-data/nordpass-csv).

func fullName(id *model.IdentityView) string {
	name := ""
	for _, p := range []string{id.Title, id.FirstName, id.MiddleName} {
		if !importer.IsNullOrWhitespace(p) {
			name += p + " "
		}
	}
	if !importer.IsNullOrWhitespace(id.LastName) {
		name += id.LastName
	}
	return importer.JSTrim(name)
}

func parseOne(t *testing.T, opts importer.Options, data string) *model.ImportResult {
	t.Helper()
	r := importertest.Parse(t, New(opts), data)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("success=%v ciphers=%d", r.Success, len(r.Ciphers))
	}
	return r
}

func TestEmptyData(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "")
	if r.Success {
		t.Fatal("expected success = false")
	}
}

func TestLogin(t *testing.T) {
	c := parseOne(t, importertest.Options(), importertest.ReadFile(t, "nordpass.login.txt")).Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "SomeVaultItemName" || c.Notes != "Some note for the VaultItem" ||
		c.Login.Uri() != "https://example.com" || !reflect.DeepEqual(importertest.URIs(c), []string{"https://example.com"}) ||
		c.Login.Username != "hello@bitwarden.com" || c.Login.Password != "someStrongPassword" {
		t.Fatal(importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("textLabel", "text value", model.FieldTypeText),
		importertest.F("hiddenLabel", "hidden value", model.FieldTypeHidden))
}

func TestLoginWithAdditionalUrls(t *testing.T) {
	c := parseOne(t, importertest.Options(), importertest.ReadFile(t, "nordpass.login-with-additinal-urls.txt")).Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "SomeVaultItemName" || c.Notes != "Some note for the VaultItem" ||
		c.Login.Uri() != "https://example.com" ||
		!reflect.DeepEqual(importertest.URIs(c), []string{"https://example.com", "https://example.net"}) ||
		c.Login.Username != "hello@bitwarden.com" || c.Login.Password != "someStrongPassword" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestCreditCard(t *testing.T) {
	c := parseOne(t, importertest.Options(), importertest.ReadFile(t, "nordpass.card.txt")).Ciphers[0]
	if c.Type != model.CipherTypeCard || c.Name != "SomeVisa" || c.Card.Brand != "Visa" ||
		c.Card.CardholderName != "SomeHolder" || c.Card.Number != "4024007103939509" || c.Card.Code != "123" ||
		c.Card.ExpMonth != "1" || c.Card.ExpYear != "2022" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestIdentity(t *testing.T) {
	data := strings.Replace(importertest.ReadFile(t, "nordpass.identity.txt"), "#fullName", "MyFirstName MyMiddleName MyLastName", 1)
	c := parseOne(t, importertest.Options(), data).Ciphers[0]
	id := c.Identity
	if c.Type != model.CipherTypeIdentity || c.Name != "SomeTitle" || fullName(id) != "MyFirstName MyMiddleName MyLastName" ||
		id.FirstName != "MyFirstName" || id.MiddleName != "MyMiddleName" || id.LastName != "MyLastName" ||
		id.Email != "hello@bitwarden.com" || id.Phone != "123456789" || id.Address1 != "Test street 123" ||
		id.Address2 != "additional addressinfo" || id.PostalCode != "123456" || id.City != "Cologne" ||
		id.State != "North-Rhine-Westphalia" || id.Country != "GERMANY" || c.Notes != "SomeNoteToMyIdentity" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestIdentityNames(t *testing.T) {
	cases := []struct{ fullName, first, middle, last string }{
		{"MyFirstName", "MyFirstName", "", ""},
		{"MyFirstName MyLastName", "MyFirstName", "", "MyLastName"},
		{"MyFirstName MyMiddleName MyLastName", "MyFirstName", "MyMiddleName", "MyLastName"},
		{"MyFirstName MyMiddleName MyLastName Jr", "MyFirstName", "MyMiddleName", "MyLastName Jr"},
		{"MyFirstName MyMiddleName MyLastName Jr III", "MyFirstName", "MyMiddleName", "MyLastName Jr III"},
	}
	for _, tc := range cases {
		t.Run(tc.fullName, func(t *testing.T) {
			data := strings.Replace(importertest.ReadFile(t, "nordpass.identity.txt"), "#fullName", tc.fullName, 1)
			id := parseOne(t, importertest.Options(), data).Ciphers[0].Identity
			if id.FirstName != tc.first || id.MiddleName != tc.middle || id.LastName != tc.last {
				t.Fatal(importertest.Dump(id))
			}
		})
	}
}

func TestSecureNote(t *testing.T) {
	c := parseOne(t, importertest.Options(), importertest.ReadFile(t, "nordpass.secure-note.txt")).Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Name != "MySuperSecureNoteTitle" ||
		c.SecureNote.Type != model.SecureNoteTypeGeneric || c.Notes != "MySuperSecureNote" {
		t.Fatal(importertest.Dump(c))
	}
}

func TestFolder(t *testing.T) {
	r := parseOne(t, importertest.Options(), importertest.ReadFile(t, "nordpass.secure-note.txt"))
	if len(r.Folders) != 1 || r.Folders[0].Name != "notesFolder" {
		t.Fatal(importertest.Dump(r.Folders))
	}
}

func TestCollection(t *testing.T) {
	r := parseOne(t, importertest.OrgOptions(importer.NewGuid()), importertest.ReadFile(t, "nordpass.secure-note.txt"))
	if len(r.Collections) != 1 || r.Collections[0].Name != "notesFolder" {
		t.Fatal(importertest.Dump(r.Collections))
	}
}

func TestMalformedCustomFieldsThrow(t *testing.T) {
	data := "name,type,custom_fields\nx,note,\"[{\"\"label\"\"\"\n"
	if _, err := New(importertest.Options()).Parse(data); !importer.IsSyntaxError(err) {
		t.Fatalf("err = %v", err)
	}
}
