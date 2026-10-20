package psono

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/psono/psono-json-importer.spec.ts (spec-data/psono-json).

func parse(t *testing.T, file string, opts ...string) *model.ImportResult {
	t.Helper()
	o := importertest.Options()
	if len(opts) > 0 {
		o = importertest.OrgOptions(opts[0])
	}
	return importertest.Parse(t, New(o), importertest.ReadFile(t, file))
}

func validateCustomField(t *testing.T, fields []*model.FieldView, name, value string, typ ...model.FieldType) {
	t.Helper()
	ft := model.FieldTypeText
	if len(typ) > 0 {
		ft = typ[0]
	}
	importertest.AssertCustomFieldsExist(t, fields, importertest.F(name, value, ft))
}

func TestWebsitePassword(t *testing.T) {
	c := parse(t, "WebsiteLoginsData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "TestEntry" || c.Notes != "some notes" ||
		c.Login.Username != "testUser" || c.Login.Password != "testPassword" || len(c.Login.Uris) != 1 ||
		c.Login.Uri() != "http://bitwarden.com" || len(c.Fields) != 7 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "website_password_auto_submit", "true", model.FieldTypeBoolean)
	validateCustomField(t, c.Fields, "website_password_url_filter", "filter")
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:24:09.810266Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:24:09.810292Z")
	validateCustomField(t, c.Fields, "callback_url", "callback")
	validateCustomField(t, c.Fields, "callback_user", "callbackUser")
	validateCustomField(t, c.Fields, "callback_pass", "callbackPassword")
}

func TestReducedWebsitePassword(t *testing.T) {
	c := parse(t, "ReducedWebsiteLoginsData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "export_website_1" || c.Login.Username != "username123" ||
		c.Login.Password != "password123" || c.Login.Uris != nil || len(c.Fields) != 2 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "create_date", "2022-09-10T23:05:02.351417Z")
	validateCustomField(t, c.Fields, "write_date", "2022-09-10T23:05:02.351583Z")
}

func TestApplicationPassword(t *testing.T) {
	c := parse(t, "ApplicationPasswordsData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "My App Password" || c.Notes != "some notes for the APP" ||
		c.Login.Username != "someUser" || c.Login.Password != "somePassword" || len(c.Fields) != 2 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:42:05.784077Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:42:05.784103Z")
}

func TestBookmark(t *testing.T) {
	c := parse(t, "BookmarkData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "MyBookmark" || c.Notes != "my notes for bitwarden.com" ||
		len(c.Login.Uris) != 1 || c.Login.Uri() != "https://bitwarden.com" || len(c.Fields) != 4 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:39:26.631530Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:39:26.631553Z")
}

func TestNotes(t *testing.T) {
	c := parse(t, "NotesData.json").Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Name != "My Note" || c.Notes != "Notes for my Note" || len(c.Fields) != 2 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:41:18.770714Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:41:18.770738Z")
}

func TestTOTP(t *testing.T) {
	c := parse(t, "TOTPData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "My TOTP" || c.Notes != "Notes for TOTP" ||
		c.Login.Totp != "someSecretOfMine" || len(c.Fields) != 5 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "totp_period", "30")
	validateCustomField(t, c.Fields, "totp_algorithm", "SHA1")
	validateCustomField(t, c.Fields, "totp_digits", "6")
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:41:42.972586Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:41:42.972609Z")
}

// Upstream skips its GPG test ("Skipping this until we can save GPG into notes/custom fields");
// GPG items currently import as empty logins.
func TestGPGSkipped(t *testing.T) {
	c := parse(t, "GPGData.json").Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "--" || len(c.Fields) != 0 {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestEnvironmentVariables(t *testing.T) {
	c := parse(t, "EnvVariablesData.json").Ciphers[0]
	if c.Type != model.CipherTypeSecureNote || c.Name != "My Environment Variables" ||
		c.Notes != "Notes for environment variables" || len(c.Fields) != 4 {
		t.Fatalf("%s", importertest.Dump(c))
	}
	validateCustomField(t, c.Fields, "Key1", "Value1")
	validateCustomField(t, c.Fields, "Key2", "Value2")
	validateCustomField(t, c.Fields, "create_date", "2022-12-13T19:41:02.028884Z")
	validateCustomField(t, c.Fields, "write_date", "2022-12-13T19:41:02.028909Z")
}

func TestEmptyFolders(t *testing.T) {
	if r := parse(t, "EmptyTestFolderData.json"); len(r.Folders) != 0 {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
}

func folderNames(fs []*model.FolderView) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

func TestCreateFolders(t *testing.T) {
	r := parse(t, "FoldersTestData.json")
	if got := strings.Join(folderNames(r.Folders), "|"); got != "TestFolder|TestFolder2" {
		t.Fatal(got)
	}
	if len(r.Ciphers) != len(r.FolderRelationships) {
		t.Fatalf("%d ciphers, %d relationships", len(r.Ciphers), len(r.FolderRelationships))
	}
}

func TestCollections(t *testing.T) {
	r := parse(t, "FoldersTestData.json", "someOrg")
	if len(r.Collections) != 2 || r.Collections[0].Name != "TestFolder" || r.Collections[1].Name != "TestFolder2" {
		t.Fatalf("%s", importertest.Dump(r.Collections))
	}
}

func TestSubFolders(t *testing.T) {
	r := parse(t, "SubFoldersTestData.json")
	want := "TestFolder/SubFolder1/SubSubFolder1|TestFolder/SubFolder1|TestFolder|TestFolder2"
	if got := strings.Join(folderNames(r.Folders), "|"); got != want {
		t.Fatal(got)
	}
	if len(r.FolderRelationships) != len(r.Ciphers) {
		t.Fatalf("%d ciphers, %d relationships", len(r.Ciphers), len(r.FolderRelationships))
	}
}

func TestTypeErrors(t *testing.T) {
	for _, data := range []string{
		`{"items":[null]}`,
		`{"items":[{"type":"note","note_title":"x","extra":null}]}`,
		`{"items":[{"type":"environment_variables"}]}`,
	} {
		if _, err := New(importertest.Options()).Parse(data); err == nil {
			t.Errorf("%s: expected an error", data)
		}
	}
	r := importertest.Parse(t, New(importertest.Options()), `null`)
	if r.Success {
		t.Fatal("null must fail")
	}
}
