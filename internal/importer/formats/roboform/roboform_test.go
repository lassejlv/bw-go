package roboform

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/roboform-csv-importer.spec.ts (spec-data/roboform-csv).

func parse(t *testing.T, name string) *model.ImportResult {
	t.Helper()
	return importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, name))
}

const dataNoFolder = "empty-folders/data.txt"

func TestParseCsvData(t *testing.T) {
	r := parse(t, dataNoFolder)
	if len(r.Folders) != 0 || len(r.Ciphers) != 4 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "Bitwarden" || c.Login.Username != "user@bitwarden.com" || c.Login.Password != "password" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	// The "User ID$"/"Password$" fields equal the login fields and are skipped.
	if len(c.Fields) != 0 {
		t.Fatalf("%s", importertest.Dump(c.Fields))
	}
}

func TestParseCsvDataWithFolders(t *testing.T) {
	r := parse(t, "with-folders/data.txt")
	if len(r.Folders) != 3 || len(r.Ciphers) != 5 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestTotp(t *testing.T) {
	r := parse(t, dataNoFolder)
	if got := r.Ciphers[2].Login.Totp; got != "totpKeyValue" {
		t.Fatal(got)
	}
}

func TestCustomFields(t *testing.T) {
	r := parse(t, dataNoFolder)
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[1].Fields,
		importertest.F("Custom Field 1", "Custom Field 1 Value"),
		importertest.F("Custom Field 2", "Custom Field 2 Value"),
	)
}

func TestSecureNote(t *testing.T) {
	r := parse(t, dataNoFolder)
	c := r.Ciphers[3]
	if c.Type != model.CipherTypeSecureNote || c.Notes != "This is a safe note" || c.Name != "note - 2023-03-31" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestFolderHierarchy(t *testing.T) {
	r := parse(t, "with-folders/dataWithFolderHierarchy.txt")
	if len(r.Folders) != 5 || len(r.Ciphers) != 5 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	want := []string{"folder1", "folder2", "folder2/folder3", "folder1/folder2/folder3", "folder1/folder2"}
	for i, w := range want {
		if r.Folders[i].Name != w {
			t.Errorf("folder %d: %q, want %q", i, r.Folders[i].Name, w)
		}
	}
}

func TestAlternateUserIDsAndRfFields(t *testing.T) {
	data := "Name,Url,Login,Pwd,RfFieldsV2\n" +
		`Site,https://x.com,me,pw,"User ID$,,,txt,other","Password$,,,pwd,pw","Password$,,,pwd,pw2","-no-name-,,,txt,anon"` + "\n" +
		"Last,,,,\n"
	r := importertest.Parse(t, New(importertest.Options()), data)
	// The last row (name "Last", no password) is kept: only a trailing "--" row is dropped.
	if len(r.Ciphers) != 2 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[0].Fields,
		importertest.F("Alternate User ID 1", "other", model.FieldTypeText),
		importertest.F("Alternate Password 1", "pw2", model.FieldTypeHidden),
		importertest.F("", "anon"),
	)

	legacy := "Name,Url,Login,Pwd,Rf_fields\n" + `Site,https://x.com,me,pw,"a:b:c","-no-name-:x:rck:y","short:x"` + "\n"
	r = importertest.Parse(t, New(importertest.Options()), legacy)
	importertest.AssertCustomFieldsStructure(t, r.Ciphers[0].Fields,
		importertest.F("a", "c"),
		importertest.F("", "x"),
	)
}

func TestTrailingEmptyRowSkipped(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "Name,Url,Login,Pwd\nA,,u,p\n,,u2,\n")
	if len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	// Upstream reads cipher.login.password after cleanupCipher nulled login for a note: TypeError.
	if _, err := New(importertest.Options()).Parse("Name,Url,Login,Pwd\nA,,u,p\n,,,\n"); err == nil {
		t.Fatal("expected an error")
	}
}
