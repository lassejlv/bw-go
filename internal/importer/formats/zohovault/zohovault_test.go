package zohovault

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/zohovault-csv-importer.spec.ts (spec-data/zohovault).

func TestNoData(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), "")
	if r.Success {
		t.Fatal("expected failure")
	}
}

func TestZohoVaultCsvImporter(t *testing.T) {
	cases := []struct {
		title, file, name, user, pass, totp string
	}{
		{"should parse Zoho Vault CSV format", "data.txt", "XYZ Test", "email@domain.de", "PcY_IQEXIjKGj8YW",
			"otpauth://totp?secret=PI2XO5TW0DF0SHTYOVZXOOBVHFEWM6JU&algorithm=SHA1&period=30&digits=6"},
		{"should parse legacy Zoho Vault CSV format with login_totp column", "legacyData.txt", "XYZ Test Legacy",
			"legacy@domain.de", "LegacyPassword", "otpauth://totp?secret=LEGACYSECRET&algorithm=SHA1&period=30&digits=6"},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, c.file))
			if len(r.Ciphers) == 0 {
				t.Fatal("no ciphers")
			}
			cipher := r.Ciphers[0]
			if cipher.Type != model.CipherTypeLogin || cipher.Favorite || cipher.Name != c.name ||
				cipher.Login.Username != c.user || cipher.Login.Password != c.pass || cipher.Login.Totp != c.totp ||
				!reflect.DeepEqual(importertest.URIs(cipher), []string{"https://abc.bitwarden.com:5001/#/login"}) {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
		})
	}
}

func TestFolder(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), importertest.ReadFile(t, "data.txt"))
	if !r.Success || len(r.Ciphers) == 0 || r.Folders[0].Name != "folderName" ||
		r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestOrganizationCollection(t *testing.T) {
	r := importertest.Parse(t, New(importertest.OrgOptions("someOrgId")), importertest.ReadFile(t, "data.txt"))
	if !r.Success || len(r.Ciphers) == 0 || r.Collections[0].Name != "folderName" ||
		r.CollectionRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}
