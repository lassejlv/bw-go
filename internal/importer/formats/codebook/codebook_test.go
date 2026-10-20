package codebook

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// No upstream spec; expectations follow codebook-csv-importer.ts.

const csv = "Category,Favorite,Entry,Note,Username,Email,Phone,PIN,Account,Website,Date,Password,TOTP\n" +
	"Web,True,Site,n,user,me@x.com,555,1234,,example.com,2020-01-01,pw,otp\n" +
	"Web,False,Email only,,,me@x.com,,,,,,,\n" +
	",False,Plain,just a note,,,,,,,,,"

func TestCodebookCsvImporter(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), csv)
	if !r.Success || len(r.Ciphers) != 3 {
		t.Fatal(importertest.Dump(r))
	}
	a := r.Ciphers[0]
	if !a.Favorite || a.Name != "Site" || a.Notes != "n" || a.Login.Username != "user" || a.Login.Password != "pw" ||
		a.Login.Totp != "otp" || a.Login.Uris[0].Uri != "http://example.com" {
		t.Fatal(importertest.Dump(a))
	}
	importertest.AssertCustomFieldsStructure(t, a.Fields, importertest.F("Email", "me@x.com"),
		importertest.F("Phone", "555"), importertest.F("PIN", "1234"), importertest.F("Date", "2020-01-01"))

	b := r.Ciphers[1]
	if b.Favorite || b.Login.Username != "me@x.com" || len(b.Fields) != 0 {
		t.Fatal(importertest.Dump(b))
	}
	if r.Ciphers[2].Type != model.CipherTypeSecureNote {
		t.Fatal(importertest.Dump(r.Ciphers[2]))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != "Web" || len(r.FolderRelationships) != 2 {
		t.Fatal(importertest.Dump(r))
	}

	org := importertest.Parse(t, New(importertest.OrgOptions("org")), csv)
	if len(org.Folders) != 0 || len(org.Collections) != 1 || org.Collections[0].Name != "Web" || len(org.CollectionRelationships) != 2 {
		t.Fatal(importertest.Dump(org))
	}
}
