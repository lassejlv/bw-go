package logmeonce

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/logmeonce-csv-importer.spec.ts.

const oldFormatCSV = `"name","url","username","password","group","extra"
"Facebook (auser)","https://www.facebook.com/","auser","123456","Favorites",""`

const newFormatCSV = `"name","url","note","group","username","password","passkey","extra"
"Facebook (auser)","https://www.facebook.com/","","Favorites","auser","123456","",""`

func TestLogMeOnceCsvImporter(t *testing.T) {
	for _, csv := range []string{oldFormatCSV, newFormatCSV} {
		r := importertest.Parse(t, New(importertest.Options()), csv)
		if len(r.Ciphers) != 1 {
			t.Fatalf("ciphers = %d", len(r.Ciphers))
		}
		c := r.Ciphers[0]
		if c.Name != "Facebook (auser)" || !reflect.DeepEqual(importertest.URIs(c), []string{"https://www.facebook.com/"}) ||
			c.Login.Username != "auser" || c.Login.Password != "123456" {
			t.Fatal(importertest.Dump(c))
		}
		if len(r.Folders) != 1 || r.Folders[0].Name != "Favorites" ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{0, 0}}) {
			t.Fatal(importertest.Dump(r))
		}
	}
}
