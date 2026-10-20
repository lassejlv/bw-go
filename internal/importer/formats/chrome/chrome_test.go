package chrome

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/chrome-csv-importer.spec.ts (spec-data/chrome-csv).

const androidData = `name,url,username,password
,android://N2H9MndUUUt3JuQSWAKexOU9oJLJeHR4nyUGac5E1TXKppkY7xtdRl6l8vKo1hQWCqAEy4gsNLUBIbVxpdmhOP==@com.xyz.example.app.android/,username@example.com,Qh6W4Wz55YGFNU`

const simplePasswordData = `name,url,username,password
www.example.com,https://www.example.com/,username@example.com,wpC9qFvsbWQK5Z`

const notesData = "name,url,username,password,note\r\n" +
	`www.example.com,https://www.example.com/,username@example.com,fake-password,"First line, with a comma` + "\r\n" + `Second line with ""quotes"""` + "\r\n"

func TestChromeCsvImporter(t *testing.T) {
	cases := []struct {
		title, csv, name, notes, user, pass, uri string
	}{
		{"should parse app name", androidData, "com.xyz.example.app.android", "", "username@example.com", "Qh6W4Wz55YGFNU", "androidapp://com.xyz.example.app.android"},
		{"should parse password", simplePasswordData, "www.example.com", "", "username@example.com", "wpC9qFvsbWQK5Z", "https://www.example.com/"},
		{"should parse note", notesData, "www.example.com", "First line, with a comma\nSecond line with \"quotes\"", "username@example.com", "fake-password", "https://www.example.com/"},
	}
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), c.csv)
			if !r.Success || len(r.Ciphers) == 0 {
				t.Fatalf("%+v", r)
			}
			cipher := r.Ciphers[0]
			if cipher.Type != model.CipherTypeLogin || cipher.Name != c.name || cipher.Notes != c.notes ||
				cipher.Login.Username != c.user || cipher.Login.Password != c.pass ||
				!reflect.DeepEqual(importertest.URIs(cipher), []string{c.uri}) || len(cipher.Fields) != 0 || cipher.Favorite {
				t.Fatalf("%s", importertest.Dump(cipher))
			}
		})
	}
}

func TestAndroidURIWithoutAt(t *testing.T) {
	// A URL with no @ must be returned as-is (not converted to androidapp://).
	noAtURL := "android://com.example.app.noemail"
	r := importertest.Parse(t, New(importertest.Options()), "name,url,username,password\n,"+noAtURL+",user,pass")
	if got := r.Ciphers[0].Login.Uris[0].Uri; got != noAtURL {
		t.Fatal(got)
	}
}

func TestRegisteredIDs(t *testing.T) {
	for _, id := range IDs {
		imp, err := importer.New(id, importer.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := imp.(*Importer); !ok {
			t.Fatalf("%s: %T", id, imp)
		}
	}
}
