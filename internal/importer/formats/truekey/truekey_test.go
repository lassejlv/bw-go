package truekey

import (
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for truekey-csv-importer.ts; these tests follow its logic.

const data = `kind,autologin,favorite,hexColor,name,note,protectedWithPassword,subdomainOnly,type,url,username,password,login,memo,title,cardholder,number,expiryDate,document_content,extra
login,1,true,,Login,ignored,,,,example.com,,pw,user,memo text,,,,,,
cc,,FALSE,,,cc note,,,,,,,,,My Card,Jane,4111111111111111,2025-03-01,,
note,,,,,note text,,,,,,,,,My Note,,,,doc body,extra value`

func TestParse(t *testing.T) {
	old := time.Local
	time.Local = time.UTC
	defer func() { time.Local = old }()

	r := importertest.Parse(t, New(importertest.Options()), data)
	if len(r.Ciphers) != 3 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	l := r.Ciphers[0]
	if !l.Favorite || l.Name != "Login" || l.Notes != "memo text" || l.Login.Username != "user" || l.Login.Password != "pw" ||
		l.Login.Uris[0].Uri != "http://example.com" {
		t.Fatalf("%s", importertest.Dump(l))
	}
	c := r.Ciphers[1]
	if c.Type != model.CipherTypeCard || c.Favorite || c.Name != "My Card" || c.Notes != "cc note" ||
		c.Card.CardholderName != "Jane" || c.Card.Brand != "Visa" || c.Card.ExpYear != "2025" || c.Card.ExpMonth != "3" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	n := r.Ciphers[2]
	// Non-empty notes are replaced by document_content; unignored columns become fields.
	if n.Type != model.CipherTypeSecureNote || n.Name != "My Note" || n.Notes != "doc body" {
		t.Fatalf("%s", importertest.Dump(n))
	}
	importertest.AssertCustomFieldsStructure(t, n.Fields, importertest.F("extra", "extra value"))

	r = importertest.Parse(t, New(importertest.Options()), "kind,title,expiryDate\ncc,X,not a date\n")
	if c := r.Ciphers[0]; c.Card.ExpYear != "NaN" || c.Card.ExpMonth != "NaN" {
		t.Fatalf("%s", importertest.Dump(c.Card))
	}
	if !importer.IsImplemented("truekeycsv") {
		t.Fatal("not registered")
	}
}
