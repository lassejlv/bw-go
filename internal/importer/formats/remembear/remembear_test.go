package remembear

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for remembear-csv-importer.ts; these tests follow its logic.

const data = `trash,type,name,notes,website,username,password,cardholder,number,verification,expiryMonth,expiryYear,pin,zipCode
false,LoginItem,Login,n1,example.com,user,pass,,,,,,,
true,LoginItem,Trashed,,,,,,,,,,,
false,CreditCardItem,Card,,,,,Jane,4111111111111111,123,0x0C,20xx,1234,90210
false,CreditCardItem,Card2,,,,,,,,13,abc,,
false,Other,Thing,,,,,,,,,,,`

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), data)
	if len(r.Ciphers) != 4 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	l := r.Ciphers[0]
	if l.Type != model.CipherTypeLogin || l.Name != "Login" || l.Notes != "n1" || l.Login.Username != "user" ||
		l.Login.Password != "pass" || !reflect.DeepEqual(importertest.URIs(l), []string{"http://example.com"}) {
		t.Fatalf("%s", importertest.Dump(l))
	}
	c := r.Ciphers[1]
	if c.Type != model.CipherTypeCard || c.Card.CardholderName != "Jane" || c.Card.Brand != "Visa" || c.Card.Code != "123" ||
		c.Card.ExpMonth != "12" || c.Card.ExpYear != "20" || c.Login != nil {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("PIN", "1234"), importertest.F("Zip Code", "90210"))
	c2 := r.Ciphers[2]
	if c2.Card.ExpMonth != "" || c2.Card.ExpYear != "NaN" {
		t.Fatalf("%s", importertest.Dump(c2.Card))
	}
	if o := r.Ciphers[3]; o.Type != model.CipherTypeLogin || o.Name != "Thing" {
		t.Fatalf("%s", importertest.Dump(o))
	}
}

func TestRegistered(t *testing.T) {
	if !importer.IsImplemented("remembearcsv") {
		t.Fatal("not registered")
	}
}
