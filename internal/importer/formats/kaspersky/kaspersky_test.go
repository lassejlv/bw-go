package kaspersky

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Upstream has no spec for kaspersky-txt-importer.ts; these tests follow its logic.

const data = "Websites\r\n\r\n" +
	"Website name: Example\nWebsite URL: https://example.com\nLogin name: work\nLogin: user\nPassword: pass\nComment: first\nsecond\n" +
	"---\n" +
	"Website name: \nWebsite URL:\nLogin: u2\nPassword: p2\nComment:\nnot appended\n" +
	"---\n\n" +
	"Applications\n\n" +
	"Application: App\nLogin: appuser\nPassword: apppass\nComment: \n" +
	"---\n\n" +
	"Notes\n\n" +
	"Name: My note\nText: line1\nline2\n" +
	"---\n"

func TestParse(t *testing.T) {
	r := importertest.Parse(t, New(importertest.Options()), data)
	if !r.Success || len(r.Ciphers) != 4 {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	n := r.Ciphers[0]
	if n.Type != model.CipherTypeLogin || n.Name != "My note" || n.Notes != "line1\nline2" {
		t.Fatalf("%s", importertest.Dump(n))
	}
	w := r.Ciphers[1]
	if w.Name != "Example: work" || w.Login.Username != "user" || w.Login.Password != "pass" || w.Notes != "first\nsecond" ||
		!reflect.DeepEqual(importertest.URIs(w), []string{"https://example.com"}) {
		t.Fatalf("%s", importertest.Dump(w))
	}
	w2 := r.Ciphers[2]
	// "Comment:" with nothing after the colon is undefined, so later lines are not appended.
	if w2.Name != "--" || w2.Login.Uris != nil || w2.Notes != "" || w2.Login.Username != "u2" {
		t.Fatalf("%s", importertest.Dump(w2))
	}
	a := r.Ciphers[3]
	if a.Name != "App" || a.Login.Username != "appuser" || a.Notes != "" {
		t.Fatalf("%s", importertest.Dump(a))
	}
	if !importer.IsImplemented("kasperskytxt") {
		t.Fatal("not registered")
	}
}
