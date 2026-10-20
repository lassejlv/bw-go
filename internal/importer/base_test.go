package importer

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/base-importer.spec.ts.

func folderNames(r *model.ImportResult) []string {
	var out []string
	for _, f := range r.Folders {
		out = append(out, f.Name)
	}
	return out
}

func ciphersNamed(names ...string) []*model.CipherView {
	var out []*model.CipherView
	for _, n := range names {
		out = append(out, &model.CipherView{Name: n, ID: n})
	}
	return out
}

func TestProcessFolder(t *testing.T) {
	var b Base

	t.Run("adds a new folder and relationship when folderName is unique", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{{Name: "ABC"}}
		r.Ciphers = ciphersNamed("cipher1")
		b.ProcessFolder(r, "Folder1")
		if !reflect.DeepEqual(folderNames(r), []string{"ABC", "Folder1"}) ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 1}}) {
			t.Fatalf("%v %v", folderNames(r), r.FolderRelationships)
		}
	})

	t.Run("does not add duplicate folders and adds relationships", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{{Name: "Folder1"}}
		r.Ciphers = ciphersNamed("cipher1")
		b.ProcessFolder(r, "Folder1")
		if !reflect.DeepEqual(folderNames(r), []string{"Folder1"}) ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 0}}) {
			t.Fatalf("%v %v", folderNames(r), r.FolderRelationships)
		}
	})

	t.Run("creates parent folders for nested folder names but not duplicates", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{{Name: "Ancestor/Parent/Child"}, {Name: "Ancestor"}}
		r.Ciphers = ciphersNamed("cipher1")
		b.ProcessFolder(r, "Ancestor/Parent/Child/Grandchild/GreatGrandchild")
		want := []string{
			"Ancestor/Parent/Child",
			"Ancestor",
			"Ancestor/Parent/Child/Grandchild/GreatGrandchild",
			"Ancestor/Parent/Child/Grandchild",
			"Ancestor/Parent",
		}
		if !reflect.DeepEqual(folderNames(r), want) ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 2}}) {
			t.Fatalf("%v %v", folderNames(r), r.FolderRelationships)
		}
	})

	t.Run("does not affect existing relationships", func(t *testing.T) {
		r := model.NewImportResult()
		r.Folders = []*model.FolderView{{Name: "Parent"}, {Name: "Parent/Child"}}
		r.FolderRelationships = []model.Relationship{{1, 1}, {2, 1}}
		r.Ciphers = ciphersNamed("cipher1", "cipher2", "cipher3")
		b.ProcessFolder(r, "Parent/Child/Grandchild")
		if !reflect.DeepEqual(folderNames(r), []string{"Parent", "Parent/Child", "Parent/Child/Grandchild"}) ||
			!reflect.DeepEqual(r.FolderRelationships, []model.Relationship{{1, 1}, {2, 1}, {3, 2}}) {
			t.Fatalf("%v %v", folderNames(r), r.FolderRelationships)
		}
	})

	t.Run("does not add relationships if addRelationship is false", func(t *testing.T) {
		r := model.NewImportResult()
		b.ProcessFolder(r, "Folder1", false)
		if !reflect.DeepEqual(folderNames(r), []string{"Folder1"}) || len(r.FolderRelationships) != 0 {
			t.Fatalf("%v %v", folderNames(r), r.FolderRelationships)
		}
	})

	t.Run("replaces backslashes with forward slashes", func(t *testing.T) {
		r := model.NewImportResult()
		b.ProcessFolder(r, `Parent\Child\Grandchild`)
		if !reflect.DeepEqual(folderNames(r), []string{"Parent/Child/Grandchild", "Parent/Child", "Parent"}) {
			t.Fatalf("%v", folderNames(r))
		}
	})

	t.Run("trims leading slashes", func(t *testing.T) {
		r := model.NewImportResult()
		b.ProcessFolder(r, `\Parent\Child`)
		if !reflect.DeepEqual(folderNames(r), []string{"Parent/Child", "Parent"}) {
			t.Fatalf("%v", folderNames(r))
		}
	})

	t.Run("handles empty folder names", func(t *testing.T) {
		r := model.NewImportResult()
		b.ProcessFolder(r, "")
		b.ProcessFolder(r, "  ")
		if len(r.Folders) != 0 || len(r.FolderRelationships) != 0 {
			t.Fatal("expected nothing")
		}
	})
}

func TestSetCardExpiration(t *testing.T) {
	var b Base
	century := time.Now().Format("2006")[:2]
	newCard := func() *model.CipherView {
		c := b.InitLoginCipher()
		c.Card = &model.CardView{}
		c.Type = model.CipherTypeCard
		return c
	}
	ok := []struct{ in, month, year string }{
		{"01/2025", "1", "2025"},
		{"5/21", "5", century + "21"},
		{"10/2100", "10", "2100"},
		{"01/2032", "1", "2032"},
		{"09/2032", "9", "2032"},
		{"10/2032", "10", "2032"},
		{"12/00", "12", century + "00"},
		{"12/99", "12", century + "99"},
		{"12/32", "12", century + "32"},
		{"12/2042", "12", "2042"},
		{"01 / 2025", "1", "2025"},
		{"01  /  2025", "1", "2025"},
		{"  01/2025  ", "1", "2025"},
		{" 01/2025 ", "1", "2025"},
	}
	for _, c := range ok {
		cipher := newCard()
		if !b.SetCardExpiration(cipher, c.in) || cipher.Card.ExpMonth != c.month || cipher.Card.ExpYear != c.year {
			t.Errorf("%q -> %q/%q", c.in, cipher.Card.ExpMonth, cipher.Card.ExpYear)
		}
	}
	for _, bad := range []string{"", "  ", "0123", "01/03/23", "5/", "03/231", "12/1", "2/20221", "/2023", "003/2023", "111/32"} {
		if b.SetCardExpiration(newCard(), bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestParseXml(t *testing.T) {
	var b Base
	reject := map[string]string{
		"external entities": `<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE replace [
        <!ELEMENT replace ANY>
        <!ENTITY xxe "External entity">
        ]>
        <passwordsafe delimiter=";">
        <entry><title>PoC XXE</title><username>&xxe;</username></entry>
        </passwordsafe>`,
		"SYSTEM DTD": `<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE passwordsafe SYSTEM "http://evil.example.com/evil.dtd">
        <passwordsafe delimiter=";">
        <entry><title>PoC</title></entry>
        </passwordsafe>`,
		"PUBLIC http": `<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://evil.example.com/evil.dtd">
        <passwordsafe delimiter=";"><entry><title>PoC</title></entry></passwordsafe>`,
		"PUBLIC file": `<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE passwordsafe PUBLIC "-//x//y//EN" "file:///etc/passwd">
        <passwordsafe delimiter=";"><entry><title>PoC</title></entry></passwordsafe>`,
		"padded SYSTEM": `<!DOCTYPE passwordsafe ` + strings.Repeat(" ", 300) + `SYSTEM "http://evil.example.com/evil.dtd">
        <passwordsafe delimiter=";"><entry><title>PoC</title></entry></passwordsafe>`,
		"decoy": `<!-- <!DOCTYPE decoy> -->
        <!DOCTYPE passwordsafe SYSTEM "http://evil.example.com/evil.dtd">
        <passwordsafe delimiter=";"><entry><title>PoC</title></entry></passwordsafe>`,
		"parsererror element": `<root><parsererror/></root>`,
		"malformed":           `<root><a></root>`,
	}
	for name, xml := range reject {
		if b.ParseXml(xml) != nil {
			t.Errorf("%s: expected nil", name)
		}
	}

	start := time.Now()
	if b.ParseXml(strings.Repeat("<!DOCTYPE ", 150_000)) != nil {
		t.Error("pathological DOCTYPE accepted")
	}
	// Generous bound so the race detector's slowdown doesn't trip it; a quadratic scan of this
	// input would still take far longer.
	if time.Since(start) > 10*time.Second {
		t.Error("pathological DOCTYPE took too long")
	}

	doc := b.ParseXml(`<?xml version="1.0"?>
        <!DOCTYPE passwordsafe [<!ELEMENT passwordsafe ANY>]>
        <passwordsafe delimiter=";">
        <entry><title>Safe</title></entry>
        </passwordsafe>`)
	if doc == nil || doc.QuerySelector("passwordsafe > entry > title").TextContent() != "Safe" {
		t.Fatal("internal subset should be accepted")
	}
}

func TestParseCsvHelpers(t *testing.T) {
	var warnings []string
	b := Base{Warn: func(s string) { warnings = append(warnings, s) }}
	recs := b.ParseCsv("\ufeffname,url\r\n\"a,b\",x\r\nc\r\n", nil)
	if len(recs) != 2 || recs[0].Get("name") != "a,b" || recs[1].Has("url") {
		t.Fatalf("%+v", recs)
	}
	if !reflect.DeepEqual(warnings, []string{"Error parsing row 1: Too few fields: expected 2 fields but parsed 1"}) {
		t.Fatalf("warnings %q", warnings)
	}
	if b.ParseCsv("name,url", nil) != nil || b.ParseCsv("   ", nil) != nil || b.ParseCsvRows("", nil) != nil {
		t.Fatal("expected nil for no data")
	}
	if got := b.ParseSingleRowCsv(`https://a.com,"https://b.com,x"`); !reflect.DeepEqual(got, []string{"https://a.com", "https://b.com,x"}) {
		t.Fatalf("%q", got)
	}
	if b.ParseSingleRowCsv(" ") != nil {
		t.Fatal("blank row")
	}
}

func TestUriHelpers(t *testing.T) {
	var b Base
	if b.MakeUriArray() != nil || b.MakeUriArray("  ") != nil {
		t.Fatal("empty")
	}
	uris := b.MakeUriArray(" example.com ", "", "ftp://x", "nodot")
	var got []string
	for _, u := range uris {
		got = append(got, u.Uri)
	}
	if !reflect.DeepEqual(got, []string{"http://example.com", "ftp://x", "nodot"}) {
		t.Fatalf("%q", got)
	}
	if n := Len16(b.FixUri("https://x.com/" + strings.Repeat("a", 2000))); n != 1000 {
		t.Fatalf("len %d", n)
	}
	if b.NameFromUrl("https://www.example.com/x") != "example.com" || b.NameFromUrl("") != "" {
		t.Fatal("NameFromUrl")
	}
}

func TestCipherHelpers(t *testing.T) {
	b := Base{OrganizationID: "org"}
	c := b.InitLoginCipher()
	b.ProcessKvp(c, "short", "value")
	b.ProcessKvp(c, "multi", "a\r\nb")
	b.ProcessKvp(c, "", strings.Repeat("x", 201))
	b.ProcessKvp(c, "hidden", "h", model.FieldTypeHidden)
	b.ProcessKvp(c, "empty", "  ")
	if len(c.Fields) != 2 || c.Fields[1].Type != model.FieldTypeHidden {
		t.Fatalf("fields %+v", c.Fields)
	}
	if c.Notes != "multi: a\nb\n: "+strings.Repeat("x", 201)+"\n" {
		t.Fatalf("notes %q", c.Notes)
	}

	b.ConvertToNoteIfNeeded(c)
	if c.Type != model.CipherTypeSecureNote {
		t.Fatal("should convert to note")
	}
	b.CleanupCipher(c)
	if c.Login != nil || c.Name != "--" {
		t.Fatal("cleanup")
	}

	r := model.NewImportResult()
	r.Ciphers = ciphersNamed("a")
	b.ProcessFolder(r, "F/G")
	b.MoveFoldersToCollections(r)
	if len(r.Folders) != 0 || len(r.Collections) != 2 || r.Collections[0].OrganizationID != "org" ||
		!reflect.DeepEqual(r.CollectionRelationships, []model.Relationship{{1, 0}}) {
		t.Fatalf("%+v", r)
	}

	id := b.InitLoginCipher()
	b.ProcessFullName(id, "John Ronald Reuel Tolkien")
	if id.Identity.FirstName != "John" || id.Identity.MiddleName != "Ronald" || id.Identity.LastName != "Reuel Tolkien" {
		t.Fatalf("%+v", id.Identity)
	}
	if f, m, l := b.GetFullName("Bilbo Baggins"); f != "Bilbo" || m != "" || l != "Baggins" {
		t.Fatal(f, m, l)
	}
	if b.ProcessBankAccountType("CHECKING") != model.BankAccountTypeChecking || b.ProcessBankAccountType("x") != model.BankAccountTypeOther {
		t.Fatal("bank account type")
	}
	if b.ParseDateString("2020-06-19T22:00:00Z") != "2020-06-19" || b.ParseDateString("nope") != "" {
		t.Fatal("ParseDateString")
	}
	if b.GetValueOrDefault(" ", "--") != "--" || b.GetValueOrDefault(" ") != "" || b.GetValueOrDefault("x", "--") != "x" {
		t.Fatal("GetValueOrDefault")
	}
	if b.GetCardBrand("4111111111111111") != "Visa" || b.GetCardBrand("5555555555554444") != "Mastercard" ||
		b.GetCardBrand("378282246310005") != "Amex" || b.GetCardBrand("6011111111111117") != "Discover" ||
		b.GetCardBrand("3530111333300000") != "JCB" || b.GetCardBrand("30569309025904") != "Diners Club" || b.GetCardBrand("") != "" {
		t.Fatal("card brands")
	}
}
