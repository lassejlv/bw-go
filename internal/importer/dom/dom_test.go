package dom

import (
	"testing"
)

const sampleXML = `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [<!ELEMENT root ANY>]>
<root>
  <Database>
    <Logins>
      <Login ID="1" Name="a"><![CDATA[x<y]]></Login>
      <Login ID="2" Name="b">t &amp; u</Login>
    </Logins>
    <Groups>
      <Group ID="10" Name="g"><Group ID="11" Name="h"/></Group>
    </Groups>
  </Database>
  <!-- comment -->
  <x:item xmlns:x="urn:x" x:attr="1">ns</x:item>
</root>`

func TestParseXMLAndSelectors(t *testing.T) {
	doc, err := ParseXML(sampleXML)
	if err != nil {
		t.Fatal(err)
	}
	logins := doc.QuerySelectorAll("root > Database > Logins > Login")
	if len(logins) != 2 || logins[0].Attr("ID") != "1" || logins[0].TextContent() != "x<y" || logins[1].TextContent() != "t & u" {
		t.Fatalf("logins %+v", logins)
	}
	g := doc.QuerySelector(`root > Database > Groups > Group[ID="10"]`)
	if g == nil || g.Attr("Name") != "g" {
		t.Fatalf("group %+v", g)
	}
	if doc.QuerySelector("login") != nil {
		t.Fatal("XML type selectors are case-sensitive")
	}
	groups := doc.QuerySelector("Groups")
	if n := len(groups.QuerySelectorAllDirectChild("Group")); n != 1 {
		t.Fatalf("direct children %d", n)
	}
	if n := len(groups.QuerySelectorAll("Group")); n != 2 {
		t.Fatalf("all %d", n)
	}
	item := doc.QuerySelector("item")
	if item == nil || item.TagName() != "x:item" || item.Attr("x:attr") != "1" {
		t.Fatalf("ns item %+v", item)
	}
	if n := len(doc.QuerySelector("Logins").QuerySelectorAll("Login[ID='1'], Login[Name=b]")); n != 2 {
		t.Fatalf("list %d", n)
	}
	// Element-scoped query still evaluates combinators against the whole document.
	if doc.QuerySelector("Logins").QuerySelector("Database Login") == nil {
		t.Fatal("scoped descendant")
	}
}

func TestParseXMLErrors(t *testing.T) {
	for _, bad := range []string{
		"",
		"<a><b></a>",
		"<a>&nbsp;</a>",
		"<a/><b/>",
		"text<a/>",
		"<a>",
		"not xml at all",
	} {
		if _, err := ParseXML(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseHTML(t *testing.T) {
	doc := ParseHTML(`<!DOCTYPE html><HTML><body><p>one<p>two<br><textarea id=t class="a b">{"a":"&lt;b&gt;"} <i>x</i></textarea>
<pre>url,username
x,y</pre><ul><li>1<li>2</ul><script>if (a < b) {}</script></body></html>`)
	ta := doc.QuerySelector("textarea")
	if ta == nil || ta.TextContent() != `{"a":"<b>"} <i>x</i>` || ta.Attr("ID") != "t" {
		t.Fatalf("textarea %+v", ta)
	}
	if doc.QuerySelector("TEXTAREA.b#t") != ta {
		t.Fatal("case-insensitive selector")
	}
	if pre := doc.QuerySelector("pre"); pre == nil || pre.TextContent() != "url,username\nx,y" {
		t.Fatalf("pre %+v", pre)
	}
	if n := len(doc.QuerySelectorAll("ul > li")); n != 2 {
		t.Fatalf("li %d", n)
	}
	if n := len(doc.QuerySelectorAll("body > p")); n != 2 {
		t.Fatalf("p %d", n)
	}
	if s := doc.QuerySelector("script"); s.TextContent() != "if (a < b) {}" {
		t.Fatalf("script %q", s.TextContent())
	}
}

func TestSelectorErrors(t *testing.T) {
	for _, bad := range []string{"", "a:first-child", "a[", "a,,b", "[x="} {
		if _, err := Compile(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseXMLWithBOM(t *testing.T) {
	doc, err := ParseXML("\ufeff<?xml version=\"1.0\"?><a>x</a>")
	if err != nil || doc.QuerySelector("a").TextContent() != "x" {
		t.Fatal(err)
	}
}
