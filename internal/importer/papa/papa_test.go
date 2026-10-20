package papa

import (
	"reflect"
	"testing"
)

func TestParseRowsFastMode(t *testing.T) {
	r := Parse("a,b,c\n1,2,3", Config{})
	want := [][]string{{"a", "b", "c"}, {"1", "2", "3"}}
	if !reflect.DeepEqual(r.Rows, want) {
		t.Fatalf("got %q", r.Rows)
	}
	if r.Meta.Delimiter != "," || r.Meta.Linebreak != "\n" {
		t.Fatalf("meta %+v", r.Meta)
	}
}

func TestParseQuoted(t *testing.T) {
	in := "name,notes\nx,\"First line, with a comma\nSecond line with \"\"quotes\"\"\"\ny,  \"spaced\"  ,z"
	r := Parse(in, Config{})
	want := [][]string{
		{"name", "notes"},
		{"x", "First line, with a comma\nSecond line with \"quotes\""},
		{"y", "  \"spaced\"  ", "z"},
	}
	if !reflect.DeepEqual(r.Rows, want) {
		t.Fatalf("got %q", r.Rows)
	}
}

func TestParseQuotedFieldSpacesBeforeDelimiter(t *testing.T) {
	r := Parse("\"a\"  ,b\n\"c\"   \nd,e", Config{})
	want := [][]string{{"a", "b"}, {"c"}, {"d", "e"}}
	if !reflect.DeepEqual(r.Rows, want) {
		t.Fatalf("got %q", r.Rows)
	}
}

func TestParseDelimiterGuess(t *testing.T) {
	r := Parse("a;b;c\n1;2;3", Config{})
	if r.Meta.Delimiter != ";" || len(r.Rows[0]) != 3 {
		t.Fatalf("got %q delim %q", r.Rows, r.Meta.Delimiter)
	}
	r = Parse("a\tb\n1\t2", Config{})
	if r.Meta.Delimiter != "\t" {
		t.Fatalf("delim %q", r.Meta.Delimiter)
	}
	// One column: undetectable, defaults to "," and reports an error without a row.
	r = Parse("abc\ndef", Config{})
	if r.Meta.Delimiter != "," || len(r.Errors) != 1 || r.Errors[0].Code != "UndetectableDelimiter" || r.Errors[0].Row != nil {
		t.Fatalf("errors %+v", r.Errors)
	}
}

func TestParseHeader(t *testing.T) {
	r := Parse("a,b,a,a_1\n1,2,3,4,5\n6", Config{Header: true})
	if !reflect.DeepEqual(r.Meta.Fields, []string{"a", "b", "a_2", "a_1"}) {
		t.Fatalf("fields %q", r.Meta.Fields)
	}
	if len(r.Records) != 2 {
		t.Fatalf("records %d", len(r.Records))
	}
	rec := r.Records[0]
	if rec.Get("a") != "1" || rec.Get("a_2") != "3" || rec.Get("a_1") != "4" || !reflect.DeepEqual(rec.Extra, []string{"5"}) {
		t.Fatalf("rec %+v", rec)
	}
	if r.Records[1].Has("b") || r.Records[1].Get("a") != "6" {
		t.Fatalf("rec2 %+v", r.Records[1])
	}
	var codes []string
	for _, e := range r.Errors {
		codes = append(codes, e.Code)
	}
	if !reflect.DeepEqual(codes, []string{"TooManyFields", "TooFewFields"}) || *r.Errors[1].Row != 1 {
		t.Fatalf("errors %+v", r.Errors)
	}
	if r.Errors[1].Message != "Too few fields: expected 4 fields but parsed 1" {
		t.Fatal(r.Errors[1].Message)
	}
}

func TestParseHeaderOnly(t *testing.T) {
	r := Parse("a,b", Config{Header: true})
	if len(r.Records) != 0 {
		t.Fatal("expected no records")
	}
}

func TestSkipEmptyLines(t *testing.T) {
	in := "a,b\n\n1,2\n , \n"
	if got := Parse(in, Config{Delimiter: ","}).Len(); got != 5 {
		t.Fatalf("no skip: %d", got)
	}
	if got := Parse(in, Config{Delimiter: ",", SkipEmptyLines: SkipEmpty}).Len(); got != 3 {
		t.Fatalf("skip: %d", got)
	}
	if got := Parse(in, Config{Delimiter: ",", SkipEmptyLines: SkipGreedy}).Len(); got != 2 {
		t.Fatalf("greedy: %d", got)
	}
}

func TestEscapeChar(t *testing.T) {
	esc := `\`
	r := Parse(`a,"b \"quoted\" c",d`, Config{EscapeChar: &esc})
	want := [][]string{{"a", `b "quoted" c`, "d"}}
	if !reflect.DeepEqual(r.Rows, want) {
		t.Fatalf("got %q", r.Rows)
	}
}

func TestMissingQuotes(t *testing.T) {
	r := Parse("a,\"bc\nd", Config{Delimiter: ","})
	if len(r.Errors) != 1 || r.Errors[0].Code != "MissingQuotes" || *r.Errors[0].Row != 0 {
		t.Fatalf("errors %+v", r.Errors)
	}
	if !reflect.DeepEqual(r.Rows, [][]string{{"a", "bc\nd"}}) {
		t.Fatalf("rows %q", r.Rows)
	}
}

func TestInvalidQuotes(t *testing.T) {
	r := Parse("\"a\"b\",c", Config{Delimiter: ","})
	if len(r.Errors) != 1 || r.Errors[0].Code != "InvalidQuotes" {
		t.Fatalf("errors %+v", r.Errors)
	}
	if !reflect.DeepEqual(r.Rows, [][]string{{"a\"b", "c"}}) {
		t.Fatalf("rows %q", r.Rows)
	}
}

func TestComments(t *testing.T) {
	r := Parse("# comment\na,b\n#x\n1,2", Config{Comments: "#", Delimiter: ","})
	if !reflect.DeepEqual(r.Rows, [][]string{{"a", "b"}, {"1", "2"}}) {
		t.Fatalf("rows %q", r.Rows)
	}
}

func TestTransformHeader(t *testing.T) {
	r := Parse("A,B\n1,2", Config{Header: true, TransformHeader: func(h string, _ int) string {
		if h == "A" || h == "a" {
			return "a"
		}
		return h
	}})
	if r.Records[0].Get("a") != "1" || r.Records[0].Get("B") != "2" {
		t.Fatalf("%+v", r.Records[0])
	}
}

func TestRecordKeysOrder(t *testing.T) {
	r := NewRecord("b", "1", "2", "x", "a", "2", "1", "y")
	if got := r.Keys(); !reflect.DeepEqual(got, []string{"1", "2", "b", "a"}) {
		t.Fatalf("keys %q", got)
	}
}

func TestCRLFNewlineGuess(t *testing.T) {
	r := Parse("a,b\r\n1,2\r\n", Config{})
	if r.Meta.Linebreak != "\r\n" || len(r.Rows) != 3 {
		t.Fatalf("%q %q", r.Meta.Linebreak, r.Rows)
	}
}
