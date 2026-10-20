package importer

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Expected values produced by tldts 7.4.2 getHostname (the version upstream pins).
func TestGetHostname(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://www.example.com/", "www.example.com"},
		{"http://Example.COM:8080/path", "example.com"},
		{"example.com", "example.com"},
		{"www.Example.com", "www.example.com"},
		{"user:pw@host.com/x", "host.com"},
		{"//cdn.example.com/a", "cdn.example.com"},
		{"androidapp://com.x.y", "com.x.y"},
		{"ftp://files.example.org", "files.example.org"},
		{"[::1]", "::1"},
		{"http://[2001:db8::1]:80/", "2001:db8::1"},
		{"not a url", ""},
		{"mailto:a@b.com", "b.com"},
		{"https://example.com.", "example.com"},
		{"localhost", "localhost"},
		{"http://localhost:3000", "localhost"},
		{"192.168.0.1", "192.168.0.1"},
		{"foo", "foo"},
		{"https://sub.domain.co.uk/path?x#y", "sub.domain.co.uk"},
		{"chrome://FirefoxAccounts", "firefoxaccounts"},
		{"javascript:alert(1)", ""},
		{"a b.com", ""},
		{"HTTPS://WWW.EXAMPLE.COM", "www.example.com"},
		{"http://ex_ample.com", "ex_ample.com"},
		{"https://-bad.com", ""},
		{"example..com", ""},
		{"x://y", "y"},
		// Utils.getHostname's own guards
		{"data:text/plain,hi", ""},
		{"about:blank", ""},
		{"file:///etc/passwd", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := GetHostname(c.in); got != c.want {
			t.Errorf("GetHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Expected values produced by V8's Date parser.
func TestParseJSDate(t *testing.T) {
	utc := []struct{ in, want string }{
		{"2020-01-15", "2020-01-15T00:00:00.000Z"},
		{"2020-01-15T10:20:30Z", "2020-01-15T10:20:30.000Z"},
		{"2020-01-15T10:20:30.123+02:00", "2020-01-15T08:20:30.123Z"},
		{"2020", "2020-01-01T00:00:00.000Z"},
		{"2020-06", "2020-06-01T00:00:00.000Z"},
		{"2020-02-30", "2020-03-01T00:00:00.000Z"},
		{"Tue, 01 Mar 2022 10:00:00 GMT", "2022-03-01T10:00:00.000Z"},
		{"Tue Mar 01 2022 10:00:00 GMT+0100 (Central European Standard Time)", "2022-03-01T09:00:00.000Z"},
		{"1 Jan 2018 10:00 UTC", "2018-01-01T10:00:00.000Z"},
	}
	for _, c := range utc {
		got, ok := ParseJSDate(c.in)
		if !ok || got.UTC().Format("2006-01-02T15:04:05.000Z") != c.want {
			t.Errorf("ParseJSDate(%q) = %v %v, want %s", c.in, got, ok, c.want)
		}
	}
	local := []struct {
		in   string
		want time.Time
	}{
		{"June 20, 2020", time.Date(2020, 6, 20, 0, 0, 0, 0, time.Local)},
		{"June,20,2020", time.Date(2020, 6, 20, 0, 0, 0, 0, time.Local)},
		{"20 June 2020", time.Date(2020, 6, 20, 0, 0, 0, 0, time.Local)},
		{"06/20/2020", time.Date(2020, 6, 20, 0, 0, 0, 0, time.Local)},
		{"6/2/20", time.Date(2020, 6, 2, 0, 0, 0, 0, time.Local)},
		{"2020/06/20 10:00:00 PM", time.Date(2020, 6, 20, 22, 0, 0, 0, time.Local)},
		{"2020-01-15T10:20:30", time.Date(2020, 1, 15, 10, 20, 30, 0, time.Local)},
		{"2018-01-01 10:00", time.Date(2018, 1, 1, 10, 0, 0, 0, time.Local)},
		{"March 7 2021 5:30 pm", time.Date(2021, 3, 7, 17, 30, 0, 0, time.Local)},
		{"01.02.2020", time.Date(2020, 1, 2, 0, 0, 0, 0, time.Local)},
		{"Jun 2020", time.Date(2020, 6, 1, 0, 0, 0, 0, time.Local)},
	}
	for _, c := range local {
		got, ok := ParseJSDate(c.in)
		if !ok || !got.Equal(c.want) {
			t.Errorf("ParseJSDate(%q) = %v %v, want %v", c.in, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "garbage", "2020-13-01", "13/01/2020"} {
		if got, ok := ParseJSDate(bad); ok {
			t.Errorf("ParseJSDate(%q) = %v, want invalid", bad, got)
		}
	}
}

func TestJSHelpers(t *testing.T) {
	if JSTrim("\ufeff\u00a0 x \u3000") != "x" {
		t.Error("JSTrim")
	}
	if !IsNullOrWhitespace("\ufeff \t") || IsNullOrWhitespace(" a ") {
		t.Error("IsNullOrWhitespace")
	}
	if Len16("a😀") != 3 || Substring16("a😀b", 0, 3) != "a😀" {
		t.Error("UTF-16 helpers")
	}
	for in, want := range map[string]int{"12": 12, " -3x": -3, "+7": 7, "08": 8} {
		if got, ok := ParseInt(in); !ok || got != want {
			t.Errorf("ParseInt(%q) = %d %v", in, got, ok)
		}
	}
	if _, ok := ParseInt("x1"); ok {
		t.Error("ParseInt NaN")
	}
	if !reflect.DeepEqual(SplitNewLine("a\r\nb\rc\nd"), []string{"a", "b", "c", "d"}) {
		t.Error("SplitNewLine")
	}
	if ToValidUTF8([]byte("a\xffb")) != "a\ufffdb" {
		t.Error("ToValidUTF8")
	}
	century := strings.TrimSuffix(time.Now().Format("2006"), time.Now().Format("06"))
	for in, want := range map[string]string{"2025": "2025", "21": century + "21", "5": century + "05", "0": century + "00", "": ""} {
		if got := NormalizeExpiryYearFormat(in); got != want {
			t.Errorf("NormalizeExpiryYearFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if MonthFromName("September") != 9 || MonthFromName("ju") != 0 || MonthFromName("Junxx") != 6 {
		t.Error("MonthFromName")
	}
}

func TestSubstring16Clamps(t *testing.T) {
	if got := Substring16("2025", 5, 7); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := Substring16("2025", 7, 2); got != "25" {
		t.Fatalf("got %q", got)
	}
}
