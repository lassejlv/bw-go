package tools

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/generator"
)

func sp(s string) *string { return &s }

func responseString(t *testing.T, r *cli.Response) string {
	t.Helper()
	if !r.Success {
		t.Fatalf("unexpected failure: %s", r.MessageText())
	}
	s, ok := r.Data.(*cli.StringResponse)
	if !ok || s.Data == nil {
		t.Fatalf("expected string response, got %#v", r.Data)
	}
	return *s.Data
}

func TestNormalizeGenerateOptionsDefaults(t *testing.T) {
	n := normalizeGenerateOptions(GenerateOptions{})
	if !n.uppercase || !n.lowercase || !n.number || n.special {
		t.Fatalf("default classes: %+v", n)
	}
	if n.length != 14 || n.words != 6 || n.separator != "-" || n.minNumber != 1 || n.minSpecial != 0 {
		t.Fatalf("defaults: %+v", n)
	}
}

func TestNormalizeGenerateOptions(t *testing.T) {
	n := normalizeGenerateOptions(GenerateOptions{Special: true, Length: sp("2"), Words: sp("1")})
	if n.uppercase || n.lowercase || n.number || !n.special {
		t.Fatalf("classes: %+v", n)
	}
	if n.length != 5 || n.words != 3 {
		t.Fatalf("minimums: %+v", n)
	}
	cases := map[string]string{"space": " ", "empty": "", "_": "_", "abc": "a", "": "", "éx": "é"}
	for in, want := range cases {
		if got := normalizeGenerateOptions(GenerateOptions{Separator: sp(in)}).separator; got != want {
			t.Errorf("separator %q -> %q, want %q", in, got, want)
		}
	}
	if n := normalizeGenerateOptions(GenerateOptions{Length: sp("20abc"), MinNumber: sp("x")}); n.length != 20 || n.minNumber != 1 {
		t.Fatalf("parseInt semantics: %+v", n)
	}
}

func TestGenerateOptionsFromQuery(t *testing.T) {
	q, _ := url.ParseQuery("uppercase&lowercase=true&number=false&passphrase=TRUE&length=20&separator=space")
	o := GenerateOptionsFromQuery(q)
	if !o.Uppercase || !o.Lowercase || o.Number || o.Special || !o.Passphrase {
		t.Fatalf("booleans: %+v", o)
	}
	if o.Length == nil || *o.Length != "20" || o.Separator == nil || *o.Separator != "space" || o.Words != nil {
		t.Fatalf("strings: %+v", o)
	}
}

func TestGenerateFlagParsing(t *testing.T) {
	cmd := newGenerateCommand(nil)
	if err := cmd.ParseFlags([]string{"-lusn", "--length", "18", "-pc", "--separator", "space", "--minNumber", "3"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lowercase", "uppercase", "special", "number", "passphrase", "capitalize"} {
		if v, _ := cmd.Flags().GetBool(name); !v {
			t.Errorf("flag %s not set", name)
		}
	}
	if v, _ := cmd.Flags().GetBool("includeNumber"); v {
		t.Error("includeNumber should not be set")
	}
	if v, _ := cmd.Flags().GetString("length"); v != "18" {
		t.Errorf("length = %q", v)
	}
	if !cmd.Flags().Changed("minNumber") || cmd.Flags().Changed("words") {
		t.Error("Changed tracking")
	}
}

func TestGeneratePassword(t *testing.T) {
	for i := 0; i < 50; i++ {
		p := responseString(t, generate(GenerateOptions{Uppercase: true, Lowercase: true, Special: true, Number: true, Length: sp("18")}, nil))
		if len(p) != 18 || !strings.ContainsAny(p, generator.UppercaseFull) || !strings.ContainsAny(p, generator.LowercaseFull) ||
			!strings.ContainsAny(p, generator.DigitsFull) {
			t.Fatalf("bad password %q", p)
		}
	}
	p := responseString(t, generate(GenerateOptions{Special: true, Length: sp("10")}, nil))
	if strings.Trim(p, generator.SpecialCharacters) != "" || len(p) != 10 {
		t.Fatalf("special only: %q", p)
	}
	p = responseString(t, generate(GenerateOptions{Ambiguous: true, Length: sp("100")}, nil))
	if strings.ContainsAny(p, "IOl10") {
		t.Fatalf("ambiguous chars in %q", p)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	p := responseString(t, generate(GenerateOptions{Passphrase: true, Words: sp("5"), Separator: sp("space")}, nil))
	if n := len(strings.Split(p, " ")); n != 5 {
		t.Fatalf("expected 5 words, got %q", p)
	}
	p = responseString(t, generate(GenerateOptions{Passphrase: true, Separator: sp("_")}, nil))
	if n := len(strings.Split(p, "_")); n != 6 {
		t.Fatalf("expected 6 words, got %q", p)
	}
}

func TestGenerateWithPolicy(t *testing.T) {
	pol := &generator.GeneratorPolicy{
		Password:             generator.PasswordGeneratorPolicy{MinLength: 30, UseSpecial: true, SpecialCount: 2},
		Passphrase:           generator.PassphraseGeneratorPolicy{MinNumberWords: 7, Capitalize: true},
		OverridePasswordType: "passphrase",
	}
	// The navigation policy forces a passphrase.
	p := responseString(t, generate(GenerateOptions{Length: sp("10")}, pol))
	words := strings.Split(p, "-")
	if len(words) != 7 || words[0][0] < 'A' || words[0][0] > 'Z' {
		t.Fatalf("expected 7 capitalized words, got %q", p)
	}
	pol.OverridePasswordType = ""
	p = responseString(t, generate(GenerateOptions{Length: sp("10"), Lowercase: true}, pol))
	if len(p) != 30 {
		t.Fatalf("expected policy length 30, got %q", p)
	}
	n := 0
	for _, c := range p {
		if strings.ContainsRune(generator.SpecialCharacters, c) {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("expected >= 2 special characters: %q", p)
	}
	// Without a policy but logged in, boundaries clamp the length.
	p = responseString(t, generate(GenerateOptions{Length: sp("500")}, &generator.GeneratorPolicy{}))
	if len(p) != 128 {
		t.Fatalf("expected 128, got %d", len(p))
	}
}

func TestEncodeInput(t *testing.T) {
	got := responseString(t, EncodeInput([]byte("{\"name\":\"My Folder\"}\n")))
	if got != "eyJuYW1lIjoiTXkgRm9sZGVyIn0K" {
		t.Fatalf("got %q", got)
	}
	if got := responseString(t, EncodeInput([]byte("ü"))); got != base64.StdEncoding.EncodeToString([]byte("ü")) {
		t.Fatalf("got %q", got)
	}
}

func TestUpdateFromReleases(t *testing.T) {
	body := []byte(`[
		{"tag_name":"desktop-v1.0.0","body":"x","assets":[]},
		{"tag_name":"cli-v2026.11.0","body":"notes","assets":[
			{"browser_download_url":"https://example.com/bw-linux-2026.11.0.zip"},
			{"browser_download_url":"https://example.com/bw-macos-2026.11.0.zip"},
			{"browser_download_url":null}]}]`)
	r := updateFromReleases(200, body, "2026.10.0", "darwin")
	m, ok := r.Data.(*cli.MessageResponse)
	if !r.Success || !ok {
		t.Fatalf("unexpected %+v", r)
	}
	if *m.Title != "A new version is available: cli-v2026.11.0" || *m.Raw != "https://example.com/bw-macos-2026.11.0.zip" {
		t.Fatalf("title/raw: %q %q", *m.Title, *m.Raw)
	}
	if !strings.HasPrefix(*m.Message, "notes\n\nYou can download this update at https://example.com/bw-macos-2026.11.0.zip") {
		t.Fatalf("message: %q", *m.Message)
	}
	if r := updateFromReleases(200, body, "2026.10.0", "windows"); *r.Data.(*cli.MessageResponse).Raw != DefaultDownloadURL {
		t.Fatal("expected default download url")
	}
	r = updateFromReleases(200, body, "2026.11.0", "darwin")
	if m := r.Data.(*cli.MessageResponse); *m.Title != "No update available." || !m.NoColor || m.Message != nil {
		t.Fatalf("no update: %+v", m)
	}
	if r := updateFromReleases(403, nil, "1", "linux"); r.Success || r.MessageText() != "Error contacting update API: 403" {
		t.Fatalf("status error: %+v", r)
	}
	if r := updateFromReleases(200, []byte(`[{"tag_name":"web-v1"}]`), "1", "linux"); r.MessageText() != "Could not find latest CLI version." {
		t.Fatalf("missing release: %+v", r)
	}
}

func TestCompletion(t *testing.T) {
	rootCmd := &cobra.Command{Use: "bwgo"}
	rootCmd.PersistentFlags().Bool("pretty", false, "Format output.")
	rootCmd.Flags().BoolP("version", "v", false, "output the version number")
	sub := &cobra.Command{Use: "list <object>", Short: "List an array of objects.", Run: func(*cobra.Command, []string) {}}
	sub.Flags().String("search", "", "Perform a search on the listed objects.")
	rootCmd.AddCommand(sub)
	send := &cobra.Command{Use: "send", Short: "Work with Bitwarden sends.", Run: func(*cobra.Command, []string) {}}
	send.AddCommand(&cobra.Command{Use: "get <id>", Short: "Get Sends owned by you.", Run: func(*cobra.Command, []string) {}})
	rootCmd.AddCommand(send)
	rootCmd.AddCommand(&cobra.Command{Use: "secret", Hidden: true, Run: func(*cobra.Command, []string) {}})

	if r := Completion(rootCmd, ""); r.Success || r.MessageText() != "`shell` option was not provided." {
		t.Fatalf("%+v", r)
	}
	if r := Completion(rootCmd, "fish"); r.Success || r.MessageText() != "Unsupported shell." {
		t.Fatalf("%+v", r)
	}
	r := Completion(rootCmd, "zsh")
	got := *r.Data.(*cli.MessageResponse).Title
	want := `#compdef _bwgo bwgo

function _bwgo {
  local -a commands

  _arguments -C \
    '--pretty[Format output.]' \
    '(-v --version)'{-v,--version}'[output the version number]' \
    '(-h --help)'{-h,--help}'[output usage information]' \
    "1: :->cmnds" \
    "*::arg:->args"

  case $state in
    cmnds)
      commands=(
        "list:List an array of objects."
        "send:Work with Bitwarden sends."
      )
      _describe "command" commands
      ;;
  esac

  case "$words[1]" in
    list)
      _bwgo_list
      ;;
    send)
      _bwgo_send
      ;;
  esac
}

function _bwgo_list {
  _arguments -C \
    '--search[Perform a search on the listed objects.]' \
    '(-h --help)'{-h,--help}'[output usage information]' \
    "*::arg:->args"
}

function _bwgo_send {
  local -a commands

  case $state in
    cmnds)
      commands=(
        "get:Get Sends owned by you."
      )
      _describe "command" commands
      ;;
  esac

  case "$words[1]" in
    get)
      _bwgo_send_get
      ;;
  esac
}

function _bwgo_send_get {
` + "  " + `
}`
	if got != want {
		t.Fatalf("zsh completion mismatch:\n%s\n--- want ---\n%s", got, want)
	}
}
