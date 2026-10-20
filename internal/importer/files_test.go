package importer

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ported from libs/importer/src/services/read-import-file-contents.spec.ts, plus the CLI rules of
// import.command.ts.

func zipBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(content))
	}
	w.Close()
	return buf.Bytes()
}

func TestReadImportFileContents(t *testing.T) {
	html := []byte("<html><body><pre>url,username,password</pre></body></html>")
	cases := []struct {
		name, format, file string
		data               []byte
		want, wantErr      string
	}{
		{"plain text", "bitwardencsv", "export.csv", []byte("hello,world"), "hello,world", ""},
		{"lastpass html", "lastpasscsv", "export.html", html, "url,username,password", ""},
		{"lastpass html uppercase", "lastpasscsv", "Export.HTML", html, "url,username,password", ""},
		{"lastpass html without pre", "lastpasscsv", "export.html", []byte("<html><body>no data here</body></html>"), "", "LastPass html export has no <pre> content"},
		{"lastpass csv", "lastpasscsv", "export.csv", []byte("url,username,password"), "url,username,password", ""},
		{"1pux", "1password1pux", "export.1pux", zipBytes(t, map[string]string{"export.data": `{"accounts":[]}`}), `{"accounts":[]}`, ""},
		{"protonpass zip", "protonpass", "export.ZIP", zipBytes(t, map[string]string{"Proton Pass/data.json": `{"vaults":{}}`}), `{"vaults":{}}`, ""},
		{"missing entry", "protonpass", "export.zip", zipBytes(t, map[string]string{"other.json": "{}"}), "", "Zip entry not found: Proton Pass/data.json"},
		{"not a zip", "1password1pux", "export.1pux", []byte("not a zip"), "", "Can't find end of central directory"},
	}
	for _, c := range cases {
		got, err := ReadImportFileContents(c.format, c.file, c.data)
		if c.wantErr != "" {
			if err == nil || !strings.HasPrefix(err.Error(), c.wantErr) {
				t.Errorf("%s: err %v", c.name, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q %v", c.name, got, err)
		}
	}
}

func TestReadImportFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	csv := write("a.csv", []byte("\xef\xbb\xbfname\xff"))
	got, err := ReadImportFile("bitwardencsv", csv)
	if err != nil || got != "\ufeffname�" {
		t.Fatalf("%q %v", got, err)
	}
	pux := write("x.1pux", zipBytes(t, map[string]string{"export.data": "data"}))
	if got, err := ReadImportFile("1password1pux", pux); err != nil || got != "data" {
		t.Fatalf("%q %v", got, err)
	}
	// The CLI's suffix check is case-sensitive: an upper-case extension is read as text.
	upper := write("x.ZIP", []byte("plain"))
	if got, err := ReadImportFile("protonpass", upper); err != nil || got != "plain" {
		t.Fatalf("%q %v", got, err)
	}
	missing := filepath.Join(dir, "missing.csv")
	if _, err := ReadImportFile("bitwardencsv", missing); err == nil || err.Error() != "ENOENT: no such file or directory, open '"+missing+"'" {
		t.Fatal(err)
	}
	if _, err := ReadImportFileBytes(missing); err == nil || err.Error() != "Could not read file: "+missing {
		t.Fatal(err)
	}
	if _, err := ReadImportFile("bitwardencsv", ""); err == nil || err.Error() != "You must specify a file path." {
		t.Fatal(err)
	}
}

func TestRegistry(t *testing.T) {
	if len(Formats()) != 73 {
		t.Fatalf("formats %d", len(Formats()))
	}
	seen := map[string]bool{}
	for _, f := range Formats() {
		if seen[f.ID] {
			t.Fatalf("duplicate %s", f.ID)
		}
		seen[f.ID] = true
		for _, p := range f.PasteFormats {
			found := false
			for _, a := range f.AcceptedFileTypes {
				found = found || a == p
			}
			if !found {
				t.Errorf("%s: paste format %s not accepted", f.ID, p)
			}
		}
		if f.Source == "" {
			t.Errorf("%s: no source", f.ID)
		}
	}
	ids := CLIFormatIDs()
	if ids[0] != "1password1pif" || len(ids) != 72 {
		t.Fatalf("cli ids %v", ids)
	}
	if err := CheckFileFormat("onepassword"); err == nil || err.Error() != "1Password (direct) signs in to the vendor instead of reading a file, so it cannot be imported with the CLI." {
		t.Fatal(err)
	}
	if _, err := New("nope", Options{}); err == nil || err.Error() != MsgProperImporterTypeRequired {
		t.Fatal(err)
	}
	if f, ok := LookupFormat("keepasskdbx"); !ok || f.SDK == nil || f.SDK.CredentialKind != CredentialPasswordWithKeyFile {
		t.Fatal("kdbx sdk info")
	}
	for in, want := range map[string]string{"x.CSV": "keepercsv", "x.json": "keeperjson"} {
		if got, err := ResolveFormat("keeper", in); err != nil || got != want {
			t.Fatal(in, got, err)
		}
	}
	if _, err := ResolveFormat("keeper", "x.txt"); err == nil {
		t.Fatal("keeper txt")
	}
}
