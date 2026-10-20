package clipperz

import (
	"encoding/json"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from libs/importer/src/importers/clipperz-html-importer.spec.ts.

func clipperzExport(t *testing.T, entries any) string {
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://dtd.example.com/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <body>
    <textarea>` + string(b) + `</textarea>
  </body>
</html>`
}

func parse(t *testing.T, data string) *model.ImportResult {
	return importertest.Parse(t, New(importertest.Options()), data)
}

func TestPublicDoctype(t *testing.T) {
	r := parse(t, clipperzExport(t, []any{map[string]any{
		"label": "GitHub",
		"currentVersion": map[string]any{"fields": map[string]any{
			"0": map[string]any{"label": "username", "actionType": "username", "value": "user@example.com"},
			"1": map[string]any{"label": "password", "actionType": "password", "value": "hunter2"},
			"2": map[string]any{"label": "url", "actionType": "url", "value": "https://github.com"},
		}},
	}}))
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Name != "GitHub" || c.Login.Username != "user@example.com" || c.Login.Password != "hunter2" || c.Login.Uris[0].Uri != "https://github.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
}

func TestNotes(t *testing.T) {
	r := parse(t, clipperzExport(t, []any{map[string]any{"label": "Note", "data": map[string]any{"notes": `line one\nline two`}}}))
	if !r.Success || r.Ciphers[0].Notes != "line one\nline two" {
		t.Fatalf("%s", importertest.Dump(r))
	}
	if r.Ciphers[0].Type != model.CipherTypeSecureNote {
		t.Fatal("expected a secure note")
	}
}

func TestNoEntityResolution(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://dtd.example.com/evil.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <body>
    <textarea>[{"label":"&xxe;"}]</textarea>
  </body>
</html>`
	r := parse(t, data)
	if !r.Success || r.Ciphers[0].Name != "&xxe;" {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestMissingTextarea(t *testing.T) {
	r := parse(t, `<!DOCTYPE html><html><body></body></html>`)
	if r.Success || r.ErrorMessage != "Missing textarea." {
		t.Fatalf("%v %q", r.Success, r.ErrorMessage)
	}
}

// Go-only: label-based detection, JS for-in key order and custom fields.
func TestLabelFallbacksAndOrder(t *testing.T) {
	data := `<html><body><textarea>[{"label":"My Bank extra words","currentVersion":{"fields":{
		"b":{"label":"Website","value":"bank.example.com"},
		"10":{"label":"Pass","value":"second"},
		"2":{"label":"PIN","value":"first"},
		"a":{"label":"Login","value":"jdoe"},
		"c":{"label":"Branch","value":"Main St"},
		"d":{"label":"Count","value":5}
	}}}]</textarea></body></html>`
	r := parse(t, data)
	c := r.Ciphers[0]
	if c.Name != "My" || c.Login.Password != "first" || c.Login.Username != "jdoe" || importertest.URIs(c)[0] != "http://bank.example.com" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("Pass", "second"),
		importertest.F("Branch", "Main St"),
	)
}

func TestInvalidJSON(t *testing.T) {
	_, err := New(importertest.Options()).Parse(`<textarea>[{</textarea>`)
	if !importer.IsSyntaxError(err) {
		t.Fatalf("err = %v", err)
	}
}
