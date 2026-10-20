// Package clipperz ports libs/importer/src/importers/clipperz-html-importer.ts (format id
// "clipperzhtml").
package clipperz

import (
	"slices"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("clipperzhtml", New) }

// Importer is ClipperzHtmlImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer {
	return &Importer{Base: importer.NewBase(opts)}
}

// str returns v when it is a JavaScript string ("" and false otherwise).
func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// isNullOrWhitespace is Utils.isNullOrWhitespace on an arbitrary JSON value (non-strings count as
// null).
func isNullOrWhitespace(v any) bool {
	s, ok := str(v)
	return !ok || importer.IsNullOrWhitespace(s)
}

// strOrNull is getValueOrDefault(v): the string, or "" (null) for non-strings and blanks.
func strOrNull(v any) string {
	if isNullOrWhitespace(v) {
		return ""
	}
	s, _ := str(v)
	return s
}

// lowerOrNull is `x != null ? x.toLowerCase() : null`; ok=false is a JS TypeError (non-string).
func lowerOrNull(v any, prop string) (string, bool, error) {
	if v == nil {
		return "", false, nil
	}
	s, isStr := str(v)
	if !isStr {
		return "", false, typeError("%s.toLowerCase is not a function", prop)
	}
	return strings.ToLower(s), true, nil
}

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	// Clipperz exports are XHTML, but the only thing read out of them is the textarea's text
	// content. Parsing as HTML gets the same result without the XML parser rejecting the export's
	// XHTML DOCTYPE, and HTML parsing never resolves DTDs or entities.
	doc := i.ParseHtml(data)
	if doc == nil {
		result.Success = false
		return result, nil
	}

	textarea := doc.QuerySelector("textarea")
	if textarea == nil || i.IsNullOrWhitespace(textarea.TextContent()) {
		result.ErrorMessage = "Missing textarea."
		result.Success = false
		return result, nil
	}

	parsed, err := parseJSON(textarea.TextContent())
	if err != nil {
		return nil, err
	}
	entries, ok := parsed.([]any)
	if !ok {
		if parsed == nil {
			return nil, typeError("Cannot read properties of null (reading 'forEach')")
		}
		return nil, typeError("entries.forEach is not a function")
	}

	for _, e := range entries {
		if e == nil {
			return nil, typeError("Cannot read properties of null (reading 'label')")
		}
		entry, _ := e.(*object) // scalars have no properties
		cipher := i.InitLoginCipher()
		if label := entry.get("label"); !isNullOrWhitespace(label) {
			s, _ := str(label)
			cipher.Name = strings.Split(s, " ")[0]
		}
		if d := entry.get("data"); d != nil {
			dataObj, _ := d.(*object)
			if notes := dataObj.get("notes"); !isNullOrWhitespace(notes) {
				s, _ := str(notes)
				cipher.Notes = strings.ReplaceAll(s, `\n`, "\n")
			}
		}

		if cv := entry.get("currentVersion"); cv != nil {
			cvObj, _ := cv.(*object)
			if fields := cvObj.get("fields"); fields != nil {
				for _, property := range forInKeys(fields) {
					field := forInValue(fields, property)
					if field == nil {
						return nil, typeError("Cannot read properties of null (reading 'actionType')")
					}
					fieldObj, _ := field.(*object)
					actionType, _, err := lowerOrNull(fieldObj.get("actionType"), "field.actionType")
					if err != nil {
						return nil, err
					}
					value := fieldObj.get("value")
					switch actionType {
					case "password":
						cipher.Login.Password = strOrNull(value)
					case "email", "username", "user", "name":
						cipher.Login.Username = strOrNull(value)
					case "url":
						cipher.Login.Uris = i.MakeUriArray(strOrNull(value))
					default:
						label := fieldObj.get("label")
						labelLower, hasLabel, err := lowerOrNull(label, "field.label")
						if err != nil {
							return nil, err
						}
						labelStr, _ := str(label)
						switch {
						case cipher.Login.Password == "" && hasLabel && slices.Contains(importer.PasswordFieldNames, labelLower):
							cipher.Login.Password = strOrNull(value)
						case cipher.Login.Username == "" && hasLabel && slices.Contains(importer.UsernameFieldNames, labelLower):
							cipher.Login.Username = strOrNull(value)
						case len(cipher.Login.Uris) == 0 && hasLabel && slices.Contains(importer.UriFieldNames, labelLower):
							cipher.Login.Uris = i.MakeUriArray(strOrNull(value))
						default:
							if v, isStr := str(value); isStr {
								i.ProcessKvp(cipher, labelStr, v)
							}
						}
					}
				}
			}
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}
