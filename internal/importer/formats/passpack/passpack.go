// Package passpack ports libs/importer/src/importers/passpack-csv-importer.ts (format id
// "passpackcsv").
package passpack

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passpackcsv", New) }

// Importer is PasspackCsvImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil)
	if results == nil {
		result.Success = false
		return result, nil
	}

	for _, value := range results {
		// tagsJson = JSON.parse(value.Tags); tags = tagsJson.tags.map(JSON.parse(t).tag)
		var tags []string
		if !i.IsNullOrWhitespace(value.Get("Tags")) {
			list, err := jsonArrayProperty(value.Get("Tags"), "tags")
			if err != nil {
				return nil, err
			}
			if list != nil {
				tags = []string{}
				for _, tagJSON := range list {
					t, ok := jsonParseCoerced(tagJSON)
					tag := ""
					if m, isObj := t.(map[string]any); ok && isObj {
						s, _ := m["tag"].(string)
						tag = i.GetValueOrDefault(s)
					}
					if !i.IsNullOrWhitespace(tag) {
						tags = append(tags, tag)
					}
				}
			}
		}

		if i.Organization() && len(tags) > 0 {
			for _, tag := range tags {
				addCollection := true
				collectionIndex := len(result.Collections)

				for j, c := range result.Collections {
					if c.Name == tag {
						addCollection = false
						collectionIndex = j
						break
					}
				}

				if addCollection {
					result.Collections = append(result.Collections, &model.CollectionView{Name: tag})
				}

				result.CollectionRelationships = append(result.CollectionRelationships,
					model.Relationship{len(result.Ciphers), collectionIndex})
			}
		} else if !i.Organization() && len(tags) > 0 {
			i.ProcessFolder(result, tags[0])
		}

		cipher := i.InitLoginCipher()
		cipher.Notes = i.GetValueOrDefault(value.Get("Notes"), "")
		cipher.Notes += "\n\n" + i.GetValueOrDefault(value.Get("Shared Notes"), "") + "\n"
		cipher.Name = i.GetValueOrDefault(value.Get("Entry Name"), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("User ID"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("Password"))
		cipher.Login.Uris = i.MakeUriArray(value.Get("URL"))

		for _, extra := range value.Extra {
			if !i.IsNullOrWhitespace(extra) {
				cipher.Notes += "\n" + extra
			}
		}

		if !i.IsNullOrWhitespace(value.Get("Extra Fields")) {
			list, err := jsonArrayProperty(value.Get("Extra Fields"), "extraFields")
			if err != nil {
				return nil, err
			}
			for _, fieldJSON := range list {
				f, ok := jsonParseCoerced(fieldJSON)
				if !ok || f == nil {
					continue
				}
				// f.name / f.data: only objects have them; processKvp ignores non-string data.
				m, _ := f.(map[string]any)
				name, _ := m["name"].(string)
				data, isString := m["data"].(string)
				if isString {
					i.ProcessKvp(cipher, name, data)
				}
			}
		}

		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

// jsonArrayProperty is `json = JSON.parse(s); json != null && json[prop] != null &&
// json[prop].length > 0 ? json[prop].map(...) : null`: it returns the array to map over, nil when
// upstream yields null, and an error where upstream throws (malformed JSON, or a non-empty string
// property, whose .map is not a function).
func jsonArrayProperty(s, prop string) ([]any, error) {
	var parsed any
	if err := importer.UnmarshalJSONLenient(s, &parsed); err != nil {
		return nil, err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, nil
	}
	switch v := obj[prop].(type) {
	case []any:
		if len(v) > 0 {
			return v, nil
		}
	case string:
		if v != "" {
			return nil, errors.New("TypeError: " + prop + ".map is not a function")
		}
	}
	return nil, nil
}

// jsonParseCoerced is `try { JSON.parse(v) } catch { null }` where v is any JSON value (JSON.parse
// coerces non-strings with String(v) first). ok=false means the parse threw.
func jsonParseCoerced(v any) (any, bool) {
	var parsed any
	if err := json.Unmarshal([]byte(jsString(v)), &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

// jsString is JavaScript's String(v) for a decoded JSON value.
func jsString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return importer.FormatJSNumber(x)
	case []any:
		parts := make([]string, len(x))
		for k, e := range x {
			if e != nil {
				parts[k] = jsString(e)
			}
		}
		return strings.Join(parts, ",")
	default:
		return "[object Object]"
	}
}
