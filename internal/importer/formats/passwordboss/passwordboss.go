// Package passwordboss ports libs/importer/src/importers/passwordboss-json-importer.ts
// (passwordbossjson).
package passwordboss

import (
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/jsvalue"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("passwordbossjson", New) }

// Fields consumed explicitly below regardless of item type, or intentionally discarded
// (id/itemType/logoColor are presentational).
var commonHandledKeys = set("id", "itemType", "itemTypeName", "logoColor", "folder", "name", "notes", "customFields", "tags")

// cardType is redundant with the brand detected from cardNumber.
var cardHandledKeys = set("cardNumber", "nameOnCard", "securityCode", "expirationDate", "cardType", "issuingBank", "issueDate", "pin")

// "email" is deliberately excluded: it's only consumed as a username fallback when `username` is
// blank, so it's tracked per-item via `usernameFromEmail` instead of statically here.
var loginHandledKeys = set("url", "username", "password", "totp")

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Importer is PasswordBossJsonImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (_ *model.ImportResult, err error) {
	defer jsvalue.CatchTypeError(&err)
	results, err := jsvalue.Parse(data)
	if err != nil {
		return nil, err
	}

	// Current export ("Password Boss JSON - Not Encrypted"): a flat array of items, with card/login
	// fields living directly on each item rather than nested under `identifiers`, and no separate
	// top-level `folders` list — each item names its own folder (if any) directly.
	if results.IsArray() {
		return i.parseFlatItems(results), nil
	}

	// Older export shape, kept for anyone importing a backup made before Password Boss changed its
	// export format: a top-level object with `items` and `folders` arrays, and each item's fields
	// nested under `identifiers`.
	return i.parseLegacyExport(results), nil
}

func (i *Importer) parseFlatItems(items *jsvalue.Value) *model.ImportResult {
	result := model.NewImportResult()

	items.ForEach("items", func(value *jsvalue.Value) {
		isCard := value.Get("itemTypeName").Str() == "CreditCard"
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("name").Str(), "--")

		if isCard {
			cipher.Card = &model.CardView{}
			cipher.Type = model.CipherTypeCard
		}

		i.ProcessFolder(result, value.Get("folder").Str())

		if notes := value.Get("notes"); !notes.IsNullOrWhitespace() {
			cipher.Notes = notes.Str()
		}

		if isCard {
			cipher.Card.Number = i.GetValueOrDefault(value.Get("cardNumber").Str())
			if cipher.Card.Number != "" {
				cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
			}
			cipher.Card.CardholderName = i.GetValueOrDefault(value.Get("nameOnCard").Str())
			cipher.Card.Code = i.GetValueOrDefault(value.Get("securityCode").Str())
			if exp := value.Get("expirationDate"); !exp.IsNullOrWhitespace() {
				if expDate, ok := importer.ParseJSDate(exp.Str()); ok {
					expDate = expDate.UTC()
					cipher.Card.ExpYear = strconv.Itoa(expDate.Year())
					cipher.Card.ExpMonth = strconv.Itoa(int(expDate.Month()))
				}
			}
			i.ProcessKvp(cipher, "Issuing Bank", value.Get("issuingBank").Str())
			i.ProcessKvp(cipher, "Issue Date", value.Get("issueDate").Str())
			i.ProcessKvp(cipher, "PIN", value.Get("pin").Str(), model.FieldTypeHidden)
		}

		usernameFromEmail := false
		if !isCard {
			cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, value.Get("url"))
			cipher.Login.Username = i.GetValueOrDefault(value.Get("username").Str())
			cipher.Login.Password = i.GetValueOrDefault(value.Get("password").Str())
			if email := value.Get("email"); i.IsNullOrWhitespace(cipher.Login.Username) && !email.IsNullOrWhitespace() {
				cipher.Login.Username = email.Str()
				usernameFromEmail = true
			}
			if totp := value.Get("totp"); !totp.IsNullOrWhitespace() {
				cipher.Login.Totp = totp.Str()
			}
		}

		if customFields := value.Get("customFields"); customFields.IsArray() {
			customFields.ForEach("value.customFields", func(cf *jsvalue.Value) {
				i.ProcessKvp(cipher, cf.Get("name").Str(), cf.Get("value").Str())
			})
		}

		if tags := value.Get("tags"); tags.IsArray() && len(tags.Elems()) > 0 {
			i.ProcessKvp(cipher, "Tags", tags.Join(", "))
		}

		// Anything Password Boss adds that we don't explicitly map above still ends up on the
		// cipher, instead of silently disappearing.
		typeHandledKeys := loginHandledKeys
		if isCard {
			typeHandledKeys = cardHandledKeys
		}
		for _, property := range value.OwnKeys() {
			if commonHandledKeys[property] || typeHandledKeys[property] ||
				(property == "email" && usernameFromEmail) {
				continue
			}
			val := value.Get(property)
			isSensitive := contains(importer.PasswordFieldNames, strings.ToLower(property))
			fieldType := model.FieldTypeText
			if isSensitive {
				fieldType = model.FieldTypeHidden
			}
			str := ""
			if !val.Nullish() {
				str = val.ToString()
			}
			i.ProcessKvp(cipher, property, str, fieldType)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	})

	result.Success = true
	return result
}

// mapKey is a JavaScript Map key (SameValueZero): primitives by value, objects by identity.
type mapKey struct {
	kind jsvalue.Kind
	b    bool
	n    float64
	s    string
	obj  *jsvalue.Value
}

func keyOf(v *jsvalue.Value) mapKey {
	if v == nil {
		return mapKey{kind: jsvalue.Undefined}
	}
	switch v.Kind() {
	case jsvalue.Array, jsvalue.Object:
		return mapKey{kind: v.Kind(), obj: v}
	}
	return mapKey{kind: v.Kind(), b: v.Bool(), n: v.Num(), s: v.Str()}
}

func (i *Importer) parseLegacyExport(results *jsvalue.Value) *model.ImportResult {
	result := model.NewImportResult()
	if results.Nullish() || results.Get("items").Nullish() {
		result.Success = false
		return result
	}

	// foldersMap: Map<id, name> in insertion order.
	var folderKeys []mapKey
	folderNames := map[mapKey]*jsvalue.Value{}
	results.Get("folders").ForEach("results.folders", func(value *jsvalue.Value) {
		k := keyOf(value.Get("id"))
		if _, ok := folderNames[k]; !ok {
			folderKeys = append(folderKeys, k)
		}
		folderNames[k] = value.Get("name")
	})
	foldersIndexMap := map[mapKey]int{}
	for _, k := range folderKeys {
		foldersIndexMap[k] = len(result.Folders)
		result.Folders = append(result.Folders, &model.FolderView{Name: folderNames[k].Str()})
	}

	results.Get("items").ForEach("results.items", func(value *jsvalue.Value) {
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(value.Get("name").Str(), "--")
		cipher.Login.Uris = jsvalue.MakeUriArray(&i.Base, value.Get("login_url"))

		if folder := value.Get("folder"); !folder.Nullish() {
			if idx, ok := foldersIndexMap[keyOf(folder)]; ok {
				result.FolderRelationships = append(result.FolderRelationships, model.Relationship{len(result.Ciphers), idx})
			}
		}

		identifiers := value.Get("identifiers")
		if identifiers.Nullish() {
			return
		}

		if notes := identifiers.Get("notes"); !notes.IsNullOrWhitespace() {
			cipher.Notes = strings.ReplaceAll(strings.ReplaceAll(notes.Str(), `\r\n`, "\n"), `\n`, "\n")
		}

		if value.Get("type").Str() == "CreditCard" {
			cipher.Card = &model.CardView{}
			cipher.Type = model.CipherTypeCard
		}

		for _, property := range identifiers.OwnKeys() {
			valObj := identifiers.Get(property)
			val := ""
			if !valObj.Nullish() {
				val = valObj.ToString()
			}
			if i.IsNullOrWhitespace(val) || property == "notes" || property == "ignoreItemInSecurityScore" {
				continue
			}

			if property == "custom_fields" {
				valObj.ForEach("valObj", func(cf *jsvalue.Value) {
					i.ProcessKvp(cipher, cf.Get("name").Str(), cf.Get("value").Str())
				})
				continue
			}

			if cipher.Type == model.CipherTypeCard {
				switch property {
				case "cardNumber":
					cipher.Card.Number = val
					cipher.Card.Brand = i.GetCardBrand(cipher.Card.Number)
					continue
				case "nameOnCard":
					cipher.Card.CardholderName = val
					continue
				case "security_code":
					cipher.Card.Code = val
					continue
				case "expires":
					// new Date(val).getFullYear()/getMonth() (local time); Invalid Date gives "NaN".
					if expDate, ok := importer.ParseJSDate(val); ok {
						expDate = expDate.In(time.Local)
						cipher.Card.ExpYear = strconv.Itoa(expDate.Year())
						cipher.Card.ExpMonth = strconv.Itoa(int(expDate.Month()))
					} else {
						cipher.Card.ExpYear = "NaN"
						cipher.Card.ExpMonth = "NaN"
					}
					continue
				case "cardType":
					continue
				}
			} else {
				if (property == "username" || property == "email") && i.IsNullOrWhitespace(cipher.Login.Username) {
					cipher.Login.Username = val
					continue
				} else if property == "password" {
					cipher.Login.Password = val
					continue
				} else if property == "totp" {
					cipher.Login.Totp = val
					continue
				} else if len(cipher.Login.Uris) == 0 && contains(importer.UriFieldNames, property) {
					cipher.Login.Uris = i.MakeUriArray(val)
					continue
				}
			}

			i.ProcessKvp(cipher, property, val)
		}

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	})

	result.Success = true
	return result
}
