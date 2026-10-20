package enpass

import (
	"errors"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Types from types/enpass-json-type.ts (only the members the importer reads).

type enpassJSONFile struct {
	Folders []*enpassFolder `json:"folders"`
	Items   []*enpassItem   `json:"items"`
}

type enpassFolder struct {
	ParentUUID *importer.JSONString `json:"parent_uuid"`
	Title      *importer.JSONString `json:"title"`
	UUID       importer.JSONString  `json:"uuid"`

	children []*enpassFolder
}

type enpassItem struct {
	Favorite     importer.JSONNumber   `json:"favorite"`
	Fields       []*enpassField        `json:"fields"`
	Note         importer.JSONString   `json:"note"`
	TemplateType *importer.JSONString  `json:"template_type"`
	Title        importer.JSONString   `json:"title"`
	Folders      []importer.JSONString `json:"folders"`
}

type enpassField struct {
	Label     importer.JSONString `json:"label"`
	Sensitive importer.JSONNumber `json:"sensitive"`
	Type      importer.JSONString `json:"type"`
	Value     importer.JSONString `json:"value"`
}

// sensitiveFieldType is `field.sensitive === 1 ? FieldType.Hidden : FieldType.Text`.
func (f *enpassField) sensitiveFieldType() model.FieldType {
	if f.Sensitive.IsNumber && f.Sensitive.Value == 1 {
		return model.FieldTypeHidden
	}
	return model.FieldTypeText
}

// Bound the repetition to the base64 alphabet so it cannot be pumped across a repeated
// `androidapp://` prefix (`:` is not in the class, so it terminates the run).
var androidUrlRegex = regexp.MustCompile(`androidapp://[A-Za-z0-9\-_+/]*==@`)

// orderedMap is a JavaScript Map<string, V> (insertion order kept, re-setting a key keeps its
// position).
type orderedMap[V any] struct {
	keys []string
	m    map[string]V
}

func newOrderedMap[V any]() *orderedMap[V] { return &orderedMap[V]{m: map[string]V{}} }

func (o *orderedMap[V]) set(k string, v V) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

func (o *orderedMap[V]) get(k string) (V, bool) { v, ok := o.m[k]; return v, ok }

// JsonImporter is EnpassJsonImporter.
type JsonImporter struct{ importer.Base }

// NewJson constructs an EnpassJsonImporter.
func NewJson(opts importer.Options) importer.Importer {
	return &JsonImporter{Base: importer.NewBase(opts)}
}

var errNullItem = errors.New("Cannot read properties of null (reading 'folders')")
var errNullField = errors.New("Cannot read properties of null (reading 'value')")

// Parse is EnpassJsonImporter.parse.
func (i *JsonImporter) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	var results *enpassJSONFile
	if err := importer.UnmarshalJSONLenient(data, &results); err != nil {
		return nil, err
	}
	if results == nil || results.Items == nil || len(results.Items) == 0 {
		result.Success = false
		return result, nil
	}

	foldersMap := newOrderedMap[string]()
	foldersIndexMap := newOrderedMap[int]()
	folderTree := i.buildFolderTree(results.Folders)
	i.flattenFolderTree("", folderTree, foldersMap)
	for _, key := range foldersMap.keys {
		val, _ := foldersMap.get(key)
		foldersIndexMap.set(key, len(result.Folders))
		result.Folders = append(result.Folders, &model.FolderView{Name: val})
	}

	for _, item := range results.Items {
		if item == nil {
			return nil, errNullItem
		}
		if len(item.Folders) > 0 {
			if idx, ok := foldersIndexMap.get(string(item.Folders[0])); ok {
				result.FolderRelationships = append(result.FolderRelationships, model.Relationship{len(result.Ciphers), idx})
			}
		}

		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(string(item.Title))
		cipher.Favorite = item.Favorite.Valid && item.Favorite.Value > 0

		if item.TemplateType != nil && item.Fields != nil && len(item.Fields) > 0 {
			for _, f := range item.Fields {
				if f == nil {
					return nil, errNullField
				}
			}
			templateType := string(*item.TemplateType)
			if strings.HasPrefix(templateType, "login.") || strings.HasPrefix(templateType, "password.") {
				i.processLogin(cipher, item.Fields)
			} else if strings.HasPrefix(templateType, "creditcard.") {
				i.processCard(cipher, item.Fields)
			} else if !strings.Contains(templateType, "identity.") && i.hasPassword(item.Fields) {
				i.processLogin(cipher, item.Fields)
			} else {
				i.processNote(cipher, item.Fields)
			}
		}

		note := i.GetValueOrDefault(string(item.Note), "")
		if note != "" {
			cipher.Notes = importer.JSTrimEnd(note)
		}
		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

func (i *JsonImporter) hasPassword(fields []*enpassField) bool {
	for _, f := range fields {
		if f.Type == "password" && !i.IsNullOrWhitespace(string(f.Value)) {
			return true
		}
	}
	return false
}

func (i *JsonImporter) processLogin(cipher *model.CipherView, fields []*enpassField) {
	var urls []string
	for _, field := range fields {
		value := string(field.Value)
		if i.IsNullOrWhitespace(value) || field.Type == "section" {
			continue
		}

		switch {
		case (field.Type == "username" || field.Type == "email") && i.IsNullOrWhitespace(cipher.Login.Username):
			cipher.Login.Username = value
		case field.Type == "password" && i.IsNullOrWhitespace(cipher.Login.Password):
			cipher.Login.Password = value
		case field.Type == "totp" && i.IsNullOrWhitespace(cipher.Login.Totp):
			cipher.Login.Totp = value
		case field.Type == "url":
			urls = append(urls, value)
		case field.Type == ".Android#":
			cleanedValue := value
			if !strings.HasPrefix(value, "androidapp://") {
				cleanedValue = "androidapp://" + value
			}
			cleanedValue = strings.Replace(cleanedValue, "android://", "", 1)
			cleanedValue = androidUrlRegex.ReplaceAllLiteralString(cleanedValue, "androidapp://")
			urls = append(urls, cleanedValue)
		default:
			i.ProcessKvp(cipher, string(field.Label), value, field.sensitiveFieldType())
		}
	}
	cipher.Login.Uris = i.MakeUriArray(urls...)
}

func (i *JsonImporter) processCard(cipher *model.CipherView, fields []*enpassField) {
	cipher.Card = &model.CardView{}
	cipher.Type = model.CipherTypeCard
	for _, field := range fields {
		value := string(field.Value)
		if i.IsNullOrWhitespace(value) || field.Type == "section" || field.Type == "ccType" {
			continue
		}

		switch {
		case field.Type == "ccName" && i.IsNullOrWhitespace(cipher.Card.CardholderName):
			cipher.Card.CardholderName = value
		case field.Type == "ccNumber" && i.IsNullOrWhitespace(cipher.Card.Number):
			cipher.Card.Number = value
			cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
		case field.Type == "ccCvc" && i.IsNullOrWhitespace(cipher.Card.Code):
			cipher.Card.Code = value
		case field.Type == "ccExpiry" && i.IsNullOrWhitespace(cipher.Card.ExpYear):
			if !i.SetCardExpiration(cipher, value) {
				i.ProcessKvp(cipher, string(field.Label), value, field.sensitiveFieldType())
			}
		default:
			i.ProcessKvp(cipher, string(field.Label), value, field.sensitiveFieldType())
		}
	}
}

func (i *JsonImporter) processNote(cipher *model.CipherView, fields []*enpassField) {
	for _, field := range fields {
		value := string(field.Value)
		if i.IsNullOrWhitespace(value) || field.Type == "section" {
			continue
		}
		i.ProcessKvp(cipher, string(field.Label), value, field.sensitiveFieldType())
	}
}

func (i *JsonImporter) buildFolderTree(folders []*enpassFolder) []*enpassFolder {
	if folders == nil {
		return []*enpassFolder{}
	}
	folderTree := []*enpassFolder{}
	m := map[string]*enpassFolder{}
	for _, obj := range folders {
		if obj == nil {
			continue
		}
		m[string(obj.UUID)] = obj
		obj.children = []*enpassFolder{}
	}
	for _, obj := range folders {
		if obj == nil {
			continue
		}
		parent := importer.Str(obj.ParentUUID)
		if p, ok := m[parent]; obj.ParentUUID != nil && parent != "" && ok {
			p.children = append(p.children, obj)
		} else {
			folderTree = append(folderTree, obj)
		}
	}
	return folderTree
}

func (i *JsonImporter) flattenFolderTree(titlePrefix string, tree []*enpassFolder, m *orderedMap[string]) {
	if tree == nil {
		return
	}
	for _, f := range tree {
		if f.Title != nil && importer.JSTrim(string(*f.Title)) != "" {
			title := importer.JSTrim(string(*f.Title))
			if importer.JSTrim(titlePrefix) != "" {
				title = titlePrefix + "/" + title
			}
			m.set(string(f.UUID), title)
			if len(f.children) != 0 {
				i.flattenFolderTree(title, f.children, m)
			}
		}
	}
}
