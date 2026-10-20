// Package kaspersky ports libs/importer/src/importers/kaspersky-txt-importer.ts (kasperskytxt).
package kaspersky

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("kasperskytxt", New) }

const (
	notesHeader        = "Notes\n\n"
	applicationsHeader = "Applications\n\n"
	websitesHeader     = "Websites\n\n"
	delimiter          = "\n---\n"
)

// Importer is KasperskyTxtImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// item is a Map<string, string> whose values may be undefined.
type item struct {
	keys   []string
	values map[string]*string
}

func newItem() *item { return &item{values: map[string]*string{}} }

func (m *item) set(key string, val *string) {
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = val
}

func (m *item) has(key string) bool { _, ok := m.values[key]; return ok }

// get is Map.get ("" for undefined).
func (m *item) get(key string) string {
	if v := m.values[key]; v != nil {
		return *v
	}
	return ""
}

func (m *item) size() int { return len(m.keys) }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()

	var notesData, applicationsData, websitesData string
	workingData := strings.Join(i.SplitNewLine(data), "\n")

	if strings.Contains(workingData, notesHeader) {
		parts := strings.Split(workingData, notesHeader)
		if len(parts) > 1 {
			workingData = parts[0]
			notesData = parts[1]
		}
	}
	if strings.Contains(workingData, applicationsHeader) {
		parts := strings.Split(workingData, applicationsHeader)
		if len(parts) > 1 {
			workingData = parts[0]
			applicationsData = parts[1]
		}
	}
	if strings.Index(workingData, websitesHeader) == 0 {
		parts := strings.Split(workingData, websitesHeader)
		if len(parts) > 1 {
			workingData = parts[0]
			websitesData = parts[1]
		}
	}

	notes := i.parseDataCategory(notesData)
	applications := i.parseDataCategory(applicationsData)
	websites := i.parseDataCategory(websitesData)

	for _, n := range notes {
		cipher := i.InitLoginCipher()
		cipher.Name = i.GetValueOrDefault(n.get("Name"))
		cipher.Notes = i.GetValueOrDefault(n.get("Text"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	for _, w := range append(websites, applications...) {
		cipher := i.InitLoginCipher()
		nameKey := "Application"
		if w.has("Website name") {
			nameKey = "Website name"
		}
		cipher.Name = i.GetValueOrDefault(w.get(nameKey), "")
		if !i.IsNullOrWhitespace(w.get("Login name")) {
			if !i.IsNullOrWhitespace(cipher.Name) {
				cipher.Name += ": "
			}
			cipher.Name += w.get("Login name")
		}
		cipher.Notes = i.GetValueOrDefault(w.get("Comment"))
		if w.has("Website URL") {
			cipher.Login.Uris = i.MakeUriArray(w.get("Website URL"))
		}
		cipher.Login.Username = i.GetValueOrDefault(w.get("Login"))
		cipher.Login.Password = i.GetValueOrDefault(w.get("Password"))
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}

	result.Success = true
	return result, nil
}

func (i *Importer) parseDataCategory(data string) []*item {
	if i.IsNullOrWhitespace(data) || !strings.Contains(data, delimiter) {
		return nil
	}
	var items []*item
	for _, p := range strings.Split(data, delimiter) {
		if !strings.Contains(p, "\n") {
			continue
		}
		it := newItem()
		var itemComment *string
		itemCommentKey := ""
		for _, l := range strings.Split(p, "\n") {
			if itemComment != nil {
				c := *itemComment + "\n" + l
				itemComment = &c
				continue
			}
			colonIndex := strings.Index(l, ":")
			if colonIndex == -1 {
				continue
			}
			key := l[:colonIndex]
			var val *string
			if importer.Len16(l) > importer.Len16(key)+1 {
				// l.substring(colonIndex + 2): skips the colon and one UTF-16 unit after it.
				v := importer.Substring16(l, importer.Len16(key)+2, importer.Len16(l))
				val = &v
			}
			it.set(key, val)
			if key == "Comment" || key == "Text" {
				itemComment = val
				itemCommentKey = key
			}
		}
		if itemComment != nil && itemCommentKey != "" {
			it.set(itemCommentKey, itemComment)
		}
		if it.size() == 0 {
			continue
		}
		items = append(items, it)
	}
	return items
}
