package vault

import (
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

// NormalizeSearchQuery mirrors normalizeSearchQuery: NFD and removal of combining diacritics
// (U+0300–U+036F).
func NormalizeSearchQuery(q string) string {
	d := norm.NFD.String(q)
	return strings.Map(func(r rune) rune {
		if r >= 0x300 && r <= 0x36f {
			return -1
		}
		return r
	}, d)
}

func jsLower(s string) string { return strings.ToLower(s) }

var whitespaceSplit = func(r rune) bool { return unicode.IsSpace(r) }

// SearchCiphersBasic mirrors SearchService.searchCiphersBasic (used by `list items --search` and
// `get` by name): every whitespace separated term must occur (case/diacritic-insensitive) in the
// name, the id (terms of 8+ chars, prefix), the subtitle, a login URI hostname or the notes.
func SearchCiphersBasic(ciphers []*CipherView, query string) []*CipherView {
	terms := strings.FieldsFunc(NormalizeSearchQuery(jsLower(strings.TrimSpace(query))), whitespaceSplit)
	out := []*CipherView{}
	for _, c := range ciphers {
		if matchesAllTerms(c, terms) {
			out = append(out, c)
		}
	}
	return out
}

func contains(hay *string, term string) bool {
	return hay != nil && strings.Contains(NormalizeSearchQuery(jsLower(*hay)), term)
}

func matchesAllTerms(c *CipherView, terms []string) bool {
	for _, term := range terms {
		name := c.Name
		if contains(&name, term) {
			continue
		}
		if len(term) >= 8 && strings.HasPrefix(c.ID, term) {
			continue
		}
		if contains(c.Subtitle(), term) {
			continue
		}
		if c.Type == CipherTypeLogin && c.Login != nil {
			found := false
			for _, u := range c.Login.URIs {
				if u.URI == nil || *u.URI == "" || (u.Match != nil && *u.Match == UriMatchRegularExpression) {
					continue
				}
				if contains(GetHostname(*u.URI), term) {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}
		if c.Notes != nil && *c.Notes != "" && contains(c.Notes, term) {
			continue
		}
		return false
	}
	return true
}

// SearchFolders mirrors CliUtils.searchFolders.
func SearchFolders(folders []*FolderView, search string) []*FolderView {
	s := jsLower(search)
	out := []*FolderView{}
	for _, f := range folders {
		if strings.Contains(jsLower(f.Name), s) {
			out = append(out, f)
		}
	}
	return out
}

// SearchCollections mirrors CliUtils.searchCollections.
func SearchCollections(cols []*CollectionView, search string) []*CollectionView {
	s := jsLower(search)
	out := []*CollectionView{}
	for _, c := range cols {
		if strings.Contains(jsLower(c.DisplayName()), s) {
			out = append(out, c)
		}
	}
	return out
}

// SearchOrganizations mirrors CliUtils.searchOrganizations.
func SearchOrganizations(orgs []*Organization, search string) []*Organization {
	s := jsLower(search)
	out := []*Organization{}
	for _, o := range orgs {
		if strings.Contains(jsLower(o.Name), s) {
			out = append(out, o)
		}
	}
	return out
}

// newCollator approximates `new Intl.Collator(locale, {numeric: true, sensitivity: "base"})`.
func newCollator() *collate.Collator {
	return collate.New(language.English, collate.Loose, collate.Numeric)
}

// CompareNames compares two names like the i18n collator.
func CompareNames(a, b string) int { return newCollator().CompareString(a, b) }

// SortCiphers mirrors CipherService.getLocaleSortingFunction (name, then name+username for
// logins with equal names).
func SortCiphers(ciphers []*CipherView) {
	col := newCollator()
	sort.SliceStable(ciphers, func(i, j int) bool {
		a, b := ciphers[i], ciphers[j]
		r := col.CompareString(a.Name, b.Name)
		if r != 0 || a.Type != CipherTypeLogin || b.Type != CipherTypeLogin {
			return r < 0
		}
		an, bn := a.Name, b.Name
		if a.Login != nil && a.Login.Username != nil {
			an += *a.Login.Username
		}
		if b.Login != nil && b.Login.Username != nil {
			bn += *b.Login.Username
		}
		return col.CompareString(an, bn) < 0
	})
}

// SortFolders sorts by name with the collator.
func SortFolders(f []*FolderView) {
	col := newCollator()
	sort.SliceStable(f, func(i, j int) bool { return col.CompareString(f[i].Name, f[j].Name) < 0 })
}

// SortCollections sorts by (display) name with the collator.
func SortCollections(c []*CollectionView) {
	col := newCollator()
	sort.SliceStable(c, func(i, j int) bool { return col.CompareString(c[i].DisplayName(), c[j].DisplayName()) < 0 })
}
