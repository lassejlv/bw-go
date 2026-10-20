package sendcore

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// FromState returns the encrypted Send with the given id from state, or nil (SendService.getFromState).
func FromState(a *app.App, id string) (*Data, error) {
	acct := a.ActiveAccount()
	if acct == nil {
		return nil, errors.New("You are not logged in.")
	}
	raw, ok := acct.Vault.Sends[id]
	if !ok {
		return nil, nil
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// All returns every encrypted Send in state.
func All(a *app.App) ([]*Data, error) {
	acct := a.ActiveAccount()
	if acct == nil {
		return nil, errors.New("You are not logged in.")
	}
	out := make([]*Data, 0, len(acct.Vault.Sends))
	for _, id := range state.OrderedIDs(acct.Vault.Sends, acct.Vault.SendOrder) {
		raw := acct.Vault.Sends[id]
		var d Data
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, nil
}

// AllDecrypted decrypts every Send in state, sorted by name (SendService.getAllDecryptedFromState).
// Item Sends are skipped like the legacy decryption path does.
func AllDecrypted(a *app.App, userKey *crypto.SymmetricKey) ([]*View, error) {
	sends, err := All(a)
	if err != nil {
		return nil, err
	}
	views := make([]*View, 0, len(sends))
	for _, s := range sends {
		if s.Type == TypeItem {
			continue
		}
		v, err := Decrypt(s, userKey)
		if err != nil {
			return nil, err
		}
		views = append(views, v)
	}
	SortByName(views)
	return views, nil
}

// SortByName sorts views by name like Utils.getSortFunction(i18nService, "name").
func SortByName(views []*View) {
	name := func(v *View) string {
		if v.Name == nil {
			return ""
		}
		return *v.Name
	}
	sort.SliceStable(views, func(i, j int) bool {
		a, b := name(views[i]), name(views[j])
		la, lb := strings.ToLower(a), strings.ToLower(b)
		if la != lb {
			return la < lb
		}
		return a < b
	})
}

// Upsert stores a raw server Send response in state keyed by its id (SendService.upsert).
func Upsert(a *app.App, raw []byte) (*Data, error) {
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d.ID == "" {
		return nil, errors.New("Invalid Send response.")
	}
	err := a.UpdateAccount(func(acct *state.Account) error {
		if acct.Vault.Sends == nil {
			acct.Vault.Sends = map[string]json.RawMessage{}
		}
		acct.Vault.Sends[d.ID] = json.RawMessage(append([]byte(nil), raw...))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Remove deletes a Send from state (SendService.delete).
func Remove(a *app.App, id string) error {
	return a.UpdateAccount(func(acct *state.Account) error {
		delete(acct.Vault.Sends, id)
		return nil
	})
}

// HasPremium reports premium from any source using the synced profile
// (BillingAccountProfileStateService.hasPremiumFromAnySource$).
func HasPremium(a *app.App) bool {
	acct := a.ActiveAccount()
	if acct == nil || len(acct.Vault.Profile) == 0 {
		return false
	}
	var p struct {
		Premium                 bool `json:"premium"`
		PremiumFromOrganization bool `json:"premiumFromOrganization"`
	}
	if json.Unmarshal(acct.Vault.Profile, &p) != nil {
		return false
	}
	return p.Premium || p.PremiumFromOrganization
}

// Search filters views by a query (SearchService.searchSends).
func Search(views []*View, query string) []*View {
	query = normalizeSearchQuery(strings.ToLower(strings.TrimSpace(query)))
	var matched, low []*View
	contains := func(s *string) bool { return s != nil && strings.Contains(strings.ToLower(*s), query) }
	for _, s := range views {
		switch {
		case contains(s.Name):
			matched = append(matched, s)
		case len(query) >= 8 && (strings.HasPrefix(s.ID, query) ||
			strings.HasPrefix(strings.ToLower(s.AccessID), query) ||
			(s.File != nil && s.File.ID != nil && strings.HasPrefix(*s.File.ID, query))):
			low = append(low, s)
		case contains(s.Notes):
			low = append(low, s)
		case s.Text != nil && contains(s.Text.Text):
			low = append(low, s)
		case s.File != nil && contains(s.File.FileName):
			low = append(low, s)
		}
	}
	return append(matched, low...)
}

// normalizeSearchQuery strips combining diacritical marks (U+0300-U+036F) after a simple
// decomposition of common accented Latin letters.
func normalizeSearchQuery(q string) string {
	var b strings.Builder
	for _, r := range q {
		if r >= 0x300 && r <= 0x36f {
			continue
		}
		if base, ok := latinBase[r]; ok {
			b.WriteRune(base)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

var latinBase = func() map[rune]rune {
	m := map[rune]rune{}
	groups := map[rune]string{
		'a': "àáâãäåāăą", 'c': "çćĉċč", 'e': "èéêëēĕėęě", 'i': "ìíîïĩīĭį", 'n': "ñńņňŉ",
		'o': "òóôõöōŏő", 'u': "ùúûüũūŭůűų", 'y': "ýÿŷ", 'z': "źżž", 's': "śŝşš", 'g': "ĝğġģ",
		'd': "ď", 'l': "ĺļľ", 'r': "ŕŗř", 't': "ţť", 'h': "ĥ", 'j': "ĵ", 'k': "ķ", 'w': "ŵ",
	}
	for base, chars := range groups {
		for _, c := range chars {
			m[c] = base
		}
	}
	return m
}()
