// Package fsecure ports libs/importer/src/importers/fsecure/fsecure-fsk-importer.ts (format id
// "fsecurefsk").
package fsecure

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("fsecurefsk", New) }

// FskEntryType values.
const (
	fskEntryTypeLogin      = 1
	fskEntryTypeCreditCard = 2
)

// jsString decodes a JSON string; any other JSON value decodes to "" (the TS code only ever uses
// these values through getValueOrDefault/isNullOrWhitespace, which treat non-strings as null).
type jsString string

func (s *jsString) UnmarshalJSON(b []byte) error {
	var v string
	if json.Unmarshal(b, &v) == nil {
		*s = jsString(v)
	} else {
		*s = ""
	}
	return nil
}

type fskEntry struct {
	CreditCvv    jsString            `json:"creditCvv"`
	CreditExpiry jsString            `json:"creditExpiry"`
	CreditNumber jsString            `json:"creditNumber"`
	Favorite     importer.JSONNumber `json:"favorite"`
	Notes        jsString            `json:"notes"`
	Password     jsString            `json:"password"`
	Service      jsString            `json:"service"`
	Type         importer.JSONNumber `json:"type"`
	URL          jsString            `json:"url"`
	Username     jsString            `json:"username"`
}

type fskFile struct {
	Data json.RawMessage `json:"data"`
}

// Importer is FSecureFskImporter.
type Importer struct{ importer.Base }

// New constructs the importer.
func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

// Parse implements importer.Importer.
func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	var raw json.RawMessage
	if err := importer.UnmarshalJSONLenient(data, &raw); err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		result.Success = false
		return result, nil
	}
	var results fskFile
	if raw[0] == '{' {
		if err := json.Unmarshal(raw, &results); err != nil {
			return nil, importer.NewSyntaxError(err)
		}
	}
	d := bytes.TrimSpace(results.Data)
	if len(d) == 0 || bytes.Equal(d, []byte("null")) {
		result.Success = false
		return result, nil
	}

	values, err := objectValues(d)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		cipher, err := i.parseEntry(value)
		if err != nil {
			return nil, err
		}
		if cipher != nil {
			result.Ciphers = append(result.Ciphers, cipher)
		}
	}

	result.Success = true
	return result, nil
}

func (i *Importer) parseEntry(rawEntry json.RawMessage) (*model.CipherView, error) {
	rawEntry = bytes.TrimSpace(rawEntry)
	if bytes.Equal(rawEntry, []byte("null")) {
		// entry.service on null throws in TS.
		return nil, errors.New("Cannot read properties of null (reading 'service')")
	}
	var entry fskEntry
	if rawEntry[0] == '{' {
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			return nil, importer.NewSyntaxError(err)
		}
	}

	cipher := i.InitLoginCipher()
	cipher.Name = i.GetValueOrDefault(string(entry.Service))
	cipher.Notes = i.GetValueOrDefault(string(entry.Notes))
	cipher.Favorite = entry.Favorite.Valid && entry.Favorite.Value > 0

	if !entry.Type.IsNumber {
		return nil, nil
	}
	switch entry.Type.Value {
	case fskEntryTypeLogin:
		i.handleLoginEntry(&entry, cipher)
	case fskEntryTypeCreditCard:
		i.handleCreditCardEntry(&entry, cipher)
	default:
		return nil, nil
	}

	i.ConvertToNoteIfNeeded(cipher)
	i.CleanupCipher(cipher)
	return cipher, nil
}

func (i *Importer) handleLoginEntry(entry *fskEntry, cipher *model.CipherView) {
	cipher.Login.Username = i.GetValueOrDefault(string(entry.Username))
	cipher.Login.Password = i.GetValueOrDefault(string(entry.Password))
	cipher.Login.Uris = i.MakeUriArray(string(entry.URL))
}

func (i *Importer) handleCreditCardEntry(entry *fskEntry, cipher *model.CipherView) {
	cipher.Type = model.CipherTypeCard
	cipher.Card = &model.CardView{}
	cipher.Card.CardholderName = i.GetValueOrDefault(string(entry.Username))
	cipher.Card.Number = i.GetValueOrDefault(string(entry.CreditNumber))
	cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
	cipher.Card.Code = i.GetValueOrDefault(string(entry.CreditCvv))
	if !i.IsNullOrWhitespace(string(entry.CreditExpiry)) {
		if !i.SetCardExpiration(cipher, string(entry.CreditExpiry)) {
			i.ProcessKvp(cipher, "Expiration", string(entry.CreditExpiry))
		}
	}
	if !i.IsNullOrWhitespace(string(entry.Password)) {
		i.ProcessKvp(cipher, "PIN", string(entry.Password))
	}
}

// objectValues is Object.values(v) for a parsed JSON value: an object's values in JavaScript
// property order (array-index keys ascending, then insertion order; a duplicate key keeps its
// first position and its last value), an array's elements, nothing for scalars. Strings are not
// expanded into characters: their "entries" would never produce a cipher.
func objectValues(d json.RawMessage) ([]json.RawMessage, error) {
	switch d[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(d, &arr); err != nil {
			return nil, importer.NewSyntaxError(err)
		}
		return arr, nil
	case '{':
	default:
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(d))
	if _, err := dec.Token(); err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	var order []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, importer.NewSyntaxError(err)
		}
		key, _ := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, importer.NewSyntaxError(err)
		}
		if _, ok := vals[key]; !ok {
			order = append(order, key)
		}
		vals[key] = v
	}
	var ints, strs []string
	for _, k := range order {
		if isArrayIndex(k) {
			ints = append(ints, k)
		} else {
			strs = append(strs, k)
		}
	}
	sort.SliceStable(ints, func(a, b int) bool {
		x, _ := strconv.ParseUint(ints[a], 10, 64)
		y, _ := strconv.ParseUint(ints[b], 10, 64)
		return x < y
	})
	out := make([]json.RawMessage, 0, len(order))
	for _, k := range append(ints, strs...) {
		out = append(out, vals[k])
	}
	return out, nil
}

func isArrayIndex(k string) bool {
	if k == "" || (len(k) > 1 && k[0] == '0') {
		return false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 1<<32-1
}
