package dashlane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

var handledResults = setOf(
	"ADDRESS",
	"AUTHENTIFIANT",
	"BANKSTATEMENT",
	"IDCARD",
	"IDENTITY",
	"PAYMENTMEANS_CREDITCARD",
	"PAYMENTMEAN_PAYPAL",
	"EMAIL",
)

// JsonImporter is DashlaneJsonImporter. The input is decoded into JavaScript-like values (see
// jsValue) because the importer walks arbitrary keys with `for...in` and `toString()`.
type JsonImporter struct {
	importer.Base
	result *model.ImportResult
}

// NewJson builds a DashlaneJsonImporter.
func NewJson(opts importer.Options) importer.Importer {
	return &JsonImporter{Base: importer.NewBase(opts)}
}

// Parse implements importer.Importer.
func (i *JsonImporter) Parse(data string) (*model.ImportResult, error) {
	i.result = model.NewImportResult()
	results, err := parseJS(data)
	if err != nil {
		return nil, importer.NewSyntaxError(err)
	}
	if results == nil || jsLengthIsZero(results) {
		i.result.Success = false
		return i.result, nil
	}

	if v := jsGetLoose(results, "ADDRESS"); !jsIsNullish(v) {
		if err := i.processAddress(v); err != nil {
			return nil, err
		}
	}
	if v := jsGetLoose(results, "AUTHENTIFIANT"); !jsIsNullish(v) {
		if err := i.processAuth(v); err != nil {
			return nil, err
		}
	}
	if v := jsGetLoose(results, "BANKSTATEMENT"); !jsIsNullish(v) {
		if err := i.processNote(v, "BankAccountName", nil); err != nil {
			return nil, err
		}
	}
	if v := jsGetLoose(results, "IDCARD"); !jsIsNullish(v) {
		if err := i.processNote(v, "Fullname", nil); err != nil {
			return nil, err
		}
	}
	if v := jsGetLoose(results, "PAYMENTMEANS_CREDITCARD"); !jsIsNullish(v) {
		if err := i.processCard(v); err != nil {
			return nil, err
		}
	}
	if v := jsGetLoose(results, "IDENTITY"); !jsIsNullish(v) {
		if err := i.processIdentity(v); err != nil {
			return nil, err
		}
	}

	genericNote := "Generic Note"
	for _, kv := range jsForIn(results) {
		if !handledResults[kv.key] {
			if err := i.processNote(kv.value, "", &genericNote); err != nil {
				return nil, err
			}
		}
	}

	i.result.Success = true
	return i.result, nil
}

func (i *JsonImporter) processAuth(results any) error {
	return jsForEach(results, func(credential any) error {
		cipher := i.InitLoginCipher()
		title, err := jsGet(credential, "title")
		if err != nil {
			return err
		}
		cipher.Name = i.GetValueOrDefault(jsStr(title))

		login, err := jsGet(credential, "login")
		if err != nil {
			return err
		}
		secondaryLogin, _ := jsGet(credential, "secondaryLogin")
		email, _ := jsGet(credential, "email")
		cipher.Login.Username = i.GetValueOrDefault(jsStr(login), i.GetValueOrDefault(jsStr(secondaryLogin)))
		if i.IsNullOrWhitespace(cipher.Login.Username) {
			cipher.Login.Username = i.GetValueOrDefault(jsStr(email))
		} else if s, ok := email.(string); ok && !i.IsNullOrWhitespace(s) {
			cipher.Notes = "Email: " + s + "\n"
		}

		password, _ := jsGet(credential, "password")
		cipher.Login.Password = i.GetValueOrDefault(jsStr(password))
		domain, _ := jsGet(credential, "domain")
		uris, err := i.makeUriArray(domain)
		if err != nil {
			return err
		}
		cipher.Login.Uris = uris
		note, _ := jsGet(credential, "note")
		cipher.Notes += i.GetValueOrDefault(jsStr(note), "")

		i.ConvertToNoteIfNeeded(cipher)
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		return nil
	})
}

// makeUriArray is BaseImporter.makeUriArray applied to an arbitrary JSON value.
func (i *JsonImporter) makeUriArray(uri any) ([]*model.LoginUriView, error) {
	switch u := uri.(type) {
	case string:
		return i.MakeUriArray(u), nil
	case []any:
		var list []string
		for _, e := range u {
			switch s := e.(type) {
			case nil:
				// fixUri(null) is null and skipped
			case string:
				list = append(list, s)
			default:
				return nil, errors.New("TypeError: uri.trim is not a function")
			}
		}
		return i.MakeUriArray(list...), nil
	}
	return nil, nil
}

func (i *JsonImporter) processIdentity(results any) error {
	return jsForEach(results, func(obj any) error {
		cipher := model.NewCipherView()
		cipher.Identity = &model.IdentityView{}
		cipher.Type = model.CipherTypeIdentity
		fullName, err := jsGet(obj, "fullName")
		if err != nil {
			return err
		}
		cipher.Name = i.GetValueOrDefault(jsStr(fullName), "")
		nameParts := strings.Split(cipher.Name, " ")
		if len(nameParts) > 0 {
			cipher.Identity.FirstName = i.GetValueOrDefault(nameParts[0])
		}
		if len(nameParts) == 2 {
			cipher.Identity.LastName = i.GetValueOrDefault(nameParts[1])
		} else if len(nameParts) == 3 {
			cipher.Identity.MiddleName = i.GetValueOrDefault(nameParts[1])
			cipher.Identity.LastName = i.GetValueOrDefault(nameParts[2])
		}
		pseudo, _ := jsGet(obj, "pseudo")
		cipher.Identity.Username = i.GetValueOrDefault(jsStr(pseudo))
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		return nil
	})
}

var upperCaser = cases.Upper(language.Und)

func (i *JsonImporter) processAddress(results any) error {
	return jsForEach(results, func(obj any) error {
		cipher := model.NewCipherView()
		cipher.Identity = &model.IdentityView{}
		cipher.Type = model.CipherTypeIdentity
		addressName, err := jsGet(obj, "addressName")
		if err != nil {
			return err
		}
		get := func(k string) string { v, _ := jsGet(obj, k); return jsStr(v) }
		cipher.Name = i.GetValueOrDefault(jsStr(addressName))
		cipher.Identity.Address1 = i.GetValueOrDefault(get("addressFull"))
		cipher.Identity.City = i.GetValueOrDefault(get("city"))
		cipher.Identity.State = i.GetValueOrDefault(get("state"))
		cipher.Identity.PostalCode = i.GetValueOrDefault(get("zipcode"))
		cipher.Identity.Country = i.GetValueOrDefault(get("country"))
		if cipher.Identity.Country != "" {
			cipher.Identity.Country = upperCaser.String(cipher.Identity.Country)
		}
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		return nil
	})
}

func (i *JsonImporter) processCard(results any) error {
	return jsForEach(results, func(obj any) error {
		cipher := model.NewCipherView()
		cipher.Card = &model.CardView{}
		cipher.Type = model.CipherTypeCard
		bank, err := jsGet(obj, "bank")
		if err != nil {
			return err
		}
		get := func(k string) string { v, _ := jsGet(obj, k); return jsStr(v) }
		cipher.Name = i.GetValueOrDefault(jsStr(bank))
		cipher.Card.Number = i.GetValueOrDefault(get("cardNumber"))
		cipher.Card.Brand = model.GetCardBrandByPatterns(cipher.Card.Number)
		cipher.Card.CardholderName = i.GetValueOrDefault(get("owner"))
		if !i.IsNullOrWhitespace(cipher.Card.Brand) {
			if i.IsNullOrWhitespace(cipher.Name) {
				cipher.Name = cipher.Card.Brand
			} else {
				cipher.Name += " - " + cipher.Card.Brand
			}
		}
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		return nil
	})
}

// processNote is processNote(results, nameProperty, name = null); nameProperty "" stands for
// null (only passed together with a name).
func (i *JsonImporter) processNote(results any, nameProperty string, name *string) error {
	return jsForEach(results, func(obj any) error {
		cipher := model.NewCipherView()
		cipher.SecureNote = &model.SecureNoteView{}
		cipher.Type = model.CipherTypeSecureNote
		cipher.SecureNote.Type = model.SecureNoteTypeGeneric
		if name != nil {
			cipher.Name = *name
		} else {
			v, err := jsGet(obj, nameProperty)
			if err != nil {
				return err
			}
			cipher.Name = i.GetValueOrDefault(jsStr(v))
		}
		for _, kv := range jsForIn(obj) {
			if nameProperty != "" && kv.key == nameProperty {
				continue
			}
			s, err := jsToString(kv.value, kv.key)
			if err != nil {
				return err
			}
			i.ProcessKvp(cipher, kv.key, s)
		}
		i.CleanupCipher(cipher)
		i.result.Ciphers = append(i.result.Ciphers, cipher)
		return nil
	})
}

// --- JavaScript value helpers ---------------------------------------------------------------

// JSON values are decoded as: nil (null), bool, jsNumber, string, []any, *jsObject.
type jsNumber float64

type jsObject struct {
	keys   []string
	values map[string]any
}

type jsKV struct {
	key   string
	value any
}

// undefined is the value of a missing property.
type undefinedT struct{}

var undefined = undefinedT{}

func parseJS(data string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("unexpected data after top-level value")
		}
		return nil, err
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &jsObject{values: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				if _, dup := obj.values[key]; !dup {
					obj.keys = append(obj.keys, key)
				}
				obj.values[key] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			// Out of range numbers are ±Infinity in JavaScript.
			var ne *strconv.NumError
			if errors.As(err, &ne) && ne.Err == strconv.ErrRange {
				return jsNumber(f), nil
			}
			return nil, err
		}
		return jsNumber(f), nil
	default:
		return t, nil // nil, bool, string
	}
}

func jsIsNullish(v any) bool { return v == nil || v == undefined }

// jsLengthIsZero is `results.length === 0`.
func jsLengthIsZero(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case string:
		return t == ""
	case *jsObject:
		if l, ok := t.values["length"].(jsNumber); ok {
			return l == 0
		}
	}
	return false
}

// jsStr is the value when it is a JS string, else "" (Utils.isNullOrWhitespace treats every
// non-string as null).
func jsStr(v any) string {
	s, _ := v.(string)
	return s
}

// jsGetLoose is `v[key]` on a value known not to be null/undefined.
func jsGetLoose(v any, key string) any {
	r, _ := jsGet(v, key)
	return r
}

// jsGet is `v[key]`: undefined for a missing property, a TypeError for null.
func jsGet(v any, key string) (any, error) {
	switch t := v.(type) {
	case nil, undefinedT:
		what := "null"
		if t != nil {
			what = "undefined"
		}
		return nil, fmt.Errorf("TypeError: Cannot read properties of %s (reading '%s')", what, key)
	case *jsObject:
		if val, ok := t.values[key]; ok {
			return val, nil
		}
	case []any:
		if n, ok := arrayIndex(key); ok && n < len(t) {
			return t[n], nil
		}
		if key == "length" {
			return jsNumber(len(t)), nil
		}
	case string:
		u := utf16Units(t)
		if n, ok := arrayIndex(key); ok && n < len(u) {
			return string(rune16(u[n])), nil
		}
		if key == "length" {
			return jsNumber(len(u)), nil
		}
	}
	return undefined, nil
}

// jsForIn lists the enumerable own properties of v in `for...in` order.
func jsForIn(v any) []jsKV {
	switch t := v.(type) {
	case *jsObject:
		var ints, strs []string
		for _, k := range t.keys {
			if _, ok := arrayIndex(k); ok {
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
		out := make([]jsKV, 0, len(t.keys))
		for _, k := range append(ints, strs...) {
			out = append(out, jsKV{k, t.values[k]})
		}
		return out
	case []any:
		out := make([]jsKV, len(t))
		for n, e := range t {
			out[n] = jsKV{strconv.Itoa(n), e}
		}
		return out
	case string:
		u := utf16Units(t)
		out := make([]jsKV, len(u))
		for n, c := range u {
			out[n] = jsKV{strconv.Itoa(n), string(rune16(c))}
		}
		return out
	}
	return nil
}

// jsForEach is `v.forEach(fn)`; only arrays have forEach.
func jsForEach(v any, fn func(any) error) error {
	arr, ok := v.([]any)
	if !ok {
		return errors.New("TypeError: results.forEach is not a function")
	}
	for _, e := range arr {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// jsToString is `v.toString()` (key is used in the TypeError message for null).
func jsToString(v any, key string) (string, error) {
	if jsIsNullish(v) {
		what := "null"
		if v != nil {
			what = "undefined"
		}
		return "", fmt.Errorf("TypeError: Cannot read properties of %s (reading 'toString')", what)
	}
	return jsString(v), nil
}

// jsString is String(v) for non-nullish values (array elements that are null become "").
func jsString(v any) string {
	switch t := v.(type) {
	case nil, undefinedT:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	case jsNumber:
		return importer.FormatJSNumber(float64(t))
	case string:
		return t
	case []any:
		var b bytes.Buffer
		for n, e := range t {
			if n > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsString(e))
		}
		return b.String()
	case *jsObject:
		return "[object Object]"
	}
	return ""
}

func arrayIndex(k string) (int, bool) {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(k, 10, 64)
	if err != nil || n >= 1<<32-1 {
		return 0, false
	}
	return int(n), true
}

func utf16Units(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// rune16 converts one UTF-16 code unit to a rune (lone surrogates become U+FFFD when encoded).
func rune16(u uint16) rune { return rune(u) }
