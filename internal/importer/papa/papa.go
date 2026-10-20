// Package papa is a port of the parts of PapaParse 5.5.3 (the CSV parser used by the TypeScript
// importers) that BaseImporter.parseCsv relies on: delimiter and newline auto-detection, quoted
// fields with configurable quote/escape characters, the "fast mode" shortcut for input without
// quotes, header rows (including the 5.4+ duplicate-header renaming), `__parsed_extra`,
// skipEmptyLines (true / "greedy"), comments and transformHeader, plus the same error objects.
//
// Indexes are byte offsets into the UTF-8 input; every delimiter, quote and newline that can be
// configured is matched as a substring, which gives the same results as PapaParse's UTF-16 code
// unit offsets.
package papa

import (
	"sort"
	"strconv"
	"strings"
)

// Special delimiter characters, as Papa.RECORD_SEP / Papa.UNIT_SEP.
const (
	RecordSep        = "\x1e"
	UnitSep          = "\x1f"
	DefaultDelimiter = ","
	ParsedExtraKey   = "__parsed_extra"
)

var badDelimiters = []string{"\r", "\n", `"`, "\ufeff"}

func isBadDelimiter(s string) bool {
	for _, b := range badDelimiters {
		if s == b {
			return true
		}
	}
	return false
}

// SkipEmptyLines selects PapaParse's skipEmptyLines option.
type SkipEmptyLines int

const (
	// SkipNone keeps empty lines (skipEmptyLines: false).
	SkipNone SkipEmptyLines = iota
	// SkipEmpty drops lines that parse to a single empty field (skipEmptyLines: true).
	SkipEmpty
	// SkipGreedy drops lines whose fields are all whitespace (skipEmptyLines: "greedy").
	SkipGreedy
)

// Config mirrors the subset of Papa.ParseConfig the importers use. Zero values mean "PapaParse
// default".
type Config struct {
	// Header treats the first row as field names (rows are returned as Records).
	Header bool
	// Delimiter; "" means auto-detect among , \t | ; RS US.
	Delimiter string
	// Newline; "" means auto-detect.
	Newline string
	// QuoteChar; "" means `"`.
	QuoteChar string
	// EscapeChar; nil means "same as QuoteChar".
	EscapeChar *string
	// Comments: lines starting with this string are skipped ("" disables).
	Comments string
	// SkipEmptyLines selects false / true / "greedy".
	SkipEmptyLines SkipEmptyLines
	// TransformHeader is applied to every header value (applied twice, like PapaParse 5.5: once
	// while renaming duplicates and once when building the field list).
	TransformHeader func(header string, index int) string
	// DelimitersToGuess overrides the auto-detection candidates.
	DelimitersToGuess []string

	// preview limits the number of rows (used by delimiter guessing).
	preview int
}

// Error mirrors PapaParse's ParseError. Row is nil when the error is not tied to a row.
type Error struct {
	Type    string
	Code    string
	Message string
	Row     *int
	Index   *int
}

// Record is one data row of a header-mode parse: a JS object keyed by header names.
type Record struct {
	values map[string]string
	order  []string
	// Extra holds the values that had no header (`__parsed_extra`).
	Extra []string
}

// NewRecord builds a record from alternating key/value pairs (handy in tests).
func NewRecord(kv ...string) Record {
	r := Record{values: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		r.Set(kv[i], kv[i+1])
	}
	return r
}

// Get returns the value of key, or "" when absent (JS: undefined).
func (r Record) Get(key string) string { return r.values[key] }

// Lookup returns the value and whether the key exists (JS: hasOwnProperty / `!= null`).
func (r Record) Lookup(key string) (string, bool) {
	v, ok := r.values[key]
	return v, ok
}

// Has reports whether key exists on the record.
func (r Record) Has(key string) bool { _, ok := r.values[key]; return ok }

// Set assigns key (keeping the first-assignment position, like a JS object).
func (r *Record) Set(key, value string) {
	if r.values == nil {
		r.values = map[string]string{}
	}
	if _, ok := r.values[key]; !ok {
		r.order = append(r.order, key)
	}
	r.values[key] = value
}

// Delete removes key.
func (r *Record) Delete(key string) {
	if _, ok := r.values[key]; !ok {
		return
	}
	delete(r.values, key)
	for i, k := range r.order {
		if k == key {
			r.order = append(r.order[:i:i], r.order[i+1:]...)
			break
		}
	}
}

// Len is the number of keys (excluding `__parsed_extra`).
func (r Record) Len() int { return len(r.order) }

// Keys returns the keys in JavaScript `Object.keys` order: integer-like keys ascending first, then
// the remaining keys in insertion order. `__parsed_extra` is not included (see Extra).
func (r Record) Keys() []string {
	var ints, strs []string
	for _, k := range r.order {
		if isArrayIndex(k) {
			ints = append(ints, k)
		} else {
			strs = append(strs, k)
		}
	}
	sort.SliceStable(ints, func(i, j int) bool {
		a, _ := strconv.ParseUint(ints[i], 10, 64)
		b, _ := strconv.ParseUint(ints[j], 10, 64)
		return a < b
	})
	return append(ints, strs...)
}

// Values returns the values in Keys() order (JS Object.values).
func (r Record) Values() []string {
	keys := r.Keys()
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = r.values[k]
	}
	return out
}

func isArrayIndex(k string) bool {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 4294967295
}

// Meta mirrors ParseMeta.
type Meta struct {
	Delimiter      string
	Linebreak      string
	Aborted        bool
	Truncated      bool
	Cursor         int
	Fields         []string
	RenamedHeaders map[string]string
}

// Result is the parse output. Rows is set when Header is false, Records when it is true.
type Result struct {
	Rows    [][]string
	Records []Record
	Errors  []Error
	Meta    Meta
}

// Len returns the number of data rows.
func (r Result) Len() int {
	if r.Rows != nil {
		return len(r.Rows)
	}
	return len(r.Records)
}

// Parse parses input like Papa.parse(string, config).
func Parse(input string, cfg Config) Result {
	input = strings.TrimPrefix(input, "\ufeff") // CsvToJson.stripBom
	quoteChar := cfg.QuoteChar
	if quoteChar == "" {
		quoteChar = `"`
	}
	if cfg.Newline == "" {
		cfg.Newline = guessLineEndings(input, quoteChar)
	}
	delimiterError := false
	if cfg.Delimiter == "" {
		best, ok := guessDelimiter(input, cfg.Newline, cfg.SkipEmptyLines, cfg.Comments, cfg.DelimitersToGuess)
		if ok {
			cfg.Delimiter = best
		} else {
			delimiterError = true
			cfg.Delimiter = DefaultDelimiter
		}
	}

	raw := newParser(cfg).parse(input)
	res := Result{Errors: raw.errors, Meta: raw.meta}

	if delimiterError {
		res.Errors = append(res.Errors, Error{Type: "Delimiter", Code: "UndetectableDelimiter",
			Message: "Unable to auto-detect delimiting character; defaulted to '" + DefaultDelimiter + "'"})
	}

	data := raw.data
	if cfg.SkipEmptyLines != SkipNone {
		kept := data[:0:0]
		for _, d := range data {
			if !testEmptyLine(d, cfg.SkipEmptyLines) {
				kept = append(kept, d)
			}
		}
		data = kept
	}

	if !cfg.Header {
		if data == nil {
			data = [][]string{}
		}
		res.Rows = data
		return res
	}

	// fillHeaderFields
	var fields []string
	if len(data) > 0 {
		for i, h := range data[0] {
			if cfg.TransformHeader != nil {
				h = cfg.TransformHeader(h, i)
			}
			fields = append(fields, h)
		}
		data = data[1:]
	}
	if fields == nil {
		fields = []string{}
	}
	res.Meta.Fields = fields

	records := make([]Record, 0, len(data))
	for i, src := range data {
		rec := Record{values: make(map[string]string, len(fields))}
		j := 0
		for ; j < len(src); j++ {
			if j >= len(fields) {
				rec.Extra = append(rec.Extra, src[j])
			} else {
				rec.Set(fields[j], src[j])
			}
		}
		row := i
		if j > len(fields) {
			res.Errors = append(res.Errors, Error{Type: "FieldMismatch", Code: "TooManyFields",
				Message: "Too many fields: expected " + strconv.Itoa(len(fields)) + " fields but parsed " + strconv.Itoa(j), Row: &row})
		} else if j < len(fields) {
			res.Errors = append(res.Errors, Error{Type: "FieldMismatch", Code: "TooFewFields",
				Message: "Too few fields: expected " + strconv.Itoa(len(fields)) + " fields but parsed " + strconv.Itoa(j), Row: &row})
		}
		records = append(records, rec)
	}
	res.Records = records
	return res
}

func testEmptyLine(s []string, mode SkipEmptyLines) bool {
	if mode == SkipGreedy {
		return jsTrim(strings.Join(s, "")) == ""
	}
	return len(s) == 1 && len(s[0]) == 0
}

func guessLineEndings(input, quoteChar string) string {
	if len(input) > 1024*1024 {
		input = input[:1024*1024]
	}
	// Remove quoted sections (non-greedy, like /"([^]*?)"/gm).
	var b strings.Builder
	for {
		i := strings.Index(input, quoteChar)
		if i < 0 {
			b.WriteString(input)
			break
		}
		j := strings.Index(input[i+len(quoteChar):], quoteChar)
		if j < 0 {
			b.WriteString(input)
			break
		}
		b.WriteString(input[:i])
		input = input[i+len(quoteChar)+j+len(quoteChar):]
	}
	input = b.String()

	r := strings.Split(input, "\r")
	n := strings.Split(input, "\n")
	nAppearsFirst := len(n) > 1 && len(n[0]) < len(r[0])
	if len(r) == 1 || nAppearsFirst {
		return "\n"
	}
	numWithN := 0
	for _, s := range r {
		if strings.HasPrefix(s, "\n") {
			numWithN++
		}
	}
	if float64(numWithN) >= float64(len(r))/2 {
		return "\r\n"
	}
	return "\r"
}

func guessDelimiter(input, newline string, skip SkipEmptyLines, comments string, candidates []string) (string, bool) {
	if len(candidates) == 0 {
		candidates = []string{",", "\t", "|", ";", RecordSep, UnitSep}
	}
	var bestDelim string
	bestDelta := -1
	maxFieldCount := -1.0
	haveBest := false
	for _, delim := range candidates {
		delta := 0
		avgFieldCount := 0.0
		emptyLinesCount := 0
		fieldCountPrevRow := -1
		preview := newParser(Config{Comments: comments, Delimiter: delim, Newline: newline, preview: 10}).parse(input)
		for _, row := range preview.data {
			if skip != SkipNone && testEmptyLine(row, skip) {
				emptyLinesCount++
				continue
			}
			fieldCount := len(row)
			avgFieldCount += float64(fieldCount)
			if fieldCountPrevRow < 0 {
				fieldCountPrevRow = fieldCount
				continue
			} else if fieldCount > 0 {
				d := fieldCount - fieldCountPrevRow
				if d < 0 {
					d = -d
				}
				delta += d
				fieldCountPrevRow = fieldCount
			}
		}
		if len(preview.data) > 0 {
			avgFieldCount /= float64(len(preview.data) - emptyLinesCount) // may be +Inf/NaN like JS
		}
		if (!haveBest || delta <= bestDelta) && (maxFieldCount < 0 || avgFieldCount > maxFieldCount) && avgFieldCount > 1.99 {
			bestDelta = delta
			bestDelim = delim
			maxFieldCount = avgFieldCount
			haveBest = true
		}
	}
	return bestDelim, haveBest
}

type parsed struct {
	data   [][]string
	errors []Error
	meta   Meta
}

type parser struct {
	delim, newline, comments, quoteChar, escapeChar string
	header                                          bool
	transformHeader                                 func(string, int) string
	preview                                         int
}

func newParser(cfg Config) *parser {
	p := &parser{delim: cfg.Delimiter, newline: cfg.Newline, comments: cfg.Comments, header: cfg.Header,
		transformHeader: cfg.TransformHeader, preview: cfg.preview}
	p.quoteChar = cfg.QuoteChar
	if p.quoteChar == "" {
		p.quoteChar = `"`
	}
	p.escapeChar = p.quoteChar
	if cfg.EscapeChar != nil {
		p.escapeChar = *cfg.EscapeChar
	}
	if p.delim == "" || isBadDelimiter(p.delim) {
		p.delim = ","
	}
	if p.comments == p.delim {
		panic("Comment character same as delimiter")
	}
	if isBadDelimiter(p.comments) {
		p.comments = ""
	}
	if p.newline != "\n" && p.newline != "\r" && p.newline != "\r\n" {
		p.newline = "\n"
	}
	return p
}

func indexFrom(s, sub string, from int) int {
	if from > len(s) {
		return -1
	}
	if from < 0 {
		from = 0
	}
	i := strings.Index(s[from:], sub)
	if i < 0 {
		return -1
	}
	return i + from
}

func substr(s string, start, length int) string {
	if start >= len(s) || length <= 0 {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func substring(s string, a, b int) string {
	if a > b {
		a, b = b, a
	}
	if a < 0 {
		a = 0
	}
	if b > len(s) {
		b = len(s)
	}
	if a > len(s) {
		return ""
	}
	return s[a:b]
}

func (p *parser) parse(input string) parsed {
	data := [][]string{}
	var errs []Error
	var row []string
	cursor, lastCursor := 0, 0
	inputLen := len(input)
	delimLen, newlineLen := len(p.delim), len(p.newline)
	headerParsed := false
	var renamed map[string]string

	returnable := func(stopped bool) parsed {
		if p.header && len(data) > 0 && !headerParsed {
			result := data[0]
			headerCount := map[string]int{}
			used := map[string]bool{}
			for _, h := range result {
				used[h] = true
			}
			for i := range result {
				h := result[i]
				if p.transformHeader != nil {
					h = p.transformHeader(h, i)
				}
				if headerCount[h] == 0 {
					headerCount[h] = 1
					result[i] = h
				} else {
					suffix := headerCount[h]
					var nh string
					for {
						nh = h + "_" + strconv.Itoa(suffix)
						suffix++
						if !used[nh] {
							break
						}
					}
					used[nh] = true
					result[i] = nh
					headerCount[h]++
					if renamed == nil {
						renamed = map[string]string{}
					}
					renamed[nh] = h
				}
				used[h] = true
			}
			headerParsed = true
		}
		return parsed{data: data, errors: errs, meta: Meta{Delimiter: p.delim, Linebreak: p.newline,
			Truncated: stopped, Cursor: lastCursor, RenamedHeaders: renamed}}
	}
	pushRow := func(r []string) {
		data = append(data, r)
		lastCursor = cursor
	}

	if input == "" {
		return returnable(false)
	}

	// Fast mode: no quote characters anywhere.
	if !strings.Contains(input, p.quoteChar) {
		rows := strings.Split(input, p.newline)
		for i, r := range rows {
			cursor += len(r)
			if i != len(rows)-1 {
				cursor += newlineLen
			}
			if p.comments != "" && strings.HasPrefix(r, p.comments) {
				continue
			}
			pushRow(strings.Split(r, p.delim))
			if p.preview > 0 && i >= p.preview {
				data = data[:p.preview]
				return returnable(true)
			}
		}
		return returnable(false)
	}

	nextDelim := indexFrom(input, p.delim, cursor)
	nextNewline := indexFrom(input, p.newline, cursor)
	unescape := func(s string) string {
		return strings.ReplaceAll(s, p.escapeChar+p.quoteChar, p.quoteChar)
	}
	quoteSearch := indexFrom(input, p.quoteChar, cursor)

	extraSpaces := func(index int) int {
		if index == -1 {
			return 0
		}
		between := substring(input, quoteSearch+1, index)
		if between != "" && jsTrim(between) == "" {
			return len(between)
		}
		return 0
	}
	finish := func(value *string) parsed {
		v := ""
		if value == nil {
			v = substring(input, cursor, inputLen)
		} else {
			v = *value
		}
		row = append(row, v)
		cursor = inputLen
		pushRow(row)
		return returnable(false)
	}
	saveRow := func(newCursor int) {
		cursor = newCursor
		pushRow(row)
		row = []string{}
		nextNewline = indexFrom(input, p.newline, cursor)
	}

	for {
		if cursor < inputLen && strings.HasPrefix(input[cursor:], p.quoteChar) {
			quoteSearch = cursor
			cursor += len(p.quoteChar)
			for {
				quoteSearch = indexFrom(input, p.quoteChar, quoteSearch+1)
				if quoteSearch == -1 {
					r, idx := len(data), cursor
					errs = append(errs, Error{Type: "Quotes", Code: "MissingQuotes",
						Message: "Quoted field unterminated", Row: &r, Index: &idx})
					return finish(nil)
				}
				if quoteSearch == inputLen-len(p.quoteChar) {
					v := unescape(substring(input, cursor, quoteSearch))
					return finish(&v)
				}
				if p.quoteChar == p.escapeChar && strings.HasPrefix(input[quoteSearch+len(p.quoteChar):], p.escapeChar) {
					quoteSearch++
					continue
				}
				if p.quoteChar != p.escapeChar && quoteSearch != 0 && strings.HasSuffix(input[:quoteSearch], p.escapeChar) {
					continue
				}
				if nextDelim != -1 && nextDelim < quoteSearch+1 {
					nextDelim = indexFrom(input, p.delim, quoteSearch+1)
				}
				if nextNewline != -1 && nextNewline < quoteSearch+1 {
					nextNewline = indexFrom(input, p.newline, quoteSearch+1)
				}
				// nextNewline === -1 ? nextDelim : Math.min(nextDelim, nextNewline)
				checkUpTo := nextDelim
				if nextNewline != -1 {
					checkUpTo = min(nextDelim, nextNewline)
				}
				spacesDelim := extraSpaces(checkUpTo)
				if substr(input, quoteSearch+1+spacesDelim, delimLen) == p.delim {
					row = append(row, unescape(substring(input, cursor, quoteSearch)))
					cursor = quoteSearch + 1 + spacesDelim + delimLen
					if !strings.HasPrefix(input[min(cursor, inputLen):], p.quoteChar) {
						quoteSearch = indexFrom(input, p.quoteChar, cursor)
					}
					nextDelim = indexFrom(input, p.delim, cursor)
					nextNewline = indexFrom(input, p.newline, cursor)
					break
				}
				spacesNewline := extraSpaces(nextNewline)
				if substring(input, quoteSearch+1+spacesNewline, quoteSearch+1+spacesNewline+newlineLen) == p.newline {
					row = append(row, unescape(substring(input, cursor, quoteSearch)))
					saveRow(quoteSearch + 1 + spacesNewline + newlineLen)
					nextDelim = indexFrom(input, p.delim, cursor)
					quoteSearch = indexFrom(input, p.quoteChar, cursor)
					if p.preview > 0 && len(data) >= p.preview {
						return returnable(true)
					}
					break
				}
				r, idx := len(data), cursor
				errs = append(errs, Error{Type: "Quotes", Code: "InvalidQuotes",
					Message: "Trailing quote on quoted field is malformed", Row: &r, Index: &idx})
				quoteSearch++
			}
			continue
		}

		if p.comments != "" && len(row) == 0 && strings.HasPrefix(input[cursor:], p.comments) {
			if nextNewline == -1 {
				return returnable(false)
			}
			cursor = nextNewline + newlineLen
			nextNewline = indexFrom(input, p.newline, cursor)
			nextDelim = indexFrom(input, p.delim, cursor)
			continue
		}

		if nextDelim != -1 && (nextDelim < nextNewline || nextNewline == -1) {
			row = append(row, substring(input, cursor, nextDelim))
			cursor = nextDelim + delimLen
			nextDelim = indexFrom(input, p.delim, cursor)
			continue
		}

		if nextNewline != -1 {
			row = append(row, substring(input, cursor, nextNewline))
			saveRow(nextNewline + newlineLen)
			if p.preview > 0 && len(data) >= p.preview {
				return returnable(true)
			}
			continue
		}
		break
	}
	return finish(nil)
}

// jsTrim mirrors String.prototype.trim.
func jsTrim(s string) string {
	return strings.TrimFunc(s, IsJSSpace)
}

// IsJSSpace reports whether r is whitespace for JavaScript's trim() and \s.
func IsJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}
