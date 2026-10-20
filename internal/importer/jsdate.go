package importer

import (
	"math"
	"time"
	"unicode"
	"unicode/utf8"
)

// ParseJSDate is `new Date(s)` / Date.parse(s) as implemented by V8 (Node): a port of V8's
// DateParser (src/date/dateparser*.{h,cc}) — the ES5 ISO format first, then V8's legacy,
// Safari-compatible parser. Date-only ISO forms are UTC; every other form without an explicit
// zone is local time (time.Local). ok is false where JavaScript yields an Invalid Date.
func ParseJSDate(s string) (time.Time, bool) {
	p := v8DateParser{in: []rune(s)}
	p.next()
	out, ok := p.parse()
	if !ok {
		return time.Time{}, false
	}
	return out.toTime()
}

// MonthFromName returns 1-12 when V8 would read name as a month keyword (its first three
// letters, case-insensitive, abbreviate a month), or 0.
func MonthFromName(name string) int {
	kw := lookupDateKeyword(name)
	if kw.typ == kwMonthName {
		return kw.value
	}
	return 0
}

const (
	dpNone              = math.MinInt32
	dpMaxSignificantDig = 9
)

type dateKwType int

const (
	kwInvalid dateKwType = iota
	kwMonthName
	kwTimeZoneName
	kwTimeSeparator
	kwAmPm
)

type dateKeyword struct {
	prefix string
	typ    dateKwType
	value  int
}

var dateKeywords = []dateKeyword{
	{"jan", kwMonthName, 1}, {"feb", kwMonthName, 2}, {"mar", kwMonthName, 3},
	{"apr", kwMonthName, 4}, {"may", kwMonthName, 5}, {"jun", kwMonthName, 6},
	{"jul", kwMonthName, 7}, {"aug", kwMonthName, 8}, {"sep", kwMonthName, 9},
	{"oct", kwMonthName, 10}, {"nov", kwMonthName, 11}, {"dec", kwMonthName, 12},
	{"am", kwAmPm, 0}, {"pm", kwAmPm, 12},
	{"ut", kwTimeZoneName, 0}, {"utc", kwTimeZoneName, 0}, {"z", kwTimeZoneName, 0},
	{"gmt", kwTimeZoneName, 0}, {"cdt", kwTimeZoneName, -5}, {"cst", kwTimeZoneName, -6},
	{"edt", kwTimeZoneName, -4}, {"est", kwTimeZoneName, -5}, {"mdt", kwTimeZoneName, -6},
	{"mst", kwTimeZoneName, -7}, {"pdt", kwTimeZoneName, -7}, {"pst", kwTimeZoneName, -8},
	{"t", kwTimeSeparator, 0},
}

func lookupDateKeyword(word string) dateKeyword {
	rs := []rune(word)
	var pre [3]rune
	for i := 0; i < len(rs) && i < 3; i++ {
		r := rs[i]
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		pre[i] = r
	}
	for _, k := range dateKeywords {
		var kp [3]rune
		for i, r := range k.prefix {
			kp[i] = r
		}
		if kp == pre && (len(rs) <= 3 || k.typ == kwMonthName) {
			return k
		}
	}
	return dateKeyword{typ: kwInvalid}
}

type dtKind int

const (
	tkInvalid dtKind = iota
	tkUnknown
	tkNumber
	tkSymbol
	tkWhiteSpace
	tkKeyword
	tkEnd
)

type dateToken struct {
	kind   dtKind
	length int
	value  int // number value, symbol rune, keyword value
	kwType dateKwType
}

func (t dateToken) isNumber() bool                 { return t.kind == tkNumber }
func (t dateToken) isSymbol(c rune) bool           { return t.kind == tkSymbol && t.value == int(c) }
func (t dateToken) isAsciiSign() bool              { return t.isSymbol('+') || t.isSymbol('-') }
func (t dateToken) isFixedLengthNumber(n int) bool { return t.kind == tkNumber && t.length == n }
func (t dateToken) isKeywordType(k dateKwType) bool {
	return t.kind == tkKeyword && t.kwType == k
}
func (t dateToken) isKeywordZ() bool {
	return t.isKeywordType(kwTimeZoneName) && t.length == 1 && t.value == 0
}
func (t dateToken) asciiSign() int {
	if t.value == '-' {
		return -1
	}
	return 1
}

type v8DateParser struct {
	in   []rune
	pos  int
	ch   rune // current char, -1 at end
	peek dateToken
	day  dayComposer
	tm   timeComposer
	tz   tzComposer
}

func (p *v8DateParser) next() {
	if p.pos < len(p.in) {
		p.ch = p.in[p.pos]
		p.pos++
	} else {
		p.ch = -1
		p.pos = len(p.in) + 1
	}
}

func (p *v8DateParser) position() int { return p.pos - 1 }

func isDateWhiteSpace(r rune) bool {
	return r == '\u0009' || r == '\u000b' || r == '\u000c' || r == ' ' || r == ' ' ||
		r == '\ufeff' || r == '\n' || r == '\r' || r == ' ' || r == ' ' ||
		(r > 127 && unicode.Is(unicode.Zs, r))
}

func (p *v8DateParser) scan() dateToken {
	pre := p.position()
	if p.ch < 0 {
		return dateToken{kind: tkEnd}
	}
	if p.ch >= '0' && p.ch <= '9' {
		n, i := 0, 0
		for p.ch == '0' {
			p.next()
		}
		for p.ch >= '0' && p.ch <= '9' {
			if i < dpMaxSignificantDig {
				n = n*10 + int(p.ch-'0')
			}
			i++
			p.next()
		}
		return dateToken{kind: tkNumber, value: n, length: p.position() - pre}
	}
	for _, c := range []rune{':', '-', '+', '.', ')'} {
		if p.ch == c {
			p.next()
			return dateToken{kind: tkSymbol, value: int(c), length: 1}
		}
	}
	if p.ch >= 'A' && !isDateWhiteSpace(p.ch) {
		start := p.pos - 1
		for p.ch >= 'A' && !isDateWhiteSpace(p.ch) {
			p.next()
		}
		word := string(p.in[start : p.pos-1])
		kw := lookupDateKeyword(word)
		return dateToken{kind: tkKeyword, kwType: kw.typ, value: kw.value, length: utf8.RuneCountInString(word)}
	}
	if isDateWhiteSpace(p.ch) {
		p.next()
		return dateToken{kind: tkWhiteSpace, length: p.position() - pre}
	}
	if p.ch == '(' {
		balance := 0
		for {
			if p.ch == ')' {
				balance--
			} else if p.ch == '(' {
				balance++
			}
			p.next()
			if balance <= 0 || p.ch < 0 {
				break
			}
		}
		return dateToken{kind: tkUnknown}
	}
	p.next()
	return dateToken{kind: tkUnknown}
}

// Tokenizer API (DateStringTokenizer): Next returns the lookahead and scans a new one.
func (p *v8DateParser) tokNext() dateToken {
	t := p.peek
	p.peek = p.scan()
	return t
}

func (p *v8DateParser) skipSymbol(c rune) bool {
	if p.peek.isSymbol(c) {
		p.tokNext()
		return true
	}
	return false
}

type dayComposer struct {
	comp       [3]int
	index      int
	namedMonth int
	isISO      bool
}

func (d *dayComposer) isEmpty() bool { return d.index == 0 }
func (d *dayComposer) add(n int) bool {
	if d.index < 3 {
		d.comp[d.index] = n
		d.index++
		return true
	}
	return false
}
func between(x, lo, hi int) bool { return x >= lo && x <= hi }
func isMonth(x int) bool         { return between(x, 1, 12) }
func isDayNum(x int) bool        { return between(x, 1, 31) }

type timeComposer struct {
	comp       [4]int
	index      int
	hourOffset int
}

func (t *timeComposer) isEmpty() bool { return t.index == 0 }
func (t *timeComposer) isExpecting(n int) bool {
	return (t.index == 1 && between(n, 0, 59)) || (t.index == 2 && between(n, 0, 59)) ||
		(t.index == 3 && between(n, 0, 999))
}
func (t *timeComposer) add(n int) bool {
	if t.index < 4 {
		t.comp[t.index] = n
		t.index++
		return true
	}
	return false
}
func (t *timeComposer) addFinal(n int) bool {
	if !t.add(n) {
		return false
	}
	for t.index < 4 {
		t.comp[t.index] = 0
		t.index++
	}
	return true
}

type tzComposer struct{ sign, hour, minute int }

func (z *tzComposer) set(offsetHours int) {
	z.sign = 1
	if offsetHours < 0 {
		z.sign = -1
	}
	z.hour = offsetHours * z.sign
	z.minute = 0
}
func (z *tzComposer) setSign(s int) {
	z.sign = 1
	if s < 0 {
		z.sign = -1
	}
}
func (z *tzComposer) isExpecting(n int) bool {
	return z.hour != dpNone && z.minute == dpNone && between(n, 0, 59)
}
func (z *tzComposer) isUTC() bool   { return z.hour == 0 && z.minute == 0 }
func (z *tzComposer) isEmpty() bool { return z.sign == dpNone }

func readMilliseconds(t dateToken) int {
	n, length := t.value, t.length
	switch {
	case length == 1:
		n *= 100
	case length == 2:
		n *= 10
	case length > 3:
		if length > dpMaxSignificantDig {
			length = dpMaxSignificantDig
		}
		factor := 1
		for length > 3 {
			factor *= 10
			length--
		}
		n /= factor
	}
	return n
}

// parseES5 is DateParser::ParseES5DateTime; it returns the first token it did not handle.
func (p *v8DateParser) parseES5() dateToken {
	day, tm, tz := &p.day, &p.tm, &p.tz
	if p.peek.isAsciiSign() {
		signTok := p.tokNext()
		if !p.peek.isFixedLengthNumber(6) {
			return signTok
		}
		sign := signTok.asciiSign()
		year := p.tokNext().value
		if sign < 0 && year == 0 {
			return signTok
		}
		day.add(sign * year)
	} else if p.peek.isFixedLengthNumber(4) {
		day.add(p.tokNext().value)
	} else {
		return p.tokNext()
	}
	if p.skipSymbol('-') {
		if !p.peek.isFixedLengthNumber(2) || !isMonth(p.peek.value) {
			return p.tokNext()
		}
		day.add(p.tokNext().value)
		if p.skipSymbol('-') {
			if !p.peek.isFixedLengthNumber(2) || !isDayNum(p.peek.value) {
				return p.tokNext()
			}
			day.add(p.tokNext().value)
		}
	}
	if !p.peek.isKeywordType(kwTimeSeparator) {
		if p.peek.kind != tkEnd {
			return p.tokNext()
		}
	} else {
		p.tokNext()
		if !p.peek.isFixedLengthNumber(2) || !between(p.peek.value, 0, 24) {
			return dateToken{kind: tkInvalid}
		}
		hourIs24 := p.peek.value == 24
		tm.add(p.tokNext().value)
		if !p.skipSymbol(':') {
			return dateToken{kind: tkInvalid}
		}
		if !p.peek.isFixedLengthNumber(2) || !between(p.peek.value, 0, 59) || (hourIs24 && p.peek.value > 0) {
			return dateToken{kind: tkInvalid}
		}
		tm.add(p.tokNext().value)
		if p.skipSymbol(':') {
			if !p.peek.isFixedLengthNumber(2) || !between(p.peek.value, 0, 59) || (hourIs24 && p.peek.value > 0) {
				return dateToken{kind: tkInvalid}
			}
			tm.add(p.tokNext().value)
			if p.skipSymbol('.') {
				if !p.peek.isNumber() || (hourIs24 && p.peek.value > 0) {
					return dateToken{kind: tkInvalid}
				}
				tm.add(readMilliseconds(p.tokNext()))
			}
		}
		if p.peek.isKeywordZ() {
			p.tokNext()
			tz.set(0)
		} else if p.peek.isSymbol('+') || p.peek.isSymbol('-') {
			tz.setSign(p.tokNext().asciiSign())
			if p.peek.isFixedLengthNumber(4) {
				hm := p.tokNext().value
				h, m := hm/100, hm%100
				if !between(h, 0, 23) || !between(m, 0, 59) {
					return dateToken{kind: tkInvalid}
				}
				tz.hour, tz.minute = h, m
			} else {
				if !p.peek.isFixedLengthNumber(2) || !between(p.peek.value, 0, 23) {
					return dateToken{kind: tkInvalid}
				}
				tz.hour = p.tokNext().value
				if !p.skipSymbol(':') {
					return dateToken{kind: tkInvalid}
				}
				if !p.peek.isFixedLengthNumber(2) || !between(p.peek.value, 0, 59) {
					return dateToken{kind: tkInvalid}
				}
				tz.minute = p.tokNext().value
			}
		}
		if p.peek.kind != tkEnd {
			return dateToken{kind: tkInvalid}
		}
	}
	if tz.isEmpty() && tm.isEmpty() {
		tz.set(0)
	}
	day.isISO = true
	return dateToken{kind: tkEnd}
}

type jsDateFields struct {
	year, month, day         int
	hour, minute, second, ms int
	utcOffsetSeconds         int
	local                    bool
}

func (p *v8DateParser) parse() (jsDateFields, bool) {
	p.day = dayComposer{namedMonth: dpNone}
	p.tm = timeComposer{hourOffset: dpNone}
	p.tz = tzComposer{sign: dpNone, hour: dpNone, minute: dpNone}
	p.peek = p.scan()

	tok := p.parseES5()
	if tok.kind == tkInvalid {
		return jsDateFields{}, false
	}
	hasReadNumber := !p.day.isEmpty()
	for ; tok.kind != tkEnd; tok = p.tokNext() {
		switch {
		case tok.isNumber():
			hasReadNumber = true
			n := tok.value
			if p.skipSymbol(':') {
				if p.skipSymbol(':') {
					if !p.tm.isEmpty() {
						return jsDateFields{}, false
					}
					p.tm.add(n)
					p.tm.add(0)
				} else {
					if !p.tm.add(n) {
						return jsDateFields{}, false
					}
					if p.peek.isSymbol('.') {
						p.tokNext()
					}
				}
			} else if p.skipSymbol('.') && p.tm.isExpecting(n) {
				p.tm.add(n)
				if !p.peek.isNumber() {
					return jsDateFields{}, false
				}
				ms := readMilliseconds(p.tokNext())
				if ms < 0 {
					return jsDateFields{}, false
				}
				p.tm.addFinal(ms)
			} else if p.tz.isExpecting(n) {
				p.tz.minute = n
			} else if p.tm.isExpecting(n) {
				p.tm.addFinal(n)
				pk := p.peek
				if pk.kind != tkEnd && pk.kind != tkWhiteSpace && !pk.isKeywordZ() && !pk.isAsciiSign() {
					return jsDateFields{}, false
				}
			} else {
				if !p.day.add(n) {
					return jsDateFields{}, false
				}
				p.skipSymbol('-')
			}
		case tok.kind == tkKeyword:
			if tok.kwType == kwAmPm && !p.tm.isEmpty() {
				p.tm.hourOffset = tok.value
			} else if tok.kwType == kwMonthName {
				p.day.namedMonth = tok.value
				p.skipSymbol('-')
			} else if tok.kwType == kwTimeZoneName && hasReadNumber {
				p.tz.set(tok.value)
			} else {
				if hasReadNumber {
					return jsDateFields{}, false
				}
				if p.peek.isNumber() {
					return jsDateFields{}, false
				}
			}
		case tok.isAsciiSign() && (p.tz.isUTC() || !p.tm.isEmpty()):
			p.tz.setSign(tok.asciiSign())
			n, length := 0, 0
			if p.peek.isNumber() {
				t := p.tokNext()
				length, n = t.length, t.value
			}
			hasReadNumber = true
			if p.peek.isSymbol(':') {
				p.tz.hour = n
				p.tz.minute = dpNone
			} else if length == 2 || length == 1 {
				p.tz.hour, p.tz.minute = n, 0
			} else if length == 4 || length == 3 {
				p.tz.hour, p.tz.minute = n/100, n%100
			} else {
				return jsDateFields{}, false
			}
		case (tok.isAsciiSign() || tok.isSymbol(')')) && hasReadNumber:
			return jsDateFields{}, false
		}
	}

	var out jsDateFields
	// DayComposer::Write
	d := &p.day
	if d.index < 1 {
		return out, false
	}
	for d.index < 3 {
		d.comp[d.index] = 1
		d.index++
	}
	year, month, day := 0, dpNone, dpNone
	if d.namedMonth == dpNone {
		if d.isISO || (d.index == 3 && !isDayNum(d.comp[0])) {
			year, month, day = d.comp[0], d.comp[1], d.comp[2]
		} else {
			month, day = d.comp[0], d.comp[1]
			if d.index == 3 {
				year = d.comp[2]
			}
		}
	} else {
		month = d.namedMonth
		if d.index == 1 {
			day = d.comp[0]
		} else if !isDayNum(d.comp[0]) {
			year, day = d.comp[0], d.comp[1]
		} else {
			day, year = d.comp[0], d.comp[1]
		}
	}
	if !d.isISO {
		if between(year, 0, 49) {
			year += 2000
		} else if between(year, 50, 99) {
			year += 1900
		}
	}
	if !isMonth(month) || !isDayNum(day) {
		return out, false
	}
	out.year, out.month, out.day = year, month, day

	// TimeComposer::Write
	t := &p.tm
	for t.index < 4 {
		t.comp[t.index] = 0
		t.index++
	}
	hour, minute, second, ms := t.comp[0], t.comp[1], t.comp[2], t.comp[3]
	if t.hourOffset != dpNone {
		if !between(hour, 0, 12) {
			return out, false
		}
		hour %= 12
		hour += t.hourOffset
	}
	if !between(hour, 0, 23) || !between(minute, 0, 59) || !between(second, 0, 59) || !between(ms, 0, 999) {
		if hour != 24 || minute != 0 || second != 0 || ms != 0 {
			return out, false
		}
	}
	out.hour, out.minute, out.second, out.ms = hour, minute, second, ms

	// TimeZoneComposer::Write
	z := &p.tz
	if z.sign != dpNone {
		if z.hour == dpNone {
			z.hour = 0
		}
		if z.minute == dpNone {
			z.minute = 0
		}
		// V8 computes this in unsigned 32-bit arithmetic and rejects values above Smi::kMaxValue
		// (2^31-1 in Node, which does not use pointer compression).
		u := uint32(z.hour)*3600 + uint32(z.minute)*60
		if u > math.MaxInt32 {
			return out, false
		}
		total := int(u)
		if z.sign < 0 {
			total = -total
		}
		out.utcOffsetSeconds = total
	} else {
		out.local = true
	}
	return out, true
}

const maxJSTimeMs = 8.64e15

func (f jsDateFields) toTime() (time.Time, bool) {
	loc := time.UTC
	if f.local {
		loc = time.Local
	}
	t := time.Date(f.year, time.Month(f.month), f.day, f.hour, f.minute, f.second, f.ms*int(time.Millisecond), loc)
	if !f.local {
		t = t.Add(-time.Duration(f.utcOffsetSeconds) * time.Second)
	}
	ms := float64(t.Unix())*1000 + float64(t.Nanosecond()/1e6)
	if math.Abs(ms) > maxJSTimeMs {
		return time.Time{}, false
	}
	return t, true
}
