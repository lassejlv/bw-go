package zxcvbn

import (
	"sort"
	"strconv"
	"strings"
)

// Match is one pattern found in the password (a zxcvbn match object). Token and the other
// strings are JavaScript code units.
type Match struct {
	Pattern string
	I, J    int
	Token   []uint16

	// dictionary
	MatchedWord    []uint16
	Rank           int
	DictionaryName string
	Reversed       bool
	L33t           bool
	Sub            map[uint16]uint16

	// spatial
	Graph        string
	Turns        int
	ShiftedCount int

	// repeat
	BaseToken   []uint16
	BaseGuesses float64
	BaseMatches []*Match
	RepeatCount float64

	// sequence
	SequenceName  string
	SequenceSpace int
	Ascending     bool

	// regex
	RegexName  string
	RegexMatch []uint16

	// date
	Separator        []uint16
	Year, Month, Day int

	Guesses      float64
	GuessesLog10 float64
	hasGuesses   bool
}

type matcher struct {
	dicts         []dictionary
	referenceYear int
}

func sorted(matches []*Match) []*Match {
	sort.SliceStable(matches, func(a, b int) bool {
		if matches[a].I != matches[b].I {
			return matches[a].I < matches[b].I
		}
		return matches[a].J < matches[b].J
	})
	return matches
}

// omnimatch mirrors matching.omnimatch.
func (m *matcher) omnimatch(password []uint16) []*Match {
	var matches []*Match
	matches = append(matches, m.dictionaryMatch(password)...)
	matches = append(matches, m.reverseDictionaryMatch(password)...)
	matches = append(matches, m.l33tMatch(password)...)
	matches = append(matches, spatialMatch(password)...)
	matches = append(matches, m.repeatMatch(password)...)
	matches = append(matches, sequenceMatch(password)...)
	matches = append(matches, regexMatch(password)...)
	matches = append(matches, m.dateMatch(password)...)
	return sorted(matches)
}

// ---------- dictionary ----------

func (m *matcher) dictionaryMatch(password []uint16) []*Match {
	var matches []*Match
	n := len(password)
	lower := toLower(password)
	for _, d := range m.dicts {
		for i := 0; i < n; i++ {
			for j := i; j < n; j++ {
				if j-i+1 > d.maxLen {
					break
				}
				word := slice(lower, i, j+1)
				rank, ok := d.ranks[key(word)]
				if !ok {
					continue
				}
				matches = append(matches, &Match{
					Pattern: "dictionary", I: i, J: j, Token: password[i : j+1],
					MatchedWord: word, Rank: rank, DictionaryName: d.name,
				})
			}
		}
	}
	return sorted(matches)
}

func reverseUnits(s []uint16) []uint16 {
	out := make([]uint16, len(s))
	for i, u := range s {
		out[len(s)-1-i] = u
	}
	return out
}

func (m *matcher) reverseDictionaryMatch(password []uint16) []*Match {
	matches := m.dictionaryMatch(reverseUnits(password))
	for _, x := range matches {
		x.Token = reverseUnits(x.Token)
		x.Reversed = true
		x.I, x.J = len(password)-1-x.J, len(password)-1-x.I
	}
	return sorted(matches)
}

// ---------- l33t ----------

type l33tEntry struct {
	letter uint16
	subs   []uint16
}

// l33tTable mirrors L33T_TABLE (in key order).
var l33tTable = []l33tEntry{
	{'a', []uint16{'4', '@'}},
	{'b', []uint16{'8'}},
	{'c', []uint16{'(', '{', '[', '<'}},
	{'e', []uint16{'3'}},
	{'g', []uint16{'6', '9'}},
	{'i', []uint16{'1', '!', '|'}},
	{'l', []uint16{'1', '|', '7'}},
	{'o', []uint16{'0'}},
	{'s', []uint16{'$', '5'}},
	{'t', []uint16{'+', '7'}},
	{'x', []uint16{'%'}},
	{'z', []uint16{'2'}},
}

func relevantL33tSubtable(password []uint16) []l33tEntry {
	chars := map[uint16]bool{}
	for _, u := range password {
		chars[u] = true
	}
	var out []l33tEntry
	for _, e := range l33tTable {
		var subs []uint16
		for _, s := range e.subs {
			if chars[s] {
				subs = append(subs, s)
			}
		}
		if len(subs) > 0 {
			out = append(out, l33tEntry{e.letter, subs})
		}
	}
	return out
}

type l33tPair struct{ l33t, letter uint16 }

// enumerateL33tSubs mirrors matching.enumerate_l33t_subs.
func enumerateL33tSubs(table []l33tEntry) []map[uint16]uint16 {
	subs := [][]l33tPair{{}}
	dedup := func(subs [][]l33tPair) [][]l33tPair {
		var out [][]l33tPair
		seen := map[string]bool{}
		for _, sub := range subs {
			labels := make([]string, len(sub))
			for i, p := range sub {
				labels[i] = string(rune(p.l33t)) + "," + string(rune(p.letter)) + "," + strconv.Itoa(i)
			}
			sort.Strings(labels)
			label := ""
			for i, l := range labels {
				if i > 0 {
					label += "-"
				}
				label += l
			}
			if !seen[label] {
				seen[label] = true
				out = append(out, sub)
			}
		}
		return out
	}
	for _, e := range table {
		var next [][]l33tPair
		for _, l33tChr := range e.subs {
			for _, sub := range subs {
				dup := -1
				for i := range sub {
					if sub[i].l33t == l33tChr {
						dup = i
						break
					}
				}
				if dup == -1 {
					ext := append(append([]l33tPair{}, sub...), l33tPair{l33tChr, e.letter})
					next = append(next, ext)
				} else {
					alt := append([]l33tPair{}, sub[:dup]...)
					alt = append(alt, sub[dup+1:]...)
					alt = append(alt, l33tPair{l33tChr, e.letter})
					next = append(next, sub, alt)
				}
			}
		}
		subs = dedup(next)
	}
	out := make([]map[uint16]uint16, 0, len(subs))
	for _, sub := range subs {
		d := map[uint16]uint16{}
		for _, p := range sub {
			d[p.l33t] = p.letter
		}
		out = append(out, d)
	}
	return out
}

func (m *matcher) l33tMatch(password []uint16) []*Match {
	var matches []*Match
	for _, sub := range enumerateL33tSubs(relevantL33tSubtable(password)) {
		if len(sub) == 0 {
			break // corner case: password has no relevant subs
		}
		subbed := make([]uint16, len(password))
		for i, u := range password {
			if r, ok := sub[u]; ok {
				subbed[i] = r
			} else {
				subbed[i] = u
			}
		}
		for _, x := range m.dictionaryMatch(subbed) {
			token := password[x.I : x.J+1]
			if equalUnits(toLower(token), x.MatchedWord) {
				continue // only return the matches that contain an actual substitution
			}
			matchSub := map[uint16]uint16{}
			for subbedChr, chr := range sub {
				for _, u := range token {
					if u == subbedChr {
						matchSub[subbedChr] = chr
						break
					}
				}
			}
			x.L33t = true
			x.Token = token
			x.Sub = matchSub
			matches = append(matches, x)
		}
	}
	// filter single-character l33t matches to reduce noise
	out := matches[:0]
	for _, x := range matches {
		if len(x.Token) > 1 {
			out = append(out, x)
		}
	}
	return sorted(out)
}

// ---------- spatial ----------

// isShifted mirrors SHIFTED_RX: /[~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:"ZXCVBNM<>?]/.
func isShifted(u uint16) bool {
	return u < 0x80 && strings.IndexByte(`~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:"ZXCVBNM<>?`, byte(u)) >= 0
}

func spatialMatch(password []uint16) []*Match {
	var matches []*Match
	for _, name := range graphNames {
		matches = append(matches, spatialMatchHelper(password, graph(name), name)...)
	}
	return sorted(matches)
}

func spatialMatchHelper(password []uint16, g map[string][]string, name string) []*Match {
	var matches []*Match
	i := 0
	for i < len(password)-1 {
		j := i + 1
		lastDirection := -2 // null
		turns := 0
		shiftedCount := 0
		if (name == "qwerty" || name == "dvorak") && isShifted(password[i]) {
			shiftedCount = 1
		}
		for {
			prev := password[j-1]
			found := false
			foundDirection := -1
			curDirection := -1
			var adjacents []string
			if prev < 0x80 {
				adjacents = g[string(rune(prev))]
			}
			if j < len(password) {
				cur := password[j]
				for _, adj := range adjacents {
					curDirection++
					idx := -1
					if cur < 0x80 {
						for k := 0; k < len(adj); k++ {
							if uint16(adj[k]) == cur {
								idx = k
								break
							}
						}
					}
					if adj != "" && idx != -1 {
						found = true
						foundDirection = curDirection
						if idx == 1 {
							shiftedCount++
						}
						if lastDirection != foundDirection {
							turns++
							lastDirection = foundDirection
						}
						break
					}
				}
			}
			if found {
				j++
				continue
			}
			if j-i > 2 {
				matches = append(matches, &Match{
					Pattern: "spatial", I: i, J: j - 1, Token: password[i:j],
					Graph: name, Turns: turns, ShiftedCount: shiftedCount,
				})
			}
			i = j
			break
		}
	}
	return matches
}

// ---------- repeat ----------

// isLineTerminator reports the code units JavaScript's `.` does not match.
func isLineTerminator(u uint16) bool {
	return u == '\n' || u == '\r' || u == 0x2028 || u == 0x2029
}

// repeatAt finds the (.+)\1+ / (.+?)\1+ match starting exactly at s: the group length and the
// total match length, or 0, 0 when none matches there.
func repeatAt(p []uint16, s int, greedy bool) (groupLen, total int) {
	run := 0
	for s+run < len(p) && !isLineTerminator(p[s+run]) {
		run++
	}
	try := func(l int) int {
		if s+2*l > len(p) {
			return 0
		}
		reps := 0
		for pos := s + l; pos+l <= len(p) && equalUnits(p[pos:pos+l], p[s:s+l]); pos += l {
			reps++
		}
		return reps
	}
	if greedy {
		for l := run; l >= 1; l-- {
			if reps := try(l); reps > 0 {
				return l, l * (reps + 1)
			}
		}
	} else {
		for l := 1; l <= run; l++ {
			if reps := try(l); reps > 0 {
				return l, l * (reps + 1)
			}
		}
	}
	return 0, 0
}

func (m *matcher) repeatMatch(password []uint16) []*Match {
	var matches []*Match
	lastIndex := 0
	for lastIndex < len(password) {
		start := -1
		var gl, gt, ll, lt int
		for s := lastIndex; s < len(password); s++ {
			if gl, gt = repeatAt(password, s, true); gt > 0 {
				ll, lt = repeatAt(password, s, false)
				start = s
				break
			}
		}
		if start < 0 {
			break
		}
		var token, base []uint16
		if gt > lt {
			// greedy beats lazy for 'aabaab'; the greedy repeated string might itself be
			// repeated, so find its shortest repeated unit (^(.+?)\1+$).
			token = password[start : start+gt]
			for l := 1; l <= gl; l++ {
				if gt%l != 0 || gt/l < 2 {
					continue
				}
				ok := true
				for k := l; k < gt; k += l {
					if !equalUnits(token[k:k+l], token[:l]) {
						ok = false
						break
					}
				}
				if ok {
					base = token[:l]
					break
				}
			}
		} else {
			token = password[start : start+lt]
			base = token[:ll]
		}
		i, j := start, start+len(token)-1
		analysis := m.mostGuessableMatchSequence(base, m.omnimatch(base), false)
		matches = append(matches, &Match{
			Pattern: "repeat", I: i, J: j, Token: token, BaseToken: base,
			BaseGuesses: analysis.guesses, BaseMatches: analysis.sequence,
			RepeatCount: float64(len(token)) / float64(len(base)),
		})
		lastIndex = j + 1
	}
	return matches
}

// ---------- sequence ----------

const maxDelta = 5

func allUnits(s []uint16, f func(uint16) bool) bool {
	if len(s) == 0 {
		return false
	}
	for _, u := range s {
		if !f(u) {
			return false
		}
	}
	return true
}

func sequenceMatch(password []uint16) []*Match {
	if len(password) <= 1 {
		return nil
	}
	var result []*Match
	update := func(i, j, delta int) {
		ad := delta
		if ad < 0 {
			ad = -ad
		}
		if !(j-i > 1 || ad == 1) || !(0 < ad && ad <= maxDelta) {
			return
		}
		token := password[i : j+1]
		name, space := "unicode", 26
		switch {
		case allUnits(token, isLower):
			name = "lower"
		case allUnits(token, isUpper):
			name = "upper"
		case allUnits(token, isDigit):
			name, space = "digits", 10
		}
		result = append(result, &Match{
			Pattern: "sequence", I: i, J: j, Token: token,
			SequenceName: name, SequenceSpace: space, Ascending: delta > 0,
		})
	}
	i := 0
	lastDelta, hasLast := 0, false
	for k := 1; k < len(password); k++ {
		delta := int(password[k]) - int(password[k-1])
		if !hasLast {
			lastDelta, hasLast = delta, true
		}
		if delta == lastDelta {
			continue
		}
		j := k - 1
		update(i, j, lastDelta)
		i = j
		lastDelta = delta
	}
	update(i, len(password)-1, lastDelta)
	return result
}

// ---------- regex ----------

// regexMatch mirrors regex_match with REGEXEN = {recent_year: /19\d\d|200\d|201\d/g}.
func regexMatch(password []uint16) []*Match {
	var matches []*Match
	for p := 0; p+4 <= len(password); {
		t := password[p : p+4]
		if (t[0] == '1' && t[1] == '9' && isDigit(t[2]) && isDigit(t[3])) ||
			(t[0] == '2' && t[1] == '0' && (t[2] == '0' || t[2] == '1') && isDigit(t[3])) {
			matches = append(matches, &Match{
				Pattern: "regex", Token: t, I: p, J: p + 3, RegexName: "recent_year", RegexMatch: t,
			})
			p += 4
			continue
		}
		p++
	}
	return sorted(matches)
}

// ---------- date ----------

const (
	dateMaxYear = 2050
	dateMinYear = 1000
)

var dateSplits = map[int][][2]int{
	4: {{1, 2}, {2, 3}},
	5: {{1, 3}, {2, 3}},
	6: {{1, 2}, {2, 4}, {4, 5}},
	7: {{1, 3}, {2, 3}, {4, 5}, {4, 6}},
	8: {{2, 4}, {4, 6}},
}

func atoiUnits(s []uint16) int {
	n := 0
	for _, u := range s {
		n = n*10 + int(u-'0')
	}
	return n
}

// isJSSpace mirrors \s in JavaScript regular expressions.
func isJSSpace(u uint16) bool {
	switch u {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return 0x2000 <= u && u <= 0x200a
}

type dmy struct{ year, month, day int }

func (m *matcher) dateMatch(password []uint16) []*Match {
	var matches []*Match
	n := len(password)
	abs := func(x int) int {
		if x < 0 {
			return -x
		}
		return x
	}
	// dates without separators are between length 4 '1191' and 8 '11111991'
	for i := 0; i <= n-4; i++ {
		for j := i + 3; j <= i+7; j++ {
			if j >= n {
				break
			}
			token := password[i : j+1]
			if !allUnits(token, isDigit) {
				continue
			}
			var candidates []dmy
			for _, kl := range dateSplits[len(token)] {
				k, l := kl[0], kl[1]
				if d, ok := mapIntsToDMY([3]int{atoiUnits(token[:k]), atoiUnits(token[k:l]), atoiUnits(token[l:])}); ok {
					candidates = append(candidates, d)
				}
			}
			if len(candidates) == 0 {
				continue
			}
			best := candidates[0]
			minDistance := abs(candidates[0].year - m.referenceYear)
			for _, c := range candidates[1:] {
				if d := abs(c.year - m.referenceYear); d < minDistance {
					best, minDistance = c, d
				}
			}
			matches = append(matches, &Match{
				Pattern: "date", Token: token, I: i, J: j, Separator: []uint16{},
				Year: best.year, Month: best.month, Day: best.day,
			})
		}
	}
	// dates with separators are between length 6 '1/1/91' and 10 '11/11/1991'
	for i := 0; i <= n-6; i++ {
		for j := i + 5; j <= i+9; j++ {
			if j >= n {
				break
			}
			token := password[i : j+1]
			ints, sep, ok := parseSeparatedDate(token)
			if !ok {
				continue
			}
			d, ok := mapIntsToDMY(ints)
			if !ok {
				continue
			}
			matches = append(matches, &Match{
				Pattern: "date", Token: token, I: i, J: j, Separator: sep,
				Year: d.year, Month: d.month, Day: d.day,
			})
		}
	}
	// remove date matches that are strict substrings of others
	var out []*Match
	for a, x := range matches {
		sub := false
		for b, o := range matches {
			if a == b {
				continue
			}
			if o.I <= x.I && o.J >= x.J {
				sub = true
				break
			}
		}
		if !sub {
			out = append(out, x)
		}
	}
	return sorted(out)
}

// parseSeparatedDate mirrors /^(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})$/.
func parseSeparatedDate(t []uint16) ([3]int, []uint16, bool) {
	digitsAt := func(p int) int {
		n := 0
		for p+n < len(t) && isDigit(t[p+n]) {
			n++
		}
		return n
	}
	a := digitsAt(0)
	if a < 1 || a > 4 || a >= len(t) {
		return [3]int{}, nil, false
	}
	sep := t[a]
	if !(isJSSpace(sep) || sep == '/' || sep == '\\' || sep == '_' || sep == '.' || sep == '-') {
		return [3]int{}, nil, false
	}
	b := digitsAt(a + 1)
	if b < 1 || b > 2 || a+1+b >= len(t) || t[a+1+b] != sep {
		return [3]int{}, nil, false
	}
	c := digitsAt(a + 2 + b)
	if c < 1 || c > 4 || a+2+b+c != len(t) {
		return [3]int{}, nil, false
	}
	return [3]int{atoiUnits(t[:a]), atoiUnits(t[a+1 : a+1+b]), atoiUnits(t[a+2+b:])}, t[a : a+1], true
}

// mapIntsToDMY mirrors matching.map_ints_to_dmy.
func mapIntsToDMY(ints [3]int) (dmy, bool) {
	if ints[1] > 31 || ints[1] <= 0 {
		return dmy{}, false
	}
	over12, over31, under1 := 0, 0, 0
	for _, x := range ints {
		if (99 < x && x < dateMinYear) || x > dateMaxYear {
			return dmy{}, false
		}
		if x > 31 {
			over31++
		}
		if x > 12 {
			over12++
		}
		if x <= 0 {
			under1++
		}
	}
	if over31 >= 2 || over12 == 3 || under1 >= 2 {
		return dmy{}, false
	}
	splits := []struct {
		y    int
		rest [2]int
	}{
		{ints[2], [2]int{ints[0], ints[1]}}, // year last
		{ints[0], [2]int{ints[1], ints[2]}}, // year first
	}
	for _, s := range splits {
		if dateMinYear <= s.y && s.y <= dateMaxYear {
			if d, m, ok := mapIntsToDM(s.rest); ok {
				return dmy{s.y, m, d}, true
			}
			// a four-digit year whose remaining ints aren't a day and month is not a date
			return dmy{}, false
		}
	}
	for _, s := range splits {
		if d, m, ok := mapIntsToDM(s.rest); ok {
			return dmy{twoToFourDigitYear(s.y), m, d}, true
		}
	}
	return dmy{}, false
}

func mapIntsToDM(ints [2]int) (day, month int, ok bool) {
	for _, dm := range [][2]int{{ints[0], ints[1]}, {ints[1], ints[0]}} {
		if 1 <= dm[0] && dm[0] <= 31 && 1 <= dm[1] && dm[1] <= 12 {
			return dm[0], dm[1], true
		}
	}
	return 0, 0, false
}

func twoToFourDigitYear(y int) int {
	switch {
	case y > 99:
		return y
	case y > 50:
		return y + 1900
	}
	return y + 2000
}
