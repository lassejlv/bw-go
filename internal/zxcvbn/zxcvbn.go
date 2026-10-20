// Package zxcvbn is a port of zxcvbn 4.4.2 (https://github.com/dropbox/zxcvbn, the version the
// Bitwarden clients use for password strength). Matching and scoring follow the CoffeeScript
// source (src/matching.coffee, src/scoring.coffee) and run on UTF-16 code units, like the
// JavaScript original, so lengths, sequences and repeats of non-ASCII passwords score the same.
// The frequency lists and keyboard graphs come from github.com/trustelem/zxcvbn, which carries
// the 4.4.2 data (one mis-escaped password list entry is corrected here).
//
// Feedback messages and crack time displays are not ported.
package zxcvbn

import (
	"math"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/trustelem/zxcvbn/adjacency"
	"github.com/trustelem/zxcvbn/frequency"
)

// Result mirrors the parts of the zxcvbn result used by the Bitwarden clients.
type Result struct {
	Guesses      float64
	GuessesLog10 float64
	// Score is 0 (too guessable) to 4 (very unguessable).
	Score    int
	Sequence []*Match
}

// PasswordStrength mirrors zxcvbn(password, user_inputs).
func PasswordStrength(password string, userInputs []string) Result {
	return PasswordStrengthUTF16(utf16.Encode([]rune(password)), userInputs)
}

// PasswordStrengthUTF16 is PasswordStrength for a password given as JavaScript string code units.
func PasswordStrengthUTF16(password []uint16, userInputs []string) Result {
	// zxcvbn lower-cases the user inputs and ranks them by position (later duplicates win).
	inputs := make(rankedDict, len(userInputs))
	maxLen := 0
	for i, in := range userInputs {
		lower := toLower(utf16.Encode([]rune(in)))
		inputs[key(lower)] = i + 1
		if len(lower) > maxLen {
			maxLen = len(lower)
		}
	}
	dicts := append([]dictionary{}, rankedDictionaries()...)
	dicts = append(dicts, dictionary{name: "user_inputs", ranks: inputs, maxLen: maxLen})
	m := &matcher{dicts: dicts, referenceYear: referenceYear}
	matches := m.omnimatch(password)
	r := m.mostGuessableMatchSequence(password, matches, false)
	return Result{
		Guesses:      r.guesses,
		GuessesLog10: log10(r.guesses),
		Score:        guessesToScore(r.guesses),
		Sequence:     r.sequence,
	}
}

// guessesToScore mirrors time_estimates.guesses_to_score.
func guessesToScore(guesses float64) int {
	const delta = 5
	switch {
	case guesses < 1e3+delta:
		return 0
	case guesses < 1e6+delta:
		return 1
	case guesses < 1e8+delta:
		return 2
	case guesses < 1e10+delta:
		return 3
	}
	return 4
}

// referenceYear mirrors scoring.REFERENCE_YEAR (the current year when the module loads).
var referenceYear = time.Now().Year()

type rankedDict map[string]int

type dictionary struct {
	name   string
	ranks  rankedDict
	maxLen int // longest word, in code units (only an optimization)
}

var (
	dictsOnce sync.Once
	dicts     []dictionary
)

// rankedDictionaries mirrors RANKED_DICTIONARIES, in frequency_lists order.
func rankedDictionaries() []dictionary {
	dictsOnce.Do(func() {
		for _, name := range []string{"passwords", "english_wikipedia", "female_names", "surnames", "us_tv_and_film", "male_names"} {
			d := dictionary{name: name, ranks: rankedDict{}}
			for i, w := range frequency.FrequencyLists[name] {
				if name == "passwords" && w == `pic\'s` {
					w = "pic's" // mis-escaped in the trustelem data
				}
				d.ranks[w] = i + 1
				if n := len(utf16.Encode([]rune(w))); n > d.maxLen {
					d.maxLen = n
				}
			}
			dicts = append(dicts, d)
		}
	})
	return dicts
}

// key converts code units to a map key. Dictionary words are ASCII, so lone surrogates (which
// decode to U+FFFD) can never produce a false match.
func key(units []uint16) string {
	ascii := true
	for _, u := range units {
		if u >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		b := make([]byte, len(units))
		for i, u := range units {
			b[i] = byte(u)
		}
		return string(b)
	}
	return string(utf16.Decode(units))
}

// ToLower mirrors String.prototype.toLowerCase.
func ToLower(s string) string {
	return string(utf16.Decode(toLower(utf16.Encode([]rune(s)))))
}

// toLower mirrors String.prototype.toLowerCase on code units (full case mapping for U+0130,
// simple mapping otherwise).
func toLower(s []uint16) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); i++ {
		u := s[i]
		if u < 0x80 {
			if 'A' <= u && u <= 'Z' {
				u += 'a' - 'A'
			}
			out = append(out, u)
			continue
		}
		if utf16.IsSurrogate(rune(u)) && i+1 < len(s) {
			if r := utf16.DecodeRune(rune(u), rune(s[i+1])); r != unicode.ReplacementChar {
				out = utf16.AppendRune(out, unicode.ToLower(r))
				i++
				continue
			}
		}
		if utf16.IsSurrogate(rune(u)) {
			out = append(out, u)
			continue
		}
		if u == 0x130 { // LATIN CAPITAL LETTER I WITH DOT ABOVE -> i + COMBINING DOT ABOVE
			out = append(out, 'i', 0x307)
			continue
		}
		out = utf16.AppendRune(out, unicode.ToLower(rune(u)))
	}
	return out
}

func equalUnits(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// slice mirrors String.prototype.slice(start, end) for non-negative arguments.
func slice(s []uint16, start, end int) []uint16 {
	if end > len(s) {
		end = len(s)
	}
	if start > end {
		return nil
	}
	return s[start:end]
}

func log10(n float64) float64 { return math.Log(n) / math.Log(10) }

func isDigit(u uint16) bool { return '0' <= u && u <= '9' }
func isUpper(u uint16) bool { return 'A' <= u && u <= 'Z' }
func isLower(u uint16) bool { return 'a' <= u && u <= 'z' }

// graphNames mirrors the keys of GRAPHS.
var graphNames = []string{"qwerty", "dvorak", "keypad", "mac_keypad"}

func graph(name string) map[string][]string { return adjacency.Graphs[name].Graph }
