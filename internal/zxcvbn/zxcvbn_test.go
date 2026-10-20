package zxcvbn

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// testdata/zxcvbn-4.4.2.json holds results of the JavaScript zxcvbn 4.4.2 package (the version
// pinned by bitwarden/clients) with scoring.REFERENCE_YEAR pinned to 2026: hand-written cases and
// generated ASCII, l33t, date, keyboard, repeat and non-ASCII (UTF-16 surrogate) passwords.
func TestMatchesJavaScriptZxcvbn(t *testing.T) {
	old := referenceYear
	referenceYear = 2026
	t.Cleanup(func() { referenceYear = old })

	b, err := os.ReadFile("testdata/zxcvbn-4.4.2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Pw           string   `json:"pw"`
		Inputs       []string `json:"inputs"`
		Score        int      `json:"score"`
		GuessesLog10 float64  `json:"guesses_log10"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 1000 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		got := PasswordStrength(v.Pw, v.Inputs)
		if got.Score != v.Score || math.Abs(got.GuessesLog10-v.GuessesLog10) > 1e-9 {
			t.Errorf("%q %v: got score %d log10 %.12f, want %d %.12f", v.Pw, v.Inputs, got.Score, got.GuessesLog10, v.Score, v.GuessesLog10)
		}
	}
}

func TestKnownScores(t *testing.T) {
	old := referenceYear
	referenceYear = 2026
	t.Cleanup(func() { referenceYear = old })

	// values from zxcvbn 4.4.2 under Node.js
	cases := []struct {
		pw      string
		inputs  []string
		score   int
		guesses float64
	}{
		{"password", nil, 0, 3},
		{"zxcvbn", nil, 0, 58},
		{"correcthorsebatterystaple", nil, 4, 273500327700640},
		{"Tr0ub4dour&3", nil, 2, 19058000},
		{"bitwarden", []string{"bitwarden", "bit", "warden"}, 0, 2},
		{"bitwarden", nil, 2, 1312210},
		{"İstanbul", nil, 2, 100000001},   // toLowerCase grows the string: no dictionary match
		{"King", nil, 0, 30},              // KELVIN SIGN lower-cases to ASCII k
		{"😀😀", nil, 0, 203},               // repeat of a surrogate pair (2 code units)
		{"ПАРОЛЬПАРОЛЬ", nil, 2, 2000003}, // repeat, 6 code units per half
	}
	for _, c := range cases {
		r := PasswordStrength(c.pw, c.inputs)
		if r.Score != c.score || r.Guesses != c.guesses {
			t.Errorf("%q: score %d guesses %v, want %d %v", c.pw, r.Score, r.Guesses, c.score, c.guesses)
		}
	}
}
