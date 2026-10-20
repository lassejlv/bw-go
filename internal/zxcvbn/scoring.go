package zxcvbn

import (
	"math"
	"sort"
	"sync"
)

const (
	bruteforceCardinality           = 10
	minGuessesBeforeGrowingSequence = 10000
	minSubmatchGuessesSingleChar    = 10
	minSubmatchGuessesMultiChar     = 50
	minYearSpace                    = 20
)

// nCk mirrors scoring.nCk (floating point, like JavaScript).
func nCk(n, k int) float64 {
	if k > n {
		return 0
	}
	if k == 0 {
		return 1
	}
	r := 1.0
	fn := float64(n)
	for d := 1; d <= k; d++ {
		r *= fn
		r /= float64(d)
		fn--
	}
	return r
}

func factorial(n int) float64 {
	if n < 2 {
		return 1
	}
	f := 1.0
	for i := 2; i <= n; i++ {
		f *= float64(i)
	}
	return f
}

type sequenceResult struct {
	guesses  float64
	sequence []*Match
}

type optimalEntry struct {
	m  *Match
	pi float64
	g  float64
}

// sortedLengths returns the keys of an optimal.* object in JavaScript iteration order
// (integer keys ascending).
func sortedLengths(o map[int]*optimalEntry) []int {
	ls := make([]int, 0, len(o))
	for l := range o {
		ls = append(ls, l)
	}
	sort.Ints(ls)
	return ls
}

// mostGuessableMatchSequence mirrors scoring.most_guessable_match_sequence.
func (m *matcher) mostGuessableMatchSequence(password []uint16, matches []*Match, excludeAdditive bool) sequenceResult {
	n := len(password)
	matchesByJ := make([][]*Match, n)
	for _, x := range matches {
		matchesByJ[x.J] = append(matchesByJ[x.J], x)
	}
	for _, lst := range matchesByJ {
		sort.SliceStable(lst, func(a, b int) bool { return lst[a].I < lst[b].I })
	}
	optimal := make([]map[int]*optimalEntry, n)
	for k := range optimal {
		optimal[k] = map[int]*optimalEntry{}
	}

	update := func(x *Match, l int) {
		k := x.J
		pi := m.estimateGuesses(x, password)
		if l > 1 {
			pi *= optimal[x.I-1][l-1].pi
		}
		g := factorial(l) * pi
		if !excludeAdditive {
			g += math.Pow(minGuessesBeforeGrowingSequence, float64(l-1))
		}
		for competingL, competing := range optimal[k] {
			if competingL > l {
				continue
			}
			if competing.g <= g {
				return
			}
		}
		optimal[k][l] = &optimalEntry{m: x, pi: pi, g: g}
	}

	makeBruteforce := func(i, j int) *Match {
		return &Match{Pattern: "bruteforce", Token: password[i : j+1], I: i, J: j}
	}

	bruteforceUpdate := func(k int) {
		update(makeBruteforce(0, k), 1)
		for i := 1; i <= k; i++ {
			x := makeBruteforce(i, k)
			for _, l := range sortedLengths(optimal[i-1]) {
				if optimal[i-1][l].m.Pattern == "bruteforce" {
					continue
				}
				update(x, l+1)
			}
		}
	}

	unwind := func(n int) []*Match {
		var seq []*Match
		k := n - 1
		l := 0
		g := math.Inf(1)
		for _, cl := range sortedLengths(optimal[k]) {
			if cg := optimal[k][cl].g; cg < g {
				l, g = cl, cg
			}
		}
		for k >= 0 {
			x := optimal[k][l].m
			seq = append([]*Match{x}, seq...)
			k = x.I - 1
			l--
		}
		return seq
	}

	for k := 0; k < n; k++ {
		for _, x := range matchesByJ[k] {
			if x.I > 0 {
				for _, l := range sortedLengths(optimal[x.I-1]) {
					update(x, l+1)
				}
			} else {
				update(x, 1)
			}
		}
		bruteforceUpdate(k)
	}
	if n == 0 {
		return sequenceResult{guesses: 1, sequence: []*Match{}}
	}
	seq := unwind(n)
	return sequenceResult{guesses: optimal[n-1][len(seq)].g, sequence: seq}
}

// estimateGuesses mirrors scoring.estimate_guesses.
func (m *matcher) estimateGuesses(x *Match, password []uint16) float64 {
	if x.hasGuesses {
		return x.Guesses
	}
	minGuesses := 1.0
	if len(x.Token) < len(password) {
		if len(x.Token) == 1 {
			minGuesses = minSubmatchGuessesSingleChar
		} else {
			minGuesses = minSubmatchGuessesMultiChar
		}
	}
	var guesses float64
	switch x.Pattern {
	case "bruteforce":
		guesses = bruteforceGuesses(x)
	case "dictionary":
		guesses = dictionaryGuesses(x)
	case "spatial":
		guesses = spatialGuesses(x)
	case "repeat":
		guesses = x.BaseGuesses * x.RepeatCount
	case "sequence":
		guesses = sequenceGuesses(x)
	case "regex":
		guesses = m.regexGuesses(x)
	case "date":
		guesses = m.dateGuesses(x)
	}
	x.Guesses = math.Max(guesses, minGuesses)
	x.GuessesLog10 = log10(x.Guesses)
	x.hasGuesses = true
	return x.Guesses
}

func bruteforceGuesses(x *Match) float64 {
	guesses := math.Pow(bruteforceCardinality, float64(len(x.Token)))
	if math.IsInf(guesses, 1) {
		guesses = math.MaxFloat64
	}
	minGuesses := float64(minSubmatchGuessesMultiChar + 1)
	if len(x.Token) == 1 {
		minGuesses = minSubmatchGuessesSingleChar + 1
	}
	return math.Max(guesses, minGuesses)
}

func sequenceGuesses(x *Match) float64 {
	var base float64
	switch first := x.Token[0]; {
	case first == 'a' || first == 'A' || first == 'z' || first == 'Z' || first == '0' || first == '1' || first == '9':
		base = 4
	case isDigit(first):
		base = 10
	default:
		base = 26
	}
	if !x.Ascending {
		base *= 2
	}
	return base * float64(len(x.Token))
}

func (m *matcher) regexGuesses(x *Match) float64 {
	// only recent_year is used by zxcvbn's REGEXEN
	yearSpace := math.Abs(float64(atoiUnits(x.RegexMatch) - m.referenceYear))
	return math.Max(yearSpace, minYearSpace)
}

func (m *matcher) dateGuesses(x *Match) float64 {
	yearSpace := math.Max(math.Abs(float64(x.Year-m.referenceYear)), minYearSpace)
	guesses := yearSpace * 365
	if len(x.Separator) > 0 {
		guesses *= 4
	}
	return guesses
}

var (
	graphStatsOnce                             sync.Once
	keyboardAverageDegree, keypadAverageDegree float64
	keyboardStartingPositions                  float64
	keypadStartingPositions                    float64
)

func graphStats() {
	graphStatsOnce.Do(func() {
		avg := func(g map[string][]string) float64 {
			total := 0
			for _, neighbors := range g {
				for _, n := range neighbors {
					if n != "" {
						total++
					}
				}
			}
			return float64(total) / float64(len(g))
		}
		keyboardAverageDegree = avg(graph("qwerty"))
		keypadAverageDegree = avg(graph("keypad"))
		keyboardStartingPositions = float64(len(graph("qwerty")))
		keypadStartingPositions = float64(len(graph("keypad")))
	})
}

func spatialGuesses(x *Match) float64 {
	graphStats()
	s, d := keypadStartingPositions, keypadAverageDegree
	if x.Graph == "qwerty" || x.Graph == "dvorak" {
		s, d = keyboardStartingPositions, keyboardAverageDegree
	}
	guesses := 0.0
	L := len(x.Token)
	t := x.Turns
	for i := 2; i <= L; i++ {
		possibleTurns := min(t, i-1)
		for j := 1; j <= possibleTurns; j++ {
			guesses += nCk(i-1, j-1) * s * math.Pow(d, float64(j))
		}
	}
	if x.ShiftedCount != 0 {
		S := x.ShiftedCount
		U := len(x.Token) - x.ShiftedCount
		if S == 0 || U == 0 {
			guesses *= 2
		} else {
			variations := 0.0
			for i := 1; i <= min(S, U); i++ {
				variations += nCk(S+U, i)
			}
			guesses *= variations
		}
	}
	return guesses
}

func dictionaryGuesses(x *Match) float64 {
	reversed := 1.0
	if x.Reversed {
		reversed = 2
	}
	return float64(x.Rank) * uppercaseVariations(x) * l33tVariations(x) * reversed
}

func uppercaseVariations(x *Match) float64 {
	w := x.Token
	noUpper := !anyUnit(w, isUpper)
	if (len(w) > 0 && noUpper) || equalUnits(toLower(w), w) {
		return 1
	}
	// START_UPPER /^[A-Z][^A-Z]+$/, END_UPPER /^[^A-Z]+[A-Z]$/, ALL_UPPER /^[^a-z]+$/
	if len(w) >= 2 && isUpper(w[0]) && !anyUnit(w[1:], isUpper) {
		return 2
	}
	if len(w) >= 2 && isUpper(w[len(w)-1]) && !anyUnit(w[:len(w)-1], isUpper) {
		return 2
	}
	if len(w) > 0 && !anyUnit(w, isLower) {
		return 2
	}
	U, L := 0, 0
	for _, u := range w {
		if isUpper(u) {
			U++
		}
		if isLower(u) {
			L++
		}
	}
	variations := 0.0
	for i := 1; i <= min(U, L); i++ {
		variations += nCk(U+L, i)
	}
	return variations
}

func l33tVariations(x *Match) float64 {
	if !x.L33t {
		return 1
	}
	variations := 1.0
	chrs := toLower(x.Token)
	for subbed, unsubbed := range x.Sub {
		S, U := 0, 0
		for _, c := range chrs {
			if c == subbed {
				S++
			}
			if c == unsubbed {
				U++
			}
		}
		if S == 0 || U == 0 {
			variations *= 2
		} else {
			p := min(U, S)
			possibilities := 0.0
			for i := 1; i <= p; i++ {
				possibilities += nCk(U+S, i)
			}
			variations *= possibilities
		}
	}
	return variations
}

func anyUnit(s []uint16, f func(uint16) bool) bool {
	for _, u := range s {
		if f(u) {
			return true
		}
	}
	return false
}
