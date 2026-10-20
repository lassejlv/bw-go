// Package generator ports Bitwarden's password and passphrase generation
// (libs/tools/generator/core: PasswordRandomizer, the password/passphrase strategies, their
// defaults, boundaries and policy evaluators).
package generator

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/lassejlv/bw-go/internal/wordlist"
)

// Character sets (engine/data.ts Ascii.Full and Ascii.Unmistakable).
const (
	UppercaseFull = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	LowercaseFull = "abcdefghijklmnopqrstuvwxyz"
	DigitsFull    = "0123456789"

	UppercaseUnmistakable = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	LowercaseUnmistakable = "abcdefghijkmnopqrstuvwxyz"
	DigitsUnmistakable    = "23456789"

	SpecialCharacters = "!@#$%^&*"
)

// Boundaries (data/default-password-boundaries.ts, data/default-passphrase-boundaries.ts).
const (
	MinPasswordLength       = 5
	MaxPasswordLength       = 128
	MaxMinDigits            = 9
	MaxMinSpecialCharacters = 9
	MinNumWords             = 3
	MaxNumWords             = 20
)

// PasswordOptions mirror PasswordGenerationOptions. A character class contributes its Min* count
// of required characters only when it is enabled; the remaining length is drawn from the union of
// all enabled classes.
type PasswordOptions struct {
	Length int
	// Ambiguous allows characters with ambiguous glyphs (I, l, 1, O, 0, ...). Upstream semantics:
	// true = include them. The CLI's `--ambiguous` flag ("Avoid ambiguous characters") sets false.
	Ambiguous    bool
	Uppercase    bool
	MinUppercase int
	Lowercase    bool
	MinLowercase int
	Number       bool
	MinNumber    int
	Special      bool
	MinSpecial   int
}

// PassphraseOptions mirror PassphraseGenerationOptions.
type PassphraseOptions struct {
	NumWords      int
	WordSeparator string
	Capitalize    bool
	IncludeNumber bool
}

// DefaultPasswordOptions returns DefaultPasswordGenerationOptions.
func DefaultPasswordOptions() PasswordOptions {
	return PasswordOptions{
		Length:       14,
		Ambiguous:    true,
		Uppercase:    true,
		MinUppercase: 1,
		Lowercase:    true,
		MinLowercase: 1,
		Number:       true,
		MinNumber:    1,
		Special:      false,
		MinSpecial:   0,
	}
}

// DefaultPassphraseOptions returns DefaultPassphraseGenerationOptions.
func DefaultPassphraseOptions() PassphraseOptions {
	return PassphraseOptions{NumWords: 6, WordSeparator: "-", Capitalize: false, IncludeNumber: false}
}

// randReader is the entropy source; tests may replace it.
var randReader io.Reader = rand.Reader

// Uniform returns a uniformly distributed integer in [min, max] (inclusive) from crypto/rand.
// crypto/rand.Int uses rejection sampling, so the result is unbiased.
func Uniform(min, max int) (int, error) {
	if max < min {
		return 0, errors.New("max must be greater than or equal to min")
	}
	if max == min {
		return min, nil
	}
	n, err := rand.Int(randReader, big.NewInt(int64(max-min)+1))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func pick[T any](list []T) (T, error) {
	var zero T
	if len(list) == 0 {
		return zero, errors.New("list must have at least one entry.")
	}
	i, err := Uniform(0, len(list)-1)
	if err != nil {
		return zero, err
	}
	return list[i], nil
}

// shuffle is an in-place Fisher-Yates shuffle (SdkRandomizer.shuffle).
func shuffle[T any](items []T) error {
	if len(items) == 0 {
		return errors.New("items must have at least one entry.")
	}
	for i := len(items) - 1; i > 0; i-- {
		j, err := Uniform(0, i)
		if err != nil {
			return err
		}
		items[i], items[j] = items[j], items[i]
	}
	return nil
}

// asciiRequest is RandomAsciiRequest; a nil class pointer means the class is disabled.
type asciiRequest struct {
	all                                   int
	uppercase, lowercase, digits, special *int
	ambiguous                             bool
}

// optionsToRandomAsciiRequest (util.ts).
func optionsToRandomAsciiRequest(o PasswordOptions) asciiRequest {
	class := func(enabled bool, quantity int) *int {
		if !enabled {
			return nil
		}
		q := quantity
		return &q
	}
	r := asciiRequest{
		uppercase: class(o.Uppercase, o.MinUppercase),
		lowercase: class(o.Lowercase, o.MinLowercase),
		digits:    class(o.Number, o.MinNumber),
		special:   class(o.Special, o.MinSpecial),
		ambiguous: o.Ambiguous,
	}
	required := 0
	for _, p := range []*int{r.uppercase, r.lowercase, r.digits, r.special} {
		if p != nil {
			required += *p
		}
	}
	r.all = max(o.Length-required, 0)
	return r
}

// toASCIISets expands a request into one character set per generated character.
func toASCIISets(r asciiRequest) []string {
	upper, lower, digit := UppercaseUnmistakable, LowercaseUnmistakable, DigitsUnmistakable
	if r.ambiguous {
		upper, lower, digit = UppercaseFull, LowercaseFull, DigitsFull
	}
	var parts []string
	all := ""
	add := func(count *int, set string) {
		if count == nil {
			return
		}
		for i := 0; i < *count; i++ {
			parts = append(parts, set)
		}
		all += set
	}
	add(r.uppercase, upper)
	add(r.lowercase, lower)
	add(r.digits, digit)
	add(r.special, SpecialCharacters)
	for i := 0; i < r.all; i++ {
		parts = append(parts, all)
	}
	return parts
}

// GeneratePassword creates a random password (PasswordRandomizer.randomAscii). Required
// characters for each enabled class are placed at random positions; the rest are drawn from the
// union of the enabled classes. Options are used as given; call
// PasswordGeneratorPolicy.Enforce first to apply boundaries and policy.
func GeneratePassword(o PasswordOptions) (string, error) {
	sets := toASCIISets(optionsToRandomAsciiRequest(o))
	if err := shuffle(sets); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, set := range sets {
		c, err := pick([]byte(set))
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

// GeneratePassphrase creates a passphrase from the EFF long word list
// (PasswordRandomizer.randomEffLongWords). At least MinNumWords words are generated.
func GeneratePassphrase(o PassphraseOptions) (string, error) {
	n := max(o.NumWords, MinNumWords)
	lucky := -1
	if o.IncludeNumber {
		var err error
		if lucky, err = Uniform(0, n-1); err != nil {
			return "", err
		}
	}
	words := make([]string, n)
	for i := range words {
		w, err := pick(wordlist.EFFLongWordList)
		if err != nil {
			return "", err
		}
		if o.Capitalize && w != "" {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		if i == lucky {
			d, err := Uniform(0, 9)
			if err != nil {
				return "", err
			}
			w += strconv.Itoa(d)
		}
		words[i] = w
	}
	return strings.Join(words, o.WordSeparator), nil
}
