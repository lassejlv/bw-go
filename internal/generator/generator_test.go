package generator

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/lassejlv/bw-go/internal/wordlist"
)

func countIn(s, set string) int {
	n := 0
	for _, c := range s {
		if strings.ContainsRune(set, c) {
			n++
		}
	}
	return n
}

func TestUniformRange(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 2000; i++ {
		v, err := Uniform(3, 7)
		if err != nil {
			t.Fatal(err)
		}
		if v < 3 || v > 7 {
			t.Fatalf("out of range: %d", v)
		}
		seen[v] = true
	}
	if len(seen) != 5 {
		t.Fatalf("expected all values 3..7, got %v", seen)
	}
	if v, _ := Uniform(4, 4); v != 4 {
		t.Fatalf("Uniform(4,4) = %d", v)
	}
	if _, err := Uniform(5, 4); err == nil {
		t.Fatal("expected error for max < min")
	}
}

func TestGeneratePasswordDefaults(t *testing.T) {
	for i := 0; i < 200; i++ {
		p, err := GeneratePassword(DefaultPasswordOptions())
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 14 {
			t.Fatalf("len %d", len(p))
		}
		if countIn(p, UppercaseFull) < 1 || countIn(p, LowercaseFull) < 1 || countIn(p, DigitsFull) < 1 {
			t.Fatalf("missing required class in %q", p)
		}
		if countIn(p, SpecialCharacters) != 0 {
			t.Fatalf("unexpected special in %q", p)
		}
	}
}

func TestGeneratePasswordMinimums(t *testing.T) {
	o := PasswordOptions{Length: 20, Ambiguous: true, Uppercase: true, MinUppercase: 1,
		Lowercase: true, MinLowercase: 1, Number: true, MinNumber: 5, Special: true, MinSpecial: 4}
	for i := 0; i < 200; i++ {
		p, err := GeneratePassword(o)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 20 {
			t.Fatalf("len %d", len(p))
		}
		if countIn(p, DigitsFull) < 5 || countIn(p, SpecialCharacters) < 4 ||
			countIn(p, UppercaseFull) < 1 || countIn(p, LowercaseFull) < 1 {
			t.Fatalf("minimums not met in %q", p)
		}
	}
}

func TestGeneratePasswordOnlyEnabledClasses(t *testing.T) {
	o := PasswordOptions{Length: 30, Ambiguous: true, Special: true}
	p, err := GeneratePassword(o)
	if err != nil {
		t.Fatal(err)
	}
	if countIn(p, SpecialCharacters) != 30 {
		t.Fatalf("expected only specials: %q", p)
	}
	o = PasswordOptions{Length: 30, Ambiguous: true, Lowercase: true, MinLowercase: 1}
	p, _ = GeneratePassword(o)
	if countIn(p, LowercaseFull) != 30 {
		t.Fatalf("expected only lowercase: %q", p)
	}
}

func TestGeneratePasswordAvoidAmbiguous(t *testing.T) {
	o := DefaultPasswordOptions()
	o.Ambiguous = false
	o.Length = 128
	for i := 0; i < 50; i++ {
		p, _ := GeneratePassword(o)
		if strings.ContainsAny(p, "IOl10") {
			t.Fatalf("ambiguous character in %q", p)
		}
	}
}

func TestGeneratePasswordRequiredExceedsLength(t *testing.T) {
	// Character classes win over the length (optionsToRandomAsciiRequest).
	o := PasswordOptions{Length: 5, Ambiguous: true, Number: true, MinNumber: 9}
	p, _ := GeneratePassword(o)
	if len(p) != 9 || countIn(p, DigitsFull) != 9 {
		t.Fatalf("got %q", p)
	}
}

func TestGeneratePasswordNoSets(t *testing.T) {
	if _, err := GeneratePassword(PasswordOptions{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := GeneratePassword(PasswordOptions{Length: 5}); err == nil {
		t.Fatal("expected error when no class is enabled")
	}
}

func TestGeneratePassphrase(t *testing.T) {
	words := map[string]bool{}
	for _, w := range wordlist.EFFLongWordList {
		words[w] = true
	}
	p, err := GeneratePassphrase(DefaultPassphraseOptions())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(p, "-")
	if len(parts) != 6 {
		t.Fatalf("expected 6 words: %q", p)
	}
	for _, w := range parts {
		if !words[w] {
			t.Fatalf("not a list word: %q", w)
		}
	}

	p, _ = GeneratePassphrase(PassphraseOptions{NumWords: 1, WordSeparator: " "})
	if n := len(strings.Split(p, " ")); n != MinNumWords {
		t.Fatalf("expected minimum %d words, got %d (%q)", MinNumWords, n, p)
	}

	p, _ = GeneratePassphrase(PassphraseOptions{NumWords: 5, WordSeparator: ""})
	if strings.ContainsAny(p, " _") || len(p) < 5*3 {
		t.Fatalf("unexpected separator: %q", p)
	}

	for i := 0; i < 50; i++ {
		p, _ = GeneratePassphrase(PassphraseOptions{NumWords: 4, WordSeparator: "_", Capitalize: true, IncludeNumber: true})
		parts = strings.Split(p, "_")
		if len(parts) != 4 {
			t.Fatalf("expected 4 words: %q", p)
		}
		digits := 0
		for _, w := range parts {
			if !unicode.IsUpper(rune(w[0])) {
				t.Fatalf("not capitalized: %q", w)
			}
			last := w[len(w)-1]
			if last >= '0' && last <= '9' {
				digits++
				w = w[:len(w)-1]
			}
			if !words[strings.ToLower(w[:1])+w[1:]] {
				t.Fatalf("not a list word: %q", w)
			}
		}
		if digits != 1 {
			t.Fatalf("expected exactly one number: %q", p)
		}
	}
}

func TestPasswordPolicyEnforce(t *testing.T) {
	// No policy: boundaries still apply.
	var none PasswordGeneratorPolicy
	o := none.Enforce(PasswordOptions{Length: 500, Lowercase: true, MinNumber: 20, Special: true})
	if o.Length != MaxPasswordLength || o.MinNumber != MaxMinDigits || !o.Number {
		t.Fatalf("boundaries not applied: %+v", o)
	}
	if o.MinSpecial != 1 || o.MinLowercase != 1 || o.MinUppercase != 0 {
		t.Fatalf("cascade not applied: %+v", o)
	}

	p := PasswordGeneratorPolicy{MinLength: 30, UseUppercase: true, UseSpecial: true, SpecialCount: 3, NumberCount: 2}
	o = p.Enforce(PasswordOptions{Length: 10, Lowercase: true})
	if o.Length != 30 || !o.Uppercase || !o.Special || o.MinSpecial != 3 {
		t.Fatalf("policy not applied: %+v", o)
	}
	// Upstream: numberCount without useNumbers does not enable digits unless requested.
	if o.Number || o.MinNumber != 0 {
		t.Fatalf("unexpected number cascade: %+v", o)
	}
	if o = p.Enforce(PasswordOptions{Length: 10, Number: true}); o.MinNumber != 2 {
		t.Fatalf("numberCount not applied: %+v", o)
	}
	if !p.InEffect() || none.InEffect() {
		t.Fatal("InEffect mismatch")
	}
}

func TestPassphrasePolicyEnforce(t *testing.T) {
	p := PassphraseGeneratorPolicy{MinNumberWords: 8, Capitalize: true}
	o := p.Enforce(PassphraseOptions{NumWords: 4, WordSeparator: "ab"})
	if o.NumWords != 8 || !o.Capitalize || o.IncludeNumber || o.WordSeparator != "a" {
		t.Fatalf("got %+v", o)
	}
	var none PassphraseGeneratorPolicy
	if o := none.Enforce(PassphraseOptions{NumWords: 50}); o.NumWords != MaxNumWords {
		t.Fatalf("got %+v", o)
	}
}

func TestCombineAndFilterPolicies(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"Id":"1","OrganizationId":"o1","Type":2,"Enabled":true,"Data":{"minLength":20,"useUpper":true,"minNumbers":3,"overridePasswordType":"passphrase","minNumberWords":5}}`),
		json.RawMessage(`{"id":"2","organizationId":"o2","type":2,"enabled":true,"data":{"minLength":12,"useSpecial":true,"minSpecial":2,"overridePasswordType":"password","capitalize":true}}`),
		json.RawMessage(`{"id":"3","organizationId":"o1","type":2,"enabled":false,"data":{"minLength":99}}`),
		json.RawMessage(`{"id":"4","organizationId":"o1","type":1,"enabled":true,"data":{"minLength":99}}`),
		json.RawMessage(`{"id":"5","organizationId":"o3","type":2,"enabled":true,"data":{"minLength":77}}`),
	}
	profile := json.RawMessage(`{"organizations":[
		{"id":"o1","status":2,"enabled":true,"usePolicies":true},
		{"id":"o2","status":1,"enabled":true,"usePolicies":true},
		{"id":"o3","status":0,"enabled":true,"usePolicies":true}]}`)
	pols := PoliciesFromState(raw, profile)
	if len(pols) != 3 {
		t.Fatalf("expected 3 applicable policies, got %d", len(pols))
	}
	g := CombinePolicies(pols)
	want := PasswordGeneratorPolicy{MinLength: 20, UseUppercase: true, NumberCount: 3, UseSpecial: true, SpecialCount: 2}
	if g.Password != want {
		t.Fatalf("password policy %+v", g.Password)
	}
	if g.Passphrase != (PassphraseGeneratorPolicy{MinNumberWords: 5, Capitalize: true}) {
		t.Fatalf("passphrase policy %+v", g.Passphrase)
	}
	if g.OverridePasswordType != "password" || g.ResolveType("passphrase") != "password" {
		t.Fatalf("override %q", g.OverridePasswordType)
	}
	if (GeneratorPolicy{}).ResolveType("passphrase") != "passphrase" {
		t.Fatal("ResolveType without policy")
	}
	// Without a stored profile, organization filtering is skipped.
	if n := len(PoliciesFromState(raw, nil)); n != 4 {
		t.Fatalf("expected 4 enabled policies without profile, got %d", n)
	}
}
