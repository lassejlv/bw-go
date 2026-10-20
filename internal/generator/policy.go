package generator

import (
	"encoding/json"
)

// PolicyTypePasswordGenerator is PolicyType.PasswordGenerator.
const PolicyTypePasswordGenerator = 2

// Organization user status (OrganizationUserStatusType).
const (
	orgUserStatusAccepted = 1
)

// PasswordGeneratorPolicy is the combined password policy (PasswordGeneratorPolicy type);
// the zero value is the disabled policy.
type PasswordGeneratorPolicy struct {
	MinLength    int
	UseUppercase bool
	UseLowercase bool
	UseNumbers   bool
	NumberCount  int
	UseSpecial   bool
	SpecialCount int
}

// PassphraseGeneratorPolicy is the combined passphrase policy; the zero value is disabled.
type PassphraseGeneratorPolicy struct {
	MinNumberWords int
	Capitalize     bool
	IncludeNumber  bool
}

// GeneratorPolicy combines all password generator policies that apply to a user.
type GeneratorPolicy struct {
	Password   PasswordGeneratorPolicy
	Passphrase PassphraseGeneratorPolicy
	// OverridePasswordType is "", "password" or "passphrase" (GeneratorNavigationPolicy).
	OverridePasswordType string
}

// Policy is a policy as returned by the server's sync/policies endpoints.
type Policy struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Type           int             `json:"type"`
	Data           json.RawMessage `json:"data"`
	Enabled        bool            `json:"enabled"`
}

type policyData struct {
	MinLength            *int   `json:"minLength"`
	UseUpper             bool   `json:"useUpper"`
	UseLower             bool   `json:"useLower"`
	UseNumbers           bool   `json:"useNumbers"`
	MinNumbers           *int   `json:"minNumbers"`
	UseSpecial           bool   `json:"useSpecial"`
	MinSpecial           *int   `json:"minSpecial"`
	MinNumberWords       *int   `json:"minNumberWords"`
	Capitalize           bool   `json:"capitalize"`
	IncludeNumber        bool   `json:"includeNumber"`
	OverridePasswordType string `json:"overridePasswordType"`
}

func decodePolicyData(raw json.RawMessage) policyData {
	var d policyData
	if len(raw) == 0 {
		return d
	}
	// Data is normally an object, but tolerate a JSON encoded string.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		raw = json.RawMessage(s)
	}
	_ = json.Unmarshal(raw, &d)
	return d
}

func maxPtr(acc int, v *int) int {
	if v == nil {
		return acc
	}
	return max(acc, *v)
}

// CombinePolicies reduces policies into the most restrictive generator policy
// (passwordLeastPrivilege, passphraseLeastPrivilege and preferPassword). Policies that are not
// enabled password generator policies are ignored.
func CombinePolicies(policies []Policy) GeneratorPolicy {
	var g GeneratorPolicy
	for _, p := range policies {
		if p.Type != PolicyTypePasswordGenerator || !p.Enabled {
			continue
		}
		d := decodePolicyData(p.Data)
		g.Password = PasswordGeneratorPolicy{
			MinLength:    maxPtr(g.Password.MinLength, d.MinLength),
			UseUppercase: d.UseUpper || g.Password.UseUppercase,
			UseLowercase: d.UseLower || g.Password.UseLowercase,
			UseNumbers:   d.UseNumbers || g.Password.UseNumbers,
			NumberCount:  maxPtr(g.Password.NumberCount, d.MinNumbers),
			UseSpecial:   d.UseSpecial || g.Password.UseSpecial,
			SpecialCount: maxPtr(g.Password.SpecialCount, d.MinSpecial),
		}
		g.Passphrase = PassphraseGeneratorPolicy{
			MinNumberWords: maxPtr(g.Passphrase.MinNumberWords, d.MinNumberWords),
			Capitalize:     d.Capitalize || g.Passphrase.Capitalize,
			IncludeNumber:  d.IncludeNumber || g.Passphrase.IncludeNumber,
		}
		if g.OverridePasswordType != "password" && d.OverridePasswordType != "" {
			g.OverridePasswordType = d.OverridePasswordType
		}
	}
	return g
}

type profileOrganization struct {
	ID          string `json:"id"`
	Status      int    `json:"status"`
	Enabled     bool   `json:"enabled"`
	UsePolicies bool   `json:"usePolicies"`
}

// PoliciesFromState decodes stored raw server policies and keeps those that apply to the user:
// enabled policies of organizations (from the stored sync profile) that the user has accepted or
// confirmed membership of and that are enabled and use policies. Password generator policies
// apply to every member, including owners and admins. When no profile is stored, organization
// filtering is skipped.
func PoliciesFromState(raw []json.RawMessage, profile json.RawMessage) []Policy {
	var orgs map[string]profileOrganization
	if len(profile) > 0 {
		var p struct {
			Organizations []profileOrganization `json:"organizations"`
		}
		if json.Unmarshal(profile, &p) == nil {
			orgs = map[string]profileOrganization{}
			for _, o := range p.Organizations {
				orgs[o.ID] = o
			}
		}
	}
	var out []Policy
	for _, r := range raw {
		var p Policy
		if json.Unmarshal(r, &p) != nil || !p.Enabled {
			continue
		}
		if orgs != nil {
			o, ok := orgs[p.OrganizationID]
			if !ok || o.Status < orgUserStatusAccepted || !o.Enabled || !o.UsePolicies {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

type boundary struct{ min, max int }

func newBoundary(value int, def boundary) boundary {
	return boundary{min: max(def.min, value), max: max(def.max, value)}
}

func fitToBounds(value int, b boundary) int {
	return max(min(value, b.max), b.min)
}

// InEffect reports whether the password policy changes anything
// (PasswordGeneratorOptionsEvaluator.policyInEffect).
func (p PasswordGeneratorPolicy) InEffect() bool {
	return p.UseUppercase || p.UseLowercase || p.UseNumbers || p.UseSpecial ||
		p.MinLength > MinPasswordLength || p.NumberCount > 0 || p.SpecialCount > 0
}

func (p PasswordGeneratorPolicy) bounds() (length, minDigits, minSpecial boundary) {
	minDigits = newBoundary(p.NumberCount, boundary{0, MaxMinDigits})
	minSpecial = newBoundary(p.SpecialCount, boundary{0, MaxMinSpecialCharacters})
	minPolicyLength := MinPasswordLength
	if p.MinLength > 0 {
		minPolicyLength = p.MinLength
	}
	minLength := max(minPolicyLength, minDigits.min+minSpecial.min, MinPasswordLength)
	length = boundary{min: minLength, max: max(MaxPasswordLength, minLength)}
	return
}

// ApplyPolicy applies policy overrides and boundaries
// (PasswordGeneratorOptionsEvaluator.applyPolicy).
func (p PasswordGeneratorPolicy) ApplyPolicy(o PasswordOptions) PasswordOptions {
	length, minDigits, minSpecial := p.bounds()
	o.Uppercase = p.UseUppercase || o.Uppercase
	o.Lowercase = p.UseLowercase || o.Lowercase
	o.Number = p.UseNumbers || o.Number || o.MinNumber > 0
	o.Special = p.UseSpecial || o.Special || o.MinSpecial > 0
	o.Length = fitToBounds(o.Length, length)
	o.MinNumber = fitToBounds(o.MinNumber, minDigits)
	o.MinSpecial = fitToBounds(o.MinSpecial, minSpecial)
	return o
}

// Sanitize makes the options internally consistent (PasswordGeneratorOptionsEvaluator.sanitize):
// enabled classes require at least one character, disabled classes none, and the length is at
// least the sum of the minimums.
func (p PasswordGeneratorPolicy) Sanitize(o PasswordOptions) PasswordOptions {
	length, _, _ := p.bounds()
	cascade := func(enabled bool, value int) int {
		if !enabled {
			return 0
		}
		if value == 0 {
			return 1
		}
		return value
	}
	o.MinLowercase = cascade(o.Lowercase, o.MinLowercase)
	o.MinUppercase = cascade(o.Uppercase, o.MinUppercase)
	o.MinNumber = cascade(o.Number, o.MinNumber)
	o.MinSpecial = cascade(o.Special, o.MinSpecial)
	minLength := max(o.MinLowercase+o.MinUppercase+o.MinNumber+o.MinSpecial, length.min)
	o.Length = max(o.Length, minLength)
	return o
}

// Enforce applies the policy then sanitizes (DefaultGeneratorService.enforcePolicy).
func (p PasswordGeneratorPolicy) Enforce(o PasswordOptions) PasswordOptions {
	return p.Sanitize(p.ApplyPolicy(o))
}

// InEffect reports whether the passphrase policy changes anything.
func (p PassphraseGeneratorPolicy) InEffect() bool {
	return p.Capitalize || p.IncludeNumber || p.MinNumberWords > MinNumWords
}

// ApplyPolicy applies policy overrides and word count boundaries
// (PassphraseGeneratorOptionsEvaluator.applyPolicy).
func (p PassphraseGeneratorPolicy) ApplyPolicy(o PassphraseOptions) PassphraseOptions {
	b := newBoundary(p.MinNumberWords, boundary{MinNumWords, MaxNumWords})
	o.Capitalize = p.Capitalize || o.Capitalize
	o.IncludeNumber = p.IncludeNumber || o.IncludeNumber
	o.NumWords = fitToBounds(o.NumWords, b)
	return o
}

// Sanitize limits the separator to a single character or the empty string
// (PassphraseGeneratorOptionsEvaluator.sanitize).
func (p PassphraseGeneratorPolicy) Sanitize(o PassphraseOptions) PassphraseOptions {
	o.WordSeparator = FirstChar(o.WordSeparator)
	return o
}

// Enforce applies the policy then sanitizes.
func (p PassphraseGeneratorPolicy) Enforce(o PassphraseOptions) PassphraseOptions {
	return p.Sanitize(p.ApplyPolicy(o))
}

// FirstChar returns the first character (rune) of s, or "" for an empty string.
func FirstChar(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

// ResolveType applies the navigation policy to the requested generator type ("password" or
// "passphrase") (GeneratorNavigationEvaluator.applyPolicy + sanitize).
func (g GeneratorPolicy) ResolveType(requested string) string {
	if g.OverridePasswordType == "password" || g.OverridePasswordType == "passphrase" {
		return g.OverridePasswordType
	}
	if requested == "" {
		return "password"
	}
	return requested
}
