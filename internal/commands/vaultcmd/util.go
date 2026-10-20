package vaultcmd

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/vault"
)

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

// isGUID mirrors Utils.isGuid.
func isGUID(s string) bool { return guidRe.MatchString(s) }

// isNullOrWhitespace mirrors Utils.isNullOrWhitespace.
func isNullOrWhitespace(p *string) bool { return p == nil || strings.TrimSpace(*p) == "" }

// convertBooleanOption mirrors CliUtils.convertBooleanOption for a query parameter: a present
// parameter is true when empty or "true" (case-insensitive); an absent one is false.
func convertBooleanOption(q url.Values, name string) bool {
	vals, ok := q[name]
	if !ok {
		return false
	}
	v := ""
	if len(vals) > 0 {
		v = vals[0]
	}
	return v == "" || strings.ToLower(v) == "true"
}

// queryOption mirrors `passedOptions?.lower || passedOptions?.camel` (empty strings fall through).
func queryOption(q url.Values, names ...string) string {
	for _, n := range names {
		if v := q.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// defaultURIMatch mirrors DomainSettingsService.resolvedDefaultUriMatchStrategy$ for the CLI:
// `policySettingValue || userSettingValue`, where the user setting is the CLI default (Domain,
// returned as nil) and the policy value comes from the first enforced UriMatchDefaults policy.
func defaultURIMatch(v *vault.Vault) *vault.UriMatch {
	policies := vault.PoliciesByType(v.Policies(), v.Organizations(), vault.PolicyUriMatchDefaults)
	if len(policies) == 0 {
		return nil
	}
	p := policies[0]
	if !p.Enabled || len(p.Data) == 0 || string(p.Data) == "null" {
		return nil
	}
	var data struct {
		URIMatchDetection any `json:"uriMatchDetection"`
	}
	if json.Unmarshal(p.Data, &data) != nil {
		var s string
		if json.Unmarshal(p.Data, &s) != nil || json.Unmarshal([]byte(s), &data) != nil {
			return nil
		}
	}
	// Only valid (numeric) UriMatchStrategy values; 0 (Domain) is falsy and falls back to the
	// user setting.
	n, ok := data.URIMatchDetection.(float64)
	if !ok || n != float64(int(n)) || n < 1 || n > float64(vault.UriMatchNever) {
		return nil
	}
	m := vault.UriMatch(n)
	return &m
}
