package vault

import (
	"encoding/json"
)

// policyExemptRoles mirrors the SDK policy definitions' exempt roles (default Owner/Admin;
// providers are always exempt and Accepted/Confirmed members are always subject).
func policyExemptRoles(t PolicyType) []OrganizationUserType {
	switch t {
	case PolicyAutomaticAppLogIn, PolicyAutomaticUserConfirmation, PolicyFillAssist,
		PolicyFreeFamiliesSponsorship, PolicyMasterPassword, PolicyOrganizationUserNotification,
		PolicyPasswordGenerator, PolicyRemoveUnlockWithPin, PolicyRestrictedItemTypes:
		return nil
	case PolicyMaximumVaultTimeout:
		return []OrganizationUserType{OrgUserOwner}
	}
	return []OrganizationUserType{OrgUserOwner, OrgUserAdmin}
}

// policyEnforced mirrors PolicyView::into_enforced for one policy: enabled, and (when the user
// has a context for the organization) org enabled, usePolicies, status Accepted/Confirmed, role
// not exempt, and not a provider user.
func policyEnforced(p *Policy, org *Organization) bool {
	if !p.Enabled {
		return false
	}
	if org == nil {
		return true // no context: err on the side of enforcement
	}
	if !org.Enabled || !org.UsePolicies {
		return false
	}
	if org.Status != OrgUserStatusAccepted && org.Status != OrgUserStatusConfirmed {
		return false
	}
	for _, r := range policyExemptRoles(p.Type) {
		if org.Type == r {
			return false
		}
	}
	return !org.IsProviderUser
}

// PoliciesByType mirrors PolicyService.policiesByType$: enforced policies of the given type.
func PoliciesByType(policies []*Policy, orgs []*Organization, t PolicyType) []*Policy {
	byID := map[string]*Organization{}
	for _, o := range orgs {
		byID[o.ID] = o
	}
	out := []*Policy{}
	for _, p := range policies {
		if p.Type == t && policyEnforced(p, byID[p.OrganizationID]) {
			out = append(out, p)
		}
	}
	return out
}

// PolicyAppliesToUser mirrors PolicyService.policyAppliesToUser$.
func PolicyAppliesToUser(policies []*Policy, orgs []*Organization, t PolicyType) bool {
	return len(PoliciesByType(policies, orgs, t)) > 0
}

// RestrictedCipherType mirrors RestrictedCipherType.
type RestrictedCipherType struct {
	CipherType      CipherType
	AllowViewOrgIDs []string
}

// restrictedTypesOf returns policy data as cipher types, defaulting to [Card].
func restrictedTypesOf(p *Policy) []CipherType {
	var types []CipherType
	if len(p.Data) > 0 && string(p.Data) != "null" {
		if json.Unmarshal(p.Data, &types) == nil {
			return types
		}
		// data may also arrive as a JSON string containing the array
		var s string
		if json.Unmarshal(p.Data, &s) == nil && json.Unmarshal([]byte(s), &types) == nil {
			return types
		}
	}
	return []CipherType{CipherTypeCard}
}

// RestrictedTypes mirrors RestrictedItemTypesService.restricted$.
func RestrictedTypes(policies []*Policy, orgs []*Organization) []RestrictedCipherType {
	enabled := PoliciesByType(policies, orgs, PolicyRestrictedItemTypes)
	var all []CipherType
	seen := map[CipherType]bool{}
	for _, p := range enabled {
		for _, t := range restrictedTypesOf(p) {
			if !seen[t] {
				seen[t] = true
				all = append(all, t)
			}
		}
	}
	out := []RestrictedCipherType{}
	for _, t := range all {
		r := RestrictedCipherType{CipherType: t, AllowViewOrgIDs: []string{}}
		for _, o := range orgs {
			var orgPolicy *Policy
			for _, p := range enabled {
				if p.OrganizationID == o.ID {
					orgPolicy = p
					break
				}
			}
			allowed := orgPolicy == nil
			if !allowed {
				allowed = true
				for _, rt := range restrictedTypesOf(orgPolicy) {
					if rt == t {
						allowed = false
						break
					}
				}
			}
			if allowed {
				r.AllowViewOrgIDs = append(r.AllowViewOrgIDs, o.ID)
			}
		}
		out = append(out, r)
	}
	return out
}

// IsCipherRestricted mirrors RestrictedItemTypesService.isCipherRestricted.
func IsCipherRestricted(cipherType CipherType, organizationID *string, restrictions []RestrictedCipherType) bool {
	for _, r := range restrictions {
		if r.CipherType != cipherType {
			continue
		}
		if organizationID != nil && *organizationID != "" {
			for _, id := range r.AllowViewOrgIDs {
				if id == *organizationID {
					return false
				}
			}
			return true
		}
		return true
	}
	return false
}

// FilterRestrictedCiphers mirrors CliRestrictedItemTypesService.filterRestrictedCiphers.
func FilterRestrictedCiphers(ciphers []*CipherView, restrictions []RestrictedCipherType) []*CipherView {
	out := []*CipherView{}
	for _, c := range ciphers {
		if !IsCipherRestricted(c.Type, c.OrganizationID, restrictions) {
			out = append(out, c)
		}
	}
	return out
}
