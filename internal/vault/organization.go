package vault

// Organization mirrors the Organization domain model built from sync data
// (OrganizationData with isMember / isProviderUser).
type Organization struct {
	ProfileOrganization
	IsMember       bool
	IsProviderUser bool
}

// BuildOrganizations mirrors DefaultSyncService.syncProfileOrganizations: member organizations
// first (isMember), then provider organizations not already present (isProviderUser).
func BuildOrganizations(p *Profile) []*Organization {
	if p == nil {
		return nil
	}
	var out []*Organization
	byID := map[string]*Organization{}
	for _, o := range p.MemberOrganizations() {
		org := &Organization{ProfileOrganization: o, IsMember: true}
		if existing, ok := byID[o.ID]; ok {
			*existing = *org
			continue
		}
		byID[o.ID] = org
		out = append(out, org)
	}
	for _, o := range p.ProviderOrganizations {
		if existing, ok := byID[o.ID]; ok {
			existing.IsProviderUser = true
			continue
		}
		org := &Organization{ProfileOrganization: o, IsProviderUser: true}
		byID[o.ID] = org
		out = append(out, org)
	}
	return out
}

// CanAccess mirrors Organization.canAccess.
func (o *Organization) CanAccess() bool {
	if o.IsOwner() {
		return true
	}
	return o.Enabled && o.Status == OrgUserStatusConfirmed
}

// IsAdmin mirrors Organization.isAdmin.
func (o *Organization) IsAdmin() bool { return o.Type == OrgUserAdmin || o.IsOwner() }

// IsOwner mirrors Organization.isOwner.
func (o *Organization) IsOwner() bool { return o.Type == OrgUserOwner || o.IsProviderUser }

// CanAccessImport mirrors Organization.canAccessImport.
func (o *Organization) CanAccessImport() bool {
	return o.IsProviderUser || o.Type == OrgUserOwner || o.Type == OrgUserAdmin || o.Permissions.AccessImportExport
}

// CanAccessExport mirrors Organization.canAccessExport.
func (o *Organization) CanAccessExport() bool {
	return o.IsMember && (o.Type == OrgUserOwner || o.Type == OrgUserAdmin || o.Permissions.AccessImportExport)
}

// CanCreateNewCollections mirrors Organization.canCreateNewCollections.
func (o *Organization) CanCreateNewCollections() bool {
	return !o.LimitCollectionCreation || o.IsAdmin() || o.Permissions.CreateNewCollections
}

// CanEditAnyCollection mirrors Organization.canEditAnyCollection.
func (o *Organization) CanEditAnyCollection() bool {
	return o.IsProviderUser || (o.Type == OrgUserCustom && o.Permissions.EditAnyCollection) ||
		(o.AllowAdminAccessToAllCollectionItems && o.IsAdmin())
}

// CanEditUnmanagedCollections mirrors Organization.canEditUnmanagedCollections.
func (o *Organization) CanEditUnmanagedCollections() bool {
	return o.IsAdmin() || o.Permissions.EditAnyCollection
}

// CanEditUnassignedCiphers mirrors Organization.canEditUnassignedCiphers.
func (o *Organization) CanEditUnassignedCiphers() bool {
	return o.Type == OrgUserAdmin || o.Type == OrgUserOwner || o.Permissions.EditAnyCollection
}

// CanEditAllCiphers mirrors Organization.canEditAllCiphers.
func (o *Organization) CanEditAllCiphers() bool {
	return (o.Type == OrgUserCustom && o.Permissions.EditAnyCollection) ||
		(o.AllowAdminAccessToAllCollectionItems && (o.Type == OrgUserAdmin || o.Type == OrgUserOwner))
}

// CanDeleteAnyCollection mirrors Organization.canDeleteAnyCollection.
func (o *Organization) CanDeleteAnyCollection() bool {
	if o.IsProviderUser || o.Permissions.DeleteAnyCollection {
		return true
	}
	if o.AllowAdminAccessToAllCollectionItems {
		return o.Type == OrgUserOwner || o.Type == OrgUserAdmin
	}
	return false
}

// CanViewAllCollections mirrors Organization.canViewAllCollections.
func (o *Organization) CanViewAllCollections() bool {
	return o.IsAdmin() || o.Permissions.EditAnyCollection || o.Permissions.DeleteAnyCollection
}

// CanManageUsers mirrors Organization.canManageUsers.
func (o *Organization) CanManageUsers() bool { return o.IsAdmin() || o.Permissions.ManageUsers }

// CanManageGroups mirrors Organization.canManageGroups.
func (o *Organization) CanManageGroups() bool {
	return (o.IsAdmin() || o.Permissions.ManageGroups) && o.UseGroups
}

// CanManagePolicies mirrors Organization.canManagePolicies.
func (o *Organization) CanManagePolicies() bool {
	return (o.IsAdmin() || o.Permissions.ManagePolicies) && o.UsePolicies
}

// IsExemptFromPolicies mirrors Organization.isExemptFromPolicies.
func (o *Organization) IsExemptFromPolicies() bool { return o.CanManagePolicies() }

// HasProvider mirrors Organization.hasProvider.
func (o *Organization) HasProvider() bool { return o.ProviderID != nil || o.ProviderName != nil }

// IsFreeOrg mirrors Organization.isFreeOrg.
func (o *Organization) IsFreeOrg() bool { return !o.UseTotp }
