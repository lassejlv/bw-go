package vaultcmd

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/events"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ListOptions mirrors the Options class of list.command.ts. Empty strings mean "not given"
// (upstream normalises "" to undefined with `||`).
type ListOptions struct {
	OrganizationID string
	CollectionID   string
	FolderID       string
	Search         string
	URL            string
	Trash          bool
	Archived       bool
}

// ListOptionsFromQuery builds options from `serve` query parameters (ctx.request.query).
func ListOptionsFromQuery(q url.Values) ListOptions {
	return ListOptions{
		OrganizationID: queryOption(q, "organizationid", "organizationId"),
		CollectionID:   queryOption(q, "collectionid", "collectionId"),
		FolderID:       queryOption(q, "folderid", "folderId"),
		Search:         q.Get("search"),
		URL:            q.Get("url"),
		Trash:          convertBooleanOption(q, "trash"),
		Archived:       convertBooleanOption(q, "archived"),
	}
}

// List mirrors ListCommand.run.
func List(a *app.App, object string, opts ListOptions) *cli.Response {
	switch strings.ToLower(object) {
	case "items":
		return listCiphers(a, opts)
	case "folders":
		return listFolders(a, opts)
	case "collections":
		return listCollections(a, opts)
	case "org-collections":
		return listOrganizationCollections(a, opts)
	case "org-members":
		return listOrganizationMembers(a, opts)
	case "organizations":
		return listOrganizations(a, opts)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

func hasSearch(s string) bool { return strings.TrimSpace(s) != "" }

func listCiphers(a *app.App, opts ListOptions) *cli.Response {
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	// cipherArchiveService.userCanArchive$: premium from any source.
	userCanArchive := v.HasPremium()
	opts.Archived = userCanArchive && opts.Archived

	var ciphers []*vault.CipherView
	if hasSearch(opts.URL) {
		ciphers = v.CiphersForURL(opts.URL, defaultURIMatch(v))
	} else {
		ciphers = v.Ciphers()
	}

	if opts.FolderID != "" || opts.CollectionID != "" || opts.OrganizationID != "" {
		ciphers = filterCiphers(ciphers, func(c *vault.CipherView) bool {
			if !matchesStateOptions(c, opts) {
				return false
			}
			// Combining multiple filters performs a logical OR operation.
			if opts.FolderID != "" {
				if opts.FolderID == "notnull" && c.FolderID != nil {
					return true
				}
				if opts.FolderID == "null" {
					if c.FolderID == nil {
						return true
					}
				} else if c.FolderID != nil && *c.FolderID == opts.FolderID {
					return true
				}
			}
			if opts.OrganizationID != "" {
				if opts.OrganizationID == "notnull" && c.OrganizationID != nil {
					return true
				}
				if opts.OrganizationID == "null" {
					if c.OrganizationID == nil {
						return true
					}
				} else if c.OrganizationID != nil && *c.OrganizationID == opts.OrganizationID {
					return true
				}
			}
			if opts.CollectionID != "" {
				if opts.CollectionID == "notnull" && len(c.CollectionIDs) > 0 {
					return true
				}
				if opts.CollectionID == "null" {
					if len(c.CollectionIDs) == 0 {
						return true
					}
				} else {
					for _, id := range c.CollectionIDs {
						if id == opts.CollectionID {
							return true
						}
					}
				}
			}
			return false
		})
	} else if !hasSearch(opts.Search) {
		ciphers = filterCiphers(ciphers, func(c *vault.CipherView) bool { return matchesStateOptions(c, opts) })
	}

	if hasSearch(opts.Search) {
		// Combining search with a filter performs a logical AND operation.
		ciphers = filterCiphers(ciphers, func(c *vault.CipherView) bool { return matchesStateOptions(c, opts) })
		ciphers = vault.SearchCiphersBasic(ciphers, opts.Search)
	}

	ciphers = v.FilterRestrictedCiphers(ciphers)

	events.CollectMany(a, v, events.CipherClientViewed, ciphers, true)

	out := make([]*vault.CipherResponse, 0, len(ciphers))
	for _, c := range ciphers {
		out = append(out, vault.NewCipherResponse(c))
	}
	return cli.Success(cli.NewList(out))
}

// matchesStateOptions mirrors ListCommand.matchesStateOptions.
func matchesStateOptions(c *vault.CipherView, opts ListOptions) bool {
	return opts.Trash == c.IsDeleted() && opts.Archived == c.IsArchived()
}

func filterCiphers(in []*vault.CipherView, keep func(*vault.CipherView) bool) []*vault.CipherView {
	out := []*vault.CipherView{}
	for _, c := range in {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}

func listFolders(a *app.App, opts ListOptions) *cli.Response {
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	folders := v.Folders()
	if hasSearch(opts.Search) {
		folders = vault.SearchFolders(folders, opts.Search)
	}
	out := make([]*vault.FolderResponse, 0, len(folders))
	for _, f := range folders {
		out = append(out, vault.NewFolderResponse(f))
	}
	return cli.Success(cli.NewList(out))
}

func collectionList(cols []*vault.CollectionView) *cli.ListResponse {
	out := make([]*vault.CollectionResponse, 0, len(cols))
	for _, c := range cols {
		out = append(out, vault.NewCollectionResponse(c))
	}
	return cli.NewList(out)
}

func listCollections(a *app.App, opts ListOptions) *cli.Response {
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	collections := v.Collections()
	if opts.OrganizationID != "" {
		filtered := []*vault.CollectionView{}
		for _, c := range collections {
			if c.OrganizationID == opts.OrganizationID {
				filtered = append(filtered, c)
			}
		}
		collections = filtered
	}
	if hasSearch(opts.Search) {
		collections = vault.SearchCollections(collections, opts.Search)
	}
	return cli.Success(collectionList(collections))
}

// validateOrganizationID performs the `organizationid` checks shared by org-collections and
// org-members.
func validateOrganizationID(orgID string) *cli.Response {
	if orgID == "" {
		return cli.BadRequest("`organizationid` option is required.")
	}
	if !isGUID(orgID) {
		return cli.BadRequest("`" + orgID + "` is not a GUID.")
	}
	return nil
}

// findOrganization mirrors organizationService.organizations$(userId).find(o => o.id == id).
func findOrganization(a *app.App, orgID string) (*vault.Vault, *vault.Organization, *cli.Response) {
	if acct := a.ActiveAccount(); acct == nil || acct.UserID == "" {
		return nil, nil, cli.BadRequest("No user found.")
	}
	v, err := vault.Load(a)
	if err != nil {
		return nil, nil, cli.Error(err)
	}
	org := v.Organization(orgID)
	if org == nil {
		return nil, nil, cli.Error("Organization not found.")
	}
	return v, org, nil
}

func listOrganizationCollections(a *app.App, opts ListOptions) *cli.Response {
	if r := validateOrganizationID(opts.OrganizationID); r != nil {
		return r
	}
	v, org, r := findOrganization(a, opts.OrganizationID)
	if r != nil {
		return r
	}

	path := "/collections" // apiService.getUserCollections
	if org.CanViewAllCollections() {
		path = "/organizations/" + opts.OrganizationID + "/collections" // apiService.getCollections
	}
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := a.API.Get(path, &resp); err != nil {
		return cli.Error(err)
	}
	collections := []*vault.CollectionView{}
	for _, raw := range resp.Data {
		var head struct {
			OrganizationID string `json:"organizationId"`
		}
		if json.Unmarshal(raw, &head) != nil || head.OrganizationID != opts.OrganizationID {
			continue
		}
		// Collection.fromCollectionData(new CollectionData(r)) + collectionService.decryptMany$:
		// undecryptable names become "[error: cannot decrypt]".
		c, err := v.DecryptCollectionRaw(raw)
		if err != nil {
			return cli.Error(err)
		}
		collections = append(collections, c)
	}
	vault.SortCollections(collections)
	if hasSearch(opts.Search) {
		collections = vault.SearchCollections(collections, opts.Search)
	}
	return cli.Success(collectionList(collections))
}

func listOrganizationMembers(a *app.App, opts ListOptions) *cli.Response {
	if r := validateOrganizationID(opts.OrganizationID); r != nil {
		return r
	}
	if _, _, r := findOrganization(a, opts.OrganizationID); r != nil {
		return r
	}
	// organizationUserApiService.getAllUsers(orgId) without options: an empty URLSearchParams
	// still leaves the trailing "?".
	var resp struct {
		Data []struct {
			ID               string                       `json:"id"`
			Email            string                       `json:"email"`
			Name             *string                      `json:"name"`
			Status           vault.OrganizationUserStatus `json:"status"`
			Type             vault.OrganizationUserType   `json:"type"`
			TwoFactorEnabled bool                         `json:"twoFactorEnabled"`
		} `json:"data"`
	}
	if err := a.API.Get("/organizations/"+opts.OrganizationID+"/users?", &resp); err != nil {
		return cli.Error(err)
	}
	out := make([]*vault.OrganizationUserResponse, 0, len(resp.Data))
	for _, u := range resp.Data {
		out = append(out, vault.NewOrganizationUserResponse(u.ID, u.Email, u.Name, u.Status, u.Type, u.TwoFactorEnabled))
	}
	return cli.Success(cli.NewList(out))
}

func listOrganizations(a *app.App, opts ListOptions) *cli.Response {
	if acct := a.ActiveAccount(); acct == nil || acct.UserID == "" {
		return cli.BadRequest("No user found.")
	}
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	orgs := v.MemberOrganizations()
	if hasSearch(opts.Search) {
		orgs = vault.SearchOrganizations(orgs, opts.Search)
	}
	out := make([]*vault.OrganizationResponse, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, vault.NewOrganizationResponse(o))
	}
	return cli.Success(cli.NewList(out))
}
