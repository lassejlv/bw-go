package vaultcmd

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/events"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/vault"
)

// GetOptions mirrors the Options class of get.command.ts. Empty strings mean "not given".
type GetOptions struct {
	ItemID         string
	OrganizationID string
	Output         string
}

// GetOptionsFromQuery builds options from `serve` query parameters (ctx.request.query).
func GetOptionsFromQuery(q url.Values) GetOptions {
	return GetOptions{
		OrganizationID: queryOption(q, "organizationid", "organizationId"),
		ItemID:         queryOption(q, "itemid", "itemId"),
		Output:         q.Get("output"),
	}
}

// NewItemTypesEnabled reports FeatureFlag.PM32009NewItemTypes (bank account, driver's license
// and passport templates) from the server config; it is a variable so tests can override it.
var NewItemTypesEnabled = func(a *app.App) bool { return features.Enabled(a, features.NewItemTypes) }

const restrictedMessage = "Access to this item type is restricted by organizational policy."

// Get mirrors GetCommand.run. Note that, like upstream, "send" passes the object validation of
// `bw get` but is not handled here ("Unknown object."); `serve` routes it to the send package.
func Get(a *app.App, object, id string, opts GetOptions) *cli.Response {
	id = strings.ToLower(id)
	switch strings.ToLower(object) {
	case "item":
		return withVault(a, func(v *vault.Vault) *cli.Response {
			r, _ := getCipher(a, v, id, nil)
			return r
		})
	case "username":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getUsername(a, v, id) })
	case "password":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getPassword(a, v, id) })
	case "uri":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getURI(a, v, id) })
	case "totp":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getTotp(a, v, id) })
	case "notes":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getNotes(a, v, id) })
	case "exposed":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getExposed(a, v, id) })
	case "attachment":
		return getAttachment(a, id, opts)
	case "folder":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getFolder(v, id) })
	case "collection":
		return withVault(a, func(v *vault.Vault) *cli.Response { return getCollection(v, id) })
	case "org-collection":
		return getOrganizationCollection(a, id, opts)
	case "organization":
		return getOrganization(a, id)
	case "template":
		return getTemplate(a, id)
	case "fingerprint":
		return getFingerprint(a, id)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

func withVault(a *app.App, fn func(v *vault.Vault) *cli.Response) *cli.Response {
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	return fn(v)
}

// getCipherView mirrors GetCommand.getCipherView: a GUID is looked up directly (deleted and
// archived items included); anything else is a basic search over active items. More than one
// match is returned as multi.
func getCipherView(v *vault.Vault, id string) (single *vault.CipherView, multi []*vault.CipherView, err error) {
	if isGUID(id) {
		c, err := v.Cipher(id)
		if errors.Is(err, vault.ErrNotFound) {
			return nil, nil, nil
		}
		return c, nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, nil, nil
	}
	ciphers := filterCiphers(v.Ciphers(), func(c *vault.CipherView) bool { return !c.IsDeleted() && !c.IsArchived() })
	ciphers = vault.SearchCiphersBasic(ciphers, id)
	if len(ciphers) > 1 {
		return nil, ciphers, nil
	}
	if len(ciphers) > 0 {
		return ciphers[0], nil, nil
	}
	return nil, nil, nil
}

// getCipher mirrors GetCommand.getCipher. On success it also returns the cipher response.
func getCipher(a *app.App, v *vault.Vault, id string, filter func(c *vault.CipherView) bool) (*cli.Response, *vault.CipherResponse) {
	single, multi, err := getCipherView(v, id)
	if err != nil {
		return cli.Error(err), nil
	}
	if single == nil && multi == nil {
		return cli.NotFound(), nil
	}
	if multi != nil {
		multi = v.FilterRestrictedCiphers(multi)
		if len(multi) == 0 {
			return cli.Error(restrictedMessage), nil
		}
		if filter != nil {
			multi = filterCiphers(multi, filter)
		}
		if len(multi) == 0 {
			return cli.NotFound(), nil
		}
		if len(multi) > 1 {
			ids := make([]string, 0, len(multi))
			for _, c := range multi {
				ids = append(ids, c.ID)
			}
			return cli.MultipleResults(ids), nil
		}
		single = multi[0]
	} else {
		if v.IsCipherRestricted(single) {
			return cli.Error(restrictedMessage), nil
		}
		if filter != nil && !filter(single) {
			return cli.NotFound(), nil
		}
	}

	cipherID := single.ID
	events.Collect(a, v, events.CipherClientViewed, &cipherID, true, single.OrganizationID)

	res := vault.NewCipherResponse(single)
	return cli.Success(res), res
}

func isLogin(c *vault.CipherView) bool { return c.Type == vault.CipherTypeLogin && c.Login != nil }

func loginField(c *vault.CipherView, get func(l *vault.LoginView) *string) *string {
	if !isLogin(c) {
		return nil
	}
	return get(c.Login)
}

func respLogin(r *vault.CipherResponse) *vault.LoginResponse {
	if r.Login == nil {
		return &vault.LoginResponse{}
	}
	return r.Login
}

func getUsername(a *app.App, v *vault.Vault, id string) *cli.Response {
	r, cipher := getCipher(a, v, id, func(c *vault.CipherView) bool {
		return isLogin(c) && !isNullOrWhitespace(loginField(c, func(l *vault.LoginView) *string { return l.Username }))
	})
	if !r.Success {
		return r
	}
	if cipher.Type != vault.CipherTypeLogin {
		return cli.BadRequest("Not a login.")
	}
	username := respLogin(cipher).Username.Ptr()
	if isNullOrWhitespace(username) {
		return cli.Error("No username available for this login.")
	}
	return cli.Success(cli.NewString(*username))
}

func getPassword(a *app.App, v *vault.Vault, id string) *cli.Response {
	r, cipher := getCipher(a, v, id, func(c *vault.CipherView) bool {
		return isLogin(c) && !isNullOrWhitespace(loginField(c, func(l *vault.LoginView) *string { return l.Password }))
	})
	if !r.Success {
		return r
	}
	if cipher.Type != vault.CipherTypeLogin {
		return cli.BadRequest("Not a login.")
	}
	// The response redacts the password when the user may not view it.
	password := respLogin(cipher).Password.Ptr()
	if isNullOrWhitespace(password) {
		return cli.Error("No password available for this login.")
	}
	return cli.Success(cli.NewString(*password))
}

func getURI(a *app.App, v *vault.Vault, id string) *cli.Response {
	firstURIUsable := func(uris []vault.LoginURIExport) bool {
		// `uris[0].uri !== ""`: an undefined/null uri passes.
		return len(uris) > 0 && (uris[0].URI.Val == nil || *uris[0].URI.Val != "")
	}
	r, cipher := getCipher(a, v, id, func(c *vault.CipherView) bool {
		return isLogin(c) && len(c.Login.URIs) > 0 && (c.Login.URIs[0].URI == nil || *c.Login.URIs[0].URI != "")
	})
	if !r.Success {
		return r
	}
	if cipher.Type != vault.CipherTypeLogin {
		return cli.BadRequest("Not a login.")
	}
	uris := respLogin(cipher).URIs
	if !firstURIUsable(uris) {
		return cli.Error("No uri available for this login.")
	}
	if uris[0].URI.Val == nil {
		return cli.Success(cli.NewNullString())
	}
	return cli.Success(cli.NewString(*uris[0].URI.Val))
}

func getTotp(a *app.App, v *vault.Vault, id string) *cli.Response {
	r, cipher := getCipher(a, v, id, func(c *vault.CipherView) bool {
		return isLogin(c) && !isNullOrWhitespace(loginField(c, func(l *vault.LoginView) *string { return l.Totp }))
	})
	if !r.Success {
		return r
	}
	if cipher.Type != vault.CipherTypeLogin {
		return cli.BadRequest("Not a login.")
	}
	totp := respLogin(cipher).Totp.Ptr()
	if isNullOrWhitespace(totp) {
		return cli.Error("No TOTP available for this login.")
	}

	code, err := vault.GenerateTotp(*totp, time.Time{})
	if err != nil {
		// Upstream the SDK error is thrown out of the command (unhandled rejection).
		return cli.Error(err)
	}
	if code.Code == "" {
		return cli.Error("Couldn't generate TOTP code.")
	}

	if !v.HasPremium() {
		original, err := v.EncryptedCipher(cipher.ID)
		if err != nil || original == nil || original.OrganizationID == nil || !original.OrganizationUseTotp {
			return cli.Error("Premium status is required to use this feature.")
		}
	}
	return cli.Success(cli.NewString(code.Code))
}

func getNotes(a *app.App, v *vault.Vault, id string) *cli.Response {
	r, cipher := getCipher(a, v, id, func(c *vault.CipherView) bool { return !isNullOrWhitespace(c.Notes) })
	if !r.Success {
		return r
	}
	notes := cipher.Notes.Ptr()
	if isNullOrWhitespace(notes) {
		return cli.Error("No notes available for this item.")
	}
	return cli.Success(cli.NewString(*notes))
}

func getExposed(a *app.App, v *vault.Vault, id string) *cli.Response {
	r := getPassword(a, v, id)
	if !r.Success {
		return r
	}
	password := r.Data.(*cli.StringResponse).Data
	count, err := passwordLeaked(a.API.HTTP, *password)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(cli.NewString(count))
}

func getFolder(v *vault.Vault, id string) *cli.Response {
	var folder *vault.FolderView
	if isGUID(id) {
		f, err := v.Folder(id)
		if err != nil && !errors.Is(err, vault.ErrNotFound) {
			return cli.Error(err)
		}
		folder = f
	} else if strings.TrimSpace(id) != "" {
		folders := vault.SearchFolders(v.Folders(), id)
		if len(folders) > 1 {
			ids := make([]string, 0, len(folders))
			for _, f := range folders {
				ids = append(ids, f.ID)
			}
			return cli.MultipleResults(ids)
		}
		if len(folders) > 0 {
			folder = folders[0]
		}
	}
	if folder == nil {
		return cli.NotFound()
	}
	return cli.Success(vault.NewFolderResponse(folder))
}

func getCollection(v *vault.Vault, id string) *cli.Response {
	var col *vault.CollectionView
	if isGUID(id) {
		c, err := v.Collection(id)
		if err != nil && !errors.Is(err, vault.ErrNotFound) {
			return cli.Error(err)
		}
		col = c
	} else if strings.TrimSpace(id) != "" {
		cols := vault.SearchCollections(v.Collections(), id)
		if len(cols) > 1 {
			ids := make([]string, 0, len(cols))
			for _, c := range cols {
				ids = append(ids, c.ID)
			}
			return cli.MultipleResults(ids)
		}
		if len(cols) > 0 {
			col = cols[0]
		}
	}
	if col == nil {
		return cli.NotFound()
	}
	return cli.Success(vault.NewCollectionResponse(col))
}

// collectionAccessDetails is CollectionAccessDetailsResponse.
type collectionAccessDetails struct {
	ID                         string                    `json:"id"`
	OrganizationID             string                    `json:"organizationId"`
	Name                       *string                   `json:"name"`
	ExternalID                 vault.Opt[string]         `json:"externalId"`
	DefaultUserCollectionEmail *string                   `json:"defaultUserCollectionEmail"`
	Groups                     []vault.SelectionReadOnly `json:"groups"`
	Users                      []vault.SelectionReadOnly `json:"users"`
}

func selections(in []vault.SelectionReadOnly) []vault.SelectionReadOnly {
	// CollectionAccessDetailsResponse defaults groups/users to [] when absent.
	if in == nil {
		return []vault.SelectionReadOnly{}
	}
	return in
}

func getOrganizationCollection(a *app.App, id string, opts GetOptions) *cli.Response {
	if opts.OrganizationID == "" {
		return cli.BadRequest("`organizationid` option is required.")
	}
	if !isGUID(id) {
		return cli.BadRequest("`" + id + "` is not a GUID.")
	}
	if !isGUID(opts.OrganizationID) {
		return cli.BadRequest("`" + opts.OrganizationID + "` is not a GUID.")
	}
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	orgKey, err := v.Keys().OrgKey(opts.OrganizationID)
	if err != nil || orgKey == nil {
		// `throw new Error(...)` caught by Response.error: String(error) keeps the "Error: " prefix.
		return cli.Error("Error: No encryption key for this organization.")
	}

	var resp collectionAccessDetails
	if err := a.API.Get("/organizations/"+opts.OrganizationID+"/collections/"+id+"/details", &resp); err != nil {
		return cli.Error(err)
	}
	// CollectionView.fromCollectionAccessDetails: decryption errors are rethrown.
	name := ""
	if resp.Name != nil {
		name, err = crypto.DecryptString(*resp.Name, orgKey)
		if err != nil {
			return cli.Error("Error: " + err.Error())
		}
	}
	if resp.DefaultUserCollectionEmail != nil {
		name = *resp.DefaultUserCollectionEmail
	}
	return cli.Success(&vault.OrganizationCollectionResponse{
		Object:         "org-collection",
		ID:             resp.ID,
		OrganizationID: resp.OrganizationID,
		Name:           name,
		ExternalID:     resp.ExternalID,
		Groups:         selections(resp.Groups),
		Users:          selections(resp.Users),
	})
}

func getOrganization(a *app.App, id string) *cli.Response {
	if acct := a.ActiveAccount(); acct == nil || acct.UserID == "" {
		return cli.BadRequest("No user found.")
	}
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	var org *vault.Organization
	if isGUID(id) {
		org = v.Organization(id)
	} else if strings.TrimSpace(id) != "" {
		orgs := vault.SearchOrganizations(v.Organizations(), id)
		if len(orgs) > 1 {
			ids := make([]string, 0, len(orgs))
			for _, o := range orgs {
				ids = append(ids, o.ID)
			}
			return cli.MultipleResults(ids)
		}
		if len(orgs) > 0 {
			org = orgs[0]
		}
	}
	if org == nil {
		return cli.NotFound()
	}
	return cli.Success(vault.NewOrganizationResponse(org))
}

func getTemplate(a *app.App, id string) *cli.Response {
	name := strings.ToLower(id)
	switch name {
	case "item.bankaccount":
		if !NewItemTypesEnabled(a) {
			return cli.BadRequest("Bank account item type is not available.")
		}
	case "item.driverslicense":
		if !NewItemTypesEnabled(a) {
			return cli.BadRequest("Driver's license item type is not available.")
		}
	case "item.passport":
		if !NewItemTypesEnabled(a) {
			return cli.BadRequest("Passport item type is not available.")
		}
	case "send.file", "send.text":
		// Upstream wraps the bad-request Response itself as the template (and succeeds).
		return cli.Success(cli.NewTemplate(cli.BadRequest("Invalid template object. Use `bwgo send template " + id + "` instead.")))
	}
	for _, n := range vault.TemplateNames {
		if n == name {
			t, _ := vault.Template(name)
			return cli.Success(cli.NewTemplate(t))
		}
	}
	return cli.BadRequest("Unknown template object.")
}

func getFingerprint(a *app.App, id string) *cli.Response {
	var phrase []string
	if id == "me" {
		v, err := vault.Load(a)
		if err != nil {
			return cli.Error(err)
		}
		priv, err := v.Keys().PrivateKey()
		if err != nil || priv == nil {
			return cli.Error("No public key available for the active user.")
		}
		pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return cli.Error("No public key available for the active user.")
		}
		if phrase, err = Fingerprint(v.UserID(), pub); err != nil {
			return cli.Error(err)
		}
	} else if isGUID(id) {
		var resp struct {
			PublicKey string `json:"publicKey"`
		}
		// Errors are swallowed upstream and reported as "Not found.".
		if err := a.API.Get("/users/"+id+"/public-key", &resp); err == nil {
			if pub, err := base64.StdEncoding.DecodeString(resp.PublicKey); err == nil {
				phrase, _ = Fingerprint(id, pub)
			}
		}
	}
	if phrase == nil {
		return cli.NotFound()
	}
	return cli.Success(cli.NewString(strings.Join(phrase, "-")))
}
