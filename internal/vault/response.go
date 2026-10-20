package vault

import (
	"github.com/lassejlv/bw-go/internal/cli"
)

// CLI output models (apps/cli/src/vault/models, apps/cli/src/admin-console/models).

// AttachmentResponse mirrors AttachmentResponse (order: id, fileName, size, sizeName, url).
type AttachmentResponse struct {
	ID       Opt[string] `json:"id,omitzero"`
	FileName Opt[string] `json:"fileName,omitzero"`
	Size     Opt[string] `json:"size,omitzero"`
	SizeName Opt[string] `json:"sizeName,omitzero"`
	URL      Opt[string] `json:"url,omitzero"`
}

// PasswordHistoryResponse mirrors PasswordHistoryResponse (order: lastUsedDate, password).
type PasswordHistoryResponse struct {
	LastUsedDate *cli.Date `json:"lastUsedDate"`
	Password     *string   `json:"password"`
}

// LoginResponse mirrors apps/cli LoginResponse (LoginExport + passwordRevisionDate).
type LoginResponse struct {
	LoginExport
	PasswordRevisionDate *cli.Date `json:"passwordRevisionDate"`
}

// CipherResponse mirrors apps/cli CipherResponse (object "item"). Field order follows the
// JSON.stringify order of the TS object: CipherExport initialisers (type, favorite, reprompt),
// CipherWithIdExport initialisers (id, collectionIds), object, then build() assignments.
type CipherResponse struct {
	Type            CipherType                `json:"type"`
	Favorite        bool                      `json:"favorite"`
	Reprompt        RepromptType              `json:"reprompt"`
	ID              string                    `json:"id"`
	CollectionIDs   []string                  `json:"collectionIds"`
	Object          string                    `json:"object"`
	OrganizationID  Opt[string]               `json:"organizationId,omitzero"`
	FolderID        Opt[string]               `json:"folderId,omitzero"`
	Name            string                    `json:"name"`
	Notes           Opt[string]               `json:"notes,omitzero"`
	Fields          []FieldExport             `json:"fields,omitzero"`
	Login           *LoginResponse            `json:"login,omitempty"`
	SecureNote      *SecureNoteExport         `json:"secureNote,omitempty"`
	Card            *CardExport               `json:"card,omitempty"`
	Identity        *IdentityExport           `json:"identity,omitempty"`
	SshKey          *SshKeyExport             `json:"sshKey,omitempty"`
	BankAccount     *BankAccountExport        `json:"bankAccount,omitempty"`
	DriversLicense  *DriversLicenseExport     `json:"driversLicense,omitempty"`
	Passport        *PassportExport           `json:"passport,omitempty"`
	PasswordHistory []PasswordHistoryResponse `json:"passwordHistory,omitzero"`
	CreationDate    *cli.Date                 `json:"creationDate,omitempty"`
	RevisionDate    *cli.Date                 `json:"revisionDate,omitempty"`
	DeletedDate     *cli.Date                 `json:"deletedDate,omitempty"`
	ArchivedDate    *cli.Date                 `json:"archivedDate,omitempty"`
	Attachments     []AttachmentResponse      `json:"attachments,omitzero"`
}

// NewCipherResponse mirrors `new CipherResponse(cipherView)`: the item key is redacted, and
// without viewPassword the password history, login password/totp and hidden field values are
// redacted.
func NewCipherResponse(v *CipherView) *CipherResponse {
	r := &CipherResponse{
		Type: v.Type, Favorite: v.Favorite, Reprompt: v.Reprompt, ID: v.ID,
		CollectionIDs:  v.CollectionIDs,
		Object:         "item",
		OrganizationID: FromPtr(v.OrganizationID),
		FolderID:       FromPtr(v.FolderID),
		Name:           v.Name,
		Notes:          FromPtr(v.Notes),
		CreationDate:   &cli.Date{Time: v.CreationDate},
		RevisionDate:   &cli.Date{Time: v.RevisionDate},
		DeletedDate:    cliDate(v.DeletedDate),
		ArchivedDate:   cliDate(v.ArchivedDate),
	}
	if r.CollectionIDs == nil {
		r.CollectionIDs = []string{}
	}
	if v.Fields != nil {
		r.Fields = []FieldExport{}
		for i := range v.Fields {
			f := NewFieldExport(&v.Fields[i])
			if !v.ViewPassword && f.Type == FieldTypeHidden {
				f.Value = Null[string]()
			}
			r.Fields = append(r.Fields, f)
		}
	}
	var login *LoginExport
	buildTypeExports(v, &login, &r.SecureNote, &r.Card, &r.Identity, &r.SshKey, &r.BankAccount, &r.DriversLicense, &r.Passport)
	if v.Type == CipherTypeLogin && v.Login != nil {
		lr := &LoginResponse{LoginExport: *NewLoginExport(v.Login), PasswordRevisionDate: cliDate(v.Login.PasswordRevisionDate)}
		if !v.ViewPassword {
			lr.Password = Null[string]()
			lr.Totp = Null[string]()
		}
		r.Login = lr
	} else if login != nil {
		r.Login = &LoginResponse{LoginExport: *login}
	}
	if v.ViewPassword && v.PasswordHistory != nil {
		r.PasswordHistory = []PasswordHistoryResponse{}
		for _, p := range v.PasswordHistory {
			r.PasswordHistory = append(r.PasswordHistory, PasswordHistoryResponse{LastUsedDate: cliDate(p.LastUsedDate), Password: clonePtr(p.Password)})
		}
	}
	if v.Attachments != nil {
		r.Attachments = []AttachmentResponse{}
		for _, a := range v.Attachments {
			r.Attachments = append(r.Attachments, AttachmentResponse{ID: FromPtr(a.ID), FileName: FromPtr(a.FileName),
				Size: FromPtr(a.Size), SizeName: FromPtr(a.SizeName), URL: FromPtr(a.URL)})
		}
	}
	return r
}

// FolderResponse mirrors FolderResponse (object "folder"); order: name, object, id because
// FolderExport initialises `name` in its constructor.
type FolderResponse struct {
	Name   string `json:"name"`
	Object string `json:"object"`
	ID     string `json:"id"`
}

// NewFolderResponse builds a FolderResponse.
func NewFolderResponse(f *FolderView) *FolderResponse {
	return &FolderResponse{Name: f.Name, Object: "folder", ID: f.ID}
}

// CollectionResponse mirrors CollectionResponse (object "collection").
type CollectionResponse struct {
	Object         string      `json:"object"`
	ID             string      `json:"id"`
	OrganizationID string      `json:"organizationId"`
	Name           string      `json:"name"`
	ExternalID     Opt[string] `json:"externalId,omitzero"`
}

// NewCollectionResponse builds a CollectionResponse.
func NewCollectionResponse(c *CollectionView) *CollectionResponse {
	return &CollectionResponse{Object: "collection", ID: c.ID, OrganizationID: c.OrganizationID,
		Name: c.DisplayName(), ExternalID: collectionExternalID(c)}
}

// OrganizationCollectionResponse mirrors OrganizationCollectionResponse (object "org-collection").
type OrganizationCollectionResponse struct {
	Object         string              `json:"object"`
	ID             string              `json:"id"`
	OrganizationID string              `json:"organizationId"`
	Name           string              `json:"name"`
	ExternalID     Opt[string]         `json:"externalId,omitzero"`
	Groups         []SelectionReadOnly `json:"groups"`
	Users          []SelectionReadOnly `json:"users"`
}

// NewOrganizationCollectionResponse builds an OrganizationCollectionResponse.
func NewOrganizationCollectionResponse(c *CollectionView, groups, users []SelectionReadOnly) *OrganizationCollectionResponse {
	return &OrganizationCollectionResponse{Object: "org-collection", ID: c.ID, OrganizationID: c.OrganizationID,
		Name: c.DisplayName(), ExternalID: collectionExternalID(c), Groups: groups, Users: users}
}

// OrganizationResponse mirrors OrganizationResponse (object "organization").
type OrganizationResponse struct {
	Object  string                 `json:"object"`
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Status  OrganizationUserStatus `json:"status"`
	Type    OrganizationUserType   `json:"type"`
	Enabled bool                   `json:"enabled"`
}

// NewOrganizationResponse builds an OrganizationResponse.
func NewOrganizationResponse(o *Organization) *OrganizationResponse {
	return &OrganizationResponse{Object: "organization", ID: o.ID, Name: o.Name, Status: o.Status, Type: o.Type, Enabled: o.Enabled}
}

// OrganizationUserResponse mirrors OrganizationUserResponse (object "org-member").
type OrganizationUserResponse struct {
	Object           string                 `json:"object"`
	ID               string                 `json:"id"`
	Email            string                 `json:"email"`
	Name             Opt[string]            `json:"name,omitzero"`
	Status           OrganizationUserStatus `json:"status"`
	Type             OrganizationUserType   `json:"type"`
	TwoFactorEnabled bool                   `json:"twoFactorEnabled"`
}

// NewOrganizationUserResponse builds an OrganizationUserResponse. name is nil when the server
// sent null (emitted as null, like the Node CLI passing the response value through).
func NewOrganizationUserResponse(id, email string, name *string, status OrganizationUserStatus, typ OrganizationUserType, twoFactor bool) *OrganizationUserResponse {
	return &OrganizationUserResponse{Object: "org-member", ID: id, Email: email, Name: NullFromPtr(name),
		Status: status, Type: typ, TwoFactorEnabled: twoFactor}
}
