package vault

import (
	"github.com/lassejlv/bw-go/internal/cli"
)

// Server request models (libs/common/src/vault/models/request). Property names follow the TS
// classes; null values are sent as null like the Node client.

// LoginURIRequest is LoginUriApi in a request.
type LoginURIRequest struct {
	URI         *string   `json:"uri"`
	URIChecksum *string   `json:"uriChecksum"`
	Match       *UriMatch `json:"match"`
}

// Fido2CredentialRequest is Fido2CredentialApi in a request.
type Fido2CredentialRequest struct {
	CredentialID    *string `json:"credentialId"`
	KeyType         *string `json:"keyType"`
	KeyAlgorithm    *string `json:"keyAlgorithm"`
	KeyCurve        *string `json:"keyCurve"`
	KeyValue        *string `json:"keyValue"`
	RpID            *string `json:"rpId"`
	RpName          *string `json:"rpName"`
	Counter         *string `json:"counter"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    *string `json:"discoverable"`
	CreationDate    *string `json:"creationDate"`
}

// LoginRequest is LoginApi in a request.
type LoginRequest struct {
	URIs                 []LoginURIRequest        `json:"uris"`
	Username             *string                  `json:"username"`
	Password             *string                  `json:"password"`
	PasswordRevisionDate *string                  `json:"passwordRevisionDate"`
	Totp                 *string                  `json:"totp"`
	AutofillOnPageLoad   *bool                    `json:"autofillOnPageLoad"`
	Fido2Credentials     []Fido2CredentialRequest `json:"fido2Credentials,omitempty"`
}

// FieldRequest is FieldApi in a request.
type FieldRequest struct {
	Type     FieldType `json:"type"`
	Name     *string   `json:"name"`
	Value    *string   `json:"value"`
	LinkedID *LinkedID `json:"linkedId"`
}

// PasswordHistoryRequest mirrors PasswordHistoryRequest.
type PasswordHistoryRequest struct {
	LastUsedDate *cli.Date `json:"lastUsedDate"`
	Password     *string   `json:"password"`
}

// AttachmentRequest mirrors AttachmentRequest (attachments2 metadata).
type AttachmentRequest struct {
	FileName              *string   `json:"fileName"`
	Key                   *string   `json:"key,omitempty"`
	FileSize              *int64    `json:"fileSize,omitempty"`
	AdminRequest          *bool     `json:"adminRequest,omitempty"`
	LastKnownRevisionDate *cli.Date `json:"lastKnownRevisionDate,omitempty"`
}

// CipherRequest mirrors CipherRequest.
type CipherRequest struct {
	EncryptedFor          string                       `json:"encryptedFor,omitempty"`
	Type                  CipherType                   `json:"type"`
	FolderID              *string                      `json:"folderId"`
	OrganizationID        *string                      `json:"organizationId"`
	Name                  *string                      `json:"name"`
	Notes                 *string                      `json:"notes"`
	Favorite              bool                         `json:"favorite"`
	Login                 *LoginRequest                `json:"login,omitempty"`
	SecureNote            *SecureNoteData              `json:"secureNote,omitempty"`
	Card                  *CardData                    `json:"card,omitempty"`
	Identity              *IdentityData                `json:"identity,omitempty"`
	SshKey                *SshKeyData                  `json:"sshKey,omitempty"`
	BankAccount           *BankAccountData             `json:"bankAccount,omitempty"`
	DriversLicense        *DriversLicenseData          `json:"driversLicense,omitempty"`
	Passport              *PassportData                `json:"passport,omitempty"`
	Fields                []FieldRequest               `json:"fields,omitempty"`
	PasswordHistory       []PasswordHistoryRequest     `json:"passwordHistory,omitempty"`
	Attachments           map[string]*string           `json:"attachments,omitempty"`
	Attachments2          map[string]AttachmentRequest `json:"attachments2,omitempty"`
	LastKnownRevisionDate *cli.Date                    `json:"lastKnownRevisionDate"`
	ArchivedDate          *cli.Date                    `json:"archivedDate"`
	Reprompt              RepromptType                 `json:"reprompt"`
	Key                   *string                      `json:"key,omitempty"`
	Data                  *string                      `json:"data,omitempty"`
}

// NewCipherRequest builds a CipherRequest from an encrypted cipher. encryptedFor is the user id
// the cipher was encrypted for ("" to omit).
func NewCipherRequest(c *Cipher, encryptedFor string) *CipherRequest {
	r := &CipherRequest{
		EncryptedFor:          encryptedFor,
		Type:                  c.Type,
		FolderID:              clonePtr(c.FolderID),
		OrganizationID:        clonePtr(c.OrganizationID),
		Name:                  emptyToNil(c.Name),
		Notes:                 emptyToNil(c.Notes),
		Favorite:              c.Favorite,
		LastKnownRevisionDate: c.RevisionDate,
		ArchivedDate:          c.ArchivedDate,
		Reprompt:              c.Reprompt,
		Key:                   c.Key,
		Data:                  c.Data.Val,
	}
	switch c.Type {
	case CipherTypeLogin:
		if l := c.Login; l != nil {
			lr := &LoginRequest{
				URIs:               []LoginURIRequest{},
				Username:           emptyToNil(l.Username),
				Password:           emptyToNil(l.Password),
				Totp:               emptyToNil(l.Totp),
				AutofillOnPageLoad: l.AutofillOnPageLoad,
			}
			if l.PasswordRevisionDate != nil {
				s := cli.FormatDate(l.PasswordRevisionDate.Time)
				lr.PasswordRevisionDate = &s
			}
			for _, u := range l.URIs {
				lr.URIs = append(lr.URIs, LoginURIRequest{URI: u.URI, URIChecksum: u.URIChecksum, Match: u.Match})
			}
			if l.Fido2Credentials != nil {
				lr.Fido2Credentials = []Fido2CredentialRequest{}
				for _, f := range l.Fido2Credentials {
					fr := Fido2CredentialRequest{
						CredentialID: f.CredentialID, KeyType: f.KeyType, KeyAlgorithm: f.KeyAlgorithm,
						KeyCurve: f.KeyCurve, KeyValue: f.KeyValue, RpID: f.RpID, RpName: f.RpName,
						Counter: f.Counter, UserHandle: f.UserHandle, UserName: f.UserName,
						UserDisplayName: f.UserDisplayName, Discoverable: f.Discoverable,
					}
					if f.CreationDate != nil {
						s := cli.FormatDate(f.CreationDate.Time)
						fr.CreationDate = &s
					}
					lr.Fido2Credentials = append(lr.Fido2Credentials, fr)
				}
			}
			r.Login = lr
		}
	case CipherTypeSecureNote:
		r.SecureNote = c.SecureNote
	case CipherTypeSshKey:
		r.SshKey = c.SshKey
	case CipherTypeCard:
		r.Card = c.Card
	case CipherTypeIdentity:
		r.Identity = c.Identity
	case CipherTypeBankAccount:
		r.BankAccount = c.BankAccount
	case CipherTypeDriversLicense:
		r.DriversLicense = c.DriversLicense
	case CipherTypePassport:
		r.Passport = c.Passport
	}
	if c.Fields != nil {
		r.Fields = []FieldRequest{}
		for _, f := range c.Fields {
			r.Fields = append(r.Fields, FieldRequest{Type: f.Type, Name: emptyToNil(f.Name), Value: emptyToNil(f.Value), LinkedID: f.LinkedID})
		}
	}
	if c.PasswordHistory != nil {
		r.PasswordHistory = []PasswordHistoryRequest{}
		for _, p := range c.PasswordHistory {
			r.PasswordHistory = append(r.PasswordHistory, PasswordHistoryRequest{LastUsedDate: p.LastUsedDate, Password: emptyToNil(p.Password)})
		}
	}
	if c.Attachments != nil {
		r.Attachments = map[string]*string{}
		r.Attachments2 = map[string]AttachmentRequest{}
		for _, a := range c.Attachments {
			id := derefStr(a.ID)
			fn := emptyToNil(a.FileName)
			r.Attachments[id] = fn
			r.Attachments2[id] = AttachmentRequest{FileName: fn, Key: a.Key, LastKnownRevisionDate: c.RevisionDate}
		}
	}
	return r
}

// CipherWithIDRequest mirrors CipherWithIdRequest.
type CipherWithIDRequest struct {
	CipherRequest
	ID string `json:"id"`
}

// CipherCreateRequest mirrors CipherCreateRequest (POST /ciphers/create, /ciphers/admin).
type CipherCreateRequest struct {
	Cipher        *CipherRequest `json:"cipher"`
	CollectionIDs []string       `json:"collectionIds"`
}

// NewCipherCreateRequest builds a CipherCreateRequest.
func NewCipherCreateRequest(c *Cipher, encryptedFor string) *CipherCreateRequest {
	return &CipherCreateRequest{Cipher: NewCipherRequest(c, encryptedFor), CollectionIDs: c.CollectionIDs}
}

// CipherShareRequest mirrors CipherShareRequestModel (PUT /ciphers/{id}/share).
type CipherShareRequest struct {
	Cipher        *CipherWithIDRequest `json:"cipher"`
	CollectionIDs []string             `json:"collectionIds"`
}

// NewCipherShareRequest builds a share request for an encrypted cipher.
func NewCipherShareRequest(c *Cipher, collectionIDs []string, encryptedFor string) *CipherShareRequest {
	if collectionIDs == nil {
		collectionIDs = []string{}
	}
	return &CipherShareRequest{
		Cipher:        &CipherWithIDRequest{CipherRequest: *NewCipherRequest(c, encryptedFor), ID: c.ID},
		CollectionIDs: collectionIDs,
	}
}

// CipherPartialRequest mirrors CipherPartialRequest (PUT /ciphers/{id}/partial).
type CipherPartialRequest struct {
	FolderID *string `json:"folderId"`
	Favorite bool    `json:"favorite"`
}

// CipherBulkDeleteRequest mirrors CipherBulkDeleteRequest.
type CipherBulkDeleteRequest struct {
	IDs            []string `json:"ids"`
	OrganizationID *string  `json:"organizationId,omitempty"`
}

// CipherCollectionsRequest mirrors CipherCollectionsRequest (PUT /ciphers/{id}/collections).
type CipherCollectionsRequest struct {
	CollectionIDs []string `json:"collectionIds"`
}

// FolderRequest mirrors FolderRequest.
type FolderRequest struct {
	Name string `json:"name"`
}

// FolderWithIDRequest mirrors FolderWithIdRequest.
type FolderWithIDRequest struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// SelectionReadOnlyRequest mirrors SelectionReadOnlyRequest.
type SelectionReadOnlyRequest struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}

// CollectionRequest mirrors Create/UpdateCollectionRequest. Groups/Users nil marshal as null
// (create sends `groups: null` when the input had none).
type CollectionRequest struct {
	ExternalID *string                    `json:"externalId,omitempty"`
	Groups     []SelectionReadOnlyRequest `json:"groups"`
	Users      []SelectionReadOnlyRequest `json:"users"`
	Name       *string                    `json:"name"`
}
