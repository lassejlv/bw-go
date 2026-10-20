package vaultedit

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

// MoveEncoded is the CLI entry point of `bw move` / `bw share`: it reads the base64 encoded JSON
// array of collection ids from the argument (or stdin) and runs Move.
func MoveEncoded(a *app.App, id, organizationID, encodedJSON string) *cli.Response {
	raw, r := readEncodedJSON(encodedJSON)
	if r != nil {
		return r
	}
	var req []string
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	if len(req) == 0 {
		return cli.BadRequest("You must provide at least one collection id for this item.")
	}
	return Move(a, id, organizationID, raw)
}

// Move implements ShareCommand.run (`bw move`, deprecated `bw share`) with an already decoded
// JSON array of collection ids (as `bw serve` passes it).
func Move(a *app.App, id, organizationID string, req json.RawMessage) *cli.Response {
	if len(req) == 0 {
		return cli.BadRequest("`requestJson` was not provided.")
	}
	var collectionIDs []string
	if r := parseRequest(req, &collectionIDs); r != nil {
		return r
	}
	id = strings.ToLower(id)
	organizationID = strings.ToLower(organizationID)

	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return cli.NotFound()
	}
	if c.OrganizationID != nil {
		return cli.BadRequest("This item already belongs to an organization.")
	}
	var orgCollections []*vault.CollectionView
	for _, col := range v.Collections() {
		if col.OrganizationID == organizationID {
			orgCollections = append(orgCollections, col)
		}
	}
	org := v.Organization(organizationID)
	if org == nil {
		return cli.BadRequest("Organization not found.")
	}
	for _, collectionID := range collectionIDs {
		var found *vault.CollectionView
		for _, col := range orgCollections {
			if col.ID == collectionID {
				found = col
				break
			}
		}
		if found == nil || !found.CanEditItems(org) {
			return cli.BadRequest("You do not have permission to add items to this collection.")
		}
	}
	view, err := decryptedCipher(v, c)
	if err != nil {
		return cli.Error(err)
	}
	if collectionIDs == nil {
		collectionIDs = []string{}
	}
	if err := shareWithServer(a, v, view, organizationID, collectionIDs); err != nil {
		return cli.Error(err)
	}
	updated, err := v.EncryptedCipher(c.ID)
	if err != nil {
		return cli.Error(errNoElements)
	}
	dec, err := decryptedCipher(v, updated)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewCipherResponse(dec))
}

// shareRequest mirrors the SDK's CipherShareRequestModel (collectionIds, cipher).
type shareRequest struct {
	CollectionIDs []string             `json:"collectionIds"`
	Cipher        *vault.CipherRequest `json:"cipher"`
}

// shareWithServer mirrors cipherService.shareWithServer -> CiphersClient.share_cipher: the item
// is moved into the organization (attachments must have keys; their keys stay wrapped by the
// re-wrapped cipher key), the password history is updated, the item is re-encrypted with the
// organization key and PUT to /ciphers/{id}/share. The response is stored with the new
// collection ids.
func shareWithServer(a *app.App, v *vault.Vault, view *vault.CipherView, organizationID string, collectionIDs []string) error {
	if view.OrganizationID != nil {
		return errors.New("Cipher is already associated with an organization.")
	}
	for _, att := range view.Attachments {
		if att.Key == nil {
			return errors.New("This cipher contains attachments without keys. Those attachments will need to be reuploaded to complete the operation")
		}
	}
	orgID := organizationID
	view.OrganizationID = &orgID
	view.CollectionIDs = append([]string{}, collectionIDs...)
	v.PrepareForSave(view)
	c, err := v.EncryptCipher(view)
	if err != nil {
		return err
	}
	req := vault.NewCipherRequest(c, v.UserID())
	// The SDK request carries attachment metadata only in attachments2 (fileName, key).
	req.Attachments = nil
	for id, att := range req.Attachments2 {
		att.LastKnownRevisionDate = nil
		req.Attachments2[id] = att
	}
	var resp json.RawMessage
	if err := a.API.Put("/ciphers/"+c.ID+"/share", &shareRequest{CollectionIDs: collectionIDs, Cipher: req}, &resp); err != nil {
		return err
	}
	if isNullJSON(resp) {
		return errors.New("Failed to share cipher: no result returned from SDK")
	}
	_, err = v.UpsertCipher(resp, collectionIDs)
	return err
}
