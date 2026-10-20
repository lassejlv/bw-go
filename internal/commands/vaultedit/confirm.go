package vaultedit

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ConfirmOptions are the options of `bw confirm` (confirm.command.ts Options).
type ConfirmOptions struct {
	// OrganizationID is --organizationid.
	OrganizationID string
}

// defaultUserCollectionName is the i18n "myItems" message used for the confirmed member's
// default collection.
const defaultUserCollectionName = "My Items"

// Confirm implements ConfirmCommand.run.
func Confirm(a *app.App, object, id string, opts ConfirmOptions) *cli.Response {
	id = strings.ToLower(id)
	switch strings.ToLower(object) {
	case "org-member":
		return confirmOrganizationMember(a, id, opts)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

// organizationUserConfirmRequest mirrors OrganizationUserConfirmRequest.
type organizationUserConfirmRequest struct {
	Key                       string `json:"key"`
	DefaultUserCollectionName string `json:"defaultUserCollectionName"`
}

func confirmOrganizationMember(a *app.App, id string, opts ConfirmOptions) *cli.Response {
	orgID := opts.OrganizationID
	if orgID == "" {
		return cli.BadRequest("--organizationid <organizationid> required.")
	}
	if !isGUID(id) {
		return cli.BadRequest("`" + id + "` is not a GUID.")
	}
	if !isGUID(orgID) {
		return cli.BadRequest("`" + orgID + "` is not a GUID.")
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	orgKey, err := v.Keys().OrgKey(orgID)
	if err != nil || orgKey == nil {
		return cli.Error("No encryption key for this organization.")
	}
	var orgUser *struct {
		UserID string                       `json:"userId"`
		Status vault.OrganizationUserStatus `json:"status"`
	}
	if err := a.API.Get("/organizations/"+orgID+"/users/"+id+"?", &orgUser); err != nil {
		return cli.Error(err)
	}
	if orgUser == nil {
		return cli.Error("Member id does not exist for this organization.")
	}
	switch orgUser.Status {
	case vault.OrgUserStatusInvited:
		return cli.Error("User must accept the invitation before they can be confirmed.")
	case vault.OrgUserStatusConfirmed:
		return cli.Error("User is already confirmed.")
	case vault.OrgUserStatusRevoked:
		return cli.Error("User is revoked and cannot be confirmed.")
	case vault.OrgUserStatusAccepted:
	default:
		return cli.Error("User is not in a valid state to be confirmed.")
	}

	var keyResp struct {
		PublicKey string `json:"publicKey"`
	}
	if err := a.API.Get("/users/"+orgUser.UserID+"/public-key", &keyResp); err != nil {
		return cli.Error(err)
	}
	der, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return cli.Error(err)
	}
	pub, err := crypto.ParsePublicKey(der)
	if err != nil {
		return cli.Error(err)
	}
	// encapsulateKeyUnsigned: RSA-OAEP(SHA-1) of the encoded organization key.
	key, err := crypto.RsaEncrypt(orgKey.Bytes(), pub)
	if err != nil {
		return cli.Error(err)
	}
	name, err := crypto.EncryptString(defaultUserCollectionName, orgKey)
	if err != nil {
		return cli.Error(errors.New("Failed to encrypt default user collection name."))
	}
	req := &organizationUserConfirmRequest{Key: key, DefaultUserCollectionName: name}
	if err := a.API.Post("/organizations/"+orgID+"/users/"+id+"/confirm", req, nil); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}
