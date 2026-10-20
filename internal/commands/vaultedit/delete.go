package vaultedit

import (
	"encoding/json"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

// DeleteOptions are the options of `bw delete` (delete.command.ts Options).
type DeleteOptions struct {
	// ItemID is --itemid (attachment's item id).
	ItemID string
	// OrganizationID is --organizationid (org-collection).
	OrganizationID string
	// Permanent is -p/--permanent (item only).
	Permanent bool
}

// Delete implements DeleteCommand.run.
func Delete(a *app.App, object, id string, opts DeleteOptions) *cli.Response {
	id = strings.ToLower(id)
	switch strings.ToLower(object) {
	case "item":
		return deleteCipher(a, id, opts)
	case "attachment":
		return deleteAttachment(a, id, opts)
	case "folder":
		return deleteFolder(a, id)
	case "org-collection":
		return deleteOrganizationCollection(a, id, opts)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

func deleteCipher(a *app.App, id string, opts DeleteOptions) *cli.Response {
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return cli.NotFound()
	}
	if c.Permissions == nil || !c.Permissions.Delete {
		return cli.Error("You do not have permission to delete this item.")
	}
	if vault.IsCipherRestricted(c.Type, c.OrganizationID, v.RestrictedTypes()) {
		return cli.Error("Deleting this item type is restricted by organizational policy.")
	}
	if opts.Permanent {
		if err := a.API.Delete("/ciphers/"+id, nil); err != nil {
			return cli.Error(err)
		}
		if err := v.DeleteCiphers(id); err != nil {
			return cli.Error(err)
		}
	} else {
		if err := a.API.Put("/ciphers/"+id+"/delete", nil, nil); err != nil {
			return cli.Error(err)
		}
		if err := v.SoftDeleteCiphers(id); err != nil {
			return cli.Error(err)
		}
	}
	return cli.Success(nil)
}

func deleteAttachment(a *app.App, id string, opts DeleteOptions) *cli.Response {
	if opts.ItemID == "" {
		return cli.BadRequest("`itemid` option is required.")
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(strings.ToLower(opts.ItemID))
	if err != nil {
		return cli.NotFound()
	}
	if len(c.Attachments) == 0 {
		return cli.Error("No attachments available for this item.")
	}
	var attachmentID *string
	for _, att := range c.Attachments {
		if att.ID != nil && strings.ToLower(*att.ID) == id {
			attachmentID = att.ID
			break
		}
	}
	if attachmentID == nil {
		return cli.Error("Attachment `" + id + "` was not found.")
	}
	if c.OrganizationID == nil && !v.HasPremium() {
		return cli.Error("Premium status is required to use this feature.")
	}
	if err := deleteAttachmentWithServer(a, v, c.ID, *attachmentID); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}

func deleteFolder(a *app.App, id string) *cli.Response {
	v, r := openVault(a)
	if r != nil {
		return r
	}
	if _, ok := v.Account().Vault.Folders[id]; !ok {
		return cli.NotFound()
	}
	if err := a.API.Delete("/folders/"+id, nil); err != nil {
		return cli.Error(err)
	}
	if err := v.DeleteFolder(id); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}

func deleteOrganizationCollection(a *app.App, id string, opts DeleteOptions) *cli.Response {
	if opts.OrganizationID == "" {
		return cli.BadRequest("`organizationid` options is required.")
	}
	if !isGUID(id) {
		return cli.BadRequest("`" + id + "` is not a GUID.")
	}
	if !isGUID(opts.OrganizationID) {
		return cli.BadRequest("`" + opts.OrganizationID + "` is not a GUID.")
	}
	if err := a.API.Delete("/organizations/"+opts.OrganizationID+"/collections/"+id, nil); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}

// ---------- restore ----------

// Restore implements RestoreCommand.run: items are restored from the trash, or from the archive
// when they are archived but not deleted.
func Restore(a *app.App, object, id string) *cli.Response {
	id = strings.ToLower(id)
	switch strings.ToLower(object) {
	case "item":
		return restoreCipher(a, id)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

func restoreCipher(a *app.App, id string) *cli.Response {
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return cli.NotFound()
	}
	if c.IsArchived() && !c.IsDeleted() {
		if err := bulkArchiveWithServer(a, v, "/ciphers/unarchive", c.ID); err != nil {
			return cli.Error(err)
		}
		return cli.Success(nil)
	}
	if !c.IsDeleted() {
		return cli.BadRequest("Cipher is not in trash.")
	}
	if c.Permissions == nil || !c.Permissions.Restore {
		return cli.Error("You do not have permission to restore this item")
	}
	var resp struct {
		RevisionDate *string `json:"revisionDate"`
	}
	if err := a.API.Put("/ciphers/"+c.ID+"/restore", nil, &resp); err != nil {
		return cli.Error(err)
	}
	rd := ""
	if resp.RevisionDate != nil {
		rd = *resp.RevisionDate
	}
	if err := v.RestoreCipher(c.ID, rd); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}

// bulkArchiveWithServer mirrors DefaultCipherArchiveService.archiveWithServer /
// unarchiveWithServer: PUT the ids, then upsert the returned ciphers keeping their stored
// collection ids.
func bulkArchiveWithServer(a *app.App, v *vault.Vault, path string, ids ...string) error {
	var resp struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := a.API.Put(path, &struct {
		IDs []string `json:"ids"`
	}{IDs: ids}, &resp); err != nil {
		return err
	}
	for _, raw := range resp.Data {
		id, err := rawCipherID(raw)
		if err != nil {
			return err
		}
		var collectionIDs []string
		if existing, err := v.EncryptedCipher(id); err == nil {
			collectionIDs = existing.CollectionIDs
		}
		if _, err := v.UpsertCipher(raw, collectionIDs); err != nil {
			return err
		}
	}
	return nil
}

// ---------- archive ----------

// Archive implements ArchiveCommand.run.
func Archive(a *app.App, object, id string) *cli.Response {
	id = strings.ToLower(id)
	if strings.ToLower(object) != "item" {
		return cli.BadRequest("Unknown object.")
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return cli.NotFound()
	}
	view, err := decryptedCipher(v, c)
	if err != nil {
		return cli.Error(err)
	}
	switch {
	case !v.HasPremium():
		return cli.Error("Premium status is required to use this feature.")
	case view.IsArchived():
		return cli.Error("Item is already archived.")
	case view.IsDeleted():
		return cli.Error("Item is in the trash, the item must be restored before archiving.")
	}
	if err := bulkArchiveWithServer(a, v, "/ciphers/archive", view.ID); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}
