package vaultedit

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

// EditOptions are the options of `bw edit` (edit.command.ts Options).
type EditOptions struct {
	// OrganizationID is --organizationid (org-collection).
	OrganizationID string
}

// EditEncoded is the CLI entry point of `bw edit`: it reads the base64 encoded JSON from the
// argument (or stdin) and runs Edit.
func EditEncoded(a *app.App, object, id, encodedJSON string, opts EditOptions) *cli.Response {
	req, r := readEncodedJSON(encodedJSON)
	if r != nil {
		return r
	}
	return Edit(a, object, id, req, opts)
}

// Edit implements EditCommand.run with already decoded request JSON (as `bw serve` passes it).
func Edit(a *app.App, object, id string, req json.RawMessage, opts EditOptions) *cli.Response {
	if len(req) == 0 {
		return cli.BadRequest("`requestJson` was not provided.")
	}
	id = strings.ToLower(id)
	switch strings.ToLower(object) {
	case "item":
		return editCipher(a, id, req)
	case "item-collections":
		return editCipherCollections(a, id, req)
	case "folder":
		return editFolder(a, id, req)
	case "org-collection":
		return editOrganizationCollection(a, id, req, opts.OrganizationID)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

// hiddenFieldKey keys original hidden field values by name (a nil name is its own key).
type hiddenFieldKey struct {
	name  string
	isNil bool
}

func fieldKey(name *string) hiddenFieldKey {
	if name == nil {
		return hiddenFieldKey{isNil: true}
	}
	return hiddenFieldKey{name: *name}
}

func editCipher(a *app.App, id string, raw json.RawMessage) *cli.Response {
	var req vault.CipherExport
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	hasPremium := v.HasPremium()
	if err != nil {
		return cli.NotFound()
	}
	if !c.Edit {
		return cli.NoEditPermission()
	}
	view, err := decryptedCipher(v, c)
	if err != nil {
		return cli.Error(err)
	}
	if view.IsDeleted() {
		return cli.BadRequest("You may not edit a deleted item. Use the restore command first.")
	}

	// Users without permission to view passwords only ever see redacted (null) passwords, TOTP
	// seeds and hidden field values; keep the real values when those nulls are round-tripped.
	canViewPassword := view.ViewPassword
	var origPassword, origTotp *string
	if view.Login != nil {
		origPassword, origTotp = view.Login.Password, view.Login.Totp
	}
	origHidden := map[hiddenFieldKey][]*string{}
	for _, f := range view.Fields {
		if f.Type == vault.FieldTypeHidden {
			k := fieldKey(f.Name)
			origHidden[k] = append(origHidden[k], f.Value)
		}
	}

	if view, err = req.ToView(view, false); err != nil {
		return cli.Error(err)
	}

	if !canViewPassword {
		if view.Login != nil {
			if view.Login.Password == nil {
				view.Login.Password = origPassword
			}
			if view.Login.Totp == nil {
				view.Login.Totp = origTotp
			}
		}
		for i := range view.Fields {
			f := &view.Fields[i]
			if f.Type != vault.FieldTypeHidden || f.Value != nil {
				continue
			}
			k := fieldKey(f.Name)
			if values := origHidden[k]; len(values) > 0 {
				f.Value = values[0]
				origHidden[k] = values[1:]
			}
		}
	}

	// Editing an archived item without premium moves it back to the vault.
	if view.IsArchived() && !hasPremium {
		if !promptForArchiveEdit() {
			return cli.Error("Edit cancelled.")
		}
		view.ArchivedDate = nil
	}

	if v.IsCipherRestricted(view) {
		return cli.Error("Editing this item type is restricted by organizational policy.")
	}
	isPersonal := view.OrganizationID == nil || *view.OrganizationID == ""
	if isPersonal && v.PolicyAppliesToUser(vault.PolicyOrganizationDataOwnership) {
		return cli.Error("An organization policy restricts editing this cipher. Please use the share command first before modifying it.")
	}

	updated, err := updateWithServer(a, v, view)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewCipherResponse(updated))
}

// promptArchiveEdit asks whether to move an archived item back to the vault; replaceable in tests.
var promptArchiveEdit = func() (int, error) {
	return cli.PromptSelect("When you edit and save details for an archived item without a Premium subscription, it'll be moved from your archive back to your vault.",
		[]string{"Move now", "Cancel"})
}

// stdinIsTTY reports whether prompting is possible; replaceable in tests.
var stdinIsTTY = cli.StdinIsTTY

// promptForArchiveEdit mirrors EditCommand.promptForArchiveEdit.
func promptForArchiveEdit() bool {
	if os.Getenv("BW_SERVE") == "true" || os.Getenv("BW_NOINTERACTION") == "true" || !stdinIsTTY() {
		cli.WriteLn("Archive is only available with a Premium subscription, which has ended. Your edit was saved and the item was moved back to your vault.", false, false)
		return true
	}
	i, err := promptArchiveEdit()
	return err == nil && i == 0
}

// updateWithServer mirrors cipherService.updateWithServer (legacy path): adjust the password
// history, encrypt, PUT /ciphers/{id} (or /partial without edit permission), upsert and decrypt.
func updateWithServer(a *app.App, v *vault.Vault, view *vault.CipherView) (*vault.CipherView, error) {
	v.PrepareForSave(view)
	c, err := v.EncryptCipher(view)
	if err != nil {
		return nil, err
	}
	var resp json.RawMessage
	if c.Edit {
		err = a.API.Put("/ciphers/"+c.ID, vault.NewCipherRequest(c, v.UserID()), &resp)
	} else {
		err = a.API.Put("/ciphers/"+c.ID+"/partial", &vault.CipherPartialRequest{FolderID: c.FolderID, Favorite: c.Favorite}, &resp)
	}
	if err != nil {
		return nil, err
	}
	return upsertResponse(v, resp, c.CollectionIDs)
}

func editCipherCollections(a *app.App, id string, raw json.RawMessage) *cli.Response {
	var req []string
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return cli.NotFound()
	}
	if c.OrganizationID == nil {
		return cli.BadRequest("Item does not belong to an organization. Consider moving it first.")
	}
	if !c.CanViewPassword() {
		return cli.NoEditPermission()
	}
	if req == nil {
		req = []string{}
	}
	// cipherSdkService.saveCollectionsWithServer -> CiphersClient.update_collection
	var resp struct {
		Cipher json.RawMessage `json:"cipher"`
	}
	if err := a.API.Put("/ciphers/"+c.ID+"/collections_v2", &vault.CipherCollectionsRequest{CollectionIDs: req}, &resp); err != nil {
		return cli.Error(err)
	}
	if isNullJSON(resp.Cipher) {
		// The user no longer has access to the cipher after the collection change.
		if err := v.DeleteCiphers(c.ID); err != nil {
			return cli.Error(err)
		}
		return cli.Error(errNoElements)
	}
	// CipherDetailsResponse carries its collectionIds.
	updated, err := upsertResponse(v, resp.Cipher, nil)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewCipherResponse(updated))
}

func editFolder(a *app.App, id string, raw json.RawMessage) *cli.Response {
	var req vault.FolderExport
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	if _, ok := v.Account().Vault.Folders[id]; !ok {
		return cli.NotFound()
	}
	view, err := v.Folder(id)
	if err != nil {
		// Folder.decrypt leaves an undecryptable name as "[error: cannot decrypt]"; it is
		// replaced by the request's name anyway.
		view = &vault.FolderView{ID: id, Name: vault.DecryptError}
	}
	view = req.ToView(view)
	enc, err := vault.EncryptFolder(view, v.Keys().UserKey())
	if err != nil {
		return cli.Error(err)
	}
	var resp json.RawMessage
	if err := a.API.Put("/folders/"+id, enc, &resp); err != nil {
		return cli.Error(err)
	}
	return folderResult(v, resp)
}

func editOrganizationCollection(a *app.App, id string, raw json.RawMessage, optOrgID string) *cli.Response {
	if !isGUID(id) {
		return cli.BadRequest("`" + id + "` is not a GUID.")
	}
	var req orgCollectionRequest
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	orgID, r := resolveOrganizationID(optOrgID, &req)
	if r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	if !v.Keys().HasOrgKey(orgID) {
		return cli.Error("No encryption key for this organization.")
	}
	// BaseCollectionRequest keeps its [] defaults for null groups/users.
	groups := []vault.SelectionReadOnlyRequest{}
	if req.Groups != nil {
		groups = selectionRequests(req.Groups)
	}
	users := []vault.SelectionReadOnlyRequest{}
	if req.Users != nil {
		users = selectionRequests(req.Users)
	}
	name, err := vault.EncryptCollectionName(req.Name.Get(), orgID, v.Keys())
	if err != nil {
		return cli.Error(err)
	}
	body := &vault.CollectionRequest{ExternalID: req.ExternalID.Ptr(), Groups: groups, Users: users, Name: &name}
	var resp collectionAccessResponse
	if err := a.API.Put("/organizations/"+orgID+"/collections/"+id, body, &resp); err != nil {
		return cli.Error(err)
	}
	return orgCollectionResult(&req, &resp)
}
