package vaultedit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

// CreateOptions are the options of `bw create` (create.command.ts Options).
type CreateOptions struct {
	// ItemID is --itemid (attachment's item id).
	ItemID string
	// OrganizationID is --organizationid (org-collection).
	OrganizationID string
	// File is --file (path of the attachment to upload).
	File string
	// Upload carries an attachment uploaded through `bw serve` (additionalData). When set, File is
	// ignored like upstream does when BW_SERVE is "true".
	Upload *FileUpload
}

// FileUpload is a file received by `bw serve` (additionalData.fileBuffer / fileName).
type FileUpload struct {
	Data     []byte
	FileName string
}

// CreateEncoded is the CLI entry point of `bw create`: it reads the base64 encoded JSON from the
// argument (or stdin) and runs Create. Attachments take no JSON.
func CreateEncoded(a *app.App, object, encodedJSON string, opts CreateOptions) *cli.Response {
	var req json.RawMessage
	if object != "attachment" {
		var r *cli.Response
		if req, r = readEncodedJSON(encodedJSON); r != nil {
			return r
		}
	}
	return Create(a, object, req, opts)
}

// Create implements CreateCommand.run with already decoded request JSON (as `bw serve` passes it).
func Create(a *app.App, object string, req json.RawMessage, opts CreateOptions) *cli.Response {
	if object != "attachment" && len(req) == 0 {
		return cli.BadRequest("`requestJson` was not provided.")
	}
	switch strings.ToLower(object) {
	case "item":
		return createCipher(a, req)
	case "attachment":
		return createAttachment(a, opts)
	case "folder":
		return createFolder(a, req)
	case "org-collection":
		return createOrganizationCollection(a, req, opts.OrganizationID)
	default:
		return cli.BadRequest("Unknown object.")
	}
}

func createCipher(a *app.App, raw json.RawMessage) *cli.Response {
	var req vault.CipherExport
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	flags := Features(a)
	view, err := req.ToView(nil, flags.DeriveSSHKeys)
	if err != nil {
		return cli.Error(err)
	}
	if isNewItemType(view.Type) && !flags.NewItemTypes {
		return cli.Error(fmt.Sprintf("Item type %d is not available.", view.Type))
	}
	if v.IsCipherRestricted(view) {
		return cli.Error("Creating this item type is restricted by organizational policy.")
	}
	// upstream converts the request a second time for the actual save
	if view, err = req.ToView(nil, flags.DeriveSSHKeys); err != nil {
		return cli.Error(err)
	}
	created, err := createWithServer(a, v, view)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewCipherResponse(created))
}

// createWithServer mirrors cipherService.createWithServer (legacy path): encrypt, POST /ciphers
// (or /ciphers/create when collections are assigned), upsert and decrypt.
func createWithServer(a *app.App, v *vault.Vault, view *vault.CipherView) (*vault.CipherView, error) {
	v.PrepareForSave(view)
	c, err := v.EncryptCipher(view)
	if err != nil {
		return nil, err
	}
	var resp json.RawMessage
	if len(c.CollectionIDs) > 0 {
		err = a.API.Post("/ciphers/create", vault.NewCipherCreateRequest(c, v.UserID()), &resp)
	} else {
		err = a.API.Post("/ciphers", vault.NewCipherRequest(c, v.UserID()), &resp)
	}
	if err != nil {
		return nil, err
	}
	return upsertResponse(v, resp, c.CollectionIDs)
}

func createAttachment(a *app.App, opts CreateOptions) *cli.Response {
	if opts.ItemID == "" {
		return cli.BadRequest("`itemid` option is required.")
	}
	var data []byte
	var fileName string
	if opts.Upload != nil {
		data, fileName = opts.Upload.Data, opts.Upload.FileName
	} else if os.Getenv("BW_SERVE") == "true" {
		// In serve mode attachments only come from the multipart upload; never read the
		// server's local filesystem on behalf of an HTTP client.
		return cli.BadRequest("File not provided.")
	} else {
		if opts.File == "" {
			return cli.BadRequest("`file` option is required.")
		}
		filePath, _ := filepath.Abs(opts.File)
		if _, err := os.Stat(opts.File); err != nil {
			return cli.BadRequest("Cannot find file at " + filePath)
		}
		b, err := os.ReadFile(filePath)
		if err != nil {
			return cli.Error(err)
		}
		data, fileName = b, filepath.Base(filePath)
	}
	if data == nil {
		return cli.BadRequest("File not provided.")
	}
	if strings.TrimSpace(fileName) == "" {
		return cli.BadRequest("File name not provided.")
	}

	v, r := openVault(a)
	if r != nil {
		return r
	}
	c, err := v.EncryptedCipher(strings.ToLower(opts.ItemID))
	if err != nil {
		return cli.NotFound()
	}
	if c.OrganizationID == nil && !v.HasPremium() {
		return cli.Error("Premium status is required to use this feature.")
	}
	updated, err := saveAttachmentRawWithServer(a, v, c, fileName, data)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewCipherResponse(updated))
}

func createFolder(a *app.App, raw json.RawMessage) *cli.Response {
	var req vault.FolderExport
	if r := parseRequest(raw, &req); r != nil {
		return r
	}
	v, r := openVault(a)
	if r != nil {
		return r
	}
	enc, err := vault.EncryptFolder(req.ToView(nil), v.Keys().UserKey())
	if err != nil {
		return cli.Error(err)
	}
	var resp json.RawMessage
	if err := a.API.Post("/folders", enc, &resp); err != nil {
		return cli.Error(err)
	}
	return folderResult(v, resp)
}

// folderResult upserts a folder response (folderService.upsert) and returns the FolderResponse.
func folderResult(v *vault.Vault, resp json.RawMessage) *cli.Response {
	if isNullJSON(resp) {
		return cli.Error("Invalid response from server.")
	}
	f, err := v.UpsertFolder(resp)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(vault.NewFolderResponse(f))
}

// orgCollectionRequest is OrganizationCollectionRequest (CollectionExport + groups/users).
type orgCollectionRequest = vault.CollectionExport

// resolveOrganizationID implements the organization id resolution shared by create/edit
// org-collection: the option wins, the request's organizationId is the fallback, both must agree.
func resolveOrganizationID(optOrgID string, req *orgCollectionRequest) (string, *cli.Response) {
	reqOrgID := req.OrganizationID.Get()
	orgID := optOrgID
	if isNullOrWhitespace(optOrgID) {
		orgID = reqOrgID
	}
	if isNullOrWhitespace(orgID) {
		return "", cli.BadRequest("An organization id is required, either via the `--organizationid` option " +
			"(or `organizationId` query parameter when using `bwgo serve`), " +
			"or the request's `organizationId` property.")
	}
	if !isGUID(orgID) {
		return "", cli.BadRequest("`" + orgID + "` is not a GUID.")
	}
	if !isNullOrWhitespace(optOrgID) && !isNullOrWhitespace(reqOrgID) && optOrgID != reqOrgID {
		return "", cli.BadRequest("The `--organizationid` option (or `organizationId` query parameter) does not match " +
			"the request's `organizationId` property.")
	}
	req.OrganizationID = vault.Some(orgID)
	if req.Name.Val == nil || strings.TrimSpace(*req.Name.Val) == "" {
		return "", cli.BadRequest("Collection name is required.")
	}
	return orgID, nil
}

func selectionRequests(list []vault.SelectionReadOnly) []vault.SelectionReadOnlyRequest {
	out := []vault.SelectionReadOnlyRequest{}
	for _, s := range list {
		out = append(out, vault.SelectionReadOnlyRequest{ID: s.ID, ReadOnly: s.ReadOnly, HidePasswords: s.HidePasswords, Manage: s.Manage})
	}
	return out
}

// collectionAccessResponse is the part of CollectionAccessDetailsResponse the CLI reads.
type collectionAccessResponse struct {
	ID     string                    `json:"id"`
	Groups []vault.SelectionReadOnly `json:"groups"`
	Users  []vault.SelectionReadOnly `json:"users"`
}

// orgCollectionResult builds the OrganizationCollectionResponse from the request and the server
// response (CollectionExport.toView(req, response.id)).
func orgCollectionResult(req *orgCollectionRequest, resp *collectionAccessResponse) *cli.Response {
	view := &vault.CollectionView{ID: resp.ID, OrganizationID: req.OrganizationID.Get(), Name: req.Name.Get()}
	groups, users := resp.Groups, resp.Users
	if groups == nil {
		groups = []vault.SelectionReadOnly{}
	}
	if users == nil {
		users = []vault.SelectionReadOnly{}
	}
	res := vault.NewOrganizationCollectionResponse(view, groups, users)
	res.ExternalID = req.ExternalID // view.externalId = req.externalId (keeps null vs undefined)
	return cli.Success(res)
}

func createOrganizationCollection(a *app.App, raw json.RawMessage, optOrgID string) *cli.Response {
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
	orgKey, err := v.Keys().OrgKey(orgID)
	if err != nil || orgKey == nil {
		return cli.Error("No encryption key for this organization.")
	}
	org := v.Organization(orgID)
	if org == nil {
		return cli.Error("Cannot read properties of undefined (reading 'organizationUserId')")
	}
	currentOrgUserID := ""
	if org.OrganizationUserID != nil {
		currentOrgUserID = *org.OrganizationUserID
	}
	// BaseCollectionRequest keeps its [] defaults for null groups/users.
	groups := []vault.SelectionReadOnlyRequest{}
	if req.Groups != nil {
		groups = selectionRequests(req.Groups)
	}
	users := []vault.SelectionReadOnlyRequest{{ID: currentOrgUserID, Manage: true}}
	if req.Users != nil {
		users = selectionRequests(req.Users)
	}
	name, err := vault.EncryptCollectionName(req.Name.Get(), orgID, v.Keys())
	if err != nil {
		return cli.Error(err)
	}
	body := &vault.CollectionRequest{ExternalID: req.ExternalID.Ptr(), Groups: groups, Users: users, Name: &name}
	var resp collectionAccessResponse
	if err := a.API.Post("/organizations/"+orgID+"/collections", body, &resp); err != nil {
		return cli.Error(err)
	}
	return orgCollectionResult(&req, &resp)
}

// ---------- attachments ----------

var errUnknownUploadType = errors.New("Unknown file upload type")
