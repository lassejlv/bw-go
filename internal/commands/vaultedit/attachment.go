package vaultedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/sendcore"
	"github.com/lassejlv/bw-go/internal/vault"
)

// FileUploadType mirrors the FileUploadType enum.
const (
	fileUploadDirect = 0
	fileUploadAzure  = 1
)

// attachmentRequest mirrors the AttachmentRequest object literal built by
// CipherFileUploadService.upload (property order: key, fileName, fileSize, adminRequest,
// lastKnownRevisionDate).
type attachmentRequest struct {
	Key                   string    `json:"key"`
	FileName              string    `json:"fileName"`
	FileSize              int       `json:"fileSize"`
	AdminRequest          bool      `json:"adminRequest"`
	LastKnownRevisionDate *cli.Date `json:"lastKnownRevisionDate"`
}

// attachmentUploadData mirrors AttachmentUploadDataResponse.
type attachmentUploadData struct {
	AttachmentID       string          `json:"attachmentId"`
	FileUploadType     int             `json:"fileUploadType"`
	CipherResponse     json.RawMessage `json:"cipherResponse"`
	CipherMiniResponse json.RawMessage `json:"cipherMiniResponse"`
	URL                *string         `json:"url"`
}

// singleMessageError converts API errors to their single message (CipherFileUploadService.upload
// rethrows ErrorResponse as `new Error(e.getSingleMessage())`).
func singleMessageError(err error) error {
	var apiErr *api.ErrorResponse
	if errors.As(err, &apiErr) {
		return errors.New(apiErr.SingleMessage())
	}
	return err
}

// saveAttachmentRawWithServer mirrors cipherService.saveAttachmentRawWithServer (legacy path,
// non-admin): the file name is encrypted with the cipher key (or the user/org key), the file with a
// new attachment key wrapped by that key; the metadata is posted to /ciphers/{id}/attachment/v2 and
// the encrypted file uploaded directly or to Azure. The returned cipher response is upserted and
// decrypted.
func saveAttachmentRawWithServer(a *app.App, v *vault.Vault, c *vault.Cipher, fileName string, data []byte) (*vault.CipherView, error) {
	cipherKey, err := v.Keys().CipherKey(c)
	if err != nil {
		return nil, err
	}
	encFileName, err := crypto.EncryptString(fileName, cipherKey)
	if err != nil {
		return nil, err
	}
	attachmentKey := crypto.GenerateKey()
	wrappedKey, err := crypto.WrapKey(attachmentKey, cipherKey)
	if err != nil {
		return nil, err
	}
	encData, err := crypto.EncryptBytes(data, attachmentKey)
	if err != nil {
		return nil, err
	}
	req := &attachmentRequest{
		Key:                   wrappedKey,
		FileName:              encFileName,
		FileSize:              len(encData),
		LastKnownRevisionDate: c.RevisionDate,
	}

	var upload attachmentUploadData
	if err := a.API.Post("/ciphers/"+c.ID+"/attachment/v2", req, &upload); err != nil {
		return nil, singleMessageError(err)
	}
	responseID := c.ID
	if id, err := rawCipherID(upload.CipherResponse); err == nil {
		responseID = id
	}
	rollback := func() {
		_ = a.API.Delete("/ciphers/"+responseID+"/attachment/"+upload.AttachmentID, nil)
	}
	switch upload.FileUploadType {
	case fileUploadDirect:
		err = postAttachmentFile(a, responseID, upload.AttachmentID, encFileName, encData)
	case fileUploadAzure:
		url := ""
		if upload.URL != nil {
			url = *upload.URL
		}
		renew := func() (string, error) {
			var r attachmentUploadData
			if err := a.API.Get("/ciphers/"+responseID+"/attachment/"+upload.AttachmentID+"/renew", &r); err != nil {
				return "", err
			}
			if r.URL == nil {
				return "", nil
			}
			return *r.URL, nil
		}
		err = sendcore.UploadAzure(a.API.HTTP, url, encData, renew)
	default:
		err = errUnknownUploadType
	}
	if err != nil {
		rollback()
		return nil, singleMessageError(err)
	}
	return upsertResponse(v, upload.CipherResponse, c.CollectionIDs)
}

func rawCipherID(raw json.RawMessage) (string, error) {
	var x struct {
		ID string `json:"id"`
	}
	if isNullJSON(raw) {
		return "", errors.New("no cipher")
	}
	if err := json.Unmarshal(raw, &x); err != nil || x.ID == "" {
		return "", errors.New("no cipher id")
	}
	return x.ID, nil
}

// postAttachmentFile posts the encrypted file as multipart form data (BitwardenFileUploadService
// + apiService.postAttachmentFile): field "data" with the encrypted file name as file name.
func postAttachmentFile(a *app.App, cipherID, attachmentID, encFileName string, encData []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="data"; filename="%s"`,
		strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(encFileName)))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := part.Write(encData); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	return a.API.Send("POST", "/ciphers/"+cipherID+"/attachment/"+attachmentID, nil, true, nil, &api.RequestOptions{
		RawBody:     &body,
		ContentType: mw.FormDataContentType(),
	})
}

// deleteAttachmentWithServer mirrors cipherService.deleteAttachmentWithServer (legacy path,
// non-admin): DELETE the attachment, then remove it from the stored cipher and take over the
// revision date the server returned.
func deleteAttachmentWithServer(a *app.App, v *vault.Vault, cipherID, attachmentID string) error {
	var resp struct {
		Cipher struct {
			RevisionDate *string `json:"revisionDate"`
		} `json:"cipher"`
	}
	if err := a.API.Send("DELETE", "/ciphers/"+cipherID+"/attachment/"+attachmentID, nil, true, &resp, nil); err != nil {
		return singleMessageError(err)
	}
	raw, ok := v.Account().Vault.Ciphers[cipherID]
	if !ok {
		return nil
	}
	var stored struct {
		Attachments []json.RawMessage `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Attachments == nil {
		return nil
	}
	kept := []json.RawMessage{}
	for _, att := range stored.Attachments {
		var x struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(att, &x)
		if x.ID != attachmentID {
			kept = append(kept, att)
		}
	}
	var revision any // undefined revisionDate is stored as null
	if resp.Cipher.RevisionDate != nil {
		revision = *resp.Cipher.RevisionDate
	}
	return v.PatchCipher(cipherID, map[string]any{"attachments": kept, "revisionDate": revision})
}
