package vaultcmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/vault"
)

// getAttachment mirrors GetCommand.getAttachment (+ DownloadCommand.saveAttachmentToFile).
func getAttachment(a *app.App, id string, opts GetOptions) *cli.Response {
	if opts.ItemID == "" {
		return cli.BadRequest("--itemid <itemid> required.")
	}
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}

	itemID := strings.ToLower(opts.ItemID)
	if r, _ := getCipher(v, itemID, nil); !r.Success {
		return r
	}

	cipher, multi, err := getCipherView(v, itemID)
	if err != nil {
		return cli.Error(err)
	}
	if cipher == nil || multi != nil || len(cipher.Attachments) == 0 {
		return cli.Error("No attachments available for this item.")
	}

	var attachments []*vault.AttachmentView
	for i := range cipher.Attachments {
		att := &cipher.Attachments[i]
		if (att.ID != nil && strings.ToLower(*att.ID) == id) ||
			(att.FileName != nil && strings.Contains(strings.ToLower(*att.FileName), id)) {
			attachments = append(attachments, att)
		}
	}
	if len(attachments) == 0 {
		return cli.Error("Attachment `" + id + "` was not found.")
	}

	var exact []*vault.AttachmentView
	for _, att := range attachments {
		if att.FileName != nil && strings.ToLower(*att.FileName) == id {
			exact = append(exact, att)
		}
	}
	if len(exact) == 1 {
		attachments = exact
	}
	if len(attachments) > 1 {
		ids := make([]string, 0, len(attachments))
		for _, att := range attachments {
			ids = append(ids, derefString(att.ID))
		}
		return cli.MultipleResults(ids)
	}
	attachment := attachments[0]

	encCipher, encErr := v.EncryptedCipher(cipher.ID)
	if !v.HasPremium() {
		if encErr != nil || encCipher.OrganizationID == nil {
			return cli.Error("Premium status is required to use this feature.")
		}
	}

	// apiService.getAttachmentData: a 404 falls back to the url stored with the attachment.
	var downloadURL string
	var data struct {
		URL *string `json:"url"`
	}
	if err := a.API.Get("/ciphers/"+cipher.ID+"/attachment/"+derefString(attachment.ID), &data); err != nil {
		var apiErr *api.ErrorResponse
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			downloadURL = derefString(attachment.URL)
		} else if errors.As(err, &apiErr) {
			return cli.Error(apiErr.SingleMessage())
		} else {
			return cli.Error(err)
		}
	} else {
		downloadURL = derefString(data.URL)
	}

	fileName := fmt.Sprintf("BitwardenAttachment-%d", time.Now().UnixMilli())
	if attachment.FileName != nil {
		fileName = *attachment.FileName
	}
	fileName = path.Base(fileName)

	decrypt := func(enc []byte) ([]byte, error) {
		// cipherEncryptionService.decryptAttachmentContent: the attachment key when present,
		// otherwise the cipher key.
		key := attachment.Key
		if key == nil {
			if encErr != nil {
				return nil, encErr
			}
			k, err := v.Keys().CipherKey(encCipher)
			if err != nil {
				return nil, err
			}
			key = k
		}
		return crypto.DecryptBytes(enc, key)
	}
	return saveAttachmentToFile(a.API.HTTP, downloadURL, fileName, decrypt, opts.Output)
}

// saveAttachmentToFile mirrors DownloadCommand.saveAttachmentToFile.
func saveAttachmentToFile(client *http.Client, rawURL, fileName string, decrypt func([]byte) ([]byte, error), output string) *cli.Response {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return cli.Error(err)
	}
	// Upstream sends `cache: no-cache` as a (literal) request header.
	req.Header.Set("cache", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return cli.Error(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cli.Error(fmt.Sprintf("A %d error occurred while downloading the attachment.", resp.StatusCode))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return cli.Error("An error occurred while saving the attachment.")
	}
	dec, err := decrypt(body)
	if err != nil {
		return cli.Error("An error occurred while saving the attachment.")
	}
	if os.Getenv("BW_SERVE") == "true" {
		return cli.Success(cli.NewFile(dec, fileName))
	}
	return cli.SaveResultToFile(dec, output, fileName)
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
