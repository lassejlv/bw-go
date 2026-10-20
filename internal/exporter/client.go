package exporter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/lassejlv/bw-go/internal/api"
)

// OrganizationExportResponse mirrors OrganizationExportResponse (raw server objects).
type OrganizationExportResponse struct {
	Collections []json.RawMessage `json:"collections"`
	Ciphers     []json.RawMessage `json:"ciphers"`
}

// Client is the server access the export services need.
type Client interface {
	// GetOrganizationExport mirrors VaultExportApiService.getOrganizationExport
	// (GET /organizations/{id}/export).
	GetOrganizationExport(organizationID string) (*OrganizationExportResponse, error)
	// GetAttachmentData mirrors apiService.getAttachmentData and returns the download url
	// (GET /ciphers/{id}/attachment/{attachmentId}).
	GetAttachmentData(cipherID, attachmentID string) (string, error)
	// DownloadAttachment fetches the encrypted attachment content.
	DownloadAttachment(url string) ([]byte, error)
}

// APIClient implements Client with the CLI's API client.
type APIClient struct{ C *api.Client }

// GetOrganizationExport implements Client.
func (c APIClient) GetOrganizationExport(organizationID string) (*OrganizationExportResponse, error) {
	var r *OrganizationExportResponse
	if err := c.C.Get("/organizations/"+organizationID+"/export", &r); err != nil {
		return nil, err
	}
	return r, nil
}

// GetAttachmentData implements Client.
func (c APIClient) GetAttachmentData(cipherID, attachmentID string) (string, error) {
	var r struct {
		URL string `json:"url"`
	}
	if err := c.C.Get("/ciphers/"+cipherID+"/attachment/"+attachmentID, &r); err != nil {
		return "", err
	}
	return r.URL, nil
}

// DownloadAttachment implements Client: an unauthenticated fetch that must answer 200.
func (c APIClient) DownloadAttachment(rawURL string) ([]byte, error) {
	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cache-Control", "no-store")
	hc := c.C.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("Error downloading attachment")
	}
	return io.ReadAll(resp.Body)
}
