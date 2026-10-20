package sendcore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/version"
)

// MaxSingleBlobUploadSize is the Azure single PUT limit (256 MiB); larger files use a block upload.
const MaxSingleBlobUploadSize = 256 * 1024 * 1024

// ---------- authenticated Send API (SendApiService) ----------

// Save creates (id == "") or updates a Send on the server from an encrypted request, uploads the
// encrypted file of a new File Send, and upserts the server response into state. It returns the
// saved Send's id.
func Save(a *app.App, id string, req *Request, encFile []byte) (string, error) {
	var raw []byte
	if id == "" {
		if req.Type == TypeFile {
			var err error
			raw, err = createFileSend(a, req, encFile)
			if err != nil {
				var apiErr *api.ErrorResponse
				if errors.As(err, &apiErr) {
					return "", errors.New(apiErr.SingleMessage())
				}
				return "", err
			}
		} else {
			if err := a.API.Send("POST", "/sends", req, true, &raw, nil); err != nil {
				return "", err
			}
		}
	} else {
		if err := a.API.Send("PUT", "/sends/"+id, req, true, &raw, nil); err != nil {
			return "", err
		}
	}
	d, err := Upsert(a, raw)
	if err != nil {
		return "", err
	}
	return d.ID, nil
}

func createFileSend(a *app.App, req *Request, encFile []byte) ([]byte, error) {
	var upload FileUploadData
	if err := a.API.Send("POST", "/sends/file/v2", req, true, &upload, nil); err != nil {
		return nil, err
	}
	var resp Data
	if len(upload.SendResponse) == 0 || json.Unmarshal(upload.SendResponse, &resp) != nil {
		return nil, errors.New("Invalid file upload response.")
	}
	fileID := ""
	if resp.File != nil && resp.File.ID != nil {
		fileID = *resp.File.ID
	}
	encName := ""
	if req.File != nil && req.File.FileName != nil {
		encName = *req.File.FileName
	}
	var err error
	switch upload.FileUploadType {
	case FileUploadDirect:
		err = uploadDirect(a, resp.ID, fileID, encName, encFile)
	case FileUploadAzure:
		renew := func() (string, error) {
			var r FileUploadData
			if err := a.API.Get("/sends/"+resp.ID+"/file/"+fileID, &r); err != nil {
				return "", err
			}
			return r.URL, nil
		}
		err = UploadAzure(a.API.HTTP, upload.URL, encFile, renew)
	default:
		err = errors.New("Unknown file upload type")
	}
	if err != nil {
		_ = a.API.Delete("/sends/"+resp.ID, nil) // rollback
		return nil, err
	}
	return upload.SendResponse, nil
}

// uploadDirect posts the encrypted file as multipart form data to the Bitwarden server
// (BitwardenFileUploadService).
func uploadDirect(a *app.App, sendID, fileID, encFileName string, encFile []byte) error {
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
	if _, err := part.Write(encFile); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	return a.API.Send("POST", "/sends/"+sendID+"/file/"+fileID, nil, true, nil, &api.RequestOptions{
		RawBody:     &body,
		ContentType: mw.FormDataContentType(),
	})
}

func azureHeaders(req *http.Request, u *url.URL, length int) {
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", u.Query().Get("sv"))
	req.ContentLength = int64(length)
}

// UploadAzure uploads the encrypted file to an Azure blob SAS url (AzureFileUploadService).
func UploadAzure(hc *http.Client, rawURL string, data []byte, renew func() (string, error)) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	if len(data) <= MaxSingleBlobUploadSize {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		req, err := http.NewRequest("PUT", rawURL, bytes.NewReader(data))
		if err != nil {
			return err
		}
		azureHeaders(req, u, len(data))
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		req.Header.Set("Cache-Control", "no-store")
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			return fmt.Errorf("Failed to create Azure blob: %d", resp.StatusCode)
		}
		return nil
	}

	renewIfNecessary := func(raw string) (string, error) {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		expiry, err := time.Parse(time.RFC3339, u.Query().Get("se"))
		if err != nil {
			expiry = time.Now().Add(time.Hour)
		}
		if expiry.Before(time.Now().Add(time.Second)) {
			return renew()
		}
		return raw, nil
	}
	put := func(raw string, body []byte, params [][2]string) (int, error) {
		u, err := url.Parse(raw)
		if err != nil {
			return 0, err
		}
		sv := u.Query().Get("sv")
		q := u.RawQuery
		for _, p := range params {
			if q != "" {
				q += "&"
			}
			q += url.QueryEscape(p[0]) + "=" + url.QueryEscape(p[1])
		}
		u.RawQuery = q
		req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
		req.Header.Set("x-ms-version", sv)
		req.Header.Set("Cache-Control", "no-store")
		req.ContentLength = int64(len(body))
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	raw, err := renewIfNecessary(rawURL)
	if err != nil {
		return err
	}
	// Only one block: the max block size exceeds the max file size.
	blockID := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("0", 47) + "0"))
	status, err := put(raw, data, [][2]string{{"comp", "block"}, {"blockid", blockID}})
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("Unsuccessful block PUT. Received status %d", status)
	}
	if raw, err = renewIfNecessary(raw); err != nil {
		return err
	}
	xml := `<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>` + blockID + `</Latest></BlockList>`
	status, err = put(raw, []byte(xml), [][2]string{{"comp", "blocklist"}})
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("Unsuccessful block list PUT. Received status %d", status)
	}
	return nil
}

// DeleteSend deletes a Send on the server and removes it from state (SendApiService.delete).
func DeleteSend(a *app.App, id string) error {
	if err := a.API.Delete("/sends/"+id, nil); err != nil {
		return err
	}
	return Remove(a, id)
}

// RemovePassword removes the password of a Send and upserts the result (SendApiService.removePassword).
func RemovePassword(a *app.App, id string) error {
	var raw []byte
	if err := a.API.Send("PUT", "/sends/"+id+"/remove-password", nil, true, &raw, nil); err != nil {
		return err
	}
	_, err := Upsert(a, raw)
	return err
}

// ---------- anonymous access (receive) ----------

// AccessToken is a Send access token (SendAccessToken).
type AccessToken struct {
	Token     string
	ExpiresAt time.Time
}

// Credentials are the optional credentials of a token request (SendAccessDomainCredentials).
type Credentials struct {
	Kind            string // "password", "email" or "email_otp"
	PasswordHashB64 string
	Email           string
	OTP             string
}

// TokenError is GetSendAccessTokenError / TryGetSendAccessTokenError.
type TokenError struct {
	// Kind is "expected_server", "unexpected_server", "unknown" or "expired".
	Kind string
	// Error is the server error object (map) for server kinds, or a string for "unknown".
	Error any
}

// ErrorType returns the send_access_error_type and error of an expected server error.
func (e *TokenError) ErrorType() (errType, errCode string) {
	m, ok := e.Error.(map[string]any)
	if !ok {
		return "", ""
	}
	errType, _ = m["send_access_error_type"].(string)
	errCode, _ = m["error"].(string)
	return
}

// Is checks an expected_server error against the error code and send_access_error_type
// (the predicates of invalid-grant-errors.type.ts / invalid-request-errors.type.ts).
func (e *TokenError) Is(errCode, errType string) bool {
	if e == nil || e.Kind != "expected_server" {
		return false
	}
	t, c := e.ErrorType()
	return c == errCode && t == errType
}

// RequestAccessToken requests a Send access token from identityURL using the send_access grant
// (receive.command.ts mintSendAccessToken; the SDK request for the configured server is
// equivalent on the wire).
// requireHTTPS refuses to send the credentials over plain http (cross-instance mints).
func RequestAccessToken(hc *http.Client, identityURL, appID, sendID string, creds *Credentials, requireHTTPS bool) (*AccessToken, *TokenError) {
	if requireHTTPS && IsInsecureURL(identityURL) {
		return nil, &TokenError{Kind: "unknown", Error: "Send access requires https, but the url was " + identityURL}
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	type kv struct{ k, v string }
	fields := []kv{{"grant_type", "send_access"}, {"client_id", "send"}, {"scope", "api.send.access"}, {"send_id", sendID}}
	if creds != nil {
		switch creds.Kind {
		case "password":
			fields = append(fields, kv{"password_hash_b64", creds.PasswordHashB64})
		case "email":
			fields = append(fields, kv{"email", creds.Email})
		case "email_otp":
			fields = append(fields, kv{"email", creds.Email}, kv{"otp", creds.OTP})
		}
	}
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = encodeURIComponent(f.k) + "=" + encodeURIComponent(f.v)
	}
	req, err := http.NewRequest("POST", identityURL+"/connect/token", strings.NewReader(strings.Join(parts, "&")))
	if err != nil {
		return nil, &TokenError{Kind: "unknown", Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Device-Identifier", appID)
	req.Header.Set("Device-Type", strconv.Itoa(api.DeviceType()))
	req.Header.Set("Bitwarden-Client-Name", "cli")
	req.Header.Set("Bitwarden-Client-Version", version.Version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &TokenError{Kind: "unknown", Error: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		_ = json.Unmarshal(raw, &body)
	}
	if resp.StatusCode == 200 && body != nil && body["access_token"] != nil {
		tok, _ := body["access_token"].(string)
		exp, ok := body["expires_in"].(float64)
		if !ok {
			return nil, &TokenError{Kind: "unknown", Error: "Send access token response had no valid expires_in"}
		}
		return &AccessToken{Token: tok, ExpiresAt: time.Now().Add(time.Duration(exp * float64(time.Second)))}, nil
	}
	if resp.StatusCode == 400 && body != nil && body["error"] != nil {
		e := map[string]any{"error": body["error"]}
		if v, ok := body["error_description"]; ok {
			e["error_description"] = v
		}
		if v, ok := body["send_access_error_type"]; ok {
			e["send_access_error_type"] = v
		}
		return nil, &TokenError{Kind: "expected_server", Error: e}
	}
	return nil, &TokenError{Kind: "unknown", Error: fmt.Sprintf("Unexpected response requesting a Send access token (%d)", resp.StatusCode)}
}

// encodeURIComponent mirrors JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	const keep = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for _, c := range []byte(s) {
		if strings.IndexByte(keep, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Access posts to {apiURL}/sends/access with the access token (SendApiService.postSendAccess).
func Access(a *app.App, apiURL string, tok *AccessToken) (*AccessData, error) {
	var d AccessData
	err := a.API.Send("POST", "/sends/access", nil, false, &d, &api.RequestOptions{
		BaseURL: apiURL,
		Headers: map[string]string{"Authorization": "Bearer " + tok.Token},
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// FileDownloadURL resolves where a file Send's contents can be downloaded
// (SendApiService.getSendFileDownloadData).
func FileDownloadURL(a *app.App, apiURL, fileID string, tok *AccessToken) (string, error) {
	var d FileDownloadData
	err := a.API.Send("POST", "/sends/access/file/"+fileID, nil, false, &d, &api.RequestOptions{
		BaseURL: apiURL,
		Headers: map[string]string{"Authorization": "Bearer " + tok.Token},
	})
	if err != nil {
		return "", err
	}
	return d.URL, nil
}

// Download fetches a url and returns the status code and body.
func Download(hc *http.Client, rawURL string) (int, []byte, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("cache", "no-cache")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, nil
	}
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}
