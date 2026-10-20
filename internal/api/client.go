// Package api is the HTTP client for the Bitwarden server (identity + api services).
package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/version"
)

// Device types for CLI clients (DeviceType enum).
const (
	DeviceWindowsCLI = 23
	DeviceMacOsCLI   = 24
	DeviceLinuxCLI   = 25
)

// DeviceType returns the CLI device type for the current OS.
func DeviceType() int {
	switch runtime.GOOS {
	case "windows":
		return DeviceWindowsCLI
	case "darwin":
		return DeviceMacOsCLI
	default:
		return DeviceLinuxCLI
	}
}

// DeviceName returns the device string (platform name) for the current OS.
func DeviceName() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return "linux"
	}
}

// ErrorResponse mirrors the server error model.
type ErrorResponse struct {
	Message          string              `json:"message"`
	ValidationErrors map[string][]string `json:"validationErrors"`
	// ValidationErrorKeys holds the ValidationErrors keys in server order (JS for..in order).
	ValidationErrorKeys []string       `json:"-"`
	StatusCode          int            `json:"-"`
	Raw                 map[string]any `json:"-"`
}

func (e *ErrorResponse) Error() string { return e.SingleMessage() }

// SingleMessage returns the first validation error or the message.
func (e *ErrorResponse) SingleMessage() string {
	for _, k := range e.OrderedValidationKeys() {
		if v := e.ValidationErrors[k]; len(v) > 0 {
			return v[0]
		}
	}
	return e.Message
}

// OrderedValidationKeys returns the ValidationErrors keys in server order, falling back to
// sorted order for errors built without a raw body.
func (e *ErrorResponse) OrderedValidationKeys() []string {
	if len(e.ValidationErrorKeys) == len(e.ValidationErrors) {
		return e.ValidationErrorKeys
	}
	keys := make([]string, 0, len(e.ValidationErrors))
	for k := range e.ValidationErrors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// validationKeyOrder returns the key order of the ValidationErrors object in body (after
// descending into ErrorModel when identity is set).
func validationKeyOrder(body []byte, identity bool) []string {
	findKey := func(raw []byte, name string) []byte {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return nil
		}
		for k, v := range m {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return nil
	}
	model := body
	if identity {
		if em := findKey(body, "ErrorModel"); len(em) > 0 && string(em) != "null" {
			model = em
		}
	}
	ve := findKey(model, "ValidationErrors")
	if len(ve) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(ve))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return keys
		}
		k, _ := t.(string)
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return keys
		}
		keys = append(keys, k)
	}
	return keys
}

func getProp(m map[string]any, name string) any {
	if m == nil {
		return nil
	}
	if v, ok := m[name]; ok {
		return v
	}
	lower := strings.ToLower(name[:1]) + name[1:]
	if v, ok := m[lower]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func newErrorResponse(body []byte, status int, identity bool) *ErrorResponse {
	e := &ErrorResponse{StatusCode: status}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	e.Raw = m
	model := m
	if identity {
		if em, ok := getProp(m, "ErrorModel").(map[string]any); ok && em != nil {
			model = em
		}
	}
	if status == 429 {
		e.Message = "Rate limit exceeded. Try again later."
	} else if model != nil {
		if s, ok := getProp(model, "Message").(string); ok {
			e.Message = s
		}
		if ve, ok := getProp(model, "ValidationErrors").(map[string]any); ok {
			e.ValidationErrorKeys = validationKeyOrder(body, identity)
			e.ValidationErrors = map[string][]string{}
			for k, v := range ve {
				if arr, ok := v.([]any); ok {
					for _, s := range arr {
						if str, ok := s.(string); ok {
							e.ValidationErrors[k] = append(e.ValidationErrors[k], str)
						}
					}
				}
			}
		}
	}
	if e.Message == "" && len(e.ValidationErrors) == 0 {
		switch {
		case status == 401:
			e.Message = "Unauthorized."
		case status == 404:
			e.Message = "Not found."
		case status >= 500:
			e.Message = "An unexpected server error occurred."
		default:
			if desc, ok := getProp(m, "error_description").(string); ok {
				e.Message = desc
			} else if s, ok := getProp(m, "error").(string); ok {
				e.Message = s
			}
		}
	}
	return e
}

// Client talks to the Bitwarden server on behalf of the active account.
type Client struct {
	Store *state.Store
	HTTP  *http.Client
}

// New creates an API client.
func New(store *state.Store) *Client {
	return &Client{Store: store, HTTP: &http.Client{Timeout: 5 * time.Minute}}
}

// Urls returns the resolved environment URLs.
func (c *Client) Urls() Urls {
	d, err := c.Store.Load()
	if err != nil {
		return Resolve(state.Environment{})
	}
	return Resolve(d.Environment)
}

func (c *Client) applyHeaders(h http.Header) {
	h.Set("Device-Type", fmt.Sprint(DeviceType()))
	h.Set("Bitwarden-Client-Name", "cli")
	h.Set("Bitwarden-Client-Version", version.Version)
	if ua := os.Getenv("BITWARDENCLI_USER_AGENT"); ua != "" {
		h.Set("User-Agent", ua)
	} else {
		h.Set("User-Agent", "Bitwarden_CLI/"+version.Version+" (Go)")
	}
}

// IdentityResult is the raw outcome of a /connect/token request.
type IdentityResult struct {
	Status int
	Body   map[string]any
	Raw    []byte
}

// PostIdentityToken posts form data to the identity token endpoint. The caller interprets the result.
// Non-JSON or unexpected failures are returned as *ErrorResponse.
func (c *Client) PostIdentityToken(form url.Values, extraHeaders map[string]string) (*IdentityResult, error) {
	req, err := http.NewRequest("POST", c.Urls().Identity+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	c.applyHeaders(req.Header)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	res := &IdentityResult{Status: resp.StatusCode, Raw: raw}
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(raw, &res.Body)
	}
	if res.Body == nil && resp.StatusCode != 200 {
		return nil, newErrorResponse(raw, resp.StatusCode, true)
	}
	return res, nil
}

// IdentityError converts an identity result into an ErrorResponse.
func IdentityError(r *IdentityResult) *ErrorResponse {
	return newErrorResponse(r.Raw, r.Status, true)
}

// RequestOptions tweak a Send call.
type RequestOptions struct {
	BaseURL string            // defaults to the API url
	Headers map[string]string // extra headers
	RawBody io.Reader         // send a raw body (e.g. multipart) instead of JSON
	// ContentType for RawBody.
	ContentType string
}

// Send performs a JSON request against the API. When authed is true an access token is attached
// (refreshing it if needed). out may be nil; if out is *[]byte the raw body is stored.
func (c *Client) Send(method, path string, body any, authed bool, out any, opts *RequestOptions) error {
	if opts == nil {
		opts = &RequestOptions{}
	}
	base := opts.BaseURL
	if base == "" {
		base = c.Urls().Api
	}
	doReq := func() (*http.Response, error) {
		var rdr io.Reader
		contentType := ""
		if opts.RawBody != nil {
			rdr = opts.RawBody
			contentType = opts.ContentType
		} else if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			rdr = bytes.NewReader(b)
			contentType = "application/json; charset=utf-8"
		}
		req, err := http.NewRequest(method, base+path, rdr)
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if out != nil {
			req.Header.Set("Accept", "application/json")
		}
		c.applyHeaders(req.Header)
		if authed {
			tok, err := c.AccessToken()
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}
		return c.HTTP.Do(req)
	}
	resp, err := doReq()
	if err != nil {
		return err
	}
	if authed && resp.StatusCode == http.StatusUnauthorized && opts.RawBody == nil {
		resp.Body.Close()
		if err := c.RefreshToken(); err != nil {
			return err
		}
		if resp, err = doReq(); err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		if authed && (resp.StatusCode == 401 || resp.StatusCode == 403) && len(raw) == 0 {
			return &ErrorResponse{StatusCode: resp.StatusCode, Message: "Unauthorized."}
		}
		return newErrorResponse(raw, resp.StatusCode, false)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if p, ok := out.(*[]byte); ok {
		*p = raw
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Get is a convenience for an authenticated GET.
func (c *Client) Get(path string, out any) error { return c.Send("GET", path, nil, true, out, nil) }

// Post is a convenience for an authenticated POST.
func (c *Client) Post(path string, body, out any) error {
	return c.Send("POST", path, body, true, out, nil)
}

// Put is a convenience for an authenticated PUT.
func (c *Client) Put(path string, body, out any) error {
	return c.Send("PUT", path, body, true, out, nil)
}

// Delete is a convenience for an authenticated DELETE.
func (c *Client) Delete(path string, body any) error {
	return c.Send("DELETE", path, body, true, nil, nil)
}

// DecodeJWT returns the claims of a JWT access token.
func DecodeJWT(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWT must have 3 parts")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// AccessToken returns a valid access token for the active account, refreshing if close to expiry.
func (c *Client) AccessToken() (string, error) {
	d, err := c.Store.Load()
	if err != nil {
		return "", err
	}
	acct := d.Active()
	if acct == nil || acct.AccessToken == "" {
		return "", errors.New("You are not logged in.")
	}
	if claims, err := DecodeJWT(acct.AccessToken); err == nil {
		if exp, ok := claims["exp"].(float64); ok && time.Until(time.Unix(int64(exp), 0)) < 5*time.Minute {
			if err := c.RefreshToken(); err != nil {
				return "", err
			}
			d, _ = c.Store.Load()
			acct = d.Active()
		}
	}
	return acct.AccessToken, nil
}

// RefreshToken refreshes the active account's access token using the refresh token, or the API key
// client credentials when the account was logged in with an API key.
func (c *Client) RefreshToken() error {
	d, err := c.Store.Load()
	if err != nil {
		return err
	}
	acct := d.Active()
	if acct == nil {
		return errors.New("You are not logged in.")
	}
	form := url.Values{}
	if acct.RefreshToken != "" {
		clientID := "cli"
		if claims, err := DecodeJWT(acct.AccessToken); err == nil {
			if s, ok := claims["client_id"].(string); ok && s != "" {
				clientID = s
			}
		}
		form.Set("grant_type", "refresh_token")
		form.Set("client_id", clientID)
		form.Set("refresh_token", acct.RefreshToken)
	} else if acct.ApiClientID != "" && acct.ApiClientSecret != "" {
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", acct.ApiClientID)
		form.Set("client_secret", acct.ApiClientSecret)
		form.Set("scope", "api")
		form.Set("deviceType", fmt.Sprint(DeviceType()))
		form.Set("deviceIdentifier", d.AppID)
		form.Set("deviceName", DeviceName())
	} else {
		return errors.New("No refresh token or api key available.")
	}
	res, err := c.PostIdentityToken(form, nil)
	if err != nil {
		return err
	}
	if res.Status != 200 {
		return IdentityError(res)
	}
	access, _ := getProp(res.Body, "access_token").(string)
	refresh, _ := getProp(res.Body, "refresh_token").(string)
	return c.Store.Update(func(d *state.Data) error {
		a := d.Accounts[acct.UserID]
		if a == nil {
			return errors.New("account disappeared during token refresh")
		}
		a.AccessToken = access
		if refresh != "" {
			a.RefreshToken = refresh
		}
		return nil
	})
}

// GetProp reads a property from a server JSON object, tolerant of PascalCase/camelCase.
func GetProp(m map[string]any, name string) any { return getProp(m, name) }
