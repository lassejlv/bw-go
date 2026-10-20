package auth

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/crypto"
)

// PreloginData mirrors PasswordPreloginData.
type PreloginData struct {
	KdfConfig crypto.KdfConfig
	Salt      string
}

// passwordPreloginResponse mirrors PasswordPreloginResponse.
type passwordPreloginResponse struct {
	KdfSettings *KdfConfigResponse `json:"KdfSettings"`
	Salt        string             `json:"Salt"`
}

// legacyPreloginResponse is the pre-2025 /accounts/prelogin response.
type legacyPreloginResponse struct {
	Kdf            *int `json:"Kdf"`
	KdfIterations  *int `json:"KdfIterations"`
	KdfMemory      *int `json:"KdfMemory"`
	KdfParallelism *int `json:"KdfParallelism"`
}

// NormalizeEmail trims and lowercases an email like the prelogin service and makeMasterKey do.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// ParsePasswordPrelogin parses and validates a /accounts/prelogin/password response.
func ParsePasswordPrelogin(raw []byte) (*PreloginData, error) {
	var r passwordPreloginResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	cfg, err := r.KdfSettings.ToKdfConfig()
	if err != nil {
		return nil, err
	}
	if err := ValidateKdfConfigForPrelogin(cfg); err != nil {
		return nil, err
	}
	return &PreloginData{KdfConfig: cfg, Salt: r.Salt}, nil
}

// ParseLegacyPrelogin parses and validates a legacy /accounts/prelogin response.
func ParseLegacyPrelogin(raw []byte, email string) (*PreloginData, error) {
	var r legacyPreloginResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	resp := &KdfConfigResponse{KdfType: r.Kdf, Iterations: r.KdfIterations, Memory: r.KdfMemory, Parallelism: r.KdfParallelism}
	cfg, err := resp.ToKdfConfig()
	if err != nil {
		return nil, err
	}
	if err := ValidateKdfConfigForPrelogin(cfg); err != nil {
		return nil, err
	}
	return &PreloginData{KdfConfig: cfg, Salt: email}, nil
}

// GetPreloginData fetches the KDF settings for email from the identity server
// (DefaultPasswordPreloginService). Servers without /accounts/prelogin/password fall back to the
// legacy /accounts/prelogin endpoint.
func GetPreloginData(c *api.Client, email string) (*PreloginData, error) {
	email = NormalizeEmail(email)
	opts := &api.RequestOptions{BaseURL: c.Urls().Identity}
	body := map[string]string{"email": email}
	var raw []byte
	err := c.Send("POST", "/accounts/prelogin/password", body, false, &raw, opts)
	if err == nil {
		return ParsePasswordPrelogin(raw)
	}
	var apiErr *api.ErrorResponse
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
		return nil, err
	}
	raw = nil
	if err := c.Send("POST", "/accounts/prelogin", body, false, &raw, opts); err != nil {
		return nil, err
	}
	return ParseLegacyPrelogin(raw, email)
}
