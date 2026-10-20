// Package features reads server feature flags like upstream's DefaultConfigService: GET /config
// (authenticated when an access token exists), cached for an hour, falling back to the cached
// value and then to the FeatureFlag enum defaults when the server can't be reached.
package features

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/state"
)

// Feature flags read by the CLI (libs/common/src/enums/feature-flag.enum.ts).
const (
	NewItemTypes  = "pm-32009-new-item-types"
	DeriveSSHKeys = "pm-40201-derive-ssh-keys"
	SendControls  = "pm-31885-send-controls"
	SdkSendsApi   = "pm-30110-sdk-sends-api"
)

// defaults are the DefaultFeatureFlagValue entries for the flags above.
var defaults = map[string]bool{
	NewItemTypes:  false,
	DeriveSSHKeys: false,
	SendControls:  false,
	SdkSendsApi:   false,
}

// RetrievalInterval is how long a fetched config is considered fresh.
const RetrievalInterval = time.Hour

var (
	mu     sync.Mutex
	loaded map[string]json.RawMessage
)

// Enabled reports whether a feature flag is on. A BW_FEATURE_<flag>=true|false environment
// variable overrides the server value (useful for testing and air-gapped servers).
func Enabled(a *app.App, flag string) bool {
	if v, ok := os.LookupEnv("BW_FEATURE_" + flag); ok {
		return v == "true"
	}
	states := featureStates(a)
	if raw, ok := states[flag]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			return b
		}
		return false
	}
	return defaults[flag]
}

func featureStates(a *app.App) map[string]json.RawMessage {
	mu.Lock()
	defer mu.Unlock()
	if loaded != nil {
		return loaded
	}
	d, err := a.Store.Load()
	if err != nil {
		return nil
	}
	apiURL := a.Urls().Api
	acct := d.Active()
	userID := ""
	if acct != nil && acct.AccessToken != "" {
		userID = acct.UserID
	}
	cached := d.ServerConfig
	fresh := cached != nil && cached.ApiURL == apiURL && cached.UserID == userID &&
		time.Since(cached.FetchedAt) < RetrievalInterval
	if fresh {
		loaded = cached.FeatureStates
		return loaded
	}
	var resp struct {
		FeatureStates map[string]json.RawMessage `json:"featureStates"`
	}
	var raw []byte
	if err := a.API.Send("GET", "/config", nil, userID != "", &raw, nil); err == nil && json.Unmarshal(raw, &resp) == nil {
		loaded = resp.FeatureStates
		if loaded == nil {
			loaded = map[string]json.RawMessage{}
		}
		_ = a.Store.Update(func(d *state.Data) error {
			d.ServerConfig = &state.ServerConfig{
				ApiURL: apiURL, UserID: userID, FetchedAt: time.Now().UTC(),
				FeatureStates: loaded, Raw: raw,
			}
			return nil
		})
		return loaded
	}
	if cached != nil && cached.ApiURL == apiURL {
		loaded = cached.FeatureStates
	} else {
		loaded = map[string]json.RawMessage{}
	}
	return loaded
}

// Reset clears the in-process cache (used after login/logout or in tests).
func Reset() {
	mu.Lock()
	loaded = nil
	mu.Unlock()
}
