package vaultedit

import "github.com/lassejlv/bw-go/internal/app"

// Tests use upstream's default flag values instead of fetching /config from the fake server.
func init() { Features = func(*app.App) featureFlags { return featureFlags{} } }
