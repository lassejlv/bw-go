package api

import (
	"strings"

	"github.com/lassejlv/bw-go/internal/state"
)

// Urls are fully resolved service URLs.
type Urls struct {
	Base          string
	WebVault      string
	Api           string
	Identity      string
	Icons         string
	Notifications string
	Events        string
	KeyConnector  string
	// Send is the configured Send domain (empty for self-hosted without a custom domain).
	Send string
}

// Cloud regions (libs/common/src/platform/services/default-environment.service.ts).
var cloudRegions = map[string]Urls{
	"US": {
		WebVault:      "https://vault.bitwarden.com",
		Api:           "https://api.bitwarden.com",
		Identity:      "https://identity.bitwarden.com",
		Icons:         "https://icons.bitwarden.net",
		Notifications: "https://notifications.bitwarden.com",
		Events:        "https://events.bitwarden.com",
		Send:          "https://send.bitwarden.com",
	},
	"EU": {
		WebVault:      "https://vault.bitwarden.eu",
		Api:           "https://api.bitwarden.eu",
		Identity:      "https://identity.bitwarden.eu",
		Icons:         "https://icons.bitwarden.eu",
		Notifications: "https://notifications.bitwarden.eu",
		Events:        "https://events.bitwarden.eu",
		Send:          "https://vault.bitwarden.eu",
	},
	"Gov": {
		WebVault:      "https://vault.bitwarden-gov.com",
		Api:           "https://api.bitwarden-gov.com",
		Identity:      "https://identity.bitwarden-gov.com",
		Icons:         "https://icons.bitwarden-gov.com",
		Notifications: "https://notifications.bitwarden-gov.com",
		Events:        "https://events.bitwarden-gov.com",
		Send:          "https://send.bitwarden-gov.com",
	},
}

func formatURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	u = strings.TrimRight(u, "/")
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	return u
}

// Resolve turns the stored environment into concrete URLs.
func Resolve(e state.Environment) Urls {
	base := formatURL(e.Base)
	var u Urls
	switch {
	case base != "":
		u = Urls{
			Base:          base,
			WebVault:      base,
			Api:           base + "/api",
			Identity:      base + "/identity",
			Icons:         base + "/icons",
			Notifications: base + "/notifications",
			Events:        base + "/events",
		}
	default:
		if r, ok := cloudRegions[e.Region]; ok {
			u = r
		} else {
			u = cloudRegions["US"]
		}
	}
	set := func(dst *string, v string) {
		if f := formatURL(v); f != "" {
			*dst = f
		}
	}
	set(&u.WebVault, e.WebVault)
	set(&u.Api, e.Api)
	set(&u.Identity, e.Identity)
	set(&u.Icons, e.Icons)
	set(&u.Notifications, e.Notifications)
	set(&u.Events, e.Events)
	set(&u.KeyConnector, e.KeyConnector)
	if s := strings.TrimSpace(e.Send); s != "" {
		u.Send = strings.TrimRight(formatURL(s), "/")
		if strings.HasSuffix(s, "/#/send/") {
			u.Send = s
		}
	}
	return u
}

// HasBaseURL reports whether a self-hosted base url is configured.
func HasBaseURL(e state.Environment) bool {
	return formatURL(e.Base) != ""
}

// SendURL is the base url used to build Send links (EnvironmentService.getSendUrl).
func (u Urls) SendURL() string {
	if u.Send != "" {
		if u.Send == "https://send.bitwarden.com" {
			return u.Send + "/#"
		}
		if strings.HasSuffix(u.Send, "/#/send/") {
			return u.Send
		}
		return u.Send + "/#/send/"
	}
	return u.WebVault + "/#/send/"
}
