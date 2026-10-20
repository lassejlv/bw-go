package send

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/sendcore"
	"github.com/lassejlv/bw-go/internal/vault"
)

// WhoCanAccessType values (libs/common/src/tools/models/send-who-can-access-type.ts).
const (
	whoCanAccessAny               = 0
	whoCanAccessPasswordProtected = 1
	whoCanAccessSpecificPeople    = 2
)

// sendPolicies returns the enforced SendControls policies of the active user
// (policyService.policiesByType$(PolicyType.SendControls, userId)).
func sendPolicies(a *app.App) ([]*vault.Policy, error) {
	v, err := vault.Load(a)
	if err != nil {
		return nil, err
	}
	return vault.PoliciesByType(v.Policies(), v.Organizations(), vault.PolicySendControls), nil
}

// policyData decodes a policy's data object (SendControlsPolicyData). The server sends an object;
// a JSON string holding the object is accepted too. Returns nil when there is no data.
func policyData(p *vault.Policy) map[string]any {
	if len(p.Data) == 0 || string(p.Data) == "null" {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(p.Data, &m) == nil {
		return m
	}
	var s string
	if json.Unmarshal(p.Data, &s) == nil && json.Unmarshal([]byte(s), &m) == nil {
		return m
	}
	return nil
}

// jsTruthy mirrors JavaScript truthiness for decoded JSON values.
func jsTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0 && !math.IsNaN(x)
	case string:
		return x != ""
	}
	return true
}

// jsValueNumber mirrors JavaScript's numeric coercion (`x * 3600000`) for decoded JSON values.
func jsValueNumber(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case string:
		return jsNumber(x)
	}
	return math.NaN()
}

// enforceSendPolicy mirrors SendCreateCommand.enforceSendPolicy: behind the SendControls feature
// flag, the first SendControls policy with a whoCanAccess setting decides the required access
// type (and allowed email domains), and the first policy with deletionHours overrides the
// deletion date. req.AuthType and req.Emails must already be set.
func enforceSendPolicy(a *app.App, req *sendInput) *cli.Response {
	if !features.Enabled(a, features.SendControls) {
		return nil
	}
	policies, err := sendPolicies(a)
	if err != nil {
		return cli.Error(err)
	}
	datas := make([]map[string]any, 0, len(policies))
	for _, p := range policies {
		datas = append(datas, policyData(p))
	}

	var whoCanAccess map[string]any
	for _, d := range datas {
		if d != nil && d["whoCanAccess"] != nil {
			whoCanAccess = d
			break
		}
	}
	authType := -1
	if req.AuthType != nil {
		authType = *req.AuthType
	}
	if whoCanAccess != nil {
		switch w, _ := whoCanAccess["whoCanAccess"].(float64); w {
		case whoCanAccessSpecificPeople:
			if authType != sendcore.AuthEmail || len(req.Emails) == 0 {
				return cli.Error("Organization policy requires Send access to be restricted to specific people. Use --emails to specify recipients.")
			}
			if rawDomains, _ := whoCanAccess["allowedDomains"].(string); rawDomains != "" {
				var allowedDomains []string
				for _, d := range strings.Split(rawDomains, ",") {
					if d = strings.ToLower(strings.TrimSpace(d)); len(d) > 0 {
						allowedDomains = append(allowedDomains, d)
					}
				}
				if len(allowedDomains) > 0 {
					var disallowed []string
					for _, email := range req.Emails {
						parts := strings.Split(email, "@")
						allowed := false
						if len(parts) > 1 {
							domain := strings.ToLower(parts[1])
							for _, d := range allowedDomains {
								if d == domain {
									allowed = true
									break
								}
							}
						}
						if !allowed {
							disallowed = append(disallowed, email)
						}
					}
					if len(disallowed) > 0 {
						return cli.Error("Organization policy restricts email domains. The following emails are not allowed: " +
							strings.Join(disallowed, ", ") + ". Allowed domains: " + strings.Join(allowedDomains, ", ") + ".")
					}
				}
			}
		case whoCanAccessPasswordProtected:
			if authType != sendcore.AuthPassword {
				return cli.Error("Organization policy requires Send access to be password protected. Use --password to set a password.")
			}
		}
	}

	// If org policy specifies a deletion date we comply with it, overriding what the user has
	// specified (matching the UI, where other deletion dates are barred by the policy).
	for _, d := range datas {
		if d == nil || !jsTruthy(d["deletionHours"]) {
			continue
		}
		ms := float64(time.Now().UnixMilli()) + jsValueNumber(d["deletionHours"])*3600000
		if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > 8.64e15 {
			req.DeletionDate = json.RawMessage(`"Invalid Date"`)
		} else {
			req.DeletionDate = json.RawMessage(strconv.FormatInt(int64(math.Trunc(ms)), 10))
		}
		break
	}
	return nil
}
