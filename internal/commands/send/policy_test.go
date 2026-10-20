package send

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/sendcore"
	"github.com/lassejlv/bw-go/internal/state"
)

const policyOrgID = "0f0f0f0f-0000-4000-8000-000000000001"

// withSendPolicies stores an organization (role User unless orgType says otherwise) and
// SendControls policies with the given data in the test vault.
func withSendPolicies(t *testing.T, a *app.App, orgType int, datas ...string) {
	t.Helper()
	profile, _ := json.Marshal(map[string]any{
		"id": "u1", "email": "u@example.com", "premium": true,
		"organizations": []any{map[string]any{"id": policyOrgID, "name": "Acme", "status": 2,
			"type": orgType, "enabled": true, "usePolicies": true}},
	})
	var policies []json.RawMessage
	for i, d := range datas {
		p, _ := json.Marshal(map[string]any{"id": "p" + string(rune('0'+i)), "organizationId": policyOrgID,
			"type": 21, "enabled": true, "data": json.RawMessage(d)})
		policies = append(policies, p)
	}
	err := a.Store.Update(func(d *state.Data) error {
		acct := d.Accounts["u1"]
		acct.Vault.Profile = profile
		acct.Vault.Policies = policies
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func textSendRequest(deletion time.Time) string {
	return encode(map[string]any{"type": 0, "name": "n", "text": map[string]any{"text": "secret"},
		"deletionDate": deletion.UTC().Format(time.RFC3339)})
}

func TestSendControlsPolicy(t *testing.T) {
	flag := "BW_FEATURE_" + features.SendControls
	week := time.Now().Add(7 * 24 * time.Hour)

	t.Run("flag off ignores policy", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "false")
		withSendPolicies(t, a, 2, `{"whoCanAccess":1}`)
		if r := Create(a, textSendRequest(week), CreateOptions{}); !r.Success {
			t.Fatal(r.MessageText())
		}
	})

	t.Run("password protected", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "true")
		withSendPolicies(t, a, 2, `{"disableSend":false,"whoCanAccess":1,"allowedDomains":null}`)
		r := Create(a, textSendRequest(week), CreateOptions{})
		if r.Success || r.MessageText() != "Organization policy requires Send access to be password protected. Use --password to set a password." {
			t.Fatalf("got %v %q", r.Success, r.MessageText())
		}
		r = Create(a, textSendRequest(week), CreateOptions{Emails: []string{"x@example.com"}})
		if r.Success {
			t.Fatal("emails must not satisfy a password policy")
		}
		r = Create(a, textSendRequest(week), CreateOptions{Password: sp("pw")})
		if !r.Success || *r.Data.(*SendResponse).AuthType != sendcore.AuthPassword {
			t.Fatal(r.MessageText())
		}
	})

	t.Run("specific people and domains", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "true")
		// the first policy without whoCanAccess is skipped
		withSendPolicies(t, a, 2, `{"deletionHours":null}`, `{"whoCanAccess":2,"allowedDomains":" Example.com, ,corp.example.org "}`)
		want := "Organization policy requires Send access to be restricted to specific people. Use --emails to specify recipients."
		if r := Create(a, textSendRequest(week), CreateOptions{}); r.MessageText() != want {
			t.Fatalf("got %q", r.MessageText())
		}
		if r := Create(a, textSendRequest(week), CreateOptions{Password: sp("pw")}); r.MessageText() != want {
			t.Fatalf("got %q", r.MessageText())
		}
		r := Create(a, textSendRequest(week), CreateOptions{Emails: []string{"a@EXAMPLE.com", "b@other.com", "nodomain", "c@corp.example.org"}})
		if r.MessageText() != "Organization policy restricts email domains. The following emails are not allowed: b@other.com, nodomain. Allowed domains: example.com, corp.example.org." {
			t.Fatalf("got %q", r.MessageText())
		}
		r = Create(a, textSendRequest(week), CreateOptions{Emails: []string{"a@example.com", "c@Corp.Example.org"}})
		if !r.Success || *r.Data.(*SendResponse).AuthType != sendcore.AuthEmail {
			t.Fatal(r.MessageText())
		}
	})

	t.Run("specific people without domain restriction", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "true")
		withSendPolicies(t, a, 2, `{"whoCanAccess":2,"allowedDomains":""}`)
		if r := Create(a, textSendRequest(week), CreateOptions{Emails: []string{"anyone@anywhere.test"}}); !r.Success {
			t.Fatal(r.MessageText())
		}
	})

	t.Run("deletion hours override", func(t *testing.T) {
		a, fs, _ := setupApp(t)
		t.Setenv(flag, "true")
		withSendPolicies(t, a, 2, `{"whoCanAccess":0,"deletionHours":0}`, `{"deletionHours":24}`)
		before := time.Now().Add(24 * time.Hour).Add(-time.Second)
		r := Create(a, textSendRequest(week), CreateOptions{})
		if !r.Success {
			t.Fatal(r.MessageText())
		}
		del, err := time.Parse(time.RFC3339, fs.lastReq["deletionDate"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if del.Before(before) || del.After(time.Now().Add(24*time.Hour)) {
			t.Fatalf("deletion date %s not ~24h from now", del)
		}
	})

	t.Run("owners are exempt", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "true")
		withSendPolicies(t, a, 0, `{"whoCanAccess":1}`)
		if r := Create(a, textSendRequest(week), CreateOptions{}); !r.Success {
			t.Fatal(r.MessageText())
		}
	})

	t.Run("edit is not checked", func(t *testing.T) {
		a, _, _ := setupApp(t)
		t.Setenv(flag, "true")
		r := Create(a, textSendRequest(week), CreateOptions{})
		if !r.Success {
			t.Fatal(r.MessageText())
		}
		id := r.Data.(*SendResponse).ID
		withSendPolicies(t, a, 2, `{"whoCanAccess":1}`)
		get := Get(a, id, GetOptions{}).Data.(*SendResponse)
		var m map[string]any
		b, _ := json.Marshal(get)
		_ = json.Unmarshal(b, &m)
		m["name"] = "renamed"
		if r := Edit(a, encode(m), EditOptions{}); !r.Success {
			t.Fatal(r.MessageText())
		}
	})
}
