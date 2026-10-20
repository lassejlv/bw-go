package vaultcmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/state"
)

// Viewing an item of an organization that uses events records and uploads Cipher_ClientViewed,
// like GetCommand/ListCommand upstream; personal items and orgs without events record nothing.
func TestViewedItemEvents(t *testing.T) {
	e := newEnv(t)
	err := e.a.Store.Update(func(d *state.Data) error {
		acct := d.Active()
		var p map[string]any
		if err := json.Unmarshal(acct.Vault.Profile, &p); err != nil {
			return err
		}
		p["organizations"].([]any)[0].(map[string]any)["useEvents"] = true
		acct.Vault.Profile, _ = json.Marshal(p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	countCollect := func() int {
		e.mu.Lock()
		defer e.mu.Unlock()
		n := 0
		for _, r := range e.requests {
			if strings.HasPrefix(r, "POST /events/collect") {
				n++
			}
		}
		return n
	}

	if r := Get(e.a, "item", cGitHub, GetOptions{}); !r.Success {
		t.Fatalf("get org item: %s", r.MessageText())
	}
	if n := countCollect(); n != 1 {
		t.Fatalf("expected one event upload for the org item, got %d", n)
	}
	if r := Get(e.a, "item", cGoogle, GetOptions{}); !r.Success {
		t.Fatalf("get personal item: %s", r.MessageText())
	}
	if n := countCollect(); n != 1 {
		t.Fatalf("personal item must not record an event, got %d uploads", n)
	}
	if r := List(e.a, "items", ListOptions{}); !r.Success {
		t.Fatalf("list: %s", r.MessageText())
	}
	if n := countCollect(); n != 2 {
		t.Fatalf("expected list to upload viewed events, got %d uploads", n)
	}
}
