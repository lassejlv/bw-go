package events

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
	"github.com/lassejlv/bw-go/internal/vault"
)

const (
	orgEvents   = "0e0e0e0e-0000-4000-8000-000000000001"
	orgNoEvents = "0e0e0e0e-0000-4000-8000-000000000002"
)

// fakeEvents is an events server whose /collect fails for the configured request numbers.
type fakeEvents struct {
	mu       sync.Mutex
	requests int
	failOn   map[int]bool
	received [][]Event
	auth     []string
}

func (f *fakeEvents) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != "POST" || r.URL.Path != "/events/collect" {
		w.WriteHeader(404)
		return
	}
	f.requests++
	if f.failOn[f.requests] {
		w.WriteHeader(500)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var batch []Event
	if err := json.Unmarshal(body, &batch); err != nil {
		w.WriteHeader(400)
		return
	}
	f.received = append(f.received, batch)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
}

func setup(t *testing.T, failOn ...int) (*app.App, *vault.Vault, *fakeEvents) {
	t.Helper()
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	t.Setenv("BW_SESSION", "")
	fe := &fakeEvents{failOn: map[int]bool{}}
	for _, n := range failOn {
		fe.failOn[n] = true
	}
	srv := httptest.NewServer(fe)
	t.Cleanup(srv.Close)
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]any{"id": "u1", "email": "u@example.com", "organizations": []any{
		map[string]any{"id": orgEvents, "name": "A", "status": 2, "type": 2, "enabled": true, "useEvents": true},
		map[string]any{"id": orgNoEvents, "name": "B", "status": 2, "type": 2, "enabled": true, "useEvents": false},
	}})
	orgCipher, _ := json.Marshal(map[string]any{"id": "c-org", "organizationId": orgEvents, "type": 1})
	personalCipher, _ := json.Marshal(map[string]any{"id": "c-personal", "type": 1})
	err = a.Store.Update(func(d *state.Data) error {
		d.Environment = state.Environment{Base: srv.URL}
		d.ActiveUserID = "u1"
		d.Accounts = map[string]*state.Account{"u1": {UserID: "u1", Email: "u@example.com", AccessToken: "token",
			Vault: state.VaultData{Profile: profile, Ciphers: map[string]json.RawMessage{"c-org": orgCipher, "c-personal": personalCipher}}}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetUserKey(crypto.GenerateKey()); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Load(a)
	if err != nil {
		t.Fatal(err)
	}
	return a, v, fe
}

func sp(s string) *string { return &s }

func TestFailedExportEventIsRetried(t *testing.T) {
	a, v, fe := setup(t, 1)
	now = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 123e6, time.UTC) }
	t.Cleanup(func() { now = time.Now })

	// first upload fails: the event is kept on disk
	Collect(a, v, UserClientExportedVault, nil, true, nil)
	if len(fe.received) != 0 || fe.requests != 1 {
		t.Fatalf("requests=%d received=%v", fe.requests, fe.received)
	}
	pending := Pending(a)
	if len(pending) != 1 || pending[0].Type != UserClientExportedVault || pending[0].Date != "2026-10-20T12:00:00.123Z" {
		t.Fatalf("pending %+v", pending)
	}
	if _, err := os.Stat(filepath.Join(a.Store.Dir, FileName)); err != nil {
		t.Fatal(err)
	}

	// the next upload sends the pending event first, then the new one
	Collect(a, v, OrganizationClientExportedVault, nil, true, sp(orgEvents))
	if fe.requests != 2 || len(fe.received) != 1 || len(fe.received[0]) != 2 {
		t.Fatalf("requests=%d received=%v", fe.requests, fe.received)
	}
	b := fe.received[0]
	if b[0].Type != UserClientExportedVault || b[0].OrganizationID != nil ||
		b[1].Type != OrganizationClientExportedVault || b[1].OrganizationID == nil || *b[1].OrganizationID != orgEvents {
		t.Fatalf("batch %+v", b)
	}
	if fe.auth[0] != "Bearer token" {
		t.Fatalf("authorization %q", fe.auth[0])
	}
	if len(Pending(a)) != 0 {
		t.Fatal("events left after a successful upload")
	}
	if _, err := os.Stat(filepath.Join(a.Store.Dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("empty event file should be removed")
	}
}

func TestUploadBatchesAndBails(t *testing.T) {
	a, _, fe := setup(t, 2)
	evs := make([]Event, 250)
	for i := range evs {
		evs[i] = Event{Type: 1100 + i, Date: "2026-01-01T00:00:00.000Z"}
	}
	if err := update(a, func(all map[string][]Event) { all["u1"] = evs }); err != nil {
		t.Fatal(err)
	}
	// batch 1 (100) succeeds, batch 2 fails, batch 3 is not attempted
	Upload(a)
	if fe.requests != 2 || len(fe.received) != 1 || len(fe.received[0]) != 100 {
		t.Fatalf("requests=%d received=%d", fe.requests, len(fe.received))
	}
	pending := Pending(a)
	if len(pending) != 150 || pending[0].Type != 1200 || pending[149].Type != 1349 {
		t.Fatalf("pending %d", len(pending))
	}
	Upload(a)
	if fe.requests != 4 || len(fe.received) != 3 || len(fe.received[1]) != 100 || len(fe.received[2]) != 50 ||
		fe.received[2][49].Type != 1349 || len(Pending(a)) != 0 {
		t.Fatalf("requests=%d received=%d pending=%d", fe.requests, len(fe.received), len(Pending(a)))
	}
}

func TestShouldUpdate(t *testing.T) {
	a, v, _ := setup(t)
	cases := []struct {
		name      string
		eventType int
		cipherID  *string
		orgID     *string
		want      bool
	}{
		{"user export", UserClientExportedVault, nil, nil, true},
		{"org export", OrganizationClientExportedVault, nil, sp(orgEvents), true},
		{"org without events", OrganizationClientExportedVault, nil, sp(orgNoEvents), false},
		{"no cipher, no org", OrganizationClientExportedVault, nil, nil, false},
		{"org cipher", 1107, sp("c-org"), nil, true},
		{"personal cipher", 1107, sp("c-personal"), nil, false},
		{"unknown cipher with org", 1107, sp("missing"), sp(orgEvents), true},
	}
	for _, c := range cases {
		if got := shouldUpdate(a, v, c.orgID, c.eventType, c.cipherID); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if err := a.Lock(); err != nil {
		t.Fatal(err)
	}
	if shouldUpdate(a, v, nil, UserClientExportedVault, nil) {
		t.Error("locked vault must not collect")
	}
}

func TestLockedUploadKeepsEventsAndLogoutDropsThem(t *testing.T) {
	a, _, fe := setup(t)
	_ = update(a, func(all map[string][]Event) { all["u1"] = []Event{{Type: 1007}} })
	_ = a.Lock()
	Upload(a)
	if fe.requests != 0 || len(Pending(a)) != 1 {
		t.Fatal("a locked vault must not upload")
	}
	_ = a.Logout()
	_ = update(a, func(map[string][]Event) {})
	all := map[string][]Event{}
	if b, err := os.ReadFile(filepath.Join(a.Store.Dir, FileName)); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	if len(all) != 0 {
		t.Fatalf("events of logged out users must be dropped: %v", all)
	}
}
