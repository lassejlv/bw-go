package features

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/state"
)

func TestEnabledFetchesAndCaches(t *testing.T) {
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" {
			t.Errorf("unexpected %s", r.URL.Path)
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"featureStates":{"pm-32009-new-item-types":true,"pm-40201-derive-ssh-keys":"x"}}`))
	}))
	defer srv.Close()
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Store.Update(func(d *state.Data) error { d.Environment = state.Environment{Base: srv.URL}; return nil })
	Reset()
	if !Enabled(a, NewItemTypes) {
		t.Fatal("expected flag on")
	}
	if Enabled(a, DeriveSSHKeys) {
		t.Fatal("non-bool flag must be off")
	}
	if Enabled(a, SendControls) {
		t.Fatal("missing flag must use default")
	}
	Reset()
	_ = Enabled(a, NewItemTypes)
	if hits != 1 {
		t.Fatalf("expected cached config, got %d fetches", hits)
	}
	t.Setenv("BW_FEATURE_"+NewItemTypes, "false")
	if Enabled(a, NewItemTypes) {
		t.Fatal("env override must win")
	}
}
