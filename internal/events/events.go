// Package events ports the event log client (libs/common/src/dirt/event-logs): EventCollectionService
// records events in a per-user collection, and EventUploadService uploads the collection to the
// events server (POST {events}/collect, in batches of 100), keeping the events that failed to
// upload so they are retried with the next upload.
//
// The collection lives in its own file, events-go.json, next to the state file: a JSON object
// mapping user ids to their pending events. Like upstream's clearOn: ["logout"], the events of
// users that are no longer logged in are dropped.
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/vault"
)

// Event types (EventType) collected by the CLI.
const (
	UserClientExportedVault         = 1007
	CipherClientViewed              = 1107
	OrganizationClientExportedVault = 1602
)

// FileName is the event collection file in the app data directory.
const FileName = "events-go.json"

// UploadBatchSize mirrors EventUploadBatchSize.
const UploadBatchSize = 100

// Event mirrors EventData / EventRequest.
type Event struct {
	Type           int     `json:"type"`
	CipherID       *string `json:"cipherId"`
	Date           string  `json:"date"`
	OrganizationID *string `json:"organizationId"`
}

// now is replaceable in tests.
var now = time.Now

// Collect mirrors EventCollectionService.collect(eventType, cipherId, uploadImmediately,
// organizationId): the event is added to the active user's collection when the vault is
// unlocked and the user belongs to an organization that uses events (see shouldUpdate), and the
// whole collection is uploaded when uploadImmediately is set. Errors are not reported, like the
// floating promise upstream.
func Collect(a *app.App, v *vault.Vault, eventType int, cipherID *string, uploadImmediately bool, organizationID *string) {
	acct := a.ActiveAccount()
	if acct == nil || !shouldUpdate(a, v, organizationID, eventType, cipherID) {
		return
	}
	ev := Event{Type: eventType, CipherID: cipherID, Date: cli.FormatDate(now()), OrganizationID: organizationID}
	_ = update(a, func(all map[string][]Event) {
		all[acct.UserID] = append(all[acct.UserID], ev)
	})
	if uploadImmediately {
		Upload(a)
	}
}

// CollectMany mirrors EventCollectionService.collectMany: one event per cipher that belongs to an
// organization using events, added when the vault is unlocked, then optionally uploaded.
func CollectMany(a *app.App, v *vault.Vault, eventType int, ciphers []*vault.CipherView, uploadImmediately bool) {
	acct := a.ActiveAccount()
	if acct == nil || !a.IsUnlocked() {
		return
	}
	orgIDs := eventOrgIDs(v)
	if len(orgIDs) == 0 {
		return
	}
	var evs []Event
	date := cli.FormatDate(now())
	for _, c := range ciphers {
		if c.OrganizationID == nil || !orgIDs[*c.OrganizationID] {
			continue
		}
		id, org := c.ID, *c.OrganizationID
		evs = append(evs, Event{Type: eventType, CipherID: &id, Date: date, OrganizationID: &org})
	}
	if len(evs) == 0 {
		return
	}
	_ = update(a, func(all map[string][]Event) {
		all[acct.UserID] = append(all[acct.UserID], evs...)
	})
	if uploadImmediately {
		Upload(a)
	}
}

// eventOrgIDs returns the ids of the user's organizations that use events.
func eventOrgIDs(v *vault.Vault) map[string]bool {
	ids := map[string]bool{}
	for _, o := range v.Organizations() {
		if o.UseEvents {
			ids[o.ID] = true
		}
	}
	return ids
}

// shouldUpdate mirrors EventCollectionService.shouldUpdate.
func shouldUpdate(a *app.App, v *vault.Vault, organizationID *string, eventType int, cipherID *string) bool {
	if !a.IsUnlocked() {
		return false
	}
	orgIDs := eventOrgIDs(v)
	if len(orgIDs) == 0 {
		return false
	}
	// Individual vault export doesn't need a cipher id or organization id.
	if eventType == UserClientExportedVault {
		return true
	}
	var cipher *vault.Cipher
	if cipherID != nil {
		cipher, _ = v.EncryptedCipher(*cipherID)
	}
	if cipher == nil && organizationID == nil {
		return false
	}
	if cipher != nil {
		return cipher.OrganizationID != nil && orgIDs[*cipher.OrganizationID]
	}
	return orgIDs[*organizationID]
}

// Pending returns the active user's events that have not been uploaded yet.
func Pending(a *app.App) []Event {
	acct := a.ActiveAccount()
	if acct == nil {
		return nil
	}
	all := map[string][]Event{}
	if b, err := os.ReadFile(path(a)); err == nil {
		_ = json.Unmarshal(b, &all)
	}
	return all[acct.UserID]
}

// Upload mirrors EventUploadService.uploadEvents for the active user: when the vault is
// unlocked the collection is taken from state and posted, and the events that failed to upload
// are put back for the next upload.
func Upload(a *app.App) {
	acct := a.ActiveAccount()
	if acct == nil || !a.IsUnlocked() {
		return
	}
	userID := acct.UserID
	var taken []Event
	if err := update(a, func(all map[string][]Event) {
		taken = all[userID]
		delete(all, userID)
	}); err != nil || len(taken) == 0 {
		return
	}
	failed := postEventsCollect(a, taken)
	if len(failed) == 0 {
		return
	}
	_ = update(a, func(all map[string][]Event) {
		// Upstream replaces the collection with the failed events; events collected meanwhile
		// (by another process) are kept after them instead of being dropped.
		all[userID] = append(failed, all[userID]...)
	})
}

// postEventsCollect mirrors ApiService.postEventsCollect: the events are posted in batches and,
// after the first failed batch, the remaining batches are not attempted. It returns the events
// that were not uploaded.
func postEventsCollect(a *app.App, events []Event) []Event {
	var failed []Event
	bail := false
	for start := 0; start < len(events); start += UploadBatchSize {
		batch := events[start:min(start+UploadBatchSize, len(events))]
		if bail {
			failed = append(failed, batch...)
			continue
		}
		if err := a.API.Send("POST", "/collect", batch, true, nil, &api.RequestOptions{BaseURL: a.Urls().Events}); err != nil {
			bail = true
			failed = append(failed, batch...)
		}
	}
	return failed
}

// ---------- file store ----------

func path(a *app.App) string { return filepath.Join(a.Store.Dir, FileName) }

// update applies fn to the event collections under a lock and writes them back. Collections of
// users without an account in state (logged out) are dropped.
func update(a *app.App, fn func(all map[string][]Event)) error {
	p := path(a)
	unlock, err := lock(p)
	if err != nil {
		return err
	}
	defer unlock()
	all := map[string][]Event{}
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		if json.Unmarshal(b, &all) != nil {
			all = map[string][]Event{}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if d, err := a.Data(); err == nil {
		for id := range all {
			if _, ok := d.Accounts[id]; !ok {
				delete(all, id)
			}
		}
	}
	fn(all)
	for id, evs := range all {
		if len(evs) == 0 {
			delete(all, id)
		}
	}
	if len(all) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// lock takes a lock directory next to the file (like the state store).
func lock(p string) (func(), error) {
	lockDir := p + ".lock"
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := os.Mkdir(lockDir, 0o700)
		if err == nil {
			return func() { _ = os.Remove(lockDir) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, statErr := os.Stat(lockDir); statErr == nil && time.Since(fi.ModTime()) > 10*time.Second {
			_ = os.Remove(lockDir) // stale lock
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("could not acquire lock on %s", p)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
