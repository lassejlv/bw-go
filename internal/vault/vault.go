package vault

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/state"
)

// ErrNotFound is returned when an entity does not exist in the local vault.
var ErrNotFound = errors.New("Not found.")

// NoFolderName is the name of the synthetic "No Folder" entry (i18n "noneFolder").
const NoFolderName = "No Folder"

// Vault gives access to the active account's vault: decrypted views (lazily computed and cached)
// and helpers that keep the stored raw sync data consistent after server writes (like
// cipherService.upsert/delete/softDelete/restore).
type Vault struct {
	acct    *state.Account
	keys    *Keys
	profile *Profile
	update  func(fn func(acct *state.Account) error) error

	mu          sync.Mutex
	ciphers     []*CipherView
	failed      []*CipherView
	cipherByID  map[string]*CipherView
	folders     []*FolderView
	collections []*CollectionView
}

// Load opens the active account's vault. The vault must be unlocked (app.ErrLocked otherwise).
func Load(a *app.App) (*Vault, error) {
	userKey, err := a.UserKey()
	if err != nil {
		return nil, err
	}
	acct := a.ActiveAccount()
	if acct == nil {
		return nil, errors.New("You are not logged in.")
	}
	return New(acct, userKey, a.UpdateAccount)
}

// New builds a Vault from an account snapshot and its user key. update persists account changes
// (app.UpdateAccount); when nil, mutations only change the in-memory snapshot.
func New(acct *state.Account, userKey *crypto.SymmetricKey, update func(fn func(acct *state.Account) error) error) (*Vault, error) {
	v := &Vault{acct: acct, update: update}
	if len(acct.Vault.Profile) > 0 && string(acct.Vault.Profile) != "null" {
		p := &Profile{}
		if err := json.Unmarshal(acct.Vault.Profile, p); err != nil {
			return nil, err
		}
		v.profile = p
	}
	v.keys = NewKeys(userKey, acct.EncPrivateKey, acct.AccountKeys, v.profile)
	return v, nil
}

// Account returns the account snapshot the vault was loaded from.
func (v *Vault) Account() *state.Account { return v.acct }

// UserID returns the active user id (CipherRequest.encryptedFor).
func (v *Vault) UserID() string { return v.acct.UserID }

// Keys returns the account keys.
func (v *Vault) Keys() *Keys { return v.keys }

// Profile returns the synced profile (nil before the first sync).
func (v *Vault) Profile() *Profile { return v.profile }

// HasPremium mirrors hasPremiumFromAnySource$.
func (v *Vault) HasPremium() bool { return v.profile.HasPremium() }

// LastSync returns the last sync time (nil if never synced).
func (v *Vault) LastSync() *time.Time { return v.acct.LastSync }

// ---------- organizations, policies, domains ----------

// Organizations returns all organizations (member and provider organizations).
func (v *Vault) Organizations() []*Organization { return BuildOrganizations(v.profile) }

// MemberOrganizations mirrors organizationService.memberOrganizations$ (used by `list organizations`).
func (v *Vault) MemberOrganizations() []*Organization {
	out := []*Organization{}
	for _, o := range v.Organizations() {
		if o.IsMember {
			out = append(out, o)
		}
	}
	return out
}

// Organization returns an organization by id, or nil.
func (v *Vault) Organization(id string) *Organization {
	for _, o := range v.Organizations() {
		if o.ID == id {
			return o
		}
	}
	return nil
}

// Policies returns the synced policies.
func (v *Vault) Policies() []*Policy {
	out := []*Policy{}
	for _, raw := range v.acct.Vault.Policies {
		p := &Policy{}
		if json.Unmarshal(raw, p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// PolicyAppliesToUser mirrors policyService.policyAppliesToUser$.
func (v *Vault) PolicyAppliesToUser(t PolicyType) bool {
	return PolicyAppliesToUser(v.Policies(), v.Organizations(), t)
}

// RestrictedTypes mirrors restrictedItemTypesService.restricted$.
func (v *Vault) RestrictedTypes() []RestrictedCipherType {
	return RestrictedTypes(v.Policies(), v.Organizations())
}

// IsCipherRestricted mirrors CliRestrictedItemTypesService.isCipherRestricted.
func (v *Vault) IsCipherRestricted(c *CipherView) bool {
	return IsCipherRestricted(c.Type, c.OrganizationID, v.RestrictedTypes())
}

// FilterRestrictedCiphers mirrors CliRestrictedItemTypesService.filterRestrictedCiphers.
func (v *Vault) FilterRestrictedCiphers(c []*CipherView) []*CipherView {
	return FilterRestrictedCiphers(c, v.RestrictedTypes())
}

// EquivalentDomains returns the equivalent domain sets from the synced settings.
func (v *Vault) EquivalentDomains() [][]string {
	if len(v.acct.Vault.Domains) == 0 {
		return nil
	}
	d := &Domains{}
	if json.Unmarshal(v.acct.Vault.Domains, d) != nil {
		return nil
	}
	return d.EquivalentDomainSets()
}

// ---------- ciphers ----------

// EncryptedCipher returns the stored encrypted cipher, or ErrNotFound.
func (v *Vault) EncryptedCipher(id string) (*Cipher, error) {
	raw, ok := v.acct.Vault.Ciphers[id]
	if !ok {
		return nil, ErrNotFound
	}
	return ParseCipher(raw)
}

// EncryptedCiphers returns all stored encrypted ciphers.
func (v *Vault) EncryptedCiphers() []*Cipher {
	out := []*Cipher{}
	for _, id := range state.OrderedIDs(v.acct.Vault.Ciphers, v.acct.Vault.CipherOrder) {
		if c, err := ParseCipher(v.acct.Vault.Ciphers[id]); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func (v *Vault) loadCiphers() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ciphers != nil {
		return
	}
	v.ciphers = []*CipherView{}
	v.failed = []*CipherView{}
	v.cipherByID = map[string]*CipherView{}
	for _, c := range v.EncryptedCiphers() {
		// excludeCiphersMissingOrgKey
		if c.OrganizationID != nil && !v.keys.HasOrgKey(*c.OrganizationID) {
			continue
		}
		view, err := DecryptCipher(c, v.keys)
		if err != nil {
			v.failed = append(v.failed, failedCipherView(c))
			continue
		}
		if view.Partial {
			continue
		}
		v.ciphers = append(v.ciphers, view)
		v.cipherByID[view.ID] = view
	}
	SortCiphers(v.ciphers)
}

// Ciphers mirrors cipherService.getAllDecrypted: successfully decrypted, non-partial items sorted
// by name. Items of organizations without an available key are skipped; undecryptable items are
// reported by FailedCiphers.
func (v *Vault) Ciphers() []*CipherView {
	v.loadCiphers()
	return append([]*CipherView{}, v.ciphers...)
}

// FailedCiphers returns placeholders ("[error: cannot decrypt]") for items that failed to decrypt.
func (v *Vault) FailedCiphers() []*CipherView {
	v.loadCiphers()
	return append([]*CipherView{}, v.failed...)
}

// Cipher mirrors cipherService.get + decrypt for one id. It returns ErrNotFound when the item is
// not stored and the decryption error when it cannot be decrypted.
func (v *Vault) Cipher(id string) (*CipherView, error) {
	c, err := v.EncryptedCipher(id)
	if err != nil {
		return nil, err
	}
	return DecryptCipher(c, v.keys)
}

// DecryptRaw decrypts a raw server cipher (e.g. a create/update response).
func (v *Vault) DecryptRaw(raw json.RawMessage) (*CipherView, error) {
	c, err := ParseCipher(raw)
	if err != nil {
		return nil, err
	}
	return DecryptCipher(c, v.keys)
}

// CiphersForURL mirrors cipherService.getAllDecryptedForUrl (defaultMatch nil = Domain).
func (v *Vault) CiphersForURL(targetURL string, defaultMatch *UriMatch) []*CipherView {
	return FilterCiphersForURL(v.Ciphers(), targetURL, v.EquivalentDomains(), defaultMatch)
}

// EncryptCipher encrypts a view with the account keys (new per-cipher keys are generated when
// the view has none; blob format for personal items on v2 accounts).
func (v *Vault) EncryptCipher(view *CipherView) (*Cipher, error) {
	c, _, err := EncryptCipher(view, v.keys)
	return c, err
}

// PrepareForSave mirrors cipherService.encrypt's adjustCipherHistory for an existing item:
// it compares with the stored item and updates password history / revision dates.
func (v *Vault) PrepareForSave(model *CipherView) {
	if model.ID == "" {
		return
	}
	existing, err := v.Cipher(model.ID)
	if err != nil {
		existing = nil
	}
	AdjustCipherHistory(model, existing)
}

// ---------- folders ----------

// Folders mirrors folderService.getAllDecryptedFromState: decryptable folders sorted by name,
// followed by the "No Folder" entry (id "").
func (v *Vault) Folders() []*FolderView {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.folders == nil {
		v.folders = []*FolderView{}
		for _, id := range state.OrderedIDs(v.acct.Vault.Folders, v.acct.Vault.FolderOrder) {
			raw := v.acct.Vault.Folders[id]
			f := &Folder{}
			if json.Unmarshal(raw, f) != nil {
				continue
			}
			fv, err := DecryptFolder(f, v.keys.UserKey())
			if err != nil {
				continue
			}
			v.folders = append(v.folders, fv)
		}
		SortFolders(v.folders)
		v.folders = append(v.folders, &FolderView{Name: NoFolderName, RevisionDate: time.Now().UTC()})
	}
	return append([]*FolderView{}, v.folders...)
}

// Folder returns a decrypted folder by id (ErrNotFound when missing or undecryptable).
func (v *Vault) Folder(id string) (*FolderView, error) {
	raw, ok := v.acct.Vault.Folders[id]
	if !ok {
		return nil, ErrNotFound
	}
	f := &Folder{}
	if err := json.Unmarshal(raw, f); err != nil {
		return nil, err
	}
	return DecryptFolder(f, v.keys.UserKey())
}

// ---------- collections ----------

// Collections mirrors collectionService.decryptedCollections$ (sorted by name).
func (v *Vault) Collections() []*CollectionView {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.collections == nil {
		v.collections = []*CollectionView{}
		for _, id := range state.OrderedIDs(v.acct.Vault.Collections, v.acct.Vault.CollectionOrder) {
			raw := v.acct.Vault.Collections[id]
			c := &Collection{}
			if json.Unmarshal(raw, c) != nil {
				continue
			}
			v.collections = append(v.collections, DecryptCollection(c, v.keys))
		}
		SortCollections(v.collections)
	}
	return append([]*CollectionView{}, v.collections...)
}

// Collection returns a decrypted collection by id.
func (v *Vault) Collection(id string) (*CollectionView, error) {
	raw, ok := v.acct.Vault.Collections[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := &Collection{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	return DecryptCollection(c, v.keys), nil
}

// DecryptCollectionRaw decrypts a raw server collection (e.g. from /organizations/{id}/collections).
func (v *Vault) DecryptCollectionRaw(raw json.RawMessage) (*CollectionView, error) {
	c := &Collection{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	return DecryptCollection(c, v.keys), nil
}

// ---------- state mutations ----------

func (v *Vault) mutate(fn func(acct *state.Account) error) error {
	if err := fn(v.acct); err != nil {
		return err
	}
	v.invalidate()
	if v.update == nil {
		return nil
	}
	return v.update(fn)
}

func (v *Vault) invalidate() {
	v.mu.Lock()
	v.ciphers, v.failed, v.cipherByID, v.folders, v.collections = nil, nil, nil, nil, nil
	v.mu.Unlock()
}

// rawID extracts the "id" of a raw server object.
func rawID(raw json.RawMessage) (string, error) {
	var x struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return "", err
	}
	if x.ID == "" {
		return "", errors.New("object has no id")
	}
	return x.ID, nil
}

// patchRaw decodes a raw object, sets/deletes keys (case-insensitively replacing existing keys)
// and re-encodes it.
func patchRaw(raw json.RawMessage, set map[string]any) (json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k, val := range set {
		for existing := range m {
			if strings.EqualFold(existing, k) {
				delete(m, existing)
			}
		}
		b, err := marshalNoEscape(val)
		if err != nil {
			return nil, err
		}
		m[k] = b
	}
	return marshalNoEscape(m)
}

// UpsertCipher stores a raw server cipher (CipherResponse/CipherDetailsResponse JSON) like
// cipherService.upsert(new CipherData(response, collectionIds)). When collectionIDs is non-nil it
// overrides the response's collectionIds (create/update responses don't carry them). It returns
// the decrypted view of the stored cipher (nil view if it cannot be decrypted).
func (v *Vault) UpsertCipher(raw json.RawMessage, collectionIDs []string) (*CipherView, error) {
	id, err := rawID(raw)
	if err != nil {
		return nil, err
	}
	if collectionIDs != nil {
		if raw, err = patchRaw(raw, map[string]any{"collectionIds": collectionIDs}); err != nil {
			return nil, err
		}
	}
	stored := append(json.RawMessage{}, raw...)
	if err := v.mutate(func(acct *state.Account) error {
		if acct.Vault.Ciphers == nil {
			acct.Vault.Ciphers = map[string]json.RawMessage{}
		}
		acct.Vault.Ciphers[id] = stored
		return nil
	}); err != nil {
		return nil, err
	}
	view, err := v.DecryptRaw(stored)
	if err != nil {
		return nil, nil
	}
	return view, nil
}

// UpsertCipherEncrypted stores an encrypted cipher model (e.g. when the server response was
// merged locally).
func (v *Vault) UpsertCipherEncrypted(c *Cipher) error {
	raw, err := marshalNoEscape(c)
	if err != nil {
		return err
	}
	_, err = v.UpsertCipher(raw, nil)
	return err
}

// DeleteCiphers removes ciphers from local state (cipherService.delete).
func (v *Vault) DeleteCiphers(ids ...string) error {
	return v.mutate(func(acct *state.Account) error {
		for _, id := range ids {
			delete(acct.Vault.Ciphers, id)
		}
		return nil
	})
}

// PatchCipher sets top-level properties of a stored cipher (nil values become null).
func (v *Vault) PatchCipher(id string, set map[string]any) error {
	return v.mutate(func(acct *state.Account) error {
		raw, ok := acct.Vault.Ciphers[id]
		if !ok {
			return nil
		}
		patched, err := patchRaw(raw, set)
		if err != nil {
			return err
		}
		acct.Vault.Ciphers[id] = patched
		return nil
	})
}

// SoftDeleteCiphers mirrors cipherService.softDelete (deletedDate = now).
func (v *Vault) SoftDeleteCiphers(ids ...string) error {
	now := cli.FormatDate(time.Now())
	for _, id := range ids {
		if err := v.PatchCipher(id, map[string]any{"deletedDate": now}); err != nil {
			return err
		}
	}
	return nil
}

// RestoreCipher mirrors cipherService.restore (deletedDate = null, revisionDate from the server).
func (v *Vault) RestoreCipher(id, revisionDate string) error {
	set := map[string]any{"deletedDate": nil}
	if revisionDate != "" {
		set["revisionDate"] = revisionDate
	}
	return v.PatchCipher(id, set)
}

// SetCipherArchived sets (or clears with nil) archivedDate and optionally revisionDate.
func (v *Vault) SetCipherArchived(id string, archivedDate *time.Time, revisionDate string) error {
	set := map[string]any{"archivedDate": nil}
	if archivedDate != nil {
		set["archivedDate"] = cli.FormatDate(*archivedDate)
	}
	if revisionDate != "" {
		set["revisionDate"] = revisionDate
	}
	return v.PatchCipher(id, set)
}

// UpsertFolder stores a raw server folder and returns its decrypted view.
func (v *Vault) UpsertFolder(raw json.RawMessage) (*FolderView, error) {
	id, err := rawID(raw)
	if err != nil {
		return nil, err
	}
	stored := append(json.RawMessage{}, raw...)
	if err := v.mutate(func(acct *state.Account) error {
		if acct.Vault.Folders == nil {
			acct.Vault.Folders = map[string]json.RawMessage{}
		}
		acct.Vault.Folders[id] = stored
		return nil
	}); err != nil {
		return nil, err
	}
	return v.Folder(id)
}

// DeleteFolder removes a folder locally and clears it from ciphers that used it (folderService.delete).
func (v *Vault) DeleteFolder(id string) error {
	return v.mutate(func(acct *state.Account) error {
		delete(acct.Vault.Folders, id)
		for cid, raw := range acct.Vault.Ciphers {
			c, err := ParseCipher(raw)
			if err != nil || c.FolderID == nil || *c.FolderID != id {
				continue
			}
			if patched, err := patchRaw(raw, map[string]any{"folderId": nil}); err == nil {
				acct.Vault.Ciphers[cid] = patched
			}
		}
		return nil
	})
}

// UpsertCollection stores a raw server collection and returns its decrypted view.
func (v *Vault) UpsertCollection(raw json.RawMessage) (*CollectionView, error) {
	id, err := rawID(raw)
	if err != nil {
		return nil, err
	}
	stored := append(json.RawMessage{}, raw...)
	if err := v.mutate(func(acct *state.Account) error {
		if acct.Vault.Collections == nil {
			acct.Vault.Collections = map[string]json.RawMessage{}
		}
		acct.Vault.Collections[id] = stored
		return nil
	}); err != nil {
		return nil, err
	}
	return v.Collection(id)
}

// DeleteCollection removes a collection locally.
func (v *Vault) DeleteCollection(id string) error {
	return v.mutate(func(acct *state.Account) error {
		delete(acct.Vault.Collections, id)
		return nil
	})
}
