// Package state persists CLI state (environment, accounts, tokens, encrypted vault data) to a
// JSON file in the application data directory, guarded by a cross-process lock.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
)

// FileName is the data file used by this port. It intentionally differs from the Node CLI's
// data.json so both clients can coexist in the same application data directory.
const FileName = "data-go.json"

// Environment holds server URLs. Empty values fall back to defaults derived from Base or cloud.
type Environment struct {
	Region        string `json:"region,omitempty"` // "US", "EU", "Gov" or "Self-hosted"
	Base          string `json:"base,omitempty"`
	WebVault      string `json:"webVault,omitempty"`
	Api           string `json:"api,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Icons         string `json:"icons,omitempty"`
	Notifications string `json:"notifications,omitempty"`
	Events        string `json:"events,omitempty"`
	KeyConnector  string `json:"keyConnector,omitempty"`
	Send          string `json:"send,omitempty"`
}

// VaultData is the encrypted vault as last synced from the server. Entities are kept as the
// raw server JSON so no fields are lost; they are keyed by id.
type VaultData struct {
	Profile     json.RawMessage            `json:"profile,omitempty"`
	Ciphers     map[string]json.RawMessage `json:"ciphers,omitempty"`
	Folders     map[string]json.RawMessage `json:"folders,omitempty"`
	Collections map[string]json.RawMessage `json:"collections,omitempty"`
	Policies    []json.RawMessage          `json:"policies,omitempty"`
	Sends       map[string]json.RawMessage `json:"sends,omitempty"`
	Domains     json.RawMessage            `json:"domains,omitempty"`

	// Server order of the entities as of the last sync (maps lose it). Iterate with OrderedIDs.
	CipherOrder     []string `json:"cipherOrder,omitempty"`
	FolderOrder     []string `json:"folderOrder,omitempty"`
	CollectionOrder []string `json:"collectionOrder,omitempty"`
	SendOrder       []string `json:"sendOrder,omitempty"`
}

// OrderedIDs returns the keys of m in server order: ids from order that are still present, then
// any keys added since the last sync, sorted (upstream appends new records to the end).
func OrderedIDs(m map[string]json.RawMessage, order []string) []string {
	out := make([]string, 0, len(m))
	seen := make(map[string]bool, len(m))
	for _, id := range order {
		if _, ok := m[id]; ok && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	var rest []string
	for id := range m {
		if !seen[id] {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// Account is everything persisted for a logged in user.
type Account struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	Name   string `json:"name,omitempty"`

	AccessToken     string `json:"accessToken,omitempty"`
	RefreshToken    string `json:"refreshToken,omitempty"`
	ApiClientID     string `json:"apiKeyClientId,omitempty"`
	ApiClientSecret string `json:"apiKeyClientSecret,omitempty"`

	Kdf     crypto.KdfConfig `json:"kdf"`
	KdfSalt string           `json:"kdfSalt,omitempty"`

	// EncUserKey is the user key wrapped by the (stretched) master key.
	EncUserKey string `json:"masterKeyEncryptedUserKey,omitempty"`
	// EncPrivateKey is the RSA private key wrapped by the user key.
	EncPrivateKey string `json:"encPrivateKey,omitempty"`
	// ProtectedUserKey is the user key encrypted with the BW_SESSION key (base64 EncArrayBuffer).
	ProtectedUserKey string `json:"protectedUserKey,omitempty"`
	// AccountKeys is the raw server AccountKeys object (v2 encryption: wrapped private key,
	// signed public key, signature key pair, security state).
	AccountKeys json.RawMessage `json:"accountKeys,omitempty"`

	HasMasterPassword      bool   `json:"hasMasterPassword"`
	UsesKeyConnector       bool   `json:"usesKeyConnector,omitempty"`
	KeyConnectorURL        string `json:"keyConnectorUrl,omitempty"`
	ForceSetPasswordReason int    `json:"forceSetPasswordReason,omitempty"`

	LastSync *time.Time `json:"lastSync,omitempty"`
	Vault    VaultData  `json:"vault"`
}

// ServerConfig caches the server's GET /config response (feature flags).
type ServerConfig struct {
	ApiURL        string                     `json:"apiUrl"`
	UserID        string                     `json:"userId,omitempty"`
	FetchedAt     time.Time                  `json:"fetchedAt"`
	FeatureStates map[string]json.RawMessage `json:"featureStates,omitempty"`
	Raw           json.RawMessage            `json:"raw,omitempty"`
}

// Data is the root of the persisted file.
type Data struct {
	AppID        string              `json:"appId,omitempty"`
	Environment  Environment         `json:"environment"`
	ServerConfig *ServerConfig       `json:"serverConfig,omitempty"`
	ActiveUserID string              `json:"activeUserId,omitempty"`
	Accounts     map[string]*Account `json:"accounts,omitempty"`
}

// Active returns the active account or nil.
func (d *Data) Active() *Account {
	if d.ActiveUserID == "" || d.Accounts == nil {
		return nil
	}
	return d.Accounts[d.ActiveUserID]
}

// Store reads and writes the data file.
type Store struct {
	Dir  string
	Path string
}

// AppDataDir resolves the application data directory like the Node CLI does.
func AppDataDir() string {
	if v := os.Getenv("BITWARDENCLI_APPDATA_DIR"); v != "" {
		p, _ := filepath.Abs(v)
		return p
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library/Application Support/Bitwarden CLI")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Bitwarden CLI")
	default:
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
			return filepath.Join(x, "Bitwarden CLI")
		}
		return filepath.Join(home, ".config/Bitwarden CLI")
	}
}

// Open prepares the store, creating the directory if needed.
func Open() (*Store, error) {
	dir := AppDataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir, Path: filepath.Join(dir, FileName)}, nil
}

func (s *Store) read() (*Data, error) {
	d := &Data{}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return d, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return d, nil
	}
	if err := json.Unmarshal(b, d); err != nil {
		// Mirror the Node CLI: back up the corrupt file and start fresh.
		_ = os.WriteFile(s.Path+".bak", b, 0o600)
		return &Data{}, nil
	}
	return d, nil
}

func (s *Store) write(d *Data) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Load reads the current state.
func (s *Store) Load() (*Data, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.read()
}

// Update applies fn to the state under the lock and writes it back. If fn returns an error the
// state is not written.
func (s *Store) Update(fn func(d *Data) error) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	d, err := s.read()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	return s.write(d)
}

// lock uses a lock directory (like proper-lockfile) so it works on every platform.
func (s *Store) lock() (func(), error) {
	lockDir := s.Path + ".lock"
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
			return nil, fmt.Errorf("could not acquire lock on %s", s.Path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
