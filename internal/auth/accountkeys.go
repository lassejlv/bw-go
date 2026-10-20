package auth

import (
	"encoding/json"
	"errors"

	"github.com/lassejlv/bw-go/internal/state"
)

// Account cryptographic state (AccountKeys: publicKeyEncryptionKeyPair {wrappedPrivateKey,
// publicKey, signedPublicKey}, signatureKeyPair {wrappedSigningKey, verifyingKey},
// securityState {securityState, securityVersion}) is needed by v2 encryption accounts. It is
// stored raw in state.Account.AccountKeys; the wrapped private key is additionally stored in
// state.Account.EncPrivateKey.

// SetAccountKeys stores (or, with a nil raw value, removes) the raw AccountKeys of a user.
// It must not be called from inside a Store.Update callback.
func SetAccountKeys(st *state.Store, userID string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = nil
	}
	return st.Update(func(d *state.Data) error {
		acct := d.Accounts[userID]
		if acct == nil {
			if raw == nil {
				return nil
			}
			return errors.New("You are not logged in.")
		}
		acct.AccountKeys = raw
		return nil
	})
}

// GetAccountKeys returns the raw AccountKeys of a user: the stored copy, or the accountKeys of the
// synced profile, or nil.
func GetAccountKeys(st *state.Store, acct *state.Account) json.RawMessage {
	if acct == nil {
		return nil
	}
	if len(acct.AccountKeys) > 0 {
		return acct.AccountKeys
	}
	if len(acct.Vault.Profile) > 0 {
		var p struct {
			AccountKeys json.RawMessage `json:"accountKeys"`
		}
		if json.Unmarshal(acct.Vault.Profile, &p) == nil && len(p.AccountKeys) > 0 && string(p.AccountKeys) != "null" {
			return p.AccountKeys
		}
	}
	return nil
}

// ParseAccountKeys decodes raw AccountKeys JSON (nil for empty input).
func ParseAccountKeys(raw json.RawMessage) *AccountKeys {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var k AccountKeys
	if json.Unmarshal(raw, &k) != nil {
		return nil
	}
	return &k
}
