package vaultedit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/vault"
)

// featureFlags are the server feature flags the upstream commands read through ConfigService.
type featureFlags struct {
	// NewItemTypes is FeatureFlag.PM32009NewItemTypes (bank account, driver's license and
	// passport items).
	NewItemTypes bool
	// DeriveSSHKeys is FeatureFlag.PM40201_DeriveSSHKeys (SSH key items may omit the public key
	// and fingerprint, which are then derived from the private key).
	DeriveSSHKeys bool
}

// Features returns the current flag values from the server config (see internal/features).
// Tests may replace it.
var Features = func(a *app.App) featureFlags {
	return featureFlags{
		NewItemTypes:  features.Enabled(a, features.NewItemTypes),
		DeriveSSHKeys: features.Enabled(a, features.DeriveSSHKeys),
	}
}

// errNoElements is the error upstream surfaces when a cipher cannot be decrypted
// (cipherEncryptionService.decrypt returns EMPTY and firstValueFrom rejects with an EmptyError).
var errNoElements = errors.New("no elements in sequence")

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

// isGUID mirrors Utils.isGuid.
func isGUID(s string) bool { return guidRe.MatchString(s) }

// isNullOrWhitespace mirrors Utils.isNullOrWhitespace.
func isNullOrWhitespace(s string) bool { return strings.TrimSpace(s) == "" }

// decodeB64Lenient decodes base64 like Node's Buffer.from(s, "base64"): url-safe characters are
// accepted, invalid characters ignored, decoding stops at the first '=' and padding is optional.
func decodeB64Lenient(s string) []byte {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			b.WriteRune(c)
		case c == '-':
			b.WriteByte('+')
		case c == '_':
			b.WriteByte('/')
		case c == '=':
			goto done
		}
	}
done:
	clean := b.String()
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out, _ := base64.RawStdEncoding.DecodeString(clean)
	return out
}

// readEncodedJSON implements the shared request handling of the create/edit/move commands:
// read stdin when no argument was given, then base64 decode and JSON parse. It returns the
// decoded JSON or a failed response.
func readEncodedJSON(encoded string) (json.RawMessage, *cli.Response) {
	if encoded == "" {
		s, err := cli.ReadStdin()
		if err != nil {
			return nil, cli.Error(err)
		}
		encoded = s
	}
	if encoded == "" {
		return nil, cli.BadRequest("`requestJson` was not provided.")
	}
	b := decodeB64Lenient(encoded)
	if !json.Valid(b) {
		return nil, cli.BadRequest("Error parsing the encoded request data.")
	}
	return json.RawMessage(b), nil
}

// isNullJSON reports whether raw is empty or the JSON literal null.
func isNullJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// parseRequest decodes the request JSON into out.
func parseRequest(raw json.RawMessage, out any) *cli.Response {
	if err := json.Unmarshal(raw, out); err != nil {
		return cli.BadRequest("Error parsing the encoded request data.")
	}
	return nil
}

// openVault opens the unlocked vault of the active account.
func openVault(a *app.App) (*vault.Vault, *cli.Response) {
	v, err := vault.Load(a)
	if err != nil {
		return nil, cli.Error(err)
	}
	return v, nil
}

// decryptedCipher decrypts a stored cipher like cipherService.decrypt (errNoElements on failure).
func decryptedCipher(v *vault.Vault, c *vault.Cipher) (*vault.CipherView, error) {
	view, err := vault.DecryptCipher(c, v.Keys())
	if err != nil || view == nil {
		return nil, errNoElements
	}
	return view, nil
}

// upsertResponse stores a server cipher response like cipherService.upsert(new CipherData(r,
// collectionIds)) and returns the decrypted view (errNoElements when it cannot be decrypted).
func upsertResponse(v *vault.Vault, raw json.RawMessage, collectionIDs []string) (*vault.CipherView, error) {
	if isNullJSON(raw) {
		return nil, errors.New("Invalid response from server.")
	}
	view, err := v.UpsertCipher(raw, collectionIDs)
	if err != nil {
		return nil, err
	}
	if view == nil {
		return nil, errNoElements
	}
	return view, nil
}

func isNewItemType(t vault.CipherType) bool {
	return t == vault.CipherTypeBankAccount || t == vault.CipherTypeDriversLicense || t == vault.CipherTypePassport
}
