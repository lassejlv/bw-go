package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/crypto"
)

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

type testEnv struct {
	userKey     *crypto.SymmetricKey
	orgKey      *crypto.SymmetricKey
	providerKey *crypto.SymmetricKey
	encPriv     string
	profile     *Profile
	keys        *Keys
}

const (
	testOrgID      = "11111111-1111-1111-1111-111111111111"
	testProvOrgID  = "22222222-2222-2222-2222-222222222222"
	testProviderID = "33333333-3333-3333-3333-333333333333"
	testUserID     = "44444444-4444-4444-4444-444444444444"
)

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	priv := testRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	env := &testEnv{userKey: crypto.GenerateKey(), orgKey: crypto.GenerateKey(), providerKey: crypto.GenerateKey()}
	e, err := crypto.Encrypt(der, env.userKey)
	if err != nil {
		t.Fatal(err)
	}
	env.encPriv = e.String()
	encOrg, err := crypto.RsaEncrypt(env.orgKey.Bytes(), &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encProv, err := crypto.RsaEncrypt(env.providerKey.Bytes(), &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	provOrgKey := crypto.GenerateKey()
	wrappedProvOrg, err := crypto.WrapKey(provOrgKey, env.providerKey)
	if err != nil {
		t.Fatal(err)
	}
	profileJSON := map[string]any{
		"id":    testUserID,
		"email": "user@example.com",
		"organizations": []any{map[string]any{
			"id": testOrgID, "name": "Acme", "key": encOrg, "status": 2, "type": 2, "enabled": true,
			"usePolicies": true, "useTotp": true,
		}},
		"providers": []any{map[string]any{"id": testProviderID, "name": "Prov", "key": encProv}},
		"providerOrganizations": []any{map[string]any{
			"id": testProvOrgID, "name": "Client Org", "key": wrappedProvOrg, "providerId": testProviderID,
			"status": 2, "type": 0, "enabled": true,
		}},
	}
	b, _ := json.Marshal(profileJSON)
	env.profile = &Profile{}
	if err := json.Unmarshal(b, env.profile); err != nil {
		t.Fatal(err)
	}
	env.keys = NewKeys(env.userKey, env.encPriv, nil, env.profile)
	return env
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := marshalNoEscape(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tm(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func tp(s string) *time.Time { t := tm(s); return &t }

func sp(s string) *string { return &s }

// roundTrip encrypts a view, serialises the encrypted cipher like the server would and decrypts it.
func roundTrip(t *testing.T, env *testEnv, v *CipherView) (*Cipher, *CipherView) {
	t.Helper()
	c, _, err := EncryptCipher(v, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCipher(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptCipher(parsed, env.keys)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, out
}
