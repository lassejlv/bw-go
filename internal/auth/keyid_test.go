package auth

import (
	"encoding/hex"
	"testing"

	"github.com/lassejlv/bw-go/internal/crypto"
)

func TestSymmetricKeyID(t *testing.T) {
	// SDK vector (symmetric_crypto_key.rs AES256_CBC_HMAC_KEY_ID): enc_key 0x00..0x1f, mac_key
	// 0x20..0x3f.
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}
	k, err := crypto.NewSymmetricKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := SymmetricKeyID(k); !ok || id != "ac4ecffb2e087a59180d1dd19950b8e9" {
		t.Errorf("aes-cbc-hmac key id = %q %v", id, ok)
	}

	// COSE keys carry their id (SDK PADDED_KEY vector: kid 0x00..0x0f).
	cose, err := crypto.KeyFromB64("pQEEAlAAAQIDBAUGBwgJCgsMDQ4PAzoAARF5BIIDBCBYIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAQ==")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := SymmetricKeyID(cose); !ok || id != "000102030405060708090a0b0c0d0e0f" {
		t.Errorf("cose key id = %q %v", id, ok)
	}
	gen, err := crypto.GenerateKeyFor(crypto.AlgXAes256Gcm)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := SymmetricKeyID(gen); !ok || id != hex.EncodeToString(gen.KeyID) {
		t.Errorf("generated cose key id = %q", id)
	}

	// The legacy AES-256-CBC key has no id.
	legacy, _ := crypto.NewSymmetricKey(make([]byte, 32))
	if _, ok := SymmetricKeyID(legacy); ok {
		t.Error("legacy key has an id")
	}

	if v, ok := ParseKeyID("AC4ECFFB2E087A59180D1DD19950B8E9"); !ok || v != "ac4ecffb2e087a59180d1dd19950b8e9" {
		t.Errorf("parse = %q %v", v, ok)
	}
	for _, bad := range []string{"", "abc", "zz4ecffb2e087a59180d1dd19950b8e9", "ac4ecffb2e087a59180d1dd19950b8e900"} {
		if _, ok := ParseKeyID(bad); ok {
			t.Errorf("ParseKeyID(%q) accepted", bad)
		}
	}
}
