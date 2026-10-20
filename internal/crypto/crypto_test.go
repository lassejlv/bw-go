package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Vectors from libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts.
func TestPBKDF2Vectors(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"password", "user@example.com", "pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I="},
		{"pǻssword", "üser@example.com", "yqvoFXgMRmHR3QPYr5pyR4uVuoHkltv9aHUP63p8n7I="},
		{"😀password🙏", "user@example.com", "ZdeOata6xoRpB4DLp8zHhXz5kLmkWtX5pd+TdRH8w8w="},
	}
	for _, c := range cases {
		k, err := MakeMasterKey(c.pw, c.salt, KdfConfig{Type: KdfPBKDF2, Iterations: 5000})
		if err != nil {
			t.Fatal(err)
		}
		if got := b64(k); got != c.want {
			t.Errorf("pbkdf2(%q) = %s, want %s", c.pw, got, c.want)
		}
	}
}

func TestHKDFVectors(t *testing.T) {
	ikm, _ := base64.StdEncoding.DecodeString("criAmKtfzxanbgea5/kelQ==")
	cases := []struct{ salt, info, want string }{
		{"salt", "info", "qBUmEYtwTwwGPuw/z6bs/qYXXYNUlocFlyAuuANI8Pw="},
		{"üser_salt", "üser_info", "6DfJwW1R3txgiZKkIFTvVAb7qVlG7lKcmJGJoxR2GBU="},
		{"😀salt🙏", "😀info🙏", "gejGI82xthA+nKtKmIh82kjw+ttHr+ODsUoGdu5sf0A="},
	}
	for _, c := range cases {
		if got := b64(HKDF(ikm, c.salt, c.info, 32)); got != c.want {
			t.Errorf("hkdf(%q) = %s, want %s", c.salt, got, c.want)
		}
	}
	prk, _ := base64.StdEncoding.DecodeString("F5h4KdYQnIVH4rKH0P9CZb1GrR4n16/sJrS0PsQEn0Y=")
	if got := b64(HKDFExpand(prk, "info", 32)); got != "BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD8=" {
		t.Errorf("hkdfExpand = %s", got)
	}
}

func TestEncStringRoundTrip(t *testing.T) {
	key := GenerateKey()
	s, err := EncryptString("hello wörld", key)
	if err != nil {
		t.Fatal(err)
	}
	if s[:2] != "2." {
		t.Fatalf("unexpected prefix %q", s)
	}
	got, err := DecryptString(s, key)
	if err != nil || got != "hello wörld" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := DecryptString(s, GenerateKey()); err == nil {
		t.Fatal("expected mac failure with wrong key")
	}
	parsed, _ := ParseEncString(s)
	if parsed.String() != s {
		t.Fatal("serialization mismatch")
	}
}

func TestLegacyAesOnly(t *testing.T) {
	key, _ := NewSymmetricKey(RandomBytes(32))
	s, err := EncryptString("legacy", key)
	if err != nil {
		t.Fatal(err)
	}
	if s[:2] != "0." {
		t.Fatalf("unexpected %q", s)
	}
	if got, err := DecryptString(s, key); err != nil || got != "legacy" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestEncArrayBuffer(t *testing.T) {
	key := GenerateKey()
	data := bytes.Repeat([]byte{1, 2, 3}, 100)
	enc, err := EncryptBytes(data, key)
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 2 || len(enc) < 49 {
		t.Fatal("bad layout")
	}
	dec, err := DecryptBytes(enc, key)
	if err != nil || !bytes.Equal(dec, data) {
		t.Fatalf("roundtrip failed: %v", err)
	}
}

func TestStretchAndUserKey(t *testing.T) {
	mk, _ := MakeMasterKey("password", "user@example.com", KdfConfig{Type: KdfPBKDF2, Iterations: 5000})
	stretched := StretchKey(mk)
	user := GenerateKey()
	wrapped, _ := Encrypt(user.Bytes(), stretched)
	got, err := DecryptToKey(wrapped.String(), stretched)
	if err != nil || !bytes.Equal(got.Bytes(), user.Bytes()) {
		t.Fatalf("user key unwrap failed: %v", err)
	}
	if HashMasterPassword("password", mk, HashServerAuthorization) == HashMasterPassword("password", mk, HashLocalAuthorization) {
		t.Fatal("server and local hashes must differ")
	}
}

func TestRSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	p, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(pubDer)
	if err != nil {
		t.Fatal(err)
	}
	orgKey := RandomBytes(64)
	enc, err := RsaEncrypt(orgKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := RsaDecrypt(enc, p)
	if err != nil || !bytes.Equal(dec, orgKey) {
		t.Fatalf("rsa roundtrip failed: %v", err)
	}
}

func TestArgon2(t *testing.T) {
	mem, par := 64, 4
	k, err := MakeMasterKey("password", "user@example.com", KdfConfig{Type: KdfArgon2id, Iterations: 3, Memory: &mem, Parallelism: &par})
	if err != nil || len(k) != 32 {
		t.Fatalf("argon2: %v", err)
	}
}
