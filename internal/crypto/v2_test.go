package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func vec(t *testing.T, name string) string {
	t.Helper()
	v, ok := sdkVectors[name]
	if !ok {
		t.Fatalf("missing vector %s", name)
	}
	return v
}

// vecBytes decodes "hex:" vectors, plain hex strings (when isHex) or standard base64.
func vecBytes(t *testing.T, name string) []byte {
	t.Helper()
	v := vec(t, name)
	if strings.HasPrefix(v, "hex:") {
		b, err := hex.DecodeString(v[4:])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if b, err := hex.DecodeString(v); err == nil {
		return b
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func mustKey(t *testing.T, b64 string) *SymmetricKey {
	t.Helper()
	k, err := KeyFromB64(b64)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------- primitives ----------

func TestXAES256GCMC2SPVectors(t *testing.T) {
	nonce := []byte("ABCDEFGHIJKLMNOPQRSTUVWX")
	cases := []struct {
		key  byte
		aad  string
		want string
	}{
		{1, "", "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"},
		{3, "c2sp.org/XAES-256-GCM", "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"},
	}
	for _, c := range cases {
		key := bytes.Repeat([]byte{c.key}, 32)
		ct, err := aeadSeal(coseAlgXAes256Gcm, key, nonce, []byte("XAES-256-GCM"), []byte(c.aad))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(ct) != c.want {
			t.Errorf("xaes ct = %x, want %s", ct, c.want)
		}
		pt, err := aeadOpen(coseAlgXAes256Gcm, key, nonce, ct, []byte(c.aad))
		if err != nil || string(pt) != "XAES-256-GCM" {
			t.Errorf("xaes open: %q %v", pt, err)
		}
	}
}

func TestCbcHmacAeadVector(t *testing.T) {
	ct := vecBytes(t, "CBCAEAD_TESTVECTOR_ENCRYPTED")
	pt, err := aeadOpen(coseAlgAes256CbcHmacAead, seq(64, 0), seq(16, 0), ct, []byte("Bitwarden SDK test vector associated data"))
	if err != nil || string(pt) != "Bitwarden SDK test vector" {
		t.Fatalf("got %q %v", pt, err)
	}
	// Our encryption with the same nonce must produce the identical ciphertext.
	again, _ := aeadSeal(coseAlgAes256CbcHmacAead, seq(64, 0), seq(16, 0), pt, []byte("Bitwarden SDK test vector associated data"))
	if !bytes.Equal(again, ct) {
		t.Fatal("cbc-hmac aead encryption mismatch")
	}
	if _, err := aeadOpen(coseAlgAes256CbcHmacAead, seq(64, 0), seq(16, 0), ct, []byte("other")); err == nil {
		t.Fatal("expected failure with wrong aad")
	}
}

func TestPadBytes(t *testing.T) {
	cases := []struct{ n, min, want int }{{63, 65, 65}, {64, 65, 65}, {65, 65, 66}, {0, 32, 32}, {10, 12, 12}}
	for _, c := range cases {
		p, err := padBytes(bytes.Repeat([]byte{1}, c.n), c.min)
		if err != nil || len(p) != c.want {
			t.Fatalf("pad(%d,%d) = %d %v", c.n, c.min, len(p), err)
		}
		u, err := unpadBytes(p)
		if err != nil || len(u) != c.n {
			t.Fatalf("unpad: %d %v", len(u), err)
		}
	}
	if _, err := padBytes(nil, 256); err == nil {
		t.Fatal("expected padding error")
	}
	for _, bad := range [][]byte{{}, {1, 2, 3, 5}, {1, 2, 3, 0}} {
		if _, err := unpadBytes(bad); err == nil {
			t.Fatalf("expected unpad error for %v", bad)
		}
	}
}

// ---------- keys ----------

func TestDecodeCoseSymmetricKeyVectors(t *testing.T) {
	cases := []struct {
		vector, thumb string
		alg           SymmetricKeyAlgorithm
	}{
		{"SKEY_XCHACHA20_POLY1305_KEY", "SKEY_XCHACHA20_POLY1305_KEY_THUMBPRINT", AlgXChaCha20Poly1305},
		{"SKEY_AES256_GCM_KEY", "SKEY_AES256_GCM_KEY_THUMBPRINT", AlgAes256Gcm},
		{"SKEY_PADDED_KEY", "", AlgXAes256Gcm},
		{"CORE_TEST_VECTOR_USER_KEY_V2_B64", "", AlgXAes256Gcm},
	}
	for _, c := range cases {
		k := mustKey(t, vec(t, c.vector))
		if k.EncType != CoseEncrypt0 || k.KeyAlgorithm() != c.alg || len(k.KeyID) != 16 || len(k.EncKey) != 32 {
			t.Fatalf("%s: unexpected key %+v", c.vector, k)
		}
		if k.B64() != vec(t, c.vector) {
			t.Errorf("%s: re-encoding mismatch\n got %s", c.vector, k.B64())
		}
		if c.thumb != "" {
			tp, err := k.Thumbprint()
			if err != nil || hex.EncodeToString(tp) != vec(t, c.thumb) {
				t.Errorf("%s: thumbprint %x %v", c.vector, tp, err)
			}
		}
	}
	// The fixed XAES key from symmetric_crypto_key.rs tests.
	fixed := &SymmetricKey{EncKey: seq(32, 0), EncType: CoseEncrypt0, Algorithm: AlgXAes256Gcm, KeyID: seq(16, 0), KeyOps: []KeyOperation{KeyOpEncrypt, KeyOpDecrypt}}
	if fixed.B64() != vec(t, "SKEY_PADDED_KEY") {
		t.Fatalf("fixed xaes key encoding = %s", fixed.B64())
	}
	parsed := mustKey(t, vec(t, "SKEY_PADDED_KEY"))
	if len(parsed.KeyOps) != 2 || !parsed.AllowsOp(KeyOpEncrypt) || !parsed.AllowsOp(KeyOpDecrypt) || parsed.AllowsOp(KeyOpWrapKey) {
		t.Fatalf("ops = %v", parsed.KeyOps)
	}
}

func TestLegacyKeyThumbprintAndID(t *testing.T) {
	k, _ := NewSymmetricKey(seq(64, 0))
	tp, err := k.Thumbprint()
	if err != nil || hex.EncodeToString(tp) != vec(t, "SKEY_AES256_CBC_HMAC_KEY_THUMBPRINT") {
		t.Fatalf("thumbprint %x %v", tp, err)
	}
	if k.IDHex() != vec(t, "SKEY_AES256_CBC_HMAC_KEY_ID") {
		t.Fatalf("id %s", k.IDHex())
	}
	if len(k.Bytes()) != 64 || !bytes.Equal(k.Bytes(), seq(64, 0)) {
		t.Fatal("legacy encoding changed")
	}
	k32, _ := NewSymmetricKey(seq(32, 0))
	if k32.ID() != nil {
		t.Fatal("aes-cbc key must have no id")
	}
	// Key length rules of try_from(&[u8]).
	for _, n := range []int{0, 31, 33, 63} {
		if _, err := NewSymmetricKey(make([]byte, n)); err == nil {
			t.Fatalf("expected error for %d bytes", n)
		}
	}
}

func TestGenerateKeyForRoundTrip(t *testing.T) {
	for _, alg := range []SymmetricKeyAlgorithm{AlgXChaCha20Poly1305, AlgAes256Gcm, AlgXAes256Gcm, AlgAes256CbcHmac} {
		k, err := GenerateKeyFor(alg)
		if err != nil {
			t.Fatal(err)
		}
		if k.KeyAlgorithm() != alg {
			t.Fatalf("alg %v", k.KeyAlgorithm())
		}
		back, err := NewSymmetricKey(k.Bytes())
		if err != nil || !bytes.Equal(back.Bytes(), k.Bytes()) || back.KeyAlgorithm() != alg {
			t.Fatalf("%v roundtrip: %v", alg, err)
		}
		if alg != AlgAes256CbcHmac && len(k.Bytes()) <= 64 {
			t.Fatal("COSE keys must be padded above 64 bytes")
		}
	}
	if _, err := GenerateKeyFor(AlgAes256Cbc); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- type 7 EncStrings ----------

func TestCoseEncrypt0TestVector(t *testing.T) {
	raw := vecBytes(t, "COSE_TEST_VECTOR_COSE_ENCRYPT0")
	key := &SymmetricKey{EncKey: seq(32, 0), EncType: CoseEncrypt0, Algorithm: AlgXChaCha20Poly1305, KeyID: seq(16, 0), KeyOps: defaultKeyOps}
	s := "7." + base64.StdEncoding.EncodeToString(raw)
	e, err := ParseEncString(s)
	if err != nil {
		t.Fatal(err)
	}
	pt, cf, err := e.DecryptWithFormat(key)
	if err != nil || string(pt) != "Message test vector" || cf != ContentFormatOctetStream {
		t.Fatalf("got %q %v %v", pt, cf, err)
	}
	if !bytes.Equal(e.KeyID(), seq(16, 0)) || e.KeyAlgorithm() != AlgXChaCha20Poly1305 {
		t.Fatal("key id / algorithm")
	}
	// Re-encoding the parsed message reproduces the exact bytes (coset-compatible encoding).
	msg, _ := parseCoseEncrypt0(raw)
	if !bytes.Equal(msg.encode(), raw) || !bytes.Equal(msg.Protected.encodeProtected(), msg.ProtectedRaw) {
		t.Fatal("COSE_Encrypt0 re-encoding mismatch")
	}
	wrongID := *key
	wrongID.KeyID = bytes.Repeat([]byte{1}, 16)
	if _, err := e.Decrypt(&wrongID); err == nil {
		t.Fatal("expected wrong key id error")
	}
	if _, err := e.Decrypt(GenerateKey()); err == nil {
		t.Fatal("legacy key must not decrypt type 7")
	}
}

func TestCoseEncStringRoundTrip(t *testing.T) {
	for _, alg := range []SymmetricKeyAlgorithm{AlgXChaCha20Poly1305, AlgXAes256Gcm} {
		key, _ := GenerateKeyFor(alg)
		for _, plain := range []string{"", "hello wörld", strings.Repeat("a", 100)} {
			s, err := EncryptString(plain, key)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(s, "7.") {
				t.Fatalf("prefix %q", s)
			}
			e, _ := ParseEncString(s)
			msg, err := parseCoseEncrypt0(e.Data)
			if err != nil {
				t.Fatal(err)
			}
			if msg.Protected.ContentType != contentTypePaddedUtf8 || !bytes.Equal(msg.Protected.KeyID, key.KeyID) || len(msg.Unprotected.IV) != 24 {
				t.Fatalf("unexpected header %+v", msg.Protected)
			}
			got, err := DecryptString(s, key)
			if err != nil || got != plain {
				t.Fatalf("got %q %v", got, err)
			}
			other, _ := GenerateKeyFor(alg)
			other.KeyID = key.KeyID
			if _, err := DecryptString(s, other); err == nil {
				t.Fatal("expected failure with wrong key material")
			}
		}
		// Utf8 padding: lengths 0..31 share a size, 32 is bigger.
		l := func(n int) int { s, _ := EncryptString(strings.Repeat("a", n), key); return len(s) }
		if l(0) != l(31) || l(31) == l(32) || l(32) != l(63) || l(63) == l(64) {
			t.Fatal("unexpected padding block sizes")
		}
		// Bytes use OctetStream and are not padded.
		e, _ := Encrypt([]byte{1, 2, 3}, key)
		_, cf, err := e.DecryptWithFormat(key)
		if err != nil || cf != ContentFormatOctetStream {
			t.Fatalf("cf %v %v", cf, err)
		}
		// EncArrayBuffer.
		buf, err := EncryptBytes(bytes.Repeat([]byte{9}, 1000), key)
		if err != nil || buf[0] != 7 {
			t.Fatalf("buffer %v", err)
		}
		dec, err := DecryptBytes(buf, key)
		if err != nil || !bytes.Equal(dec, bytes.Repeat([]byte{9}, 1000)) {
			t.Fatalf("buffer roundtrip %v", err)
		}
	}
	gcm, _ := GenerateKeyFor(AlgAes256Gcm)
	if _, err := EncryptString("x", gcm); err == nil {
		t.Fatal("AES-GCM keys cannot encrypt EncStrings")
	}
	decOnly, _ := GenerateKeyFor(AlgXAes256Gcm)
	decOnly.KeyOps = []KeyOperation{KeyOpDecrypt}
	if _, err := EncryptString("x", decOnly); err == nil {
		t.Fatal("expected KeyOperationNotSupported")
	}
	if _, _, _, err := AesEncrypt([]byte("x"), decOnly); err == nil {
		t.Fatal("AesEncrypt must reject COSE keys")
	}
}

func TestWrapKeyMatrix(t *testing.T) {
	legacy := GenerateKey()
	xaes, _ := GenerateKeyFor(AlgXAes256Gcm)
	xchacha, _ := GenerateKeyFor(AlgXChaCha20Poly1305)
	gcm, _ := GenerateKeyFor(AlgAes256Gcm)
	cases := []struct {
		wrapped, wrapping *SymmetricKey
		prefix            string
		cf                ContentFormat
	}{
		{xaes, legacy, "2.", ContentFormatUnknown},
		{gcm, legacy, "2.", ContentFormatUnknown},
		{legacy, xaes, "7.", ContentFormatBitwardenLegacyKey},
		{legacy, xchacha, "7.", ContentFormatBitwardenLegacyKey},
		{gcm, xaes, "7.", ContentFormatCoseKey},
		{xchacha, xaes, "7.", ContentFormatCoseKey},
	}
	for i, c := range cases {
		s, err := WrapKey(c.wrapped, c.wrapping)
		if err != nil || !strings.HasPrefix(s, c.prefix) {
			t.Fatalf("%d: %q %v", i, s, err)
		}
		e, _ := ParseEncString(s)
		_, cf, err := e.DecryptWithFormat(c.wrapping)
		if err != nil || cf != c.cf {
			t.Fatalf("%d: cf %v %v", i, cf, err)
		}
		got, err := DecryptToKey(s, c.wrapping)
		if err != nil || !bytes.Equal(got.Bytes(), c.wrapped.Bytes()) {
			t.Fatalf("%d: unwrap %v", i, err)
		}
	}
	if _, err := WrapKey(legacy, gcm); err == nil {
		t.Fatal("AES-GCM cannot wrap")
	}
	// Strict content format: an OctetStream EncString is not a wrapped key.
	e, _ := Encrypt(legacy.Bytes(), xaes)
	if _, err := DecryptToKey(e.String(), xaes); err == nil {
		t.Fatal("expected content format error")
	}
	// Legacy compat: user key encrypted by stretched master key, COSE user key inside type 2.
	mk, _ := MakeMasterKey("password", "user@example.com", KdfConfig{Type: KdfPBKDF2, Iterations: 5000})
	stretched := StretchKey(mk)
	wrapped, _ := Encrypt(xaes.Bytes(), stretched)
	uk, err := DecryptToKey(wrapped.String(), stretched)
	if err != nil || !uk.IsCose() || !bytes.Equal(uk.KeyID, xaes.KeyID) {
		t.Fatalf("v2 user key unwrap: %v", err)
	}
}

// ---------- v2 account (bitwarden-core test vectors) ----------

func TestV2AccountVectors(t *testing.T) {
	userKey := mustKey(t, vec(t, "CORE_TEST_VECTOR_USER_KEY_V2_B64"))
	if userKey.KeyAlgorithm() != AlgXAes256Gcm {
		t.Fatalf("user key alg %v", userKey.KeyAlgorithm())
	}

	pkEnc, _ := ParseEncString(vec(t, "CORE_TEST_VECTOR_PRIVATE_KEY_V2"))
	der, cf, err := pkEnc.DecryptWithFormat(userKey)
	if err != nil || cf != ContentFormatPkcs8PrivateKey {
		t.Fatalf("private key: %v %v", cf, err)
	}
	priv, err := ParsePrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pubDer, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if base64.StdEncoding.EncodeToString(pubDer) != vec(t, "CORE_TEST_VECTOR_PUBLIC_KEY_V2") {
		t.Fatal("public key mismatch")
	}

	skEnc, _ := ParseEncString(vec(t, "CORE_TEST_VECTOR_SIGNING_KEY_V2"))
	skBytes, cf, err := skEnc.DecryptWithFormat(userKey)
	if err != nil || cf != ContentFormatCoseKey {
		t.Fatalf("signing key: %v %v", cf, err)
	}
	sk, err := ParseSigningKey(skBytes)
	if err != nil || sk.Algorithm != SignatureAlgorithmEd25519 {
		t.Fatalf("signing key parse: %v", err)
	}
	if !bytes.Equal(sk.Bytes(), skBytes) {
		t.Fatal("signing key re-encoding mismatch")
	}
	vk := sk.VerifyingKey()
	if base64.StdEncoding.EncodeToString(vk.Bytes()) != vec(t, "CORE_TEST_VECTOR_VERIFYING_KEY_V2") {
		t.Fatalf("verifying key = %s", base64.StdEncoding.EncodeToString(vk.Bytes()))
	}

	pub, spki, err := VerifySignedPublicKey(vec(t, "CORE_TEST_VECTOR_SIGNED_PUBLIC_KEY_V2"), vk)
	if err != nil || !bytes.Equal(spki, pubDer) || pub.N.Cmp(priv.N) != 0 {
		t.Fatalf("signed public key: %v", err)
	}
	st, err := VerifySecurityState(vec(t, "CORE_TEST_VECTOR_SECURITY_STATE_V2"), vk)
	if err != nil || st.Version != 2 {
		t.Fatalf("security state: %+v %v", st, err)
	}
	if v, err := UnverifiedSecurityStateVersion(vec(t, "CORE_TEST_VECTOR_SECURITY_STATE_V2")); err != nil || v != 2 {
		t.Fatalf("unverified version %d %v", v, err)
	}

	acc, err := UnlockAccountCryptographicState(userKey, vec(t, "CORE_TEST_VECTOR_PRIVATE_KEY_V2"), vec(t, "CORE_TEST_VECTOR_SIGNING_KEY_V2"),
		vec(t, "CORE_TEST_VECTOR_SIGNED_PUBLIC_KEY_V2"), vec(t, "CORE_TEST_VECTOR_SECURITY_STATE_V2"))
	if err != nil || !acc.IsV2() || acc.SecurityState.Version != 2 || acc.PrivateKey == nil {
		t.Fatalf("unlock: %v", err)
	}
	// Tampered: security state signed by a different key.
	if _, err := UnlockAccountCryptographicState(userKey, vec(t, "CORE_TEST_VECTOR_PRIVATE_KEY_V2"), vec(t, "CORE_TEST_VECTOR_SIGNING_KEY_V2"),
		vec(t, "CORE_TEST_VECTOR_SIGNED_PUBLIC_KEY_V2"), vec(t, "SS_TEST_SIGNED_SECURITY_STATE")); err == nil {
		t.Fatal("expected verification failure")
	}
	// Wrong user key type.
	if _, err := UnlockAccountCryptographicState(GenerateKey(), vec(t, "CORE_TEST_VECTOR_PRIVATE_KEY_V2"), vec(t, "CORE_TEST_VECTOR_SIGNING_KEY_V2"),
		vec(t, "CORE_TEST_VECTOR_SIGNED_PUBLIC_KEY_V2"), vec(t, "CORE_TEST_VECTOR_SECURITY_STATE_V2")); err == nil {
		t.Fatal("expected wrong user key type")
	}
	// Signing a public key with a different key fails verification.
	if _, _, err := VerifySignedPublicKey(vec(t, "CORE_TEST_VECTOR_SIGNED_PUBLIC_KEY_V2"), mustVerifyingKey(t, vecBytes(t, "VK_VERIFYING_KEY"))); err == nil {
		t.Fatal("expected verification failure with other key")
	}
}

func mustVerifyingKey(t *testing.T, b []byte) *VerifyingKey {
	t.Helper()
	vk, err := ParseVerifyingKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return vk
}

// ---------- signing vectors ----------

func TestSigningVectors(t *testing.T) {
	vkBytes := vecBytes(t, "VK_VERIFYING_KEY")
	vk := mustVerifyingKey(t, vkBytes)
	if !bytes.Equal(vk.Bytes(), vkBytes) {
		t.Fatal("verifying key re-encoding mismatch")
	}
	if hex.EncodeToString(vk.Thumbprint()) != "ea38af8eb96812daa5217a342946814921f0ebc74edaa1e9832cbc4daf9ba803" {
		t.Fatal("ed25519 thumbprint")
	}
	if vk.verifyRaw(vecBytes(t, "VK_SIGNED_DATA_RAW"), []byte("Test message")) != nil {
		t.Fatal("raw signature")
	}
	if vk.verifyRaw(vecBytes(t, "VK_SIGNED_DATA_RAW"), []byte("Invalid message")) == nil {
		t.Fatal("raw signature must fail")
	}

	// Signed object.
	soBytes := vecBytes(t, "SO_SIGNED_OBJECT")
	so, err := ParseSignedObject(soBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(so.Bytes(), soBytes) {
		t.Fatal("signed object re-encoding mismatch")
	}
	payload, err := so.VerifyAndUnwrap(mustVerifyingKey(t, vecBytes(t, "SO_VERIFYING_KEY")), SigningNamespace(-1))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := CBORToJSON(payload)
	if string(j) != `{"field1":"Test message"}` {
		t.Fatalf("payload %s", j)
	}
	if _, err := so.VerifyAndUnwrap(vk, SigningNamespace(-2)); err == nil {
		t.Fatal("namespace mismatch must fail")
	}

	// Detached signature.
	sig, err := ParseSignedObject(vecBytes(t, "SIG_SIGNATURE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.VerifyDetached(vecBytes(t, "SIG_SERIALIZED_MESSAGE"), mustVerifyingKey(t, vecBytes(t, "SIG_VERIFYING_KEY")), SigningNamespace(-1)); err != nil {
		t.Fatal(err)
	}

	// ML-DSA-44.
	mlsk, err := ParseSigningKey(vecBytes(t, "SK_MLDSA44_SIGNING_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mlsk.Bytes(), vecBytes(t, "SK_MLDSA44_SIGNING_KEY")) {
		t.Fatal("ml-dsa signing key re-encoding mismatch")
	}
	mlvk := mlsk.VerifyingKey()
	if !bytes.Equal(mlvk.Bytes(), vecBytes(t, "SK_MLDSA44_VERIFYING_KEY")) {
		t.Fatal("ml-dsa verifying key mismatch")
	}
	if mlvk.verifyRaw(vecBytes(t, "SK_MLDSA44_SIGNED_DATA_RAW"), []byte("Test message")) != nil {
		t.Fatal("ml-dsa raw signature")
	}
	parsedML := mustVerifyingKey(t, vecBytes(t, "VK_MLDSA44_VERIFYING_KEY"))
	if hex.EncodeToString(parsedML.Thumbprint()) != "fb932d165a6ff31caf0537ecb3c267dcbdac69773de6b739211c00e68969e233" {
		t.Fatal("ml-dsa thumbprint")
	}

	// Security state vector.
	st, err := VerifySecurityState(vec(t, "SS_TEST_SIGNED_SECURITY_STATE"), mustVerifyingKey(t, vecBytes(t, "SS_TEST_VERIFYING_KEY")))
	if err != nil || st.Version != 2 {
		t.Fatalf("security state %v", err)
	}
}

func TestSigningRoundTrip(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{SignatureAlgorithmEd25519, SignatureAlgorithmMlDsa44} {
		sk, err := GenerateSigningKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigningKey(sk.Bytes())
		if err != nil || !bytes.Equal(parsed.VerifyingKey().Bytes(), sk.VerifyingKey().Bytes()) {
			t.Fatalf("%v: parse %v", alg, err)
		}
		userKey, _ := GenerateKeyFor(AlgXAes256Gcm)
		wrapped, err := WrapSigningKey(sk, userKey)
		if err != nil {
			t.Fatal(err)
		}
		priv := mustRSA(t)
		wrappedPriv, _ := der(t, priv)
		wpk, err := WrapPrivateKey(wrappedPriv, userKey)
		if err != nil {
			t.Fatal(err)
		}
		spk, err := MakeSignedPublicKey(&priv.PublicKey, sk)
		if err != nil {
			t.Fatal(err)
		}
		ss, err := MakeSecurityState(2, sk)
		if err != nil {
			t.Fatal(err)
		}
		acc, err := UnlockAccountCryptographicState(userKey, wpk, wrapped, spk, ss)
		if err != nil || acc.SecurityState.Version != 2 || acc.PublicKey.N.Cmp(priv.N) != 0 {
			t.Fatalf("%v: unlock %v", alg, err)
		}
		detached, _ := sk.SignDetached([]byte{0xa0}, SigningNamespaceSecurityState)
		obj, _ := ParseSignedObject(detached)
		if obj.VerifyDetached([]byte{0xa0}, sk.VerifyingKey(), SigningNamespaceSecurityState) != nil {
			t.Fatal("detached roundtrip")
		}
	}
}

// ---------- data envelopes ----------

func TestDataEnvelopeVectors(t *testing.T) {
	for _, c := range []struct{ cek, env string }{
		{"DE_TEST_VECTOR_CEK", "DE_TEST_VECTOR_ENVELOPE"},
		{"DE_TEST_VECTOR_AES_GCM_CEK", "DE_TEST_VECTOR_AES_GCM_ENVELOPE"},
	} {
		cek := mustKey(t, vec(t, c.cek))
		content, err := OpenDataEnvelope(vec(t, c.env), DataEnvelopeNamespace(-1), cek)
		if err != nil {
			t.Fatalf("%s: %v", c.env, err)
		}
		j, _ := CBORToJSON(content)
		if string(j) != `{"version":"1","content":{"field":123}}` {
			t.Fatalf("%s: %s", c.env, j)
		}
		if _, err := OpenDataEnvelope(vec(t, c.env), DataEnvelopeNamespace(-2), cek); err != ErrDataEnvelopeInvalidNamespace {
			t.Fatalf("expected namespace error, got %v", err)
		}
		raw, _ := base64.StdEncoding.DecodeString(vec(t, c.env))
		msg, _ := parseCoseEncrypt0(raw)
		if !bytes.Equal(msg.encode(), raw) || !bytes.Equal(msg.Protected.encodeProtected(), msg.ProtectedRaw) {
			t.Fatalf("%s: re-encoding mismatch", c.env)
		}
	}
	other, _ := GenerateKeyFor(AlgAes256Gcm)
	if _, err := OpenDataEnvelope(vec(t, "DE_TEST_VECTOR_AES_GCM_ENVELOPE"), DataEnvelopeNamespace(-1), other); err != ErrDataEnvelopeWrongKey {
		t.Fatalf("expected wrong key, got %v", err)
	}
}

func TestCipherBlobVectors(t *testing.T) {
	names := map[string]string{
		"SECURE_NOTE": "Test Secure Note", "LOGIN": "Test Login", "CARD": "Test Card", "IDENTITY": "Test Identity",
		"SSH_KEY": "", "BANK_ACCOUNT": "", "PASSPORT": "", "DRIVERS_LICENSE": "",
	}
	for kind, name := range names {
		cek := mustKey(t, vec(t, "BLOB_TEST_VECTOR_"+kind+"_CEK"))
		content, err := OpenDataEnvelope(vec(t, "BLOB_TEST_VECTOR_"+kind+"_ENVELOPE"), DataEnvelopeNamespaceVaultItem, cek)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		j, err := CBORToJSON(content)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Version string `json:"version"`
			Content struct {
				Name     string         `json:"name"`
				TypeData map[string]any `json:"typeData"`
			} `json:"content"`
		}
		if err := json.Unmarshal(j, &v); err != nil || v.Version != "1" || v.Content.TypeData["type"] == nil {
			t.Fatalf("%s: %s %v", kind, j, err)
		}
		if name != "" && v.Content.Name != name {
			t.Fatalf("%s: name %q", kind, v.Content.Name)
		}
		// JSON -> CBOR -> JSON is stable, so the vault package can work with JSON.
		c2, err := JSONToCBOR(j)
		if err != nil {
			t.Fatal(err)
		}
		j2, _ := CBORToJSON(c2)
		if !bytes.Equal(j, j2) {
			t.Fatalf("%s: JSON bridge not stable\n%s\n%s", kind, j, j2)
		}
		if kind == "LOGIN" {
			t.Logf("login blob JSON: %s", j)
		}
	}
}

func TestSealedBlobVectors(t *testing.T) {
	wrapping := mustKey(t, vec(t, "SEALED_TEST_VECTOR_WRAPPING_KEY"))
	blob := vec(t, "SEALED_TEST_VECTOR_SEALED_BLOB")
	if !IsSealedBlob(blob) || IsSealedBlob(`{"Name":"x"}`) || IsSealedBlob("2.abc|def|ghi") {
		t.Fatal("IsSealedBlob")
	}
	j, err := OpenBlob(blob, wrapping)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"1","content":{"name":"Test Cipher","notes":"Some notes","typeData":{"type":"secureNote","secureNoteType":0}}}`
	if string(j) != want {
		t.Fatalf("blob = %s", j)
	}

	// Item send: send key = HKDF(seed, "bitwarden-send", "send", 64), seed decrypted with user key.
	userKey := mustKey(t, vec(t, "SEND_TEST_USER_KEY"))
	seed, err := ParseEncString(vec(t, "SEND_TEST_SEND_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	seedBytes, err := seed.Decrypt(userKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(seedBytes) != vec(t, "SEND_TEST_SEND_KEY_B64") {
		t.Fatalf("send seed %v", err)
	}
	sendKey, _ := NewSymmetricKey(HKDF(seedBytes, "bitwarden-send", "send", 64))
	sj, err := OpenBlob(vec(t, "SEND_TEST_VECTOR_ITEM_SEND_DATA"), sendKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sj), `"name":"Item Send"`) || !strings.Contains(string(sj), `"password":"hunter2"`) {
		t.Fatalf("item send blob = %s", sj)
	}

	// Round trip with legacy and v2 wrapping keys; namespace/format checks.
	for _, alg := range []SymmetricKeyAlgorithm{AlgAes256CbcHmac, AlgXAes256Gcm} {
		k, _ := GenerateKeyFor(alg)
		s, err := SealBlob([]byte(want), k)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(s, `{"format_version":1,"wrapped_cek":"`) {
			t.Fatalf("container %s", s)
		}
		got, err := OpenBlob(s, k)
		if err != nil || string(got) != want {
			t.Fatalf("roundtrip %s %v", got, err)
		}
	}
	bad := strings.Replace(blob, `"format_version":1`, `"format_version":99`, 1)
	if _, err := OpenBlob(bad, wrapping); err == nil {
		t.Fatal("expected unsupported format version")
	}
}

func TestDataEnvelopeRoundTrip(t *testing.T) {
	content := cborMustEncode(cborMap{{"version", "1"}, {"content", cborMap{{"field", int64(42)}}}})
	env, cek, err := SealDataEnvelope(content, DataEnvelopeNamespaceOrganizationInvite)
	if err != nil {
		t.Fatal(err)
	}
	if cek.KeyAlgorithm() != AlgAes256Gcm || len(cek.KeyOps) != 1 || cek.KeyOps[0] != KeyOpDecrypt {
		t.Fatalf("cek %+v", cek)
	}
	got, err := OpenDataEnvelope(env, DataEnvelopeNamespaceOrganizationInvite, cek)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("open %v", err)
	}
	if _, err := OpenDataEnvelope(env, DataEnvelopeNamespaceVaultItem, cek); err != ErrDataEnvelopeInvalidNamespace {
		t.Fatalf("expected namespace error, got %v", err)
	}
	// The CEK survives wrapping in its decrypt-only form.
	userKey, _ := GenerateKeyFor(AlgXAes256Gcm)
	e2, wrapped, err := SealDataEnvelopeWithWrappingKey(content, DataEnvelopeNamespaceVaultItem, userKey)
	if err != nil || !strings.HasPrefix(wrapped, "7.") {
		t.Fatalf("seal with wrapping key %v", err)
	}
	if got, err := OpenDataEnvelopeWithWrappingKey(e2, wrapped, DataEnvelopeNamespaceVaultItem, userKey); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("open with wrapping key %v", err)
	}
}

func TestCBORJSONBridge(t *testing.T) {
	in := `{"b":1,"a":[true,false,null,-5,18446744073709551615,1.5,"x"],"c":{"d":"é"}}`
	c, err := JSONToCBOR([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := CBORToJSON(c)
	if err != nil || string(out) != in {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := cborDecode([]byte{0x82, 0x01}); err == nil {
		t.Fatal("expected truncated error")
	}
	// Indefinite-length items decode.
	v, err := cborDecode([]byte{0x9f, 0x01, 0x5f, 0x41, 0xaa, 0x41, 0xbb, 0xff, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	arr := v.([]any)
	if arr[0] != int64(1) || !bytes.Equal(arr[1].([]byte), []byte{0xaa, 0xbb}) {
		t.Fatalf("%v", arr)
	}
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func der(t *testing.T, k *rsa.PrivateKey) ([]byte, error) {
	t.Helper()
	return x509.MarshalPKCS8PrivateKey(k)
}
