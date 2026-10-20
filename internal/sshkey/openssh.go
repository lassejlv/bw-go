package sshkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

// OpenSSH private key format (PROTOCOL.key): a port of the parts of the RustCrypto ssh-key 0.7
// crate the SDK uses (decode, decrypt, re-encode, public key and fingerprint).

// sshError classifies decoding failures: algUnknown maps to ssh_key::Error::AlgorithmUnknown
// (UnsupportedKeyType in import.rs); everything else is a parsing error.
type sshError struct{ algUnknown bool }

func (e *sshError) Error() string {
	if e.algUnknown {
		return "ssh: unknown algorithm"
	}
	return "ssh: invalid encoding"
}

var (
	errSSH        = &sshError{}
	errAlgUnknown = &sshError{algUnknown: true}
)

func isAlgorithmUnknown(err error) bool {
	var se *sshError
	return errors.As(err, &se) && se.algUnknown
}

const (
	authMagic       = "openssh-key-v1\x00"
	openSSHWrap     = 70
	maxUsize        = 0xFFFFF // ssh-encoding MAX_USIZE
	maxLabelSize    = 48      // ssh-encoding MAX_LABEL_SIZE
	maxAlgorithmLen = 64

	algEd25519   = "ssh-ed25519"
	algRSA       = "ssh-rsa"
	algDSA       = "ssh-dss"
	algSkEd25519 = "sk-ssh-ed25519@openssh.com"
	algSkECDSA   = "sk-ecdsa-sha2-nistp256@openssh.com"
)

type keyKind int

const (
	kindEd25519 keyKind = iota + 1
	kindECDSA
	kindRSA
	kindDSA
	kindSkEd25519
	kindSkECDSA
	kindOther
)

// keypair is ssh_key::private::KeypairData (only the supported kinds are ever re-encoded).
type keypair struct {
	kind keyKind
	alg  string // canonical algorithm id written into encodings

	edPub  [32]byte
	edSeed [32]byte

	curve   string
	ecPoint []byte // SEC1 encoded public point
	ecPriv  []byte // fixed-size scalar

	rsaN, rsaE, rsaD, rsaIQMP, rsaP, rsaQ []byte // mpint bodies

	pubBlob []byte // public key blob for the unsupported kinds (comparison only)
}

// ---- reader ----

// sshReader is an ssh-encoding Reader. strict mirrors the PEM reader, whose read_prefixed
// insists that the nested value consumes the whole prefix; the slice reader used for decrypted
// data does not.
type sshReader struct {
	b      []byte
	strict bool
}

func (r *sshReader) read(n int) ([]byte, error) {
	if n < 0 || len(r.b) < n {
		return nil, errSSH
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

func (r *sshReader) u8() (byte, error) {
	b, err := r.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *sshReader) u32() (uint32, error) {
	b, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *sshReader) usize() (int, error) {
	v, err := r.u32()
	if err != nil {
		return 0, err
	}
	if v > maxUsize {
		return 0, errSSH
	}
	return int(v), nil
}

// prefixed runs f on the next length-prefixed region.
func (r *sshReader) prefixed(f func(*sshReader) error) error {
	n, err := r.usize()
	if err != nil {
		return err
	}
	if len(r.b) < n {
		return errSSH
	}
	sub := &sshReader{b: r.b[:n], strict: r.strict}
	if err := f(sub); err != nil {
		return err
	}
	if r.strict && len(sub.b) != 0 {
		return errSSH
	}
	r.b = r.b[n:]
	return nil
}

// bytesPrefixed is Vec<u8>::decode.
func (r *sshReader) bytesPrefixed() ([]byte, error) {
	var out []byte
	err := r.prefixed(func(s *sshReader) error {
		out = s.b
		s.b = nil
		return nil
	})
	return out, err
}

// fixedPrefixed reads exactly n bytes from a prefixed region (read_prefixed + read).
func (r *sshReader) fixedPrefixed(n int) ([]byte, error) {
	var out []byte
	err := r.prefixed(func(s *sshReader) error {
		var err error
		out, err = s.read(n)
		return err
	})
	return out, err
}

// label is Label::decode: a string of at most 48 bytes.
func (r *sshReader) label() (string, error) {
	b, err := r.bytesPrefixed()
	if err != nil || len(b) > maxLabelSize || !utf8.Valid(b) {
		return "", errSSH
	}
	return string(b), nil
}

func (r *sshReader) str() (string, error) {
	b, err := r.bytesPrefixed()
	if err != nil || !utf8.Valid(b) {
		return "", errSSH
	}
	return string(b), nil
}

// mpint is Mpint::decode.
func (r *sshReader) mpint() ([]byte, error) {
	b, err := r.bytesPrefixed()
	if err != nil {
		return nil, err
	}
	if (len(b) == 1 && b[0] == 0) || (len(b) >= 2 && b[0] == 0 && b[1] < 0x80) {
		return nil, errSSH
	}
	return b, nil
}

func mpintPositive(b []byte) bool {
	return (len(b) >= 1 && b[0] == 0) || (len(b) >= 1 && b[0] < 0x80)
}

func mpintFromBig(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0] >= 0x80 {
		b = append([]byte{0}, b...)
	}
	return b
}

// ---- algorithms ----

type algorithm struct {
	kind  keyKind
	curve string // ECDSA
	name  string // canonical id
}

func parseAlgorithm(id string) (algorithm, error) {
	switch id {
	case algDSA:
		return algorithm{kind: kindDSA, name: algDSA}, nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return algorithm{kind: kindECDSA, curve: strings.TrimPrefix(id, "ecdsa-sha2-"), name: id}, nil
	case algRSA, "rsa-sha2-256", "rsa-sha2-512":
		return algorithm{kind: kindRSA, name: algRSA}, nil
	case algEd25519:
		return algorithm{kind: kindEd25519, name: algEd25519}, nil
	case algSkECDSA:
		return algorithm{kind: kindSkECDSA, name: algSkECDSA}, nil
	case algSkEd25519:
		return algorithm{kind: kindSkEd25519, name: algSkEd25519}, nil
	}
	// AlgorithmName::new: "name@domain", ASCII, at most 64 bytes.
	at := strings.IndexByte(id, '@')
	if len(id) > maxAlgorithmLen || !isASCII(id) || at <= 0 || at == len(id)-1 || strings.Contains(id[at+1:], "@") {
		return algorithm{}, errSSH
	}
	return algorithm{kind: kindOther, name: id}, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func ecFieldSize(curve string) int {
	switch curve {
	case "nistp256":
		return 32
	case "nistp384":
		return 48
	case "nistp521":
		return 66
	}
	return 0
}

// ecdsaPublic is EcdsaPublicKey::decode: curve id + SEC1 point; the curve implied by the point
// size must match the curve id (AlgorithmUnknown otherwise).
func (r *sshReader) ecdsaPublic() (string, []byte, error) {
	curve, err := r.label()
	if err != nil {
		return "", nil, err
	}
	if ecFieldSize(curve) == 0 {
		return "", nil, errSSH
	}
	point, err := r.bytesPrefixed()
	if err != nil || len(point) > 1+2*66 {
		return "", nil, errSSH
	}
	pc, err := pointCurve(point)
	if err != nil {
		return "", nil, err
	}
	if pc != curve {
		return "", nil, errAlgUnknown
	}
	return curve, point, nil
}

func pointCurve(point []byte) (string, error) {
	if len(point) == 0 {
		return "", errSSH
	}
	var size int
	switch point[0] {
	case 0x02, 0x03:
		size = len(point) - 1
	case 0x04:
		size = (len(point) - 1) / 2
	default:
		return "", errSSH
	}
	var curve string
	switch size {
	case 32:
		curve = "nistp256"
	case 48:
		curve = "nistp384"
	case 66:
		curve = "nistp521"
	default:
		return "", errSSH
	}
	want := 1 + size
	if point[0] == 0x04 {
		want = 1 + 2*size
	}
	if len(point) != want {
		return "", errSSH
	}
	return curve, nil
}

// publicKeyData is public::KeyData::decode; it returns a keypair holding only public parts.
func (r *sshReader) publicKeyData() (*keypair, error) {
	id, err := r.label()
	if err != nil {
		return nil, err
	}
	alg, err := parseAlgorithm(id)
	if err != nil {
		return nil, err
	}
	if alg.kind == kindOther && strings.HasSuffix(alg.name, "-cert-v01@openssh.com") {
		return nil, errSSH // certificates never match an (opaque) private keypair
	}
	kp := &keypair{kind: alg.kind, alg: alg.name}
	start := r.b
	switch alg.kind {
	case kindEd25519:
		b, err := r.fixedPrefixed(32)
		if err != nil {
			return nil, err
		}
		copy(kp.edPub[:], b)
	case kindECDSA:
		curve, point, err := r.ecdsaPublic()
		if err != nil {
			return nil, err
		}
		if "ecdsa-sha2-"+curve != alg.name {
			return nil, errAlgUnknown
		}
		kp.curve, kp.ecPoint = curve, point
	case kindRSA:
		e, err := r.mpint()
		if err != nil {
			return nil, err
		}
		n, err := r.mpint()
		if err != nil {
			return nil, err
		}
		if !mpintPositive(e) || !mpintPositive(n) {
			return nil, errSSH
		}
		kp.rsaE, kp.rsaN = e, n
	case kindDSA:
		if err := r.dsaPublic(); err != nil {
			return nil, err
		}
	case kindSkEd25519:
		if _, err := r.fixedPrefixed(32); err != nil {
			return nil, err
		}
		if _, err := r.str(); err != nil {
			return nil, err
		}
	case kindSkECDSA:
		if err := r.skECDSAPublic(); err != nil {
			return nil, err
		}
	case kindOther:
		if _, err := r.bytesPrefixed(); err != nil {
			return nil, err
		}
	}
	if alg.kind != kindEd25519 && alg.kind != kindECDSA && alg.kind != kindRSA {
		kp.pubBlob = append([]byte(alg.name+"\x00"), start[:len(start)-len(r.b)]...)
	}
	return kp, nil
}

func (r *sshReader) dsaPublic() error {
	for i := 0; i < 4; i++ {
		m, err := r.mpint()
		if err != nil {
			return err
		}
		if !mpintPositive(m) {
			return errSSH
		}
	}
	return nil
}

func (r *sshReader) skECDSAPublic() error {
	curve, err := r.label()
	if err != nil {
		return err
	}
	if curve != "nistp256" {
		return errSSH
	}
	point, err := r.bytesPrefixed()
	if err != nil || len(point) > 65 {
		return errSSH
	}
	if c, err := pointCurve(point); err != nil || c != "nistp256" {
		return errSSH
	}
	_, err = r.str()
	return err
}

// keypairData is KeypairData::decode.
func (r *sshReader) keypairData() (*keypair, error) {
	id, err := r.label()
	if err != nil {
		return nil, err
	}
	alg, err := parseAlgorithm(id)
	if err != nil {
		return nil, err
	}
	kp := &keypair{kind: alg.kind, alg: alg.name}
	start := r.b
	switch alg.kind {
	case kindEd25519:
		pub, err := r.fixedPrefixed(32)
		if err != nil {
			return nil, err
		}
		both, err := r.fixedPrefixed(64)
		if err != nil {
			return nil, err
		}
		// Ed25519Keypair::from_bytes validates the embedded public key against the seed.
		derived := ed25519.NewKeyFromSeed(both[:32])[32:]
		if !bytes.Equal(derived, both[32:]) || !bytes.Equal(both[32:], pub) {
			return nil, errSSH
		}
		copy(kp.edSeed[:], both[:32])
		copy(kp.edPub[:], pub)
	case kindECDSA:
		curve, point, err := r.ecdsaPublic()
		if err != nil {
			return nil, err
		}
		size := ecFieldSize(curve)
		var scalar []byte
		err = r.prefixed(func(s *sshReader) error {
			l := len(s.b)
			if l == size+1 {
				z, _ := s.u8()
				if z != 0 {
					return errSSH
				}
				l = size
			}
			if l < 32 || l > size {
				return errSSH
			}
			b, err := s.read(l)
			if err != nil {
				return err
			}
			scalar = make([]byte, size)
			copy(scalar[size-l:], b)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if curve != alg.curve {
			return nil, errAlgUnknown
		}
		kp.curve, kp.ecPoint, kp.ecPriv = curve, point, scalar
	case kindRSA:
		var m [6][]byte // n, e, d, iqmp, p, q
		for i := range m {
			if m[i], err = r.mpint(); err != nil {
				return nil, err
			}
			if !mpintPositive(m[i]) {
				return nil, errSSH
			}
		}
		kp.rsaN, kp.rsaE, kp.rsaD, kp.rsaIQMP, kp.rsaP, kp.rsaQ = m[0], m[1], m[2], m[3], m[4], m[5]
	case kindDSA:
		if err := r.dsaPublic(); err != nil {
			return nil, err
		}
		pubEnd := r.b
		x, err := r.mpint()
		if err != nil || !mpintPositive(x) {
			return nil, errSSH
		}
		kp.pubBlob = append([]byte(alg.name+"\x00"), start[:len(start)-len(pubEnd)]...)
	case kindSkEd25519, kindSkECDSA:
		if alg.kind == kindSkEd25519 {
			if _, err := r.fixedPrefixed(32); err != nil {
				return nil, err
			}
			if _, err := r.str(); err != nil {
				return nil, err
			}
		} else if err := r.skECDSAPublic(); err != nil {
			return nil, err
		}
		pubEnd := r.b
		if _, err := r.u8(); err != nil {
			return nil, err
		}
		if _, err := r.bytesPrefixed(); err != nil {
			return nil, err
		}
		if _, err := r.bytesPrefixed(); err != nil {
			return nil, err
		}
		kp.pubBlob = append([]byte(alg.name+"\x00"), start[:len(start)-len(pubEnd)]...)
	case kindOther:
		if _, err := r.bytesPrefixed(); err != nil {
			return nil, err
		}
		pubEnd := r.b
		if _, err := r.bytesPrefixed(); err != nil {
			return nil, err
		}
		kp.pubBlob = append([]byte(alg.name+"\x00"), start[:len(start)-len(pubEnd)]...)
	}
	return kp, nil
}

// samePublic compares public::KeyData values.
func samePublic(a, b *keypair) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case kindEd25519:
		return a.edPub == b.edPub
	case kindECDSA:
		return a.curve == b.curve && bytes.Equal(a.ecPoint, b.ecPoint)
	case kindRSA:
		return bytes.Equal(a.rsaE, b.rsaE) && bytes.Equal(a.rsaN, b.rsaN)
	}
	return bytes.Equal(a.pubBlob, b.pubBlob)
}

// ---- private key container ----

type openSSHCipher struct {
	name      string
	keyLen    int
	ivLen     int
	blockSize int
	tag       bool
}

var openSSHCiphers = map[string]openSSHCipher{
	"none":                          {"none", 0, 0, 8, false},
	"aes128-cbc":                    {"aes128-cbc", 16, 16, 16, false},
	"aes192-cbc":                    {"aes192-cbc", 24, 16, 16, false},
	"aes256-cbc":                    {"aes256-cbc", 32, 16, 16, false},
	"aes128-ctr":                    {"aes128-ctr", 16, 16, 16, false},
	"aes192-ctr":                    {"aes192-ctr", 24, 16, 16, false},
	"aes256-ctr":                    {"aes256-ctr", 32, 16, 16, false},
	"aes128-gcm@openssh.com":        {"aes128-gcm@openssh.com", 16, 12, 16, true},
	"aes256-gcm@openssh.com":        {"aes256-gcm@openssh.com", 32, 12, 16, true},
	"chacha20-poly1305@openssh.com": {"chacha20-poly1305@openssh.com", 32, 8, 8, true},
	"3des-cbc":                      {"3des-cbc", 24, 8, 8, false}, // known, but not enabled in the SDK
}

type privateKey struct {
	cipher     openSSHCipher
	kdfBcrypt  bool
	salt       []byte
	rounds     uint32
	publicKind keyKind
	public     *keypair
	ciphertext []byte
	authTag    []byte

	keypair     *keypair
	comment     []byte
	checkint    uint32
	hasCheckint bool
}

func (pk *privateKey) encrypted() bool { return pk.cipher.name != "none" }

// decodeOpenSSHPEM is PrivateKey::from_openssh.
func decodeOpenSSHPEM(pem []byte) (*privateKey, error) {
	enc, err := parseEncapsulation(pem)
	if err != nil {
		return nil, errSSH
	}
	data, err := decodeWrappedBase64(enc.text, enc.lineWidth())
	if err != nil || enc.label != labelOpenSSH {
		return nil, errSSH
	}
	r := &sshReader{b: data, strict: true}
	pk, err := decodePrivateKey(r)
	if err != nil {
		return nil, err
	}
	if len(r.b) != 0 {
		return nil, errSSH
	}
	return pk, nil
}

func decodePrivateKey(r *sshReader) (*privateKey, error) {
	magic, err := r.read(len(authMagic))
	if err != nil || string(magic) != authMagic {
		return nil, errSSH
	}
	cname, err := r.label()
	if err != nil {
		return nil, err
	}
	c, ok := openSSHCiphers[cname]
	if !ok {
		return nil, errSSH
	}
	pk := &privateKey{cipher: c}
	kdfName, err := r.label()
	if err != nil {
		return nil, err
	}
	switch kdfName {
	case "none":
		n, err := r.usize()
		if err != nil {
			return nil, err
		}
		if n != 0 {
			return nil, errAlgUnknown
		}
	case "bcrypt":
		pk.kdfBcrypt = true
		err := r.prefixed(func(s *sshReader) error {
			var err error
			if pk.salt, err = s.bytesPrefixed(); err != nil {
				return err
			}
			pk.rounds, err = s.u32()
			return err
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errSSH
	}
	nkeys, err := r.usize()
	if err != nil {
		return nil, err
	}
	if nkeys != 1 {
		return nil, errSSH
	}
	err = r.prefixed(func(s *sshReader) error {
		var err error
		pk.public, err = s.publicKeyData()
		return err
	})
	if err != nil {
		return nil, err
	}
	pk.publicKind = pk.public.kind

	if pk.encrypted() {
		if pk.ciphertext, err = r.bytesPrefixed(); err != nil {
			return nil, err
		}
		if len(pk.ciphertext)%c.blockSize != 0 {
			return nil, errSSH
		}
		if c.tag {
			if pk.authTag, err = r.read(16); err != nil {
				return nil, err
			}
		}
		if len(r.b) != 0 {
			return nil, errSSH
		}
		return pk, nil
	}
	if pk.kdfBcrypt {
		return nil, errSSH
	}
	var dec *privateKey
	err = r.prefixed(func(s *sshReader) error {
		var err error
		// PuTTYgen uses a non-standard block size of 16, so up to 16 padding bytes are allowed.
		dec, err = decodePrivateKeyCommentPair(s, pk.public, c.blockSize, 16)
		return err
	})
	if err != nil {
		return nil, err
	}
	dec.public, dec.publicKind = pk.public, pk.publicKind
	return dec, nil
}

// decodePrivateKeyCommentPair is PrivateKey::decode_privatekey_comment_pair.
func decodePrivateKeyCommentPair(r *sshReader, public *keypair, blockSize, maxPadding int) (*privateKey, error) {
	if len(r.b)%blockSize != 0 {
		return nil, errSSH
	}
	c1, err := r.u32()
	if err != nil {
		return nil, err
	}
	c2, err := r.u32()
	if err != nil {
		return nil, err
	}
	if c1 != c2 {
		return nil, errSSH
	}
	kp, err := r.keypairData()
	if err != nil {
		return nil, err
	}
	if !samePublic(kp, public) {
		return nil, errSSH
	}
	comment, err := r.bytesPrefixed()
	if err != nil {
		return nil, err
	}
	if len(r.b) > maxPadding {
		return nil, errSSH
	}
	for i, b := range r.b {
		if int(b) != i+1 {
			return nil, errSSH
		}
	}
	r.b = nil
	return &privateKey{cipher: openSSHCiphers["none"], keypair: kp, comment: comment, checkint: c1, hasCheckint: true}, nil
}

// decrypt is PrivateKey::decrypt.
func (pk *privateKey) decrypt(password []byte) (*privateKey, error) {
	if !pk.kdfBcrypt {
		return nil, errSSH // Kdf::None → Error::Decrypted
	}
	okm, err := bcryptPBKDF(password, pk.salt, int(pk.rounds), pk.cipher.keyLen+pk.cipher.ivLen)
	if err != nil {
		return nil, err
	}
	key, iv := okm[:pk.cipher.keyLen], okm[pk.cipher.keyLen:]
	buf := append([]byte(nil), pk.ciphertext...)
	switch pk.cipher.name {
	case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
		block, _ := aes.NewCipher(key)
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if buf, err = gcm.Open(nil, iv, append(buf, pk.authTag...), nil); err != nil {
			return nil, err
		}
	case "chacha20-poly1305@openssh.com":
		// ssh-cipher's ChaCha20Poly1305: legacy ChaCha20 with an all-zero 64-bit nonce; the
		// Poly1305 key is the first 32 bytes of block 0 and the payload starts at block 1.
		c, err := chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
		if err != nil {
			return nil, err
		}
		var polyKey [32]byte
		c.XORKeyStream(polyKey[:], polyKey[:])
		var tag [16]byte
		poly1305.Sum(&tag, buf, &polyKey)
		if subtle.ConstantTimeCompare(tag[:], pk.authTag) != 1 {
			return nil, errSSH
		}
		c.SetCounter(1)
		c.XORKeyStream(buf, buf)
	case "aes128-cbc", "aes192-cbc", "aes256-cbc":
		block, _ := aes.NewCipher(key)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, buf)
	case "aes128-ctr", "aes192-ctr", "aes256-ctr":
		block, _ := aes.NewCipher(key)
		cipher.NewCTR(block, iv).XORKeyStream(buf, buf)
	default:
		return nil, errSSH // UnsupportedCipher (3des-cbc: the SDK is built without "tdes")
	}
	dec, err := decodePrivateKeyCommentPair(&sshReader{b: buf}, pk.public, pk.cipher.blockSize, pk.cipher.blockSize-1)
	if err != nil {
		return nil, err
	}
	dec.public, dec.publicKind = pk.public, pk.publicKind
	return dec, nil
}

// ---- encoding ----

type sshWriter struct{ bytes.Buffer }

func (w *sshWriter) u32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.Write(b[:])
}

func (w *sshWriter) str(b []byte) {
	w.u32(uint32(len(b)))
	w.Write(b)
}

// publicBlob is public::KeyData::encode (the "string" inside an OpenSSH public key).
func (kp *keypair) publicBlob() []byte {
	var w sshWriter
	w.str([]byte(kp.alg))
	switch kp.kind {
	case kindEd25519:
		w.str(kp.edPub[:])
	case kindECDSA:
		w.str([]byte(kp.curve))
		w.str(kp.ecPoint)
	case kindRSA:
		w.str(kp.rsaE)
		w.str(kp.rsaN)
	}
	return w.Bytes()
}

// privateEncoding is KeypairData::encode.
func (kp *keypair) privateEncoding() ([]byte, error) {
	var w sshWriter
	w.str([]byte(kp.alg))
	switch kp.kind {
	case kindEd25519:
		w.str(kp.edPub[:])
		w.str(append(append([]byte(nil), kp.edSeed[:]...), kp.edPub[:]...))
	case kindECDSA:
		w.str([]byte(kp.curve))
		w.str(kp.ecPoint)
		if kp.ecPriv[0] >= 0x80 {
			w.str(append([]byte{0}, kp.ecPriv...))
		} else {
			w.str(kp.ecPriv)
		}
	case kindRSA:
		for _, m := range [][]byte{kp.rsaN, kp.rsaE, kp.rsaD, kp.rsaIQMP, kp.rsaP, kp.rsaQ} {
			w.str(m)
		}
	default:
		return nil, errSSH
	}
	return w.Bytes(), nil
}

// checkint is KeypairData::checkint: XOR of the big-endian u32 chunks of the private key bytes.
func (kp *keypair) checkint() uint32 {
	var b []byte
	switch kp.kind {
	case kindEd25519:
		b = kp.edSeed[:]
	case kindECDSA:
		b = kp.ecPriv
	case kindRSA:
		b = kp.rsaD
	}
	var n uint32
	for i := 0; i+4 <= len(b); i += 4 {
		n ^= binary.BigEndian.Uint32(b[i:])
	}
	return n
}

// toOpenSSH is PrivateKey::to_openssh(LineEnding::LF) for an unencrypted key.
func (pk *privateKey) toOpenSSH() (string, error) {
	kd, err := pk.keypair.privateEncoding()
	if err != nil {
		return "", err
	}
	checkint := pk.checkint
	if !pk.hasCheckint {
		checkint = pk.keypair.checkint()
	}
	unpadded := 8 + len(kd) + 4 + len(pk.comment)
	padding := 0
	if rem := unpadded % 8; rem != 0 {
		padding = 8 - rem
	}
	var w sshWriter
	w.WriteString(authMagic)
	w.str([]byte("none"))
	w.str([]byte("none"))
	w.u32(0) // kdfoptions
	w.u32(1) // number of keys
	w.str(pk.keypair.publicBlob())
	w.u32(uint32(unpadded + padding))
	w.u32(checkint)
	w.u32(checkint)
	w.Write(kd)
	w.str(pk.comment)
	for i := 1; i <= padding; i++ {
		w.WriteByte(byte(i))
	}
	return encodePEM(labelOpenSSH, w.Bytes(), openSSHWrap), nil
}

// publicKeyString is PublicKey::to_openssh: "<alg> <base64>[ <comment>]" with the comment
// truncated to its longest valid UTF-8 prefix (Comment::as_str_lossy).
func (kp *keypair) publicKeyString(comment []byte) string {
	s := kp.alg + " " + base64.StdEncoding.EncodeToString(kp.publicBlob())
	c := comment
	for len(c) > 0 && !utf8.Valid(c) {
		c = c[:len(c)-1]
	}
	if len(c) > 0 {
		s += " " + string(c)
	}
	return s
}

// fingerprint is Fingerprint::new(HashAlg::Sha256, ..).to_string().
func (kp *keypair) fingerprint() string {
	sum := sha256.Sum256(kp.publicBlob())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
