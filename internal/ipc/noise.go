package ipc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Port of bitwarden-ipc's Noise crypto provider (crates/bitwarden-ipc/src/crypto_provider/noise):
// a Noise NN handshake (`-> e`, `<- e, ee`, empty prologue and payloads) as implemented by the
// snow crate, followed by a transport mode whose nonce is carried in every frame.

// CipherSuite is a Noise protocol name supported by the SDK. It serializes as its name.
type CipherSuite int

// Supported cipher suites. Noise_NN_P256_AESGCM_SHA256 is the SDK default.
const (
	NoiseNN25519ChaChaPolyBLAKE2s CipherSuite = iota
	NoiseNN25519AESGCMSHA256
	NoiseNNP256AESGCMSHA256
)

// DefaultCipherSuite is CipherSuite::default() in the SDK.
const DefaultCipherSuite = NoiseNNP256AESGCMSHA256

var cipherSuiteNames = [...]string{
	"Noise_NN_25519_ChaChaPoly_BLAKE2s",
	"Noise_NN_25519_AESGCM_SHA256",
	"Noise_NN_P256_AESGCM_SHA256",
}

func (c CipherSuite) String() string {
	if int(c) < len(cipherSuiteNames) {
		return cipherSuiteNames[c]
	}
	return "unknown"
}

func parseCipherSuite(s string) (CipherSuite, bool) {
	for i, n := range cipherSuiteNames {
		if n == s {
			return CipherSuite(i), true
		}
	}
	return 0, false
}

func (c CipherSuite) curve() ecdh.Curve {
	if c == NoiseNNP256AESGCMSHA256 {
		return ecdh.P256()
	}
	return ecdh.X25519()
}

func (c CipherSuite) newHash() hash.Hash {
	if c == NoiseNN25519ChaChaPolyBLAKE2s {
		h, _ := blake2s.New256(nil)
		return h
	}
	return sha256.New()
}

// transportCipher mirrors TransportCipher: ChaCha20Poly1305 for the ChaChaPoly suite, AES-256-GCM
// otherwise.
func (c CipherSuite) chaCha() bool { return c == NoiseNN25519ChaChaPolyBLAKE2s }

const (
	noiseKeyLen        = 32
	noiseTagLen        = 16
	noiseMaxMessageLen = 65535
)

var errNoiseDecrypt = errors.New("noise: decryption failed")

// newAEAD returns the AEAD for a 32 byte key and the snow nonce encoding: 4 zero bytes followed by
// the 64 bit counter, big endian for AES-GCM and little endian for ChaChaPoly.
func newAEAD(chaCha bool, key []byte) (cipher.AEAD, func(uint64) []byte, error) {
	if chaCha {
		a, err := chacha20poly1305.New(key)
		return a, func(n uint64) []byte {
			nonce := make([]byte, 12)
			binary.LittleEndian.PutUint64(nonce[4:], n)
			return nonce
		}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(block)
	return a, func(n uint64) []byte {
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[4:], n)
		return nonce
	}, err
}

func noiseEncrypt(chaCha bool, key []byte, n uint64, ad, plaintext []byte) ([]byte, error) {
	a, nonce, err := newAEAD(chaCha, key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce(n), plaintext, ad), nil
}

func noiseDecrypt(chaCha bool, key []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < noiseTagLen {
		return nil, errNoiseDecrypt
	}
	a, nonce, err := newAEAD(chaCha, key)
	if err != nil {
		return nil, err
	}
	out, err := a.Open(nil, nonce(n), ciphertext, ad)
	if err != nil {
		return nil, errNoiseDecrypt
	}
	return out, nil
}

// symmetricState is the Noise SymmetricState (with its CipherState folded in).
type symmetricState struct {
	suite CipherSuite
	ck, h []byte
	k     []byte // nil until the first MixKey
	n     uint64
}

func newSymmetricState(suite CipherSuite) *symmetricState {
	s := &symmetricState{suite: suite}
	name := []byte(suite.String())
	hl := suite.newHash().Size()
	if len(name) <= hl {
		s.h = make([]byte, hl)
		copy(s.h, name)
	} else {
		s.h = s.hash(name)
	}
	s.ck = append([]byte(nil), s.h...)
	return s
}

func (s *symmetricState) hash(parts ...[]byte) []byte {
	h := s.suite.newHash()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// hkdf is the Noise HKDF with two outputs.
func (s *symmetricState) hkdf(ck, ikm []byte) ([]byte, []byte) {
	mac := func(key []byte, data ...[]byte) []byte {
		m := hmac.New(s.suite.newHash, key)
		for _, d := range data {
			m.Write(d)
		}
		return m.Sum(nil)
	}
	temp := mac(ck, ikm)
	out1 := mac(temp, []byte{1})
	out2 := mac(temp, out1, []byte{2})
	return out1, out2
}

func (s *symmetricState) mixHash(data []byte) { s.h = s.hash(s.h, data) }

func (s *symmetricState) mixKey(ikm []byte) {
	ck, tk := s.hkdf(s.ck, ikm)
	s.ck, s.k, s.n = ck, tk[:noiseKeyLen], 0
}

func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	out := plaintext
	if s.k != nil {
		ct, err := noiseEncrypt(s.suite.chaCha(), s.k, s.n, s.h, plaintext)
		if err != nil {
			return nil, err
		}
		s.n++
		out = ct
	}
	s.mixHash(out)
	return out, nil
}

func (s *symmetricState) decryptAndHash(data []byte) ([]byte, error) {
	out := data
	if s.k != nil {
		pt, err := noiseDecrypt(s.suite.chaCha(), s.k, s.n, s.h, data)
		if err != nil {
			return nil, err
		}
		s.n++
		out = pt
	}
	s.mixHash(data)
	return out, nil
}

// split returns the raw (initiator-to-responder, responder-to-initiator) keys, like snow's
// dangerously_get_raw_split.
func (s *symmetricState) split() ([]byte, []byte) {
	k1, k2 := s.hkdf(s.ck, nil)
	return k1[:noiseKeyLen], k2[:noiseKeyLen]
}

// handshake is one side of a Noise NN handshake.
type handshake struct {
	suite     CipherSuite
	initiator bool
	ss        *symmetricState
	e         *ecdh.PrivateKey
	re        []byte
}

func newHandshake(suite CipherSuite, initiator bool, rnd io.Reader) (*handshake, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var e *ecdh.PrivateKey
	var err error
	if fixed, ok := rnd.(fixedEphemeral); ok {
		e, err = suite.curve().NewPrivateKey(fixed)
	} else {
		e, err = suite.curve().GenerateKey(rnd)
	}
	if err != nil {
		return nil, err
	}
	ss := newSymmetricState(suite)
	ss.mixHash(nil) // empty prologue
	return &handshake{suite: suite, initiator: initiator, ss: ss, e: e}, nil
}

// fixedEphemeral makes newHandshake use a fixed ephemeral private key (test vectors only).
type fixedEphemeral []byte

func (f fixedEphemeral) Read(p []byte) (int, error) { return copy(p, f), nil }

func (h *handshake) pubLen() int { return len(h.e.PublicKey().Bytes()) }

// writeE writes the `e` token with an empty payload.
func (h *handshake) writeE(withEE bool) ([]byte, error) {
	pub := h.e.PublicKey().Bytes()
	h.ss.mixHash(pub)
	if withEE {
		if err := h.dhEE(); err != nil {
			return nil, err
		}
	}
	payload, err := h.ss.encryptAndHash(nil)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), pub...), payload...), nil
}

// readE reads the `e` token (and `ee` for the responder's message) and the payload.
func (h *handshake) readE(msg []byte, withEE bool) error {
	n := h.pubLen()
	if len(msg) < n {
		return errors.New("noise: message too short")
	}
	h.re = append([]byte(nil), msg[:n]...)
	h.ss.mixHash(h.re)
	if withEE {
		if err := h.dhEE(); err != nil {
			return err
		}
	}
	_, err := h.ss.decryptAndHash(msg[n:])
	return err
}

func (h *handshake) dhEE() error {
	pub, err := h.suite.curve().NewPublicKey(h.re)
	if err != nil {
		return err
	}
	shared, err := h.e.ECDH(pub)
	if err != nil {
		return err
	}
	h.ss.mixKey(shared)
	return nil
}

// WriteStart is HandshakeInitiator::write_start_message.
func (h *handshake) writeStart() (HandshakeStart, error) {
	frame, err := h.writeE(false)
	return HandshakeStart{CipherSuite: h.suite, NoiseFrame: frame}, err
}

// readStart is HandshakeResponder::read_start_message.
func (h *handshake) readStart(m HandshakeStart) error { return h.readE(m.NoiseFrame, false) }

// writeResponse is HandshakeResponder::write_response_message.
func (h *handshake) writeResponse() ([]byte, error) { return h.writeE(true) }

// readResponse is HandshakeInitiator::read_response_message.
func (h *handshake) readResponse(frame []byte) error { return h.readE(frame, true) }

// transportState derives the PersistentTransportState: the initiator sends with i2r and receives
// with r2i, the responder the other way around.
func (h *handshake) transportState() *transportState {
	i2r, r2i := h.ss.split()
	t := &transportState{chaCha: h.suite.chaCha(), lastHandshake: time.Now()}
	if h.initiator {
		t.sendKey, t.receiveKey = i2r, r2i
	} else {
		t.sendKey, t.receiveKey = r2i, i2r
	}
	return t
}

// transportState is PersistentTransportState: per direction keys and monotonic nonces.
type transportState struct {
	chaCha              bool
	sendKey, receiveKey []byte
	sendNonce           uint64
	receiveNonce        uint64
	lastHandshake       time.Time
}

// rehandshakeInterval is REHANDSHAKE_INTERVAL_SECS.
const rehandshakeInterval = 300 * time.Second

func (t *transportState) shouldRehandshake(now time.Time) bool {
	return now.Unix()-t.lastHandshake.Unix() > int64(rehandshakeInterval/time.Second)
}

// send encrypts a payload with the next nonce.
func (t *transportState) send(payload []byte) (TransportFrame, error) {
	if t.sendNonce == ^uint64(0) {
		return TransportFrame{}, errors.New("noise: nonce exhausted")
	}
	t.sendNonce++
	ct, err := noiseEncrypt(t.chaCha, t.sendKey, t.sendNonce, nil, payload)
	if err != nil {
		return TransportFrame{}, err
	}
	return TransportFrame{Payload: ct, Nonce: t.sendNonce}, nil
}

// receive decrypts a frame, rejecting replayed or older nonces.
func (t *transportState) receive(f TransportFrame) ([]byte, error) {
	if f.Nonce <= t.receiveNonce {
		return nil, errors.New("noise: replayed nonce")
	}
	pt, err := noiseDecrypt(t.chaCha, t.receiveKey, f.Nonce, nil, f.Payload)
	if err != nil {
		return nil, err
	}
	t.receiveNonce = f.Nonce
	return pt, nil
}

// HandshakeStart is HandshakeStartMessage.
type HandshakeStart struct {
	CipherSuite CipherSuite
	NoiseFrame  []byte
}

// TransportFrame is the encrypted wire frame.
type TransportFrame struct {
	Payload []byte
	Nonce   uint64
}

// FrameKind identifies a Frame variant.
type FrameKind int

// Frame variants.
const (
	FrameHandshakeStart FrameKind = iota + 1
	FrameHandshakeFinish
	FrameTransport
	FrameCryptoInvalidated
)

// Frame is the CBOR encoded frame sent over IPC.
type Frame struct {
	Kind      FrameKind
	Start     HandshakeStart // FrameHandshakeStart
	Finish    []byte         // FrameHandshakeFinish (the noise frame)
	Transport TransportFrame // FrameTransport
}

// MarshalCBOR encodes the frame like ciborium encodes the SDK's Frame enum.
func (f Frame) MarshalCBOR() []byte {
	var b []byte
	switch f.Kind {
	case FrameHandshakeStart:
		b = cborHead(b, cborMap, 1)
		b = cborAppendText(b, "HandshakeStart")
		b = cborHead(b, cborMap, 2)
		b = cborAppendText(b, "ciphersuite")
		b = cborAppendText(b, f.Start.CipherSuite.String())
		b = cborAppendText(b, "noise_frame")
		b = cborAppendU8Array(b, f.Start.NoiseFrame)
	case FrameHandshakeFinish:
		b = cborHead(b, cborMap, 1)
		b = cborAppendText(b, "HandshakeFinish")
		b = cborAppendU8Array(b, f.Finish)
	case FrameTransport:
		b = cborHead(b, cborMap, 1)
		b = cborAppendText(b, "TransportFrame")
		b = cborHead(b, cborMap, 2)
		b = cborAppendText(b, "payload")
		b = cborAppendBytes(b, f.Transport.Payload)
		b = cborAppendText(b, "nonce")
		b = cborHead(b, cborUint, f.Transport.Nonce)
	default:
		b = cborAppendText(b, "CryptoInvalidated")
	}
	return b
}

var errMalformedFrame = errors.New("malformed IPC frame")

// UnmarshalFrame decodes a CBOR frame.
func UnmarshalFrame(b []byte) (Frame, error) {
	v, err := cborDecode(b)
	if err != nil {
		return Frame{}, err
	}
	if s, ok := v.(string); ok {
		if s == "CryptoInvalidated" {
			return Frame{Kind: FrameCryptoInvalidated}, nil
		}
		return Frame{}, errMalformedFrame
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return Frame{}, errMalformedFrame
	}
	for variant, body := range m {
		switch variant {
		case "HandshakeStart":
			bm, ok := body.(map[string]any)
			if !ok {
				return Frame{}, errMalformedFrame
			}
			name, _ := bm["ciphersuite"].(string)
			suite, ok := parseCipherSuite(name)
			if !ok {
				return Frame{}, errMalformedFrame
			}
			nf, err := cborByteSeq(bm["noise_frame"])
			if err != nil {
				return Frame{}, errMalformedFrame
			}
			return Frame{Kind: FrameHandshakeStart, Start: HandshakeStart{CipherSuite: suite, NoiseFrame: nf}}, nil
		case "HandshakeFinish":
			nf, err := cborByteSeq(body)
			if err != nil {
				return Frame{}, errMalformedFrame
			}
			return Frame{Kind: FrameHandshakeFinish, Finish: nf}, nil
		case "TransportFrame":
			bm, ok := body.(map[string]any)
			if !ok {
				return Frame{}, errMalformedFrame
			}
			payload, err := cborByteSeq(bm["payload"])
			if err != nil {
				return Frame{}, errMalformedFrame
			}
			nonce, ok := bm["nonce"].(uint64)
			if !ok {
				return Frame{}, errMalformedFrame
			}
			return Frame{Kind: FrameTransport, Transport: TransportFrame{Payload: payload, Nonce: nonce}}, nil
		case "CryptoInvalidated":
			return Frame{Kind: FrameCryptoInvalidated}, nil
		}
	}
	return Frame{}, errMalformedFrame
}
