package ipc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/snow_vectors.json was generated with snow 0.10.0 and ciborium 0.2.2 (the versions the
// SDK uses): for each cipher suite a Noise NN handshake between an initiator with the fixed
// ephemeral private key 0x01..0x20 and a responder with 0x21..0x40 (Builder::
// fixed_ephemeral_key_for_testing_only), the raw split keys (dangerously_get_raw_split), "hello"
// encrypted with the i2r key and nonce 1, and the ciborium encoding of the SDK Frame enum for the
// handshake messages and that transport frame.
type snowVectors struct {
	CborInvalidated string `json:"cbor_invalidated"`
	Suites          []struct {
		Suite         string `json:"suite"`
		M1            string `json:"m1"`
		M2            string `json:"m2"`
		I2R           string `json:"i2r"`
		R2I           string `json:"r2i"`
		CtHello       string `json:"ct_hello_nonce1_i2r"`
		CborStart     string `json:"cbor_start"`
		CborFinish    string `json:"cbor_finish"`
		CborTransport string `json:"cbor_transport"`
	} `json:"suites"`
}

func seq(from, to byte) []byte {
	var b []byte
	for i := from; ; i++ {
		b = append(b, i)
		if i == to {
			return b
		}
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNoiseMatchesSnowVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/snow_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v snowVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Suites) != 3 {
		t.Fatalf("want 3 suites, got %d", len(v.Suites))
	}
	if got := hex.EncodeToString(Frame{Kind: FrameCryptoInvalidated}.MarshalCBOR()); got != v.CborInvalidated {
		t.Errorf("CryptoInvalidated cbor = %s, want %s", got, v.CborInvalidated)
	}
	for _, s := range v.Suites {
		t.Run(s.Suite, func(t *testing.T) {
			suite, ok := parseCipherSuite(s.Suite)
			if !ok {
				t.Fatal("unknown suite")
			}
			ini, err := newHandshake(suite, true, fixedEphemeral(seq(1, 32)))
			if err != nil {
				t.Fatal(err)
			}
			res, err := newHandshake(suite, false, fixedEphemeral(seq(33, 64)))
			if err != nil {
				t.Fatal(err)
			}
			start, err := ini.writeStart()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(start.NoiseFrame) != s.M1 {
				t.Fatalf("m1 = %x\nwant %s", start.NoiseFrame, s.M1)
			}
			if got := hex.EncodeToString(Frame{Kind: FrameHandshakeStart, Start: start}.MarshalCBOR()); got != s.CborStart {
				t.Errorf("start cbor = %s\nwant %s", got, s.CborStart)
			}
			if err := res.readStart(start); err != nil {
				t.Fatal(err)
			}
			m2, err := res.writeResponse()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(m2) != s.M2 {
				t.Fatalf("m2 = %x\nwant %s", m2, s.M2)
			}
			if got := hex.EncodeToString(Frame{Kind: FrameHandshakeFinish, Finish: m2}.MarshalCBOR()); got != s.CborFinish {
				t.Errorf("finish cbor = %s\nwant %s", got, s.CborFinish)
			}
			if err := ini.readResponse(m2); err != nil {
				t.Fatal(err)
			}
			it, rt := ini.transportState(), res.transportState()
			if hex.EncodeToString(it.sendKey) != s.I2R || hex.EncodeToString(it.receiveKey) != s.R2I {
				t.Errorf("initiator keys = %x / %x", it.sendKey, it.receiveKey)
			}
			if !bytes.Equal(rt.sendKey, it.receiveKey) || !bytes.Equal(rt.receiveKey, it.sendKey) {
				t.Error("responder keys do not mirror the initiator's")
			}
			tf, err := it.send([]byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if tf.Nonce != 1 || hex.EncodeToString(tf.Payload) != s.CtHello {
				t.Errorf("transport frame = %d %x, want 1 %s", tf.Nonce, tf.Payload, s.CtHello)
			}
			if got := hex.EncodeToString(Frame{Kind: FrameTransport, Transport: tf}.MarshalCBOR()); got != s.CborTransport {
				t.Errorf("transport cbor = %s\nwant %s", got, s.CborTransport)
			}
			pt, err := rt.receive(tf)
			if err != nil || string(pt) != "hello" {
				t.Fatalf("receive = %q, %v", pt, err)
			}
			if _, err := rt.receive(tf); err == nil {
				t.Error("replayed frame accepted")
			}

			// The ciborium encodings decode back to the same frames.
			for _, enc := range []string{s.CborStart, s.CborFinish, s.CborTransport} {
				f, err := UnmarshalFrame(unhex(t, enc))
				if err != nil {
					t.Fatalf("decode %s: %v", enc, err)
				}
				if got := hex.EncodeToString(f.MarshalCBOR()); got != enc {
					t.Errorf("re-encode = %s, want %s", got, enc)
				}
			}
		})
	}
}

func TestTransportStateNonces(t *testing.T) {
	a := &transportState{sendKey: bytes.Repeat([]byte{1}, 32), receiveKey: bytes.Repeat([]byte{2}, 32)}
	b := &transportState{sendKey: bytes.Repeat([]byte{2}, 32), receiveKey: bytes.Repeat([]byte{1}, 32)}
	f1, _ := a.send([]byte("first"))
	f2, _ := a.send([]byte("second"))
	if _, err := b.receive(f2); err != nil {
		t.Fatal(err)
	}
	if _, err := b.receive(f1); err == nil {
		t.Error("lower nonce accepted")
	}
	f3, _ := a.send([]byte("third"))
	f3.Payload[0] ^= 0xff
	if _, err := b.receive(f3); err == nil {
		t.Error("tampered frame accepted")
	}

	now := time.Unix(1000, 0)
	s := &transportState{lastHandshake: time.Unix(1000-300, 0)}
	if s.shouldRehandshake(now) {
		t.Error("session exactly at the interval must not expire")
	}
	s.lastHandshake = time.Unix(1000-301, 0)
	if !s.shouldRehandshake(now) {
		t.Error("session older than the interval must expire")
	}
}

func TestUnmarshalFrameRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {0xff}, []byte("\x63abc"), {0xa1, 0x63, 'f', 'o', 'o', 0x01}} {
		if _, err := UnmarshalFrame(b); err == nil {
			t.Errorf("UnmarshalFrame(%x) succeeded", b)
		}
	}
	// A HandshakeFinish carried as a byte string is accepted too (serde Vec<u8> from bytes).
	f, err := UnmarshalFrame(append([]byte{0xa1, 0x6f}, append([]byte("HandshakeFinish"), 0x42, 1, 2)...))
	if err != nil || f.Kind != FrameHandshakeFinish || !bytes.Equal(f.Finish, []byte{1, 2}) {
		t.Errorf("finish from bytes = %+v, %v", f, err)
	}
}

func TestEndpointJSON(t *testing.T) {
	cases := []struct {
		e    Endpoint
		json string
	}{
		{DesktopRenderer, `"DesktopRenderer"`},
		{DesktopMain, `"DesktopMain"`},
		{Endpoint{Kind: KindCli, Host: HostID{Own: true}}, `{"Cli":{"id":"Own"}}`},
		{Endpoint{Kind: KindCli, Host: HostID{ID: 7}}, `{"Cli":{"id":{"Id":7}}}`},
		{Endpoint{Kind: KindBrowserBackground, Host: HostID{Own: true}}, `{"BrowserBackground":{"id":"Own"}}`},
		{Endpoint{Kind: KindBrowserForeground, ID: 3}, `{"BrowserForeground":{"id":3}}`},
		{Endpoint{Kind: KindWeb, TabID: 4, DocumentID: "doc"}, `{"Web":{"tab_id":4,"document_id":"doc"}}`},
		{Endpoint{Kind: KindWeb, TabID: 4, DocumentID: "doc", Origin: "https://vault.bitwarden.com"}, `{"Web":{"tab_id":4,"document_id":"doc","origin":"https://vault.bitwarden.com"}}`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.e)
		if err != nil || string(b) != c.json {
			t.Errorf("marshal %+v = %s, %v; want %s", c.e, b, err, c.json)
		}
		var back Endpoint
		if err := json.Unmarshal([]byte(c.json), &back); err != nil || back != c.e {
			t.Errorf("unmarshal %s = %+v, %v", c.json, back, err)
		}
	}
}

func TestEnvelopes(t *testing.T) {
	topic := "test-topic"
	b, err := EncodeOutgoing(OutgoingMessage{Payload: []byte{1, 2, 3}, Destination: DesktopRenderer, Topic: &topic})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[1,2,3],"topic":"test-topic"}}`
	if string(b) != want {
		t.Errorf("envelope = %s", b)
	}
	b, _ = EncodeOutgoing(OutgoingMessage{Payload: []byte{}, Destination: DesktopRenderer})
	if string(b) != `{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[]}}` {
		t.Errorf("envelope without topic = %s", b)
	}

	msg, ok, connected, err := decodeIncoming([]byte(`{"type":"forwarded-bitwarden-ipc-message","message":{"destination":{"Cli":{"id":{"Id":1}}},"payload":[9],"topic":"t"},"originalSource":"DesktopRenderer"}`))
	if err != nil || !ok || connected || msg.Source != DesktopRenderer || msg.Payload[0] != 9 || *msg.Topic != "t" {
		t.Errorf("forwarded = %+v %v %v %v", msg, ok, connected, err)
	}
	msg, ok, _, _ = decodeIncoming([]byte(`{"type":"bitwarden-ipc-message","message":{"destination":"DesktopMain","payload":[],"topic":null}}`))
	if !ok || msg.Source != DesktopMain || msg.Topic != nil {
		t.Errorf("ipc message = %+v", msg)
	}
	if _, ok, connected, _ := decodeIncoming([]byte(`{"command":"connected"}`)); ok || !connected {
		t.Error("connected message not detected")
	}
	if _, ok, connected, err := decodeIncoming([]byte(`{"command":"biometricUnlock"}`)); ok || connected || err != nil {
		t.Error("legacy message not ignored")
	}

	p, _ := marshalRPCRequest(map[string]string{"user_id": "u"}, "id", "GetBiometricsStatus", "RpcResponseMessage:id")
	if string(p) != `{"request":{"user_id":"u"},"request_id":"id","request_type":"GetBiometricsStatus","response_topic":"RpcResponseMessage:id"}` {
		t.Errorf("rpc request = %s", p)
	}
	p, _ = marshalRPCRequest(nil, "id", "DiscoverRequest", "RpcResponseMessage:id")
	if !strings.HasPrefix(string(p), `{"request":null,`) {
		t.Errorf("unit request = %s", p)
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4+7 {
		t.Fatalf("frame length = %d", buf.Len())
	}
	b, err := ReadFrame(&buf)
	if err != nil || string(b) != `{"a":1}` {
		t.Errorf("read frame = %s, %v", b, err)
	}
	if err := WriteFrame(&buf, make([]byte, MaxMessageSize+1)); err == nil || err.Error() != "Desktop IPC message exceeds 1048576 bytes" {
		t.Errorf("oversized write = %v", err)
	}
	big := []byte{0, 0, 0, 0}
	big[0], big[1], big[2], big[3] = 0xff, 0xff, 0xff, 0x7f
	if _, err := ReadFrame(bytes.NewReader(big)); err == nil {
		t.Error("oversized frame accepted")
	}
}

func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2026.8.9", "2026.9.0", true},
		{"2026.9.0", "2026.9.0", false},
		{"2026.10.0", "2026.9.0", false},
		{"2026.9.0-beta.1", "2026.9.0", true},
		{"2027.1.0-beta", "2026.9.0", false},
	}
	for _, c := range cases {
		got, err := SemverLess(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("SemverLess(%s, %s) = %v, %v", c.a, c.b, got, err)
		}
	}
	if _, err := SemverLess("garbage", "2026.9.0"); err == nil || err.Error() != "Invalid Version: garbage" {
		t.Errorf("invalid version error = %v", err)
	}
}
