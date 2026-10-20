// Package ipctest provides a fake Bitwarden desktop app (the desktop IPC socket server with the
// SDK IPC biometrics RPC handlers) and a fake desktop_proxy for tests.
package ipctest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/lassejlv/bw-go/internal/ipc"
)

// FakeDesktop is a fake desktop app listening on a unix socket. The CLI is addressed as
// Cli{Id(n)} and the desktop renderer's messages are delivered as forwarded messages, like the
// real desktop main process does.
type FakeDesktop struct {
	SocketPath string

	mu sync.Mutex
	// Version is returned for DiscoverRequest.
	Version string
	// Status is the SDK BiometricsStatus variant returned for GetBiometricsStatus.
	Status string
	// UserKey is the base64 user key returned for UnlockBiometrics (nil: cancelled prompt).
	UserKey *string
	// AuthResult is returned for AuthenticateBiometrics.
	AuthResult bool
	// Silent makes the desktop ignore every message (an old desktop without SDK IPC).
	Silent bool
	// UnlockDelay delays the UnlockBiometrics answer.
	UnlockDelay time.Duration
	// Unregistered drops the handler of the named request types (NoHandlerFound).
	Unregistered map[string]bool

	announcements []string
	requests      []Request
	listener      net.Listener
}

// Request is a received RPC request.
type Request struct {
	Type    string
	Request json.RawMessage
}

// NewFakeDesktop starts a fake desktop app. It is stopped when the test ends.
func NewFakeDesktop(t testing.TB) *FakeDesktop {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake desktop app listens on a unix socket")
	}
	// Unix socket paths are limited to ~104 bytes, so avoid the long t.TempDir() paths.
	dir, err := os.MkdirTemp("", "bwipc")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "s.bw")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	d := &FakeDesktop{SocketPath: p, Version: "2026.9.0", Status: "Available", AuthResult: true, listener: l}
	t.Cleanup(func() { l.Close(); os.RemoveAll(dir) })
	go d.serve()
	return d
}

// Set mutates the fake under its lock.
func (d *FakeDesktop) Set(fn func(d *FakeDesktop)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d)
}

// Announcements returns the client announcements received (first frame of each connection).
func (d *FakeDesktop) Announcements() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.announcements...)
}

// Requests returns the RPC requests received.
func (d *FakeDesktop) Requests() []Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Request(nil), d.requests...)
}

// RequestTypes returns the request types received, in order.
func (d *FakeDesktop) RequestTypes() []string {
	var out []string
	for _, r := range d.Requests() {
		out = append(out, r.Type)
	}
	return out
}

func (d *FakeDesktop) serve() {
	id := int32(0)
	for {
		c, err := d.listener.Accept()
		if err != nil {
			return
		}
		id++
		go d.handle(c, id)
	}
}

// serverTransport adapts one client connection to an ipc.Transport on the desktop side.
type serverTransport struct {
	conn     net.Conn
	cli      ipc.Endpoint
	writeMu  sync.Mutex
	incoming chan ipc.IncomingMessage
	once     sync.Once
}

func (s *serverTransport) Send(_ context.Context, m ipc.OutgoingMessage) error {
	b, err := json.Marshal(ipc.Envelope{
		Type:           ipc.ForwardedIpcMessageType,
		Message:        ipc.SerializedMessage{Destination: m.Destination, Payload: m.Payload, Topic: m.Topic},
		OriginalSource: &ipc.DesktopRenderer,
	})
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return ipc.WriteFrame(s.conn, b)
}

func (s *serverTransport) Incoming() <-chan ipc.IncomingMessage { return s.incoming }
func (s *serverTransport) Close()                               { s.once.Do(func() { s.conn.Close() }) }

func (d *FakeDesktop) handle(c net.Conn, id int32) {
	defer c.Close()
	first, err := ipc.ReadFrame(c)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.announcements = append(d.announcements, string(first))
	d.mu.Unlock()

	st := &serverTransport{conn: c, cli: ipc.Endpoint{Kind: ipc.KindCli, Host: ipc.HostID{ID: id}}, incoming: make(chan ipc.IncomingMessage, 16)}
	client := ipc.NewClient(st, nil)
	defer client.Close()
	d.register(client)

	for {
		b, err := ipc.ReadFrame(c)
		if err != nil {
			close(st.incoming)
			return
		}
		d.mu.Lock()
		silent := d.Silent
		d.mu.Unlock()
		if silent {
			continue
		}
		var env ipc.Envelope
		if err := json.Unmarshal(b, &env); err != nil || env.Type != ipc.IpcMessageType {
			continue
		}
		st.incoming <- ipc.IncomingMessage{Payload: env.Message.Payload, Destination: env.Message.Destination, Source: st.cli, Topic: env.Message.Topic}
	}
}

func (d *FakeDesktop) record(typ string, req json.RawMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, Request{Type: typ, Request: req})
}

func (d *FakeDesktop) register(c *ipc.Client) {
	reg := func(name string, h ipc.RPCHandler) {
		d.mu.Lock()
		skip := d.Unregistered[name]
		d.mu.Unlock()
		if skip {
			return
		}
		c.RegisterRPCHandler(name, func(req json.RawMessage, src ipc.Endpoint) (any, error) {
			d.record(name, req)
			return h(req, src)
		})
	}
	reg("DiscoverRequest", func(req json.RawMessage, _ ipc.Endpoint) (any, error) {
		if string(req) != "null" {
			return nil, errors.New("DiscoverRequest must be null")
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return map[string]string{"version": d.Version}, nil
	})
	userReq := func(req json.RawMessage) error {
		var r struct {
			UserID *string `json:"user_id"`
		}
		if err := json.Unmarshal(req, &r); err != nil || r.UserID == nil {
			return errors.New("missing field `user_id`")
		}
		return nil
	}
	reg("GetBiometricsStatus", func(req json.RawMessage, _ ipc.Endpoint) (any, error) {
		if err := userReq(req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.Status, nil
	})
	reg("UnlockBiometrics", func(req json.RawMessage, _ ipc.Endpoint) (any, error) {
		if err := userReq(req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		delay, key := d.UnlockDelay, d.UserKey
		d.mu.Unlock()
		time.Sleep(delay)
		// UnlockBiometricsResponse { user_key: Option<SymmetricCryptoKey> }.
		return map[string]*string{"user_key": key}, nil
	})
	reg("AuthenticateBiometrics", func(req json.RawMessage, _ ipc.Endpoint) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.AuthResult, nil
	})
}

// FakeProxyEnv names the environment variable that makes a test binary act as desktop_proxy (see
// RunFakeProxy): its value is the desktop socket path.
const FakeProxyEnv = "BWGO_TEST_FAKE_DESKTOP_PROXY_SOCKET"

// RunFakeProxy behaves like desktop_proxy: it connects to the desktop socket, announces the
// client from args, reports {"command":"connected"} on stdout and relays native-messaging frames
// until stdin closes. It returns the process exit code.
func RunFakeProxy(sock string, args []string, stdin io.Reader, stdout io.Writer) int {
	cli := false
	for _, a := range args {
		if a == ipc.ProxyArgClientCli {
			cli = true
		}
	}
	if !cli {
		return 3
	}
	conn, err := ipc.DialSocket(sock)
	if err != nil {
		return 1
	}
	defer conn.Close()
	var outMu sync.Mutex
	write := func(b []byte) error {
		outMu.Lock()
		defer outMu.Unlock()
		return ipc.WriteFrame(stdout, b)
	}
	if write([]byte(`{"command":"connected"}`)) != nil {
		return 1
	}
	go func() {
		for {
			b, err := ipc.ReadFrame(conn)
			if err != nil {
				_ = write([]byte(`{"command":"disconnected"}`))
				os.Exit(0)
			}
			if write(b) != nil {
				return
			}
		}
	}()
	for {
		b, err := ipc.ReadFrame(stdin)
		if err != nil {
			return 0
		}
		if ipc.WriteFrame(conn, b) != nil {
			return 1
		}
	}
}
