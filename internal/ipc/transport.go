package ipc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Port of apps/cli/src/platform/services/cli-desktop-ipc.transport.ts: the CLI spawns the desktop
// app's native-messaging proxy (desktop_proxy --client=cli) and exchanges native-messaging frames
// (a native-endian uint32 length followed by UTF-8 JSON) over its stdin/stdout.

// MaxMessageSize is MAX_MESSAGE_SIZE (and NATIVE_MESSAGING_BUFFER_SIZE).
const MaxMessageSize = 1024 * 1024

// ConnectionTimeout is CONNECTION_TIMEOUT_MS.
const ConnectionTimeout = 5 * time.Second

// ProxyArgClientCli makes the proxy announce this process to the desktop app as the CLI.
const ProxyArgClientCli = "--client=cli"

// WriteFrame writes one native-messaging frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("Desktop IPC message exceeds %d bytes", MaxMessageSize)
	}
	frame := binary.NativeEndian.AppendUint32(make([]byte, 0, 4+len(payload)), uint32(len(payload)))
	_, err := w.Write(append(frame, payload...))
	return err
}

// errFrameTooLarge is returned by ReadFrame for frames over MaxMessageSize.
var errFrameTooLarge = fmt.Errorf("[IPC] Desktop message exceeds %d bytes", MaxMessageSize)

// ReadFrame reads one native-messaging frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.NativeEndian.Uint32(hdr[:])
	if n > MaxMessageSize {
		return nil, errFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Stream is one connection to the desktop app: a spawned proxy or a direct socket connection.
type Stream struct {
	desc string // the proxy or socket path, for messages
	r    io.Reader
	w    io.WriteCloser
	// connected is closed by the stream itself when no {"command":"connected"} message is
	// expected (direct socket connections are connected once the announcement is written).
	preConnected bool
	kill         func()
	// exited, when set, reports the end of the proxy process.
	exited <-chan error
}

// Dialer opens a stream to the desktop app.
type Dialer func() (*Stream, error)

// StreamTransport implements Transport over proxy or socket streams, reconnecting on demand.
type StreamTransport struct {
	log  Logger
	dial Dialer

	mu        sync.Mutex
	cur       *conn
	writeMu   sync.Mutex
	incoming  chan IncomingMessage
	done      chan struct{}
	closeOnce sync.Once
}

type conn struct {
	s         *Stream
	connected chan struct{}
	failed    chan error
	once      sync.Once
	ok        bool
}

// NewStreamTransport creates a transport using dial for every (re)connection.
func NewStreamTransport(dial Dialer, log Logger) *StreamTransport {
	if log == nil {
		log = func(string) {}
	}
	return &StreamTransport{log: log, dial: dial, incoming: make(chan IncomingMessage, 64), done: make(chan struct{})}
}

// NewDesktopTransport is the transport the CLI uses: it spawns the installed desktop proxy. When
// no proxy binary is installed (and BITWARDEN_DESKTOP_PROXY_PATH is not set), it connects to the
// desktop app's socket directly, doing what the proxy would do.
func NewDesktopTransport(log Logger) *StreamTransport {
	return NewStreamTransport(func() (*Stream, error) {
		p, err := defaultProxyPath()
		if err != nil {
			if errors.Is(err, errProxyNotFound) {
				if sock, ok := findSocket(DefaultSocketEnv()); ok {
					return SocketStream(sock)
				}
			}
			return nil, err
		}
		return ProxyStream(p)
	}, log)
}

// ProxyStream spawns the desktop proxy at p.
func ProxyStream(p string) (*Stream, error) {
	cmd := exec.Command(p, ProxyArgClientCli)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan error, 1)
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	go func() {
		err := cmd.Wait()
		code := cmd.ProcessState.ExitCode()
		msg := "Bitwarden Desktop proxy exited"
		if code >= 0 {
			msg += fmt.Sprintf(" with code %d", code)
		} else if err != nil {
			msg += " from signal " + strings.TrimPrefix(err.Error(), "signal: ")
		}
		exited <- errors.New(msg)
	}()
	return &Stream{
		desc:   p,
		r:      stdout,
		w:      stdin,
		kill:   func() { _ = stdin.Close(); _ = cmd.Process.Kill() },
		exited: exited,
	}, nil
}

// SocketStream connects to the desktop IPC socket at p directly.
func SocketStream(p string) (*Stream, error) {
	c, err := DialSocket(p)
	if err != nil {
		return nil, err
	}
	return &Stream{desc: p, r: c, w: c, preConnected: true, kill: func() { _ = c.Close() }}, nil
}

// Incoming implements Transport.
func (t *StreamTransport) Incoming() <-chan IncomingMessage { return t.incoming }

// Send implements Transport: it connects if needed and writes an IpcMessage frame.
func (t *StreamTransport) Send(ctx context.Context, msg OutgoingMessage) error {
	c, err := t.connect(ctx)
	if err != nil {
		return err
	}
	payload, err := EncodeOutgoing(msg)
	if err != nil {
		return err
	}
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("Desktop IPC message exceeds %d bytes", MaxMessageSize)
	}
	t.mu.Lock()
	live := t.cur == c && c.ok
	t.mu.Unlock()
	if !live {
		return errors.New("Bitwarden Desktop proxy disconnected before the message could be sent")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := WriteFrame(c.s.w, payload); err != nil {
		t.disconnect(c)
		return err
	}
	return nil
}

// Close implements Transport. The transport cannot be used afterwards.
func (t *StreamTransport) Close() {
	t.closeOnce.Do(func() { close(t.done) })
	t.mu.Lock()
	c := t.cur
	t.cur = nil
	t.mu.Unlock()
	if c != nil {
		c.s.kill()
	}
}

func (t *StreamTransport) connect(ctx context.Context) (*conn, error) {
	t.mu.Lock()
	select {
	case <-t.done:
		t.mu.Unlock()
		return nil, ErrClosed
	default:
	}
	c := t.cur
	if c == nil {
		s, err := t.dial()
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		c = &conn{s: s, connected: make(chan struct{}), failed: make(chan error, 1)}
		t.cur = c
		go t.readLoop(c)
		if s.exited != nil {
			go func() {
				err := <-s.exited
				t.fail(c, err)
			}()
		}
		if s.preConnected {
			t.succeed(c)
		}
	}
	t.mu.Unlock()

	timer := time.NewTimer(ConnectionTimeout)
	defer timer.Stop()
	select {
	case <-c.connected:
		return c, nil
	case err := <-c.failed:
		c.failed <- err // let other waiters see it too
		return nil, err
	case <-timer.C:
		err := fmt.Errorf("Connection to Bitwarden Desktop via %s timed out", c.s.desc)
		t.fail(c, err)
		c.s.kill()
		return nil, err
	case <-ctx.Done():
		return nil, ErrCancelled
	}
}

func (t *StreamTransport) succeed(c *conn) {
	c.once.Do(func() {
		c.ok = true
		close(c.connected)
		t.log("[IPC] Connected to Bitwarden Desktop via " + c.s.desc)
	})
}

func (t *StreamTransport) fail(c *conn, err error) {
	c.once.Do(func() {
		c.failed <- err
	})
	t.disconnect(c)
}

func (t *StreamTransport) disconnect(c *conn) {
	t.mu.Lock()
	if t.cur == c {
		t.cur = nil
	}
	t.mu.Unlock()
}

func (t *StreamTransport) readLoop(c *conn) {
	for {
		b, err := ReadFrame(c.s.r)
		if err != nil {
			if errors.Is(err, errFrameTooLarge) {
				t.log(err.Error())
				c.s.kill()
			}
			if c.s.exited != nil {
				// A proxy connection ends with the process exit, reported by its exit status.
				return
			}
			t.fail(c, errors.New("Bitwarden Desktop proxy disconnected"))
			return
		}
		msg, ok, connected, err := decodeIncoming(b)
		if err != nil {
			t.log("[IPC] Ignoring malformed Bitwarden Desktop message")
			continue
		}
		if connected {
			t.succeed(c)
			continue
		}
		if ok {
			select {
			case t.incoming <- msg:
			case <-t.done:
				return
			}
		}
	}
}
