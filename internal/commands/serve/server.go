package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
)

// Options are the `bw serve` options.
type Options struct {
	Hostname                string // --hostname (default "localhost")
	Port                    string // --port (default 8087)
	DisableOriginProtection bool   // --disable-origin-protection
}

// BuildAllowedHosts mirrors buildServeAllowedHosts: the Host header values accepted by the
// origin protection. port is formatted like a JS number.
func BuildAllowedHosts(hostname, port string) map[string]bool {
	entries := []string{
		"localhost:" + port,
		"127.0.0.1:" + port,
		"[::1]:" + port,
		hostname + ":" + port,
	}
	if port == "80" || port == "443" {
		entries = append(entries, "localhost", "127.0.0.1", "[::1]", hostname)
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		set[strings.ToLower(e)] = true
	}
	return set
}

// Server is the `bw serve` HTTP handler (koa app + OssServeConfigurator router).
type Server struct {
	a             *app.App
	protectOrigin bool
	allowedHosts  map[string]bool // nil: any host (`--hostname all`)
	log           *logger
	router        *router
	// mu serializes command execution: commands mutate process-global state (BW_SESSION,
	// BW_* env flags, the state file).
	mu sync.Mutex
}

// HandlerOptions configure NewHandler.
type HandlerOptions struct {
	ProtectOrigin bool
	// AllowedHosts is the Host header allow-list; nil disables the Host check.
	AllowedHosts map[string]bool
}

// NewHandler builds the serve handler. It does not touch the environment; Run sets BW_SERVE and
// BW_NOINTERACTION before serving.
func NewHandler(a *app.App, o HandlerOptions) *Server {
	s := &Server{a: a, protectOrigin: o.ProtectOrigin, allowedHosts: o.AllowedHosts, log: defaultLogger, router: &router{}}
	s.configureRouter()
	return s
}

// ServeHTTP runs the middleware stack: origin protection, body parser, router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := &trackingWriter{ResponseWriter: w}
	defer func() {
		if rec := recover(); rec != nil {
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			// koa's default error handler: log the error and answer 500.
			s.log.error(fmt.Sprintf("%v\n%s", rec, debug.Stack()))
			if !rw.wrote {
				writeText(rw, http.StatusInternalServerError, "Internal Server Error")
			}
		}
	}()
	if s.protectOrigin {
		// Guards are independent; order does not affect correctness.
		if s.allowedHosts != nil && s.rejectIfHostNotAllowed(rw, r) {
			return
		}
		if s.rejectIfOriginPresent(rw, r) {
			return
		}
	}
	body, herr := parseBody(r)
	if herr != nil {
		writeText(rw, herr.status, herr.msg)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), bodyKey{}, body))
	s.router.ServeHTTP(rw, r)
}

func (s *Server) rejectIfHostNotAllowed(w http.ResponseWriter, r *http.Request) bool {
	host, present := r.Host, r.Host != ""
	if s.allowedHosts[strings.ToLower(host)] {
		return false
	}
	if !present {
		host = "(missing)"
	}
	s.log.warning(`Blocking request with disallowed Host "` + host + `"`)
	writeText(w, http.StatusForbidden, "Forbidden")
	return true
}

func (s *Server) rejectIfOriginPresent(w http.ResponseWriter, r *http.Request) bool {
	values, present := r.Header["Origin"]
	if !present {
		return false
	}
	origin := strings.Join(values, ", ")
	if origin == "" {
		origin = "(Origin header value missing)"
	}
	s.log.warning(`Blocking request from "` + origin + `"`)
	writeText(w, http.StatusForbidden, "Forbidden")
	return true
}

type bodyKey struct{}

func requestBody(r *http.Request) json.RawMessage {
	if b, ok := r.Context().Value(bodyKey{}).(json.RawMessage); ok {
		return b
	}
	return emptyObject
}

type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(code int) { t.wrote = true; t.ResponseWriter.WriteHeader(code) }
func (t *trackingWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

// ---------- listening ----------

// jsNumber mirrors Number(string): surrounding whitespace is ignored, "" is 0, 0x/0o/0b
// prefixes are accepted and anything else that is not a decimal literal is NaN.
func jsNumber(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	switch s {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789+-.eE", c) {
			return math.NaN()
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return math.NaN()
	}
	return f
}

// jsNumberString formats a number like JS String(number) for the values serve can produce.
func jsNumberString(f float64) string {
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// parseIntJS mirrors parseInt(s) (radix 10, or 16 with a 0x prefix); ok is false for NaN.
func parseIntJS(s string) (int, bool) {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	base := 10
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		base, s = 16, s[2:]
	}
	end := 0
	for end < len(s) {
		c := s[end]
		ok := c >= '0' && c <= '9' || base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')
		if !ok {
			break
		}
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(s[:end], base, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return int(n), true
}

func itoa(n int) string { return strconv.Itoa(n) }

// newHTTPServer applies Node's http.Server defaults (headersTimeout 60s, requestTimeout 300s,
// keepAliveTimeout 5s).
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 60 * time.Second,
		ReadTimeout:       300 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
}

// Run implements ServeCommand.run: it configures the environment, builds the handler and
// serves until the listener fails (it only returns early for `fd+connected://` once the
// connection is closed).
func Run(a *app.App, o Options) error {
	protectOrigin := !o.DisableOriginProtection
	port := jsNumber(o.Port)
	if math.IsNaN(port) || port == 0 {
		port = 8087
	}
	portStr := jsNumberString(port)
	hostname := o.Hostname
	if hostname == "" {
		hostname = "localhost"
	}
	log := defaultLogger
	protection := "no origin protection"
	if protectOrigin {
		protection = "origin protection"
	}
	log.info("Starting server on " + hostname + ":" + portStr + " with " + protection)

	// `--hostname all` binds every interface, so a LAN client may legitimately reach the server
	// via any local IP.
	var allowed map[string]bool
	if hostname != "all" {
		allowed = BuildAllowedHosts(hostname, portStr)
	}
	os.Setenv("BW_SERVE", "true")
	os.Setenv("BW_NOINTERACTION", "true")

	handler := NewHandler(a, HandlerOptions{ProtectOrigin: protectOrigin, AllowedHosts: allowed})
	handler.log = log

	switch {
	case strings.HasPrefix(hostname, "fd+connected://"):
		fd, ok := parseIntJS(strings.TrimPrefix(hostname, "fd+connected://"))
		if !ok || fd < 0 {
			return fmt.Errorf("invalid file descriptor: %s", hostname)
		}
		f := os.NewFile(uintptr(fd), "fd+connected")
		conn, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		// allow idle sockets, incomplete handshakes and slow requests
		srv := &http.Server{Handler: handler}
		err = srv.Serve(newSingleConnListener(conn))
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case strings.HasPrefix(hostname, "fd+listening://"):
		fd, ok := parseIntJS(strings.TrimPrefix(hostname, "fd+listening://"))
		if !ok || fd < 0 {
			return fmt.Errorf("invalid file descriptor: %s", hostname)
		}
		f := os.NewFile(uintptr(fd), "fd+listening")
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		log.info("Listening on " + hostname)
		return newHTTPServer(handler).Serve(ln)
	case strings.HasPrefix(hostname, "unix://"):
		ln, err := net.Listen("unix", strings.TrimPrefix(hostname, "unix://"))
		if err != nil {
			return err
		}
		log.info("Listening on " + hostname)
		return newHTTPServer(handler).Serve(ln)
	default:
		if port != math.Trunc(port) || port < 0 || port >= 65536 {
			return fmt.Errorf("options.port should be >= 0 and < 65536. Received type number (%s).", portStr)
		}
		host := hostname
		if hostname == "all" {
			host = ""
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(host, portStr))
		if err != nil {
			return err
		}
		log.info("Listening on " + hostname + ":" + portStr)
		return newHTTPServer(handler).Serve(ln)
	}
}

// singleConnListener hands out one already connected socket, then blocks until it is closed.
type singleConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	mu     sync.Mutex
	used   bool
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	l := &singleConnListener{closed: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, onClose: func() { l.once.Do(func() { close(l.closed) }) }}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	onClose func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.onClose()
	return err
}

// runCommand executes a route under the command mutex.
func (s *Server) runCommand(fn func() *cli.Response) *cli.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}
