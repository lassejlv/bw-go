//go:build unix

package serve

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunFdConnected serves one request over an inherited, already connected socket
// (`--hostname fd+connected://N`) and checks that Run returns once the connection is closed.
func TestRunFdConnected(t *testing.T) {
	env := newEnv(t)
	t.Setenv("BW_SERVE", "")
	t.Setenv("BW_NOINTERACTION", "")
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	clientFile := os.NewFile(uintptr(fds[1]), "client")
	client, err := net.FileConn(clientFile)
	clientFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- Run(env.a, Options{Hostname: "fd+connected://" + strconv.Itoa(fds[0])}) }()

	io.WriteString(client, "GET /status HTTP/1.1\r\nHost: localhost:8087\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"unlocked"`) {
		t.Fatalf("response %d %s", resp.StatusCode, body)
	}
	if os.Getenv("BW_SERVE") != "true" || os.Getenv("BW_NOINTERACTION") != "true" {
		t.Error("BW_SERVE / BW_NOINTERACTION not set")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the connection closed")
	}
}

func TestRunErrors(t *testing.T) {
	env := newEnv(t)
	if err := Run(env.a, Options{Port: "70000"}); err == nil ||
		err.Error() != "options.port should be >= 0 and < 65536. Received type number (70000)." {
		t.Errorf("port error %v", err)
	}
	if err := Run(env.a, Options{Hostname: "fd+listening://x"}); err == nil {
		t.Error("expected fd error")
	}
}
