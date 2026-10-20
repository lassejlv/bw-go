package vaultedit

import (
	"os"
	"path/filepath"
	"testing"
)

// In serve mode an HTTP client must not be able to make the server read its own local files.
func TestCreateAttachmentServeModeIgnoresFileOption(t *testing.T) {
	t.Setenv("BW_SERVE", "true")
	p := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(p, []byte("server-local"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := createAttachment(nil, CreateOptions{ItemID: "x", File: p})
	if r.Success || r.MessageText() != "File not provided." {
		t.Fatalf("got success=%v %q", r.Success, r.MessageText())
	}
}
