package vaultedit

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

// run executes the bw command tree and returns stdout, stderr and the exit code.
func run(t *testing.T, env *testEnv, args ...string) (string, string, int) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	cli.ExitCode = 0
	code := root.Execute(env.a, args)
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	out, _ := io.ReadAll(ro)
	errOut, _ := io.ReadAll(re)
	return string(out), string(errOut), code
}

func TestProgram(t *testing.T) {
	env := newEnv(t, envOptions{})
	t.Setenv("BW_SESSION", os.Getenv("BW_SESSION"))

	_, stderr, code := run(t, env, "delete", "thing", "x")
	if code != 1 || stderr != `Unknown object "thing". Allowed objects are: item, attachment, folder, org-collection.` {
		t.Errorf("validateObject: %d %q", code, stderr)
	}
	_, stderr, code = run(t, env, "edit", "item")
	if code != 1 || !strings.Contains(stderr, "error: missing required argument 'id'") {
		t.Errorf("missing argument: %d %q", code, stderr)
	}

	stdout, _, _ := run(t, env, "create", "--help")
	for _, want := range []string{
		"Create an object in the vault.",
		"object       Valid objects are: item, attachment, folder, org-collection",
		"encodedJson  Encoded json of the object to create. Can also be piped into stdin.",
		"--file string",
		"\n  Examples:\n\n    bw create folder eyJuYW1lIjoiTXkgRm9sZGVyIn0K\n    echo 'eyJuYW1lIjoiTXkgRm9sZGVyIn0K' | bw create folder\n" +
			"    bw create attachment --file ./myfile.csv --itemid 16b15b89-65b3-4639-ad2a-95052a6d8f66\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("create help lacks %q:\n%s", want, stdout)
		}
	}
	stdout, _, _ = run(t, env, "share", "--help")
	if !strings.Contains(stdout, "--DEPRECATED-- Move an item to an organization.") ||
		!strings.Contains(stdout, "\n--DEPRECATED See \"bw move\" for the current implementation--\n") {
		t.Errorf("share help:\n%s", stdout)
	}
	stdout, _, _ = run(t, env, "--help")
	order := []string{"\n  create ", "\n  edit ", "\n  delete ", "\n  restore ", "\n  move ", "\n  confirm ", "\n  share ", "\n  archive "}
	last := -1
	for _, c := range order {
		i := strings.Index(stdout, c)
		if i < 0 || i < last {
			t.Errorf("command %q missing or out of order in help", strings.TrimSpace(c))
		}
		last = i
	}

	// end to end: soft delete through the CLI
	env.addCipher(loginItem("x", "y"))
	env.fs.on("PUT", "/api/ciphers/"+itemID+"/delete", func(w http.ResponseWriter, r *http.Request, body []byte) { w.WriteHeader(200) })
	stdout, stderr, code = run(t, env, "delete", "item", itemID)
	if code != 0 || stdout != "" || stderr != "" {
		t.Errorf("delete: %d %q %q", code, stdout, stderr)
	}
}
