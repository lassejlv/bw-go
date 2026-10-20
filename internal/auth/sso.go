package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SsoPromptData holds the PKCE verifier/challenge and state of an SSO login.
type SsoPromptData struct {
	CodeVerifier  string
	CodeChallenge string
	State         string
}

const ssoAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// randomPassword generates a random alphanumeric string (the CLI uses the password generator
// with uppercase, lowercase and numbers, no special characters).
func randomPassword(n int) string {
	var sb strings.Builder
	max := big.NewInt(int64(len(ssoAlphabet)))
	for i := 0; i < n; i++ {
		v, _ := rand.Int(rand.Reader, max)
		sb.WriteByte(ssoAlphabet[v.Int64()])
	}
	return sb.String()
}

// CodeChallenge returns the base64url (unpadded) SHA-256 of the verifier.
func CodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// MakeSsoPromptData mirrors LoginCommand.makeSsoPromptData.
func MakeSsoPromptData() SsoPromptData {
	state := randomPassword(64)
	verifier := randomPassword(64)
	return SsoPromptData{CodeVerifier: verifier, CodeChallenge: CodeChallenge(verifier), State: state}
}

// BuildSsoURL mirrors SsoUrlService.buildSsoUrl.
func BuildSsoURL(webAppURL, clientType, redirectURI, state, codeChallenge, email, orgSsoIdentifier string) string {
	u := webAppURL + "/#/sso?clientId=" + clientType +
		"&redirectUri=" + encodeURIComponent(redirectURI) +
		"&state=" + state +
		"&codeChallenge=" + codeChallenge
	if email != "" {
		u += "&email=" + encodeURIComponent(email)
	}
	if orgSsoIdentifier != "" {
		u += "&identifier=" + encodeURIComponent(orgSsoIdentifier)
	}
	return u
}

// encodeURIComponent matches JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var sb strings.Builder
	for _, b := range []byte(s) {
		if strings.IndexByte(unreserved, b) >= 0 {
			sb.WriteByte(b)
		} else {
			fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

// OrgIdentifierFromState mirrors LoginCommand.getOrgIdentifierFromState.
func OrgIdentifierFromState(state string) string {
	parts := strings.Split(state, "_identifier=")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// CheckState mirrors LoginCommand.checkState.
func CheckState(state, check string) bool {
	if state == "" || check == "" {
		return false
	}
	return strings.Split(state, "_identifier=")[0] == strings.Split(check, "_identifier=")[0]
}

// LaunchURI opens a URL in the default browser (CliPlatformUtilsService.launchUri).
func LaunchURI(uri string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		cmd = exec.Command("xdg-open", uri)
	case "darwin":
		cmd = exec.Command("open", uri)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", uri)
	default:
		return fmt.Errorf("cannot open browser on %s", runtime.GOOS)
	}
	return cmd.Start()
}

const ssoSuccessHTML = "<html><head><title>Success | Bitwarden CLI</title></head><body>" +
	"<h1>Successfully authenticated with the Bitwarden CLI</h1>" +
	"<p>You may now close this tab and return to the terminal.</p>" +
	"</body></html>"

const ssoFailedHTML = "<html><head><title>Failed | Bitwarden CLI</title></head><body>" +
	"<h1>Something went wrong logging into the Bitwarden CLI</h1>" +
	"<p>You may now close this tab and return to the terminal.</p>" +
	"</body></html>"

// SsoResult is the outcome of the SSO browser flow.
type SsoResult struct {
	Code          string
	OrgIdentifier string
	RedirectURI   string
}

// ErrSso is returned when the SSO callback fails.
var ErrSso = errors.New("Something went wrong. Try again.")

// OpenSsoPrompt mirrors LoginCommand.openSsoPrompt: it starts a callback server on the first free
// port in 8065-8070, opens the web vault SSO page and waits for the authorization code.
func OpenSsoPrompt(webVaultURL string, data SsoPromptData, orgSsoIdentifier string) (*SsoResult, error) {
	var ln net.Listener
	var port int
	for p := 8065; p <= 8070; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", p))
		if err == nil {
			ln, port = l, p
			break
		}
	}
	if ln == nil {
		return nil, ErrSso
	}
	redirectURI := fmt.Sprintf("http://localhost:%d", port)

	type outcome struct {
		res *SsoResult
		err error
	}
	done := make(chan outcome, 1)
	srv := &http.Server{ReadHeaderTimeout: 30 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		q, _ := url.ParseQuery(r.URL.RawQuery)
		code := q.Get("code")
		state := q.Get("state")
		w.Header().Set("Content-Type", "text/html")
		if code != "" && state != "" && CheckState(state, data.State) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(ssoSuccessHTML))
			select {
			case done <- outcome{res: &SsoResult{Code: code, OrgIdentifier: OrgIdentifierFromState(state), RedirectURI: redirectURI}}:
			default:
			}
		} else {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(ssoFailedHTML))
			select {
			case done <- outcome{err: ErrSso}:
			default:
			}
		}
	})
	go func() { _ = srv.Serve(ln) }()

	_ = LaunchURI(BuildSsoURL(webVaultURL, ClientID, redirectURI, data.State, data.CodeChallenge, "", orgSsoIdentifier))

	o := <-done
	go func() {
		// Give the browser a moment to receive the response before closing.
		time.Sleep(500 * time.Millisecond)
		_ = srv.Close()
	}()
	return o.res, o.err
}
