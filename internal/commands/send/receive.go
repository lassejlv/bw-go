package send

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/sendcore"
)

// ReceiveOptions are the options of `receive` / `send receive`.
type ReceiveOptions struct {
	Password     string
	PasswordEnv  string
	PasswordFile string
	// Obj returns the Send's json object rather than its content.
	Obj bool
	// Output is where a File Send is saved.
	Output string
}

// Prompt hooks (inquirer prompts in upstream); replaceable in tests.
var (
	promptInput    = cli.PromptInput
	promptPassword = cli.PromptPassword
)

func promptConfirm(message string) bool {
	ans, err := promptInput(message + " (y/N)")
	if err != nil {
		return false
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

// receiver holds the state of one receive: the server hosting the Send and the link's key.
type receiver struct {
	a      *app.App
	server sendcore.Server
	seed   []byte
	appID  string
	decKey *crypto.SymmetricKey
}

func (r *receiver) requestToken(sendID string, creds *sendcore.Credentials) (*sendcore.AccessToken, *sendcore.TokenError) {
	return sendcore.RequestAccessToken(r.a.API.HTTP, r.server.IdentityURL, r.appID, sendID, creds, !r.server.IsConfiguredServer)
}

func (r *receiver) getTokenWithRetry(sendID string, creds *sendcore.Credentials) (*sendcore.AccessToken, *sendcore.TokenError) {
	for expired := 0; expired < 3; {
		tok, terr := r.requestToken(sendID, creds)
		if tok != nil {
			return tok, nil
		}
		if terr.Kind == "expired" {
			expired++
			continue
		}
		return nil, terr
	}
	return nil, &sendcore.TokenError{Kind: "unknown", Error: "Send access token has expired and could not be refreshed"}
}

// Receive accesses a Bitwarden Send from a url (SendReceiveCommand.run).
func Receive(a *app.App, rawURL string, opts ReceiveOptions) *cli.Response {
	canInteract := cli.CanInteract()
	u, err := sendcore.ParseURL(rawURL)
	if err != nil {
		return cli.BadRequest("Failed to parse the provided Send url")
	}
	d, err := a.Data()
	if err != nil {
		return cli.Error(err)
	}
	urls := api.Resolve(d.Environment)
	server := sendcore.ResolveServer(u, d.Environment, urls)
	if !server.Trusted {
		if !canInteract {
			return cli.BadRequest("Send access will not be attempted: the domain in the Send URL does not match the configured domain. Run interactively in order to override.")
		}
		origin := sendcore.Origin(u)
		if !promptConfirm(fmt.Sprintf("You are attempting to access a Send hosted on %s but your CLI is configured for "+
			"%s. Do not proceed if you do not trust %s. Do you want to proceed?", origin, urls.WebVault, origin)) {
			return cli.BadRequest("Send access cancelled.")
		}
	}
	id, key := sendcore.IDAndKey(u)
	if strings.TrimSpace(id) == "" || strings.TrimSpace(key) == "" {
		return cli.BadRequest("Failed to parse url, the url provided is not a valid Send url")
	}
	seed, err := sendcore.FromURLB64(key)
	if err != nil {
		return cli.Error(err)
	}
	r := &receiver{a: a, server: server, seed: seed, appID: d.AppID}
	return r.attemptAccess(id, opts, canInteract)
}

func jsonString(v any) string { return cli.MarshalJSON(v, false) }

func handleTokenError(e *sendcore.TokenError) *cli.Response {
	if e.Kind == "unexpected_server" {
		return cli.Error("Server error: " + jsonString(e.Error))
	}
	return cli.Error("Error: " + jsonString(e.Error))
}

func (r *receiver) attemptAccess(id string, opts ReceiveOptions, canInteract bool) *cli.Response {
	tok, terr := r.getTokenWithRetry(id, nil)
	if tok != nil {
		return r.accessWithToken(tok, opts)
	}
	if terr.Kind != "expected_server" {
		return handleTokenError(terr)
	}
	switch {
	case terr.Is("invalid_request", "email_required"):
		if !canInteract {
			return cli.BadRequest("Email verification required. Run in interactive mode.")
		}
		return r.handleEmailOtpAuth(id, opts)
	case terr.Is("invalid_request", "password_hash_b64_required"):
		return r.handlePasswordAuth(id, opts, canInteract)
	case terr.Is("invalid_grant", "send_id_invalid"):
		return cli.NotFound()
	}
	// The auth layer immediately returns a token for Sends without auth; reaching this is an error.
	return cli.Error("Could not determine authentication requirements")
}

func (r *receiver) handleEmailOtpAuth(id string, opts ReceiveOptions) *cli.Response {
	var email string
	for {
		e, err := promptInput("Enter your email address:")
		if err != nil {
			return cli.Error(err)
		}
		if e != "" && strings.Contains(e, "@") {
			email = e
			break
		}
		fmt.Fprintln(os.Stderr, ">> Please enter a valid email address")
	}
	tok, terr := r.getTokenWithRetry(id, &sendcore.Credentials{Kind: "email", Email: email})
	if tok != nil {
		return cli.Error("Unexpected server response")
	}
	if terr.Is("invalid_request", "email_and_otp_required") {
		otp, err := promptInput("Enter the verification code sent to your email:")
		if err != nil {
			return cli.Error(err)
		}
		tok, oerr := r.getTokenWithRetry(id, &sendcore.Credentials{Kind: "email_otp", Email: email, OTP: otp})
		if tok != nil {
			return r.accessWithToken(tok, opts)
		}
		if oerr.Is("invalid_request", "email_and_otp_required") {
			return cli.BadRequest("Invalid email or verification code")
		}
		return handleTokenError(oerr)
	}
	return handleTokenError(terr)
}

func (r *receiver) handlePasswordAuth(id string, opts ReceiveOptions, canInteract bool) *cli.Response {
	password := opts.Password
	if password == "" {
		if opts.PasswordFile != "" {
			p, err := cli.ReadFirstLine(opts.PasswordFile)
			if err != nil {
				return cli.Error(err)
			}
			password = p
		} else if opts.PasswordEnv != "" && os.Getenv(opts.PasswordEnv) != "" {
			password = os.Getenv(opts.PasswordEnv)
		}
	}
	if password == "" && canInteract {
		p, err := promptPassword("Send password:")
		if err != nil {
			return cli.Error(err)
		}
		password = p
	}
	if password == "" {
		return cli.BadRequest("Password required")
	}
	hash := sendcore.HashPassword(password, r.seed)
	tok, terr := r.getTokenWithRetry(id, &sendcore.Credentials{Kind: "password", PasswordHashB64: hash})
	if tok != nil {
		return r.accessWithToken(tok, opts)
	}
	switch terr.Kind {
	case "expected_server":
		if terr.Is("invalid_grant", "password_hash_b64_invalid") {
			return cli.BadRequest("Invalid password")
		}
	case "unexpected_server":
		return cli.Error("Server error: " + jsonString(terr.Error))
	case "unknown":
		return cli.Error(fmt.Sprint("Error: ", terr.Error))
	}
	return cli.Error("Authentication failed")
}

func isNotFound(err error) bool {
	var apiErr *api.ErrorResponse
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

func (r *receiver) accessWithToken(tok *sendcore.AccessToken, opts ReceiveOptions) *cli.Response {
	fail := func(err error) *cli.Response {
		if isNotFound(err) {
			return cli.NotFound()
		}
		return cli.Error(err)
	}
	data, err := sendcore.Access(r.a, r.server.APIURL, tok)
	if err != nil {
		return fail(err)
	}
	view, key, err := sendcore.DecryptAccess(data, r.seed)
	if err != nil {
		return fail(err)
	}
	r.decKey = key
	if opts.Obj {
		return cli.Success(NewSendAccessResponse(view))
	}
	switch view.Type {
	case sendcore.TypeText:
		if view.Text != nil && view.Text.Text != nil {
			io.WriteString(stdout, *view.Text.Text)
		}
		return cli.Success(nil)
	case sendcore.TypeFile:
		if view.File == nil || view.File.ID == nil {
			return cli.Error("Cannot read properties of null (reading 'id')")
		}
		downloadURL, err := sendcore.FileDownloadURL(r.a, r.server.APIURL, *view.File.ID, tok)
		if err != nil {
			return fail(err)
		}
		if sendcore.UnsafeURL(downloadURL, r.server.APIURL) != nil {
			return cli.Error("Download blocked: the file url failed a security check.")
		}
		name := fmt.Sprintf("BitwardenSendFile-%d", time.Now().UnixMilli())
		if view.File.FileName != nil {
			name = *view.File.FileName
		}
		return r.saveAttachmentToFile(downloadURL, basename(name), opts.Output)
	default:
		return cli.Success(NewSendAccessResponse(view))
	}
}

// basename mirrors path.basename.
func basename(p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimRight(p, "/"+string(filepath.Separator))
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// saveAttachmentToFile mirrors DownloadCommand.saveAttachmentToFile.
func (r *receiver) saveAttachmentToFile(url, fileName, output string) *cli.Response {
	status, body, err := sendcore.Download(r.a.API.HTTP, url)
	if err != nil {
		return cli.Error(err)
	}
	if status != 200 {
		return cli.Errorf("A %d error occurred while downloading the attachment.", status)
	}
	dec, err := crypto.DecryptBytes(body, r.decKey)
	if err != nil {
		return cli.Error("An error occurred while saving the attachment.")
	}
	if isServe() {
		return cli.Success(cli.NewFile(dec, fileName))
	}
	return cli.SaveResultToFile(dec, output, fileName)
}
