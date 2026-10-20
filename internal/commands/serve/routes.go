package serve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/auth"
	"github.com/lassejlv/bw-go/internal/commands/send"
	"github.com/lassejlv/bw-go/internal/commands/tools"
	"github.com/lassejlv/bw-go/internal/commands/vaultcmd"
	"github.com/lassejlv/bw-go/internal/commands/vaultedit"
)

// reqCtx is the part of the koa context the route handlers use.
type reqCtx struct {
	r     *http.Request
	query url.Values
	body  json.RawMessage
	file  *uploadedFile
}

func (c *reqCtx) param(name string) string { return c.r.PathValue(name) }

// errInternal makes the route answer like koa does when the handler throws (500). Upstream
// throws a TypeError in the cases that use it.
var errInternal = &cli.Response{}

type routeFunc func(c *reqCtx) *cli.Response

// route registers a handler. requireUnlocked runs errorIfLocked first.
func (s *Server) route(method, pattern string, requireUnlocked bool, fn routeFunc) {
	s.routeWith(method, pattern, requireUnlocked, false, fn)
}

func (s *Server) routeWith(method, pattern string, requireUnlocked, multipartFile bool, fn routeFunc) {
	s.router.handle(method, pattern, func(w http.ResponseWriter, r *http.Request) {
		c := &reqCtx{r: r, query: r.URL.Query(), body: requestBody(r)}
		if multipartFile {
			f, err := parseMultipartFile(r)
			if err != nil {
				panic(fmt.Errorf("multer: %w", err))
			}
			c.file = f
		}
		resp := s.runCommand(func() *cli.Response {
			if requireUnlocked {
				if locked := s.errorIfLocked(); locked != nil {
					return locked
				}
			}
			return fn(c)
		})
		if resp == errInternal {
			panic(fmt.Errorf("%s %s: handler failed", method, pattern))
		}
		processResponse(w, r, resp)
	})
}

// configureRouter mirrors OssServeConfigurator.configureRouter (same order, paths and methods).
func (s *Server) configureRouter() {
	a := s.a

	s.route("GET", "/generate", false, func(c *reqCtx) *cli.Response {
		return tools.Generate(a, tools.GenerateOptionsFromQuery(c.query))
	})

	s.route("GET", "/status", false, func(c *reqCtx) *cli.Response {
		return auth.Status(a)
	})

	s.route("GET", "/list/object/:object", true, func(c *reqCtx) *cli.Response {
		if c.param("object") == "send" {
			return send.List(a, c.query.Get("search"))
		}
		return vaultcmd.List(a, c.param("object"), vaultcmd.ListOptionsFromQuery(c.query))
	})

	s.route("GET", "/send/list", true, func(c *reqCtx) *cli.Response {
		return send.List(a, c.query.Get("search"))
	})

	s.route("POST", "/sync", false, func(c *reqCtx) *cli.Response {
		return auth.Sync(a, auth.SyncOptions{Last: boolOption(c.query, "last"), Force: boolOption(c.query, "force")})
	})

	s.route("POST", "/lock", false, func(c *reqCtx) *cli.Response {
		return auth.Lock(a)
	})

	s.route("POST", "/unlock", false, s.unlock)

	s.route("POST", "/confirm/:object/:id", true, func(c *reqCtx) *cli.Response {
		return vaultedit.Confirm(a, c.param("object"), c.param("id"),
			vaultedit.ConfirmOptions{OrganizationID: queryOption(c.query, "organizationid", "organizationId")})
	})

	s.route("POST", "/restore/:object/:id", true, func(c *reqCtx) *cli.Response {
		return vaultedit.Restore(a, c.param("object"), c.param("id"))
	})

	s.route("POST", "/move/:id/:organizationId", true, func(c *reqCtx) *cli.Response {
		return vaultedit.Move(a, c.param("id"), c.param("organizationId"), c.body)
	})

	s.routeWith("POST", "/attachment", true, true, func(c *reqCtx) *cli.Response {
		if c.file == nil {
			// ctx.request.file.buffer throws when no file was uploaded
			return errInternal
		}
		return vaultedit.Create(a, "attachment", c.body, vaultedit.CreateOptions{
			ItemID:         queryOption(c.query, "itemid", "itemId"),
			OrganizationID: queryOption(c.query, "organizationid", "organizationId"),
			Upload:         &vaultedit.FileUpload{Data: c.file.data, FileName: c.file.originalName},
		})
	})

	s.route("POST", "/send/:id/remove-password", true, func(c *reqCtx) *cli.Response {
		return send.RemovePassword(a, c.param("id"))
	})

	s.route("POST", "/object/:object", true, func(c *reqCtx) *cli.Response {
		object := c.param("object")
		if object == "send" {
			return send.CreateObject(a, c.body, sendCreateOptions(c.query))
		}
		itemID := queryOption(c.query, "itemid", "itemId")
		if strings.ToLower(object) == "attachment" {
			// Upstream calls createCommand.run without additionalData, so an attachment with an
			// item id throws reading additionalData.fileBuffer. Never read --file from disk here.
			if itemID == "" {
				return cli.BadRequest("`itemid` option is required.")
			}
			return errInternal
		}
		return vaultedit.Create(a, object, c.body, vaultedit.CreateOptions{
			ItemID:         itemID,
			OrganizationID: queryOption(c.query, "organizationid", "organizationId"),
		})
	})

	s.route("PUT", "/object/:object/:id", true, func(c *reqCtx) *cli.Response {
		if c.param("object") == "send" {
			return send.EditObject(a, withID(c.body, c.param("id")), send.EditOptions{
				ItemID:   queryOption(c.query, "itemId", "itemid"),
				Password: c.query.Get("password"),
				Emails:   queryList(c.query, "emails"),
			})
		}
		return vaultedit.Edit(a, c.param("object"), c.param("id"), c.body,
			vaultedit.EditOptions{OrganizationID: queryOption(c.query, "organizationid", "organizationId")})
	})

	s.route("GET", "/object/:object/:id", true, func(c *reqCtx) *cli.Response {
		if c.param("object") == "send" {
			return send.Get(a, c.param("id"), send.GetOptions{})
		}
		return vaultcmd.Get(a, c.param("object"), c.param("id"), vaultcmd.GetOptionsFromQuery(c.query))
	})

	s.route("DELETE", "/object/:object/:id", true, func(c *reqCtx) *cli.Response {
		if c.param("object") == "send" {
			return send.Delete(a, c.param("id"))
		}
		return vaultedit.Delete(a, c.param("object"), c.param("id"), vaultedit.DeleteOptions{
			ItemID:         queryOption(c.query, "itemid", "itemId"),
			OrganizationID: queryOption(c.query, "organizationid", "organizationId"),
			Permanent:      boolOption(c.query, "permanent"),
		})
	})

	s.route("POST", "/archive/:object/:id", true, func(c *reqCtx) *cli.Response {
		return vaultedit.Archive(a, c.param("object"), c.param("id"))
	})
}

// unlock is the POST /unlock route. The password comes from the JSON body; the password file
// and environment options are dropped so the location of a password can't be guessed through
// serve.
func (s *Server) unlock(c *reqCtx) *cli.Response {
	password := ""
	if obj := bodyObject(c.body); obj != nil {
		if raw, ok := obj["password"]; ok && string(raw) != "null" {
			var str string
			if json.Unmarshal(raw, &str) == nil {
				password = str
			} else {
				password = string(raw)
			}
		}
	}

	// UnlockCommand replaces BW_SESSION before checking the password. Upstream keeps the user
	// key in memory, so a failed unlock does not lock an unlocked vault; here the user key is
	// protected by BW_SESSION, so the previous session is restored unless a new user key was
	// stored.
	prevSession, hadSession := os.LookupEnv("BW_SESSION")
	prevProtected := s.protectedUserKey()
	resp := auth.Unlock(s.a, password, auth.UnlockOptions{})
	if !resp.Success && s.protectedUserKey() == prevProtected {
		if hadSession {
			os.Setenv("BW_SESSION", prevSession)
		} else {
			os.Unsetenv("BW_SESSION")
		}
	}
	return resp
}

func (s *Server) protectedUserKey() string {
	if acct := s.a.ActiveAccount(); acct != nil {
		return acct.ProtectedUserKey
	}
	return ""
}

// errorIfLocked mirrors OssServeConfigurator.errorIfLocked. Upstream's authed check is
// `userId != null || hasAccessToken(userId)`, i.e. an active account is enough.
func (s *Server) errorIfLocked() *cli.Response {
	if s.a.ActiveAccount() == nil {
		return cli.Error("You are not logged in.")
	}
	if s.a.IsUnlocked() {
		return nil
	}
	return cli.Error("Vault is locked.")
}

// processResponse mirrors OssServeConfigurator.processResponse followed by koa-json
// ({pretty: false, param: "pretty"}).
func processResponse(w http.ResponseWriter, r *http.Request, resp *cli.Response) {
	if resp == nil {
		resp = cli.Success(nil)
	}
	status := http.StatusOK
	if !resp.Success {
		status = http.StatusBadRequest
	}
	if f, ok := resp.Data.(*cli.FileResponse); ok {
		w.Header().Set("Content-Disposition", contentDisposition(f.FileName))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", itoa(len(f.Data)))
		w.WriteHeader(status)
		_, _ = w.Write(f.Data)
		return
	}
	body := cli.MarshalJSON(resp, r.URL.Query().Has("pretty"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// ---------- option helpers (the commands' Options classes applied to ctx.request.query) ----------

// queryOption mirrors `passedOptions?.a || passedOptions?.b` (empty strings fall through).
func queryOption(q url.Values, names ...string) string {
	for _, n := range names {
		if v := q.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// boolOption mirrors CliUtils.convertBooleanOption for a query parameter.
func boolOption(q url.Values, name string) bool {
	if !q.Has(name) {
		return false
	}
	v := q.Get(name)
	return v == "" || strings.ToLower(v) == "true"
}

func optionalString(q url.Values, name string) *string {
	if !q.Has(name) {
		return nil
	}
	v := q.Get(name)
	return &v
}

// queryList returns all values of a repeated parameter (nil when absent).
func queryList(q url.Values, name string) []string {
	if !q.Has(name) {
		return nil
	}
	return q[name]
}

// sendCreateOptions mirrors the Options class of the send create command.
func sendCreateOptions(q url.Values) send.CreateOptions {
	return send.CreateOptions{
		File:           q.Get("file"),
		Text:           optionalString(q, "text"),
		Hidden:         boolOption(q, "hidden"),
		MaxAccessCount: optionalString(q, "maxAccessCount"),
		Password:       optionalString(q, "password"),
		Emails:         queryList(q, "emails"),
	}
}

// withID mirrors `ctx.request.body.id = ctx.params.id`.
func withID(body json.RawMessage, id string) json.RawMessage {
	obj := bodyObject(body)
	if obj == nil {
		return body
	}
	obj["id"], _ = json.Marshal(id)
	b, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return b
}

// ---------- Content-Disposition (jshttp/content-disposition, as used by koa's attachment()) ----------

func contentDisposition(fileName string) string {
	name := path.Base(fileName)
	if fileName == "" {
		name = ""
	}
	isQuoted := name != ""
	for _, r := range name {
		if !(r >= 0x20 && r <= 0x7e || r >= 0x80 && r <= 0xff) {
			isQuoted = false
			break
		}
	}
	var fb strings.Builder
	for _, r := range name {
		if r >= 0x20 && r <= 0x7e || r >= 0xa0 && r <= 0xff {
			fb.WriteRune(r)
		} else {
			fb.WriteByte('?')
		}
	}
	fallback := fb.String()
	hasFallback := fallback != name
	out := "attachment"
	if isQuoted || hasFallback {
		v := name
		if hasFallback {
			v = fallback
		}
		out += `; filename="` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
	}
	if hasFallback || !isQuoted || hexEscapeRe.MatchString(name) {
		out += "; filename*=UTF-8''" + encodeRFC5987(name)
	}
	return out
}

var hexEscapeRe = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

func encodeRFC5987(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '!' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
