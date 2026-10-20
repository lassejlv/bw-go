package send

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/sendcore"
)

var getenv = os.Getenv

// stdout is where --text / receive write raw text content.
var stdout io.Writer = os.Stdout

func sendURL(a *app.App) string { return a.Urls().SendURL() }

// ---------- list ----------

// List returns all Sends owned by the user, optionally filtered by search (SendListCommand).
func List(a *app.App, search string) *cli.Response {
	userKey, err := a.UserKey()
	if err != nil {
		return cli.Error(err)
	}
	sends, err := sendcore.AllDecrypted(a, userKey)
	if err != nil {
		return cli.Error(err)
	}
	if strings.TrimSpace(search) != "" {
		sends = sendcore.Search(sends, search)
	}
	url := sendURL(a)
	out := make([]*SendResponse, 0, len(sends))
	for _, s := range sends {
		out = append(out, NewSendResponse(s, url))
	}
	return cli.Success(cli.NewList(out))
}

// ---------- template ----------

// Template returns a Send json template (SendTemplateCommand). Valid objects: send.text, text,
// send.file, file.
func Template(object string) *cli.Response {
	switch object {
	case "send.text", "text":
		return cli.Success(cli.NewTemplate(NewSendTemplate(sendcore.TypeText, 7)))
	case "send.file", "file":
		return cli.Success(cli.NewTemplate(NewSendTemplate(sendcore.TypeFile, 7)))
	default:
		return cli.BadRequest("Unknown template object.")
	}
}

// ---------- get ----------

// GetOptions are the options of `send get`.
type GetOptions struct {
	// Text writes only the text content of a Send to stdout.
	Text bool
	// Output is accepted for parity with upstream (which never uses it).
	Output string
}

// getSendView resolves an id or search term to one or more decrypted Sends.
func getSendView(a *app.App, id string) ([]*sendcore.View, bool, error) {
	userKey, err := a.UserKey()
	if err != nil {
		return nil, false, err
	}
	if IsGUID(id) {
		d, err := sendcore.FromState(a, id)
		if err != nil {
			return nil, false, err
		}
		if d != nil {
			v, err := sendcore.Decrypt(d, userKey)
			if err != nil {
				return nil, false, err
			}
			return []*sendcore.View{v}, true, nil
		}
	} else if strings.TrimSpace(id) != "" {
		sends, err := sendcore.AllDecrypted(a, userKey)
		if err != nil {
			return nil, false, err
		}
		sends = sendcore.Search(sends, id)
		if len(sends) > 1 {
			return sends, false, nil
		} else if len(sends) > 0 {
			return sends, true, nil
		}
	}
	return nil, false, nil
}

// Get returns a Send owned by the user by id or search term (SendGetCommand).
func Get(a *app.App, id string, opts GetOptions) *cli.Response {
	serve := isServe()
	if serve && !IsGUID(id) {
		return cli.BadRequest("`" + id + "` is not a GUID.")
	}
	sends, single, err := getSendView(a, id)
	if err != nil {
		return cli.Error(err)
	}
	if sends == nil {
		return cli.NotFound()
	}
	url := sendURL(a)
	selector := func(s *sendcore.View) *cli.Response { return cli.Success(NewSendResponse(s, url)) }
	if !serve && opts.Text {
		selector = func(s *sendcore.View) *cli.Response {
			// Write to stdout so only the text string is output.
			if s.Text != nil && s.Text.Text != nil {
				io.WriteString(stdout, *s.Text.Text)
			}
			return cli.Success(nil)
		}
	}
	if single {
		return selector(sends[0])
	}
	ids := make([]string, len(sends))
	for i, s := range sends {
		ids[i] = s.ID
	}
	return cli.MultipleResults(ids)
}

// ---------- request parsing ----------

type textInput struct {
	Text   *string `json:"text"`
	Hidden *bool   `json:"hidden"`
}

type fileInput struct {
	ID       *string         `json:"id"`
	Size     json.RawMessage `json:"size"`
	SizeName *string         `json:"sizeName"`
	FileName *string         `json:"fileName"`
}

// sendInput is a SendResponse as parsed from the user's request JSON (SendResponse.fromJson).
type sendInput struct {
	ID             *string         `json:"id"`
	AccessID       *string         `json:"accessId"`
	Name           *string         `json:"name"`
	Notes          *string         `json:"notes"`
	Key            *string         `json:"key"`
	Type           *int            `json:"type"`
	Text           *textInput      `json:"text"`
	File           *fileInput      `json:"file"`
	MaxAccessCount *int            `json:"maxAccessCount"`
	AccessCount    *int            `json:"accessCount"`
	DeletionDate   json.RawMessage `json:"deletionDate"`
	ExpirationDate json.RawMessage `json:"expirationDate"`
	Password       *string         `json:"password"`
	Emails         []string        `json:"emails"`
	Disabled       *bool           `json:"disabled"`
	HideEmail      *bool           `json:"hideEmail"`
	AuthType       *int            `json:"authType"`
}

func parseRequest(raw []byte) (*sendInput, error) {
	if strings.TrimSpace(string(raw)) == "null" {
		return nil, errors.New("Null request")
	}
	var req sendInput
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// readRequest decodes the base64 encoded request, reading stdin when it is empty and not
// running under `serve`.
func readRequest(encoded string) (*sendInput, *cli.Response) {
	if !isServe() && encoded == "" {
		s, err := cli.ReadStdin()
		if err != nil {
			return nil, cli.Error(err)
		}
		encoded = s
	}
	if encoded == "" {
		return nil, cli.BadRequest("`requestJson` was not provided.")
	}
	req, err := parseRequest(decodeB64Lenient(encoded))
	if err != nil {
		return nil, cli.BadRequest("Error parsing the encoded request data.")
	}
	return req, nil
}

// toView mirrors SendResponse.toView(req, view): it overwrites view with the request values.
func (req *sendInput) toView(view *sendcore.View) (*sendcore.View, error) {
	if view == nil {
		view = &sendcore.View{}
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	view.ID = str(req.ID)
	view.AccessID = str(req.AccessID)
	view.Name = req.Name
	view.Notes = req.Notes
	view.Key = nil
	if req.Key != nil {
		view.Key = decodeB64Lenient(*req.Key)
	}
	view.Type = -1
	if req.Type != nil {
		view.Type = *req.Type
	}
	view.File = nil
	if req.File != nil {
		view.File = &sendcore.FileView{ID: req.File.ID, Size: req.File.Size, SizeName: req.File.SizeName, FileName: req.File.FileName}
	}
	view.Text = nil
	if req.Text != nil {
		view.Text = &sendcore.TextView{Text: req.Text.Text, Hidden: req.Text.Hidden != nil && *req.Text.Hidden}
	}
	view.MaxAccessCount = req.MaxAccessCount
	if req.AccessCount != nil {
		view.AccessCount = *req.AccessCount
	}
	var dates [2]*time.Time
	for i, raw := range []json.RawMessage{req.DeletionDate, req.ExpirationDate} {
		t, _, valid := jsDate(raw)
		if !valid {
			return nil, errors.New("RangeError: Invalid time value")
		}
		dates[i] = t
	}
	view.DeletionDate, view.ExpirationDate = dates[0], dates[1]
	view.Password = req.Password
	view.Emails = req.Emails
	if view.Emails == nil {
		view.Emails = []string{}
	}
	view.Disabled = req.Disabled
	view.HideEmail = req.HideEmail
	view.AuthType = req.AuthType
	return view, nil
}

func authTypeFor(emails []string, password *string) (int, *cli.Response) {
	hasEmails := len(emails) > 0
	hasPassword := password != nil && strings.TrimSpace(*password) != ""
	if hasEmails && hasPassword {
		return 0, cli.BadRequest("--password and --emails are mutually exclusive.")
	}
	switch {
	case hasEmails:
		return sendcore.AuthEmail, nil
	case hasPassword:
		return sendcore.AuthPassword, nil
	default:
		return sendcore.AuthNone, nil
	}
}

// ---------- create ----------

// CreateOptions are the command options of `send create` (and the `bw send` shortcut).
type CreateOptions struct {
	File string  // --file <path>
	Text *string // --text <text>
	// Hidden is the --hidden flag.
	Hidden bool
	// MaxAccessCount is the raw -a/--maxAccessCount value (nil when not given).
	MaxAccessCount *string
	Password       *string
	// Emails is nil when --emails was not given.
	Emails     []string
	FullObject bool
}

// Create creates a Send from a base64 encoded JSON request, reading stdin when empty
// (SendCreateCommand.run).
func Create(a *app.App, encodedJSON string, opts CreateOptions) *cli.Response {
	req, r := readRequest(encodedJSON)
	if r != nil {
		return r
	}
	return createFromInput(a, req, opts)
}

// CreateObject creates a Send from a plain JSON request object (used by `serve`).
func CreateObject(a *app.App, rawJSON []byte, opts CreateOptions) *cli.Response {
	if len(rawJSON) == 0 {
		return cli.BadRequest("`requestJson` was not provided.")
	}
	req, err := parseRequest(rawJSON)
	if err != nil {
		return cli.BadRequest("Error parsing the encoded request data.")
	}
	return createFromInput(a, req, opts)
}

func createFromInput(a *app.App, req *sendInput, opts CreateOptions) *cli.Response {
	del, _, delValid := jsDate(req.DeletionDate)
	if del == nil || !delValid || !del.After(time.Now()) {
		return cli.BadRequest("Must specify a valid deletion date after the current time")
	}
	if _, _, valid := jsDate(req.ExpirationDate); !valid {
		return cli.BadRequest("Unable to parse expirationDate: Invalid Date")
	}

	var filePath *string
	if req.File != nil && req.File.FileName != nil {
		filePath = req.File.FileName
	} else if opts.File != "" {
		filePath = &opts.File
	}
	text := opts.Text
	hidden := opts.Hidden
	if req.Text != nil {
		if req.Text.Text != nil {
			text = req.Text.Text
		}
		if req.Text.Hidden != nil {
			hidden = *req.Text.Hidden
		}
	}
	password := req.Password
	if password == nil {
		password = opts.Password
	}
	emails := req.Emails
	if emails == nil {
		emails = opts.Emails
	}
	maxAccessCount := req.MaxAccessCount
	if maxAccessCount == nil && opts.MaxAccessCount != nil {
		maxAccessCount = parseIntJS(*opts.MaxAccessCount)
	}

	authType, r := authTypeFor(emails, password)
	if r != nil {
		return r
	}
	req.Key = nil
	req.MaxAccessCount = maxAccessCount
	req.Emails = emails
	req.AuthType = &authType

	// TODO: SendControls organization policy enforcement (enforceSendPolicy) is gated behind
	// the pm-31885-send-controls feature flag (default off) and is not ported.

	if req.Type == nil {
		return cli.BadRequest("Unknown Send type undefined. Valid types are: file, text")
	}
	switch *req.Type {
	case sendcore.TypeFile:
		if isServe() {
			return cli.Error("Creating a file-based Send is unsupported through the `serve` command at this time.")
		}
		if !sendcore.HasPremium(a) {
			return cli.Error("Premium status is required to use this feature.")
		}
		if filePath == nil {
			return cli.BadRequest("Must specify a file to Send either with the --file option or in the request JSON.")
		}
		if req.File == nil {
			req.File = &fileInput{}
		}
		base := filepath.Base(*filePath)
		req.File.FileName = &base
	case sendcore.TypeText:
		if text == nil {
			return cli.BadRequest("Must specify text content to Send either with the --text option or in the request JSON.")
		}
		req.Text = &textInput{Text: text, Hidden: &hidden}
	case sendcore.TypeItem:
		return cli.BadRequest("Item type Send functionality not yet available")
	default:
		return cli.BadRequest("Unknown Send type undefined. Valid types are: file, text")
	}

	var fileData []byte
	if *req.Type == sendcore.TypeFile {
		b, err := os.ReadFile(*filePath)
		if err != nil {
			return cli.Error(err)
		}
		fileData = append([]byte{}, b...) // non-nil even for an empty file
	}
	view, err := req.toView(nil)
	if err != nil {
		return cli.Error(err)
	}
	userKey, err := a.UserKey()
	if err != nil {
		return cli.Error(err)
	}
	request, encFile, err := sendcore.Encrypt(view, fileData, password, userKey)
	if err != nil {
		return cli.Error(err)
	}
	id, err := sendcore.Save(a, view.ID, request, encFile)
	if err != nil {
		return cli.Error(err)
	}
	return respondFromState(a, id)
}

func respondFromState(a *app.App, id string) *cli.Response {
	uk, err := a.UserKey()
	if err != nil {
		return cli.Error(err)
	}
	d, err := sendcore.FromState(a, id)
	if err != nil {
		return cli.Error(err)
	}
	if d == nil {
		return cli.NotFound()
	}
	v, err := sendcore.Decrypt(d, uk)
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(NewSendResponse(v, sendURL(a)))
}

// ---------- edit ----------

// EditOptions are the options of `send edit`.
type EditOptions struct {
	ItemID   string
	Password string
	// Emails is nil when --emails was not given.
	Emails []string
}

// Edit updates a Send from a base64 encoded JSON request, reading stdin when empty
// (SendEditCommand.run).
func Edit(a *app.App, encodedJSON string, opts EditOptions) *cli.Response {
	req, r := readRequest(encodedJSON)
	if r != nil {
		return r
	}
	return editFromInput(a, req, opts)
}

// EditObject updates a Send from a plain JSON request object (used by `serve`).
func EditObject(a *app.App, rawJSON []byte, opts EditOptions) *cli.Response {
	if len(rawJSON) == 0 {
		return cli.BadRequest("`requestJson` was not provided.")
	}
	req, err := parseRequest(rawJSON)
	if err != nil {
		return cli.BadRequest("Error parsing the encoded request data.")
	}
	return editFromInput(a, req, opts)
}

func editFromInput(a *app.App, req *sendInput, opts EditOptions) *cli.Response {
	if opts.ItemID != "" {
		id := opts.ItemID
		req.ID = &id
	}
	if opts.Emails != nil {
		req.Emails = opts.Emails
	}
	if opts.Password != "" {
		p := opts.Password
		req.Password = &p
	}
	if req.Password != nil && *req.Password == "" {
		req.Password = nil
	}
	authType, r := authTypeFor(req.Emails, req.Password)
	if r != nil {
		return r
	}
	req.AuthType = &authType

	if req.ID == nil || *req.ID == "" {
		return cli.Error("`itemid` was not provided.")
	}
	id := strings.ToLower(*req.ID)
	req.ID = &id
	send, err := sendcore.FromState(a, id)
	if err != nil {
		return cli.Error(err)
	}
	if send == nil {
		return cli.NotFound()
	}
	if req.Type == nil || send.Type != *req.Type {
		return cli.BadRequest("Cannot change a Send's type")
	}
	if send.Type == sendcore.TypeFile && !sendcore.HasPremium(a) {
		return cli.Error("Premium status is required to use this feature.")
	}
	userKey, err := a.UserKey()
	if err != nil {
		return cli.Error(err)
	}
	view, err := sendcore.Decrypt(send, userKey)
	if err != nil {
		return cli.Error(err)
	}
	if view, err = req.toView(view); err != nil {
		return cli.Error(err)
	}
	// File contents are immutable after create, so no file data is supplied on an edit.
	request, _, err := sendcore.Encrypt(view, nil, req.Password, userKey)
	if err != nil {
		return cli.Error(err)
	}
	if _, err := sendcore.Save(a, view.ID, request, nil); err != nil {
		return cli.Error(err)
	}
	return Get(a, send.ID, GetOptions{})
}

// ---------- remove-password ----------

// RemovePassword removes the password from a Send (SendRemovePasswordCommand).
func RemovePassword(a *app.App, id string) *cli.Response {
	if err := sendcore.RemovePassword(a, id); err != nil {
		return cli.Error(err)
	}
	return respondFromState(a, id)
}

// ---------- delete ----------

// Delete deletes a Send (SendDeleteCommand).
func Delete(a *app.App, id string) *cli.Response {
	send, err := sendcore.FromState(a, id)
	if err != nil {
		return cli.Error(err)
	}
	if send == nil {
		return cli.NotFound()
	}
	if err := sendcore.DeleteSend(a, id); err != nil {
		return cli.Error(err)
	}
	return cli.Success(nil)
}

// ---------- `bw send <data>` shortcut ----------

// QuickOptions are the options of the `bw send <data>` shortcut.
type QuickOptions struct {
	File         bool   // -f/--file: data is a file path
	DeleteInDays string // -d/--deleteInDays (default "7")
	Hidden       bool
	Name         *string
	Notes        *string
	Emails       []string
}

// MakeSendJSON builds the base64 encoded create request of the `bw send` shortcut
// (SendProgram.makeSendJson). It returns a non-nil response on failure.
func MakeSendJSON(data string, opts QuickOptions) (string, *cli.Response) {
	name := newGUID()
	typ := sendcore.TypeText
	var file *SendFileTemplate
	var text *SendTextTemplate
	if opts.File {
		p, err := filepath.Abs(data)
		if err == nil {
			data = p
		}
		if _, err := os.Stat(data); err != nil {
			return "", cli.BadRequest("data path does not exist")
		}
		file = &SendFileTemplate{FileName: data}
		name = filepath.Base(data)
		typ = sendcore.TypeFile
	} else {
		text = &SendTextTemplate{Text: data, Hidden: opts.Hidden}
	}
	days := opts.DeleteInDays
	t := NewSendTemplate(-1, jsNumber(days))
	if opts.Name != nil {
		name = *opts.Name
	}
	t.Name = name
	t.Notes = opts.Notes
	t.File = file
	t.Text = text
	t.Type = typ
	t.Emails = nil
	if opts.Emails != nil {
		b, _ := json.Marshal(opts.Emails)
		t.Emails = b
	}
	return base64.StdEncoding.EncodeToString([]byte(cli.MarshalJSON(t, false))), nil
}

func newGUID() string { return uuid.NewString() }
