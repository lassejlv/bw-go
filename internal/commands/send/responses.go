package send

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"time"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/sendcore"
)

// SendTextResponse mirrors apps/cli/src/tools/send/models/send-text.response.ts.
type SendTextResponse struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

// SendFileResponse mirrors send-file.response.ts.
type SendFileResponse struct {
	ID       *string         `json:"id"`
	Size     json.RawMessage `json:"size"`
	SizeName *string         `json:"sizeName"`
	FileName *string         `json:"fileName"`
}

// SendResponse mirrors send.response.ts (property order of its constructor).
type SendResponse struct {
	Object         string            `json:"object"`
	ID             string            `json:"id"`
	AccessID       string            `json:"accessId"`
	AccessURL      string            `json:"accessUrl"`
	Name           *string           `json:"name"`
	Notes          *string           `json:"notes"`
	Key            string            `json:"key"`
	Type           int               `json:"type"`
	MaxAccessCount *int              `json:"maxAccessCount"`
	AccessCount    int               `json:"accessCount"`
	RevisionDate   *cli.Date         `json:"revisionDate"`
	DeletionDate   *cli.Date         `json:"deletionDate"`
	ExpirationDate *cli.Date         `json:"expirationDate"`
	PasswordSet    bool              `json:"passwordSet"`
	Emails         []string          `json:"emails"`
	Disabled       bool              `json:"disabled"`
	HideEmail      bool              `json:"hideEmail"`
	AuthType       *int              `json:"authType,omitempty"`
	Text           *SendTextResponse `json:"text,omitempty"`
	File           *SendFileResponse `json:"file,omitempty"`
}

func date(t *time.Time) *cli.Date {
	if t == nil {
		return nil
	}
	return cli.NewDate(*t)
}

func textResponse(t *sendcore.TextView) *SendTextResponse {
	return &SendTextResponse{Text: t.Text, Hidden: t.Hidden}
}

func fileResponse(f *sendcore.FileView) *SendFileResponse {
	return &SendFileResponse{ID: f.ID, Size: f.Size, SizeName: f.SizeName, FileName: f.FileName}
}

// NewSendResponse builds the CLI representation of a decrypted Send. sendURL is
// api.Urls.SendURL().
func NewSendResponse(v *sendcore.View, sendURL string) *SendResponse {
	r := &SendResponse{
		Object:         "send",
		ID:             v.ID,
		AccessID:       v.AccessID,
		AccessURL:      sendcore.AccessURL(sendURL, v.AccessID, v.Key),
		Name:           v.Name,
		Notes:          v.Notes,
		Key:            base64.StdEncoding.EncodeToString(v.Key),
		Type:           v.Type,
		MaxAccessCount: v.MaxAccessCount,
		AccessCount:    v.AccessCount,
		RevisionDate:   date(v.RevisionDate),
		DeletionDate:   date(v.DeletionDate),
		ExpirationDate: date(v.ExpirationDate),
		PasswordSet:    v.Password != nil,
		Emails:         v.Emails,
		AuthType:       v.AuthType,
	}
	if r.Emails == nil {
		r.Emails = []string{}
	}
	if v.Disabled != nil {
		r.Disabled = *v.Disabled
	}
	if v.HideEmail != nil {
		r.HideEmail = *v.HideEmail
	}
	if v.Type == sendcore.TypeText && v.Text != nil {
		r.Text = textResponse(v.Text)
	}
	if v.Type == sendcore.TypeFile && v.File != nil {
		r.File = fileResponse(v.File)
	}
	return r
}

// SendAccessResponse mirrors send-access.response.ts.
type SendAccessResponse struct {
	Object string            `json:"object"`
	ID     string            `json:"id"`
	Name   *string           `json:"name"`
	Type   int               `json:"type"`
	Text   *SendTextResponse `json:"text,omitempty"`
	File   *SendFileResponse `json:"file,omitempty"`
}

// NewSendAccessResponse builds the CLI representation of a received Send.
func NewSendAccessResponse(v *sendcore.AccessView) *SendAccessResponse {
	r := &SendAccessResponse{Object: "send-access", ID: v.ID, Name: v.Name, Type: v.Type}
	if v.Type == sendcore.TypeText && v.Text != nil {
		r.Text = textResponse(v.Text)
	}
	if v.Type == sendcore.TypeFile && v.File != nil {
		r.File = fileResponse(v.File)
	}
	return r
}

// ---------- templates ----------

// SendTextTemplate is SendTextResponse.template().
type SendTextTemplate struct {
	Text   string `json:"text"`
	Hidden bool   `json:"hidden"`
}

// SendFileTemplate is SendFileResponse.template(): only fileName is set.
type SendFileTemplate struct {
	FileName string `json:"fileName"`
}

// SendTemplate is SendResponse.template(). Notes and Emails are omitted when nil, which only
// happens for the request built by the `bw send` shortcut (undefined in upstream).
type SendTemplate struct {
	Object         string            `json:"object"`
	Name           string            `json:"name"`
	Notes          *string           `json:"notes,omitempty"`
	Type           int               `json:"type"`
	Text           *SendTextTemplate `json:"text"`
	File           *SendFileTemplate `json:"file"`
	MaxAccessCount *int              `json:"maxAccessCount"`
	DeletionDate   *cli.Date         `json:"deletionDate"`
	ExpirationDate *cli.Date         `json:"expirationDate"`
	Password       *string           `json:"password"`
	Emails         json.RawMessage   `json:"emails,omitempty"`
	Disabled       bool              `json:"disabled"`
	HideEmail      bool              `json:"hideEmail"`
}

// NewSendTemplate mirrors SendResponse.template(sendType, deleteInDays). A NaN deleteInDays
// yields a null deletion date like JSON.stringify(Invalid Date).
func NewSendTemplate(sendType int, deleteInDays float64) *SendTemplate {
	notes := "Some notes about this send."
	t := &SendTemplate{
		Object: "send",
		Name:   "Send name",
		Notes:  &notes,
		Type:   sendcore.TypeText,
		Emails: json.RawMessage("null"),
	}
	if sendType == sendcore.TypeFile {
		t.Type = sendcore.TypeFile
		t.File = &SendFileTemplate{FileName: "file attachment location"}
	} else if sendType == sendcore.TypeText {
		t.Text = &SendTextTemplate{Text: "Text contained in the send.", Hidden: false}
	}
	ms := float64(time.Now().UnixMilli()) + deleteInDays*86400000
	if !math.IsNaN(ms) && math.Abs(ms) <= 8.64e15 { // valid JavaScript Date range
		t.DeletionDate = cli.NewDate(time.UnixMilli(int64(ms)))
	}
	return t
}
