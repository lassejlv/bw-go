// Package cli contains the response model and output handling shared by every command,
// mirroring apps/cli/src/models/response.ts and BaseProgram.processResponse.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/lassejlv/bw-go/internal/api"
)

// Response is the result of a command.
type Response struct {
	Success bool    `json:"success"`
	Message *string `json:"message,omitempty"`
	Data    any     `json:"data,omitempty"`
}

// MessageText returns the message or "".
func (r *Response) MessageText() string {
	if r.Message == nil {
		return ""
	}
	return *r.Message
}

func errorMessage(err any) string {
	switch e := err.(type) {
	case nil:
		return "null"
	case string:
		return e
	case *Response:
		return e.MessageText()
	case *api.ErrorResponse:
		if m := e.SingleMessage(); m != "" {
			return m
		}
		if e.Raw != nil {
			b, _ := json.Marshal(e.Raw)
			return string(b)
		}
		if t := http.StatusText(e.StatusCode); t != "" {
			return t
		}
		return "An unexpected error occurred."
	case error:
		var apiErr *api.ErrorResponse
		if errors.As(e, &apiErr) {
			return errorMessage(apiErr)
		}
		return e.Error()
	default:
		b, _ := json.Marshal(e)
		return string(b)
	}
}

// Error builds a failed response from an error, string or other value.
func Error(err any, data ...any) *Response {
	if r, ok := err.(*Response); ok && !r.Success {
		return r
	}
	m := errorMessage(err)
	r := &Response{Success: false, Message: &m}
	if len(data) > 0 {
		r.Data = data[0]
	}
	return r
}

// Errorf builds a failed response with a formatted message.
func Errorf(format string, args ...any) *Response { return Error(fmt.Sprintf(format, args...)) }

// NotFound is the standard not found error.
func NotFound() *Response { return Error("Not found.") }

// NoEditPermission is the standard edit permission error.
func NoEditPermission() *Response { return Error("You do not have permission to edit this item") }

// BadRequest is an error response.
func BadRequest(msg string) *Response { return Error(msg) }

// MultipleResults reports an ambiguous lookup.
func MultipleResults(ids []string) *Response {
	msg := "More than one result was found. Try getting a specific object by `id` instead. " +
		"The following objects were found:"
	for _, id := range ids {
		msg += "\n" + id
	}
	return Error(msg, ids)
}

// Success builds a successful response.
func Success(data any) *Response { return &Response{Success: true, Data: data} }

// MessageResponse is a human readable message (object "message").
type MessageResponse struct {
	Object  string  `json:"object"`
	Title   *string `json:"title"`
	Message *string `json:"message"`
	Raw     *string `json:"raw,omitempty"`
	NoColor bool    `json:"noColor"`
}

func strPtr(s string) *string { return &s }

// NewMessage creates a message response. Use NewMessageNull for a nil message body.
func NewMessage(title string, message string) *MessageResponse {
	return &MessageResponse{Object: "message", Title: strPtr(title), Message: strPtr(message)}
}

// NewMessageNull creates a message response with a null message.
func NewMessageNull(title string) *MessageResponse {
	return &MessageResponse{Object: "message", Title: strPtr(title)}
}

// SetRaw sets the raw output used with --raw.
func (m *MessageResponse) SetRaw(raw string) *MessageResponse { m.Raw = &raw; return m }

// StringResponse holds a single string (object "string").
type StringResponse struct {
	Object string  `json:"object"`
	Data   *string `json:"data"`
}

// NewString creates a string response.
func NewString(s string) *StringResponse { return &StringResponse{Object: "string", Data: &s} }

// NewNullString creates a string response with null data.
func NewNullString() *StringResponse { return &StringResponse{Object: "string"} }

// ListResponse holds a list (object "list").
type ListResponse struct {
	Object string `json:"object"`
	Data   any    `json:"data"`
}

// NewList creates a list response. data should be a slice.
func NewList(data any) *ListResponse { return &ListResponse{Object: "list", Data: data} }

// TemplateResponse holds a template (object "template").
type TemplateResponse struct {
	Object   string `json:"object"`
	Template any    `json:"template"`
}

// NewTemplate creates a template response.
func NewTemplate(t any) *TemplateResponse { return &TemplateResponse{Object: "template", Template: t} }

// FileResponse carries binary file content (object "file"), used by `serve`.
type FileResponse struct {
	Object   string `json:"object"`
	Data     []byte `json:"-"`
	FileName string `json:"fileName"`
}

// NewFile creates a file response.
func NewFile(data []byte, name string) *FileResponse {
	return &FileResponse{Object: "file", Data: data, FileName: name}
}

// ToJSON marshals like JSON.stringify (no HTML escaping), honouring BW_PRETTY.
func ToJSON(v any) string {
	return MarshalJSON(v, os.Getenv("BW_PRETTY") == "true")
}

// MarshalJSON marshals without HTML escaping, optionally pretty printed with two spaces.
func MarshalJSON(v any, pretty bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return "null"
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}
