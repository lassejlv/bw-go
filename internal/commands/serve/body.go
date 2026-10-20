package serve

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// httpError is an error koa answers with its status and (for 4xx, "exposed") message.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

// koa-bodyparser defaults.
const (
	jsonLimit = 1 << 20   // "1mb"
	formLimit = 56 * 1024 // "56kb"
)

// jsonTypes are koa-bodyparser's default extendTypes.json.
var jsonTypes = []string{
	"application/json", "application/json-patch+json", "application/vnd.api+json",
	"application/csp-report", "application/scim+json",
}

// strictJSONRe is co-body's strict mode check (only objects and arrays are accepted).
var strictJSONRe = regexp.MustCompile(`^[\x20\x09\x0a\x0d]*[\[{]`)

var emptyObject = json.RawMessage(`{}`)

func mediaType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}

// hasBody mirrors type-is's hasBody.
func hasBody(r *http.Request) bool {
	return r.ContentLength != 0 || len(r.TransferEncoding) > 0
}

func readLimited(r *http.Request, limit int64) ([]byte, *httpError) {
	if r.ContentLength > limit {
		return nil, &httpError{http.StatusRequestEntityTooLarge, "request entity too large"}
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, &httpError{http.StatusBadRequest, "request aborted"}
	}
	if int64(len(b)) > limit {
		return nil, &httpError{http.StatusRequestEntityTooLarge, "request entity too large"}
	}
	return b, nil
}

// parseBody mirrors koa-bodyparser with its defaults (json and form enabled, strict JSON): it
// returns ctx.request.body as JSON, `{}` when the request has no parseable body.
func parseBody(r *http.Request) (json.RawMessage, *httpError) {
	if !hasBody(r) {
		return emptyObject, nil
	}
	mt := mediaType(r)
	switch {
	case contains(jsonTypes, mt):
		b, herr := readLimited(r, jsonLimit)
		if herr != nil {
			return nil, herr
		}
		if len(b) == 0 {
			return emptyObject, nil
		}
		if !strictJSONRe.Match(b) {
			return nil, &httpError{http.StatusBadRequest, "invalid JSON, only supports object and array"}
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(b))
		if err := dec.Decode(&v); err != nil {
			return nil, &httpError{http.StatusBadRequest, jsonErrorMessage(err)}
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, &httpError{http.StatusBadRequest, "Unexpected non-whitespace character after JSON"}
		}
		return json.RawMessage(b), nil
	case mt == "application/x-www-form-urlencoded":
		b, herr := readLimited(r, formLimit)
		if herr != nil {
			return nil, herr
		}
		return formToJSON(string(b)), nil
	default:
		return emptyObject, nil
	}
}

func jsonErrorMessage(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return "Unexpected token in JSON at position " + itoa(int(se.Offset))
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return "Unexpected end of JSON input"
	}
	return err.Error()
}

// formToJSON converts an urlencoded body to an object like qs.parse (without qs's bracket
// nesting): repeated keys become arrays.
func formToJSON(s string) json.RawMessage {
	vals, _ := url.ParseQuery(s)
	out := make(map[string]any, len(vals))
	for k, v := range vals {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			out[k] = v
		}
	}
	b, _ := json.Marshal(out)
	return b
}

// bodyObject decodes the body as an object (nil for arrays and other JSON values).
func bodyObject(body json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	return m
}

// uploadedFile is ctx.request.file of @koa/multer (memory storage).
type uploadedFile struct {
	data         []byte
	originalName string
}

// parseMultipartFile mirrors `koaMulter().single("file")`: non-multipart requests pass through
// without a file; a file in any other field, a second file or a malformed form is an error
// koa answers with 500.
func parseMultipartFile(r *http.Request) (*uploadedFile, error) {
	ct := r.Header.Get("Content-Type")
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mt, "multipart/form-data") || !hasBody(r) {
		return nil, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, errors.New("Multipart: Boundary not found")
	}
	mr := multipart.NewReader(r.Body, boundary)
	var file *uploadedFile
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		_, dparams, derr := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if derr != nil {
			_ = part.Close()
			continue
		}
		fileName, isFile := dparams["filename"]
		if !isFile {
			// text fields end up in ctx.request.body, which the attachment route ignores
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		if dparams["name"] != "file" || file != nil {
			_ = part.Close()
			return nil, errors.New("Unexpected field")
		}
		data, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			return nil, err
		}
		if data == nil {
			data = []byte{}
		}
		file = &uploadedFile{data: data, originalName: busboyBasename(fileName)}
	}
	return file, nil
}

// busboyBasename mirrors busboy's basename (preservePath: false): the part after the last "/"
// or "\\"; "." and ".." become "".
func busboyBasename(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		p = p[i+1:]
	}
	if p == "." || p == ".." {
		return ""
	}
	return p
}
