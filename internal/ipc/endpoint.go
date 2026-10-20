package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// HostID is the SDK HostId: "Own" or {"Id": n}.
type HostID struct {
	Own bool
	ID  int32
}

// MarshalJSON encodes like serde.
func (h HostID) MarshalJSON() ([]byte, error) {
	if h.Own {
		return []byte(`"Own"`), nil
	}
	return json.Marshal(map[string]int32{"Id": h.ID})
}

// UnmarshalJSON decodes "Own" or {"Id": n}.
func (h *HostID) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if s != "Own" {
			return fmt.Errorf("unknown host id %q", s)
		}
		*h = HostID{Own: true}
		return nil
	}
	var m struct {
		ID *int32 `json:"Id"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.ID == nil {
		return errors.New("invalid host id")
	}
	*h = HostID{ID: *m.ID}
	return nil
}

// Endpoint kinds (variants of the SDK Endpoint/Source enums).
const (
	KindWeb               = "Web"
	KindBrowserForeground = "BrowserForeground"
	KindBrowserBackground = "BrowserBackground"
	KindCli               = "Cli"
	KindDesktopRenderer   = "DesktopRenderer"
	KindDesktopMain       = "DesktopMain"
)

// Endpoint is the SDK Endpoint (and, with Origin, Source) enum, JSON encoded like serde's
// externally tagged representation: "DesktopRenderer", {"Cli":{"id":"Own"}},
// {"Web":{"tab_id":1,"document_id":"x"}}, {"BrowserForeground":{"id":1}}.
type Endpoint struct {
	Kind       string
	TabID      int32  // Web
	DocumentID string // Web
	Origin     string // Web sources only
	ID         int32  // BrowserForeground
	Host       HostID // BrowserBackground, Cli
}

// Well-known singleton endpoints.
var (
	DesktopRenderer = Endpoint{Kind: KindDesktopRenderer}
	DesktopMain     = Endpoint{Kind: KindDesktopMain}
)

// ToEndpoint drops source-only metadata (Source::to_endpoint).
func (e Endpoint) ToEndpoint() Endpoint {
	e.Origin = ""
	return e
}

// Key is a comparable identity of the endpoint, used to key sessions.
func (e Endpoint) Key() string {
	b, _ := e.ToEndpoint().MarshalJSON()
	return string(b)
}

func (e Endpoint) String() string { return e.Key() }

// MarshalJSON encodes like serde.
func (e Endpoint) MarshalJSON() ([]byte, error) {
	switch e.Kind {
	case KindDesktopRenderer, KindDesktopMain:
		return json.Marshal(e.Kind)
	case KindWeb:
		var buf bytes.Buffer
		buf.WriteString(`{"Web":{"tab_id":`)
		fmt.Fprint(&buf, e.TabID)
		buf.WriteString(`,"document_id":`)
		d, _ := json.Marshal(e.DocumentID)
		buf.Write(d)
		if e.Origin != "" {
			buf.WriteString(`,"origin":`)
			o, _ := json.Marshal(e.Origin)
			buf.Write(o)
		}
		buf.WriteString("}}")
		return buf.Bytes(), nil
	case KindBrowserForeground:
		return []byte(fmt.Sprintf(`{"BrowserForeground":{"id":%d}}`, e.ID)), nil
	case KindBrowserBackground, KindCli:
		h, _ := e.Host.MarshalJSON()
		return []byte(`{"` + e.Kind + `":{"id":` + string(h) + `}}`), nil
	}
	return nil, fmt.Errorf("unknown endpoint kind %q", e.Kind)
}

// UnmarshalJSON decodes a serde Endpoint or Source.
func (e *Endpoint) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		switch s {
		case KindDesktopRenderer, KindDesktopMain:
			*e = Endpoint{Kind: s}
			return nil
		}
		return fmt.Errorf("unknown endpoint %q", s)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || len(m) != 1 {
		return errors.New("invalid endpoint")
	}
	for kind, body := range m {
		switch kind {
		case KindWeb:
			var w struct {
				TabID      int32  `json:"tab_id"`
				DocumentID string `json:"document_id"`
				Origin     string `json:"origin"`
			}
			if err := json.Unmarshal(body, &w); err != nil {
				return err
			}
			*e = Endpoint{Kind: kind, TabID: w.TabID, DocumentID: w.DocumentID, Origin: w.Origin}
		case KindBrowserForeground:
			var f struct {
				ID int32 `json:"id"`
			}
			if err := json.Unmarshal(body, &f); err != nil {
				return err
			}
			*e = Endpoint{Kind: kind, ID: f.ID}
		case KindBrowserBackground, KindCli:
			var h struct {
				ID HostID `json:"id"`
			}
			if err := json.Unmarshal(body, &h); err != nil {
				return err
			}
			*e = Endpoint{Kind: kind, Host: h.ID}
		case KindDesktopRenderer, KindDesktopMain:
			*e = Endpoint{Kind: kind}
		default:
			return fmt.Errorf("unknown endpoint %q", kind)
		}
	}
	return nil
}

// OutgoingMessage is the SDK OutgoingMessage.
type OutgoingMessage struct {
	Payload     []byte
	Destination Endpoint
	Topic       *string
}

// IncomingMessage is the SDK IncomingMessage.
type IncomingMessage struct {
	Payload     []byte
	Destination Endpoint
	Source      Endpoint
	Topic       *string
}

// SerializedMessage is SerializedOutgoingMessage: the JSON form of a message inside the
// native-messaging envelope, with the payload as an array of numbers.
type SerializedMessage struct {
	Destination Endpoint `json:"destination"`
	Payload     byteList `json:"payload"`
	Topic       *string  `json:"topic,omitempty"`
}

// byteList encodes bytes as a JSON array of numbers ([...message.payload] in TypeScript).
type byteList []byte

// MarshalJSON writes a number array.
func (b byteList) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 0, len(b)*4+2)
	buf = append(buf, '[')
	for i, v := range b {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = fmt.Appendf(buf, "%d", v)
	}
	return append(buf, ']'), nil
}

// UnmarshalJSON reads a number array.
func (b *byteList) UnmarshalJSON(data []byte) error {
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil {
		return err
	}
	out := make([]byte, len(nums))
	for i, n := range nums {
		if n < 0 || n > 255 {
			return errors.New("payload byte out of range")
		}
		out[i] = byte(n)
	}
	*b = out
	return nil
}

// Envelope types of the desktop native-messaging channel (libs/common/src/platform/ipc).
const (
	IpcMessageType          = "bitwarden-ipc-message"
	ForwardedIpcMessageType = "forwarded-bitwarden-ipc-message"
)

// Envelope is IpcMessage / ForwardedIpcMessage.
type Envelope struct {
	Type           string            `json:"type"`
	Message        SerializedMessage `json:"message"`
	OriginalSource *Endpoint         `json:"originalSource,omitempty"`
}

// EncodeOutgoing builds the IpcMessage JSON for an outgoing message.
func EncodeOutgoing(m OutgoingMessage) ([]byte, error) {
	return json.Marshal(Envelope{
		Type:    IpcMessageType,
		Message: SerializedMessage{Destination: m.Destination, Payload: m.Payload, Topic: m.Topic},
	})
}

// decodeIncoming parses a message from the desktop app. ok is false for messages that are not IPC
// messages (they are ignored); connected reports the proxy's {"command":"connected"} message.
func decodeIncoming(b []byte) (msg IncomingMessage, ok, connected bool, err error) {
	var probe struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return msg, false, false, err
	}
	if probe.Command == "connected" {
		return msg, false, true, nil
	}
	if probe.Type != IpcMessageType && probe.Type != ForwardedIpcMessageType {
		return msg, false, false, nil
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return msg, false, false, err
	}
	source := DesktopMain
	if probe.Type == ForwardedIpcMessageType {
		if env.OriginalSource == nil {
			return msg, false, false, errors.New("forwarded message without original source")
		}
		source = *env.OriginalSource
	}
	return IncomingMessage{
		Payload:     env.Message.Payload,
		Destination: env.Message.Destination,
		Source:      source,
		Topic:       env.Message.Topic,
	}, true, false, nil
}
