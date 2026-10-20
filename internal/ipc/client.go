// Package ipc is a port of the SDK IPC client (sdk-internal crates/bitwarden-ipc) as the CLI uses
// it: an IpcClient with the Noise crypto provider and in-memory sessions
// (IpcClient.newWithSdkInMemorySessions), RPC requests, the built-in DiscoverRequest, and the
// transports that carry it to the Bitwarden desktop app (apps/cli/src/platform/services
// cli-desktop-ipc.transport.ts and the desktop_proxy's socket, see transport.go and socket.go).
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Transport is the communication backend the client sends and receives raw messages through.
type Transport interface {
	// Send delivers a message, connecting first if needed.
	Send(ctx context.Context, msg OutgoingMessage) error
	// Incoming returns the channel of received messages. It stays the same across reconnects.
	Incoming() <-chan IncomingMessage
	// Close disconnects.
	Close()
}

// Logger receives the client's diagnostic messages (the SDK's tracing output).
type Logger func(msg string)

// handshakeTimeout is HANDSHAKE_TIMEOUT_SECS.
const handshakeTimeout = 2 * time.Second

// subscriptionBuffer is CHANNEL_BUFFER_CAPACITY.
const subscriptionBuffer = 50

// RPC topics.
const (
	RPCRequestTopic  = "RpcRequestMessage"
	RPCResponseTopic = "RpcResponseMessage"
)

// Errors returned by Client.
var (
	ErrHandshakeTimeout  = errors.New("Noise handshake timed out")
	ErrHandshakeProtocol = errors.New("Noise handshake protocol error")
	ErrCancelled         = errors.New("Cancelled")
	ErrClosed            = errors.New("IPC client closed")
)

// Client is IpcClientImpl<NoiseCryptoProvider, _, InMemorySessionRepository>.
type Client struct {
	transport Transport
	log       Logger
	suite     CipherSuite
	rand      io.Reader

	// sendMu serializes sends (crypto_state_guard), so two sends never reuse a nonce.
	sendMu sync.Mutex

	mu       sync.Mutex
	sessions map[string]*transportState
	waiters  map[string]chan []byte
	subs     map[*subscription]struct{}
	handlers map[string]RPCHandler
	closed   bool
	done     chan struct{}
}

type subscription struct {
	topic *string
	ch    chan IncomingMessage
}

// NewClient creates a started client using the default cipher suite.
func NewClient(t Transport, log Logger) *Client {
	if log == nil {
		log = func(string) {}
	}
	c := &Client{
		transport: t,
		log:       log,
		suite:     DefaultCipherSuite,
		sessions:  map[string]*transportState{},
		waiters:   map[string]chan []byte{},
		subs:      map[*subscription]struct{}{},
		handlers:  map[string]RPCHandler{},
		done:      make(chan struct{}),
	}
	go c.run()
	return c
}

// Close stops the client and closes its transport.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.done)
	c.mu.Unlock()
	c.transport.Close()
}

func (c *Client) run() {
	in := c.transport.Incoming()
	for {
		select {
		case <-c.done:
			return
		case msg, ok := <-in:
			if !ok {
				return
			}
			c.receive(msg)
		}
	}
}

func (c *Client) sendRaw(ctx context.Context, f Frame, dest Endpoint, topic *string) error {
	return c.transport.Send(ctx, OutgoingMessage{Payload: f.MarshalCBOR(), Destination: dest, Topic: topic})
}

// receive is NoiseCryptoProvider::receive plus the client's dispatch loop.
func (c *Client) receive(msg IncomingMessage) {
	source := msg.Source.ToEndpoint()
	key := source.Key()
	f, err := UnmarshalFrame(msg.Payload)
	if err != nil {
		c.log("Received malformed cbor message, ignoring")
		return
	}
	switch f.Kind {
	case FrameHandshakeStart:
		h, err := newHandshake(f.Start.CipherSuite, false, c.rand)
		if err != nil {
			return
		}
		if h.readStart(f.Start) != nil {
			c.log("Failed to read handshake start message")
			return
		}
		resp, err := h.writeResponse()
		if err != nil {
			return
		}
		if err := c.sendRaw(context.Background(), Frame{Kind: FrameHandshakeFinish, Finish: resp}, source, nil); err != nil {
			c.log(fmt.Sprintf("Failed to send handshake response: %v", err))
			return
		}
		c.mu.Lock()
		c.sessions[key] = h.transportState()
		c.mu.Unlock()
	case FrameHandshakeFinish:
		c.mu.Lock()
		w := c.waiters[key]
		c.mu.Unlock()
		if w != nil {
			select {
			case w <- f.Finish:
			default:
			}
		}
	case FrameTransport:
		c.mu.Lock()
		state := c.sessions[key]
		var payload []byte
		if state != nil {
			payload, err = state.receive(f.Transport)
		}
		c.mu.Unlock()
		if state == nil {
			c.log(fmt.Sprintf("No session for %s, waiting for handshake", source))
			_ = c.sendRaw(context.Background(), Frame{Kind: FrameCryptoInvalidated}, source, nil)
			return
		}
		if err != nil {
			c.log(fmt.Sprintf("Failed to decrypt message from %s", source))
			return
		}
		c.dispatch(IncomingMessage{Payload: payload, Destination: msg.Destination, Source: msg.Source, Topic: msg.Topic})
	case FrameCryptoInvalidated:
		c.log(fmt.Sprintf("Invalidated session for %s due to crypto error, deleting session and waiting for handshake", source))
		c.mu.Lock()
		delete(c.sessions, key)
		c.mu.Unlock()
	}
}

func (c *Client) dispatch(msg IncomingMessage) {
	if msg.Topic != nil && *msg.Topic == RPCRequestTopic {
		go c.handleRPCRequest(msg)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for s := range c.subs {
		if s.topic == nil || msg.Topic != nil && *s.topic == *msg.Topic {
			select {
			case s.ch <- msg:
			default:
				c.log("Failed to save incoming message")
			}
		}
	}
}

// RPCHandler handles an incoming RPC request (RpcHandler). request is the raw "request" field of
// the RpcRequestMessage; the returned value is serialized as the Ok result, an error as an
// RpcError::RequestDeserialization.
type RPCHandler func(request json.RawMessage, source Endpoint) (any, error)

// RegisterRPCHandler registers the handler for requests named name (RpcRequest::NAME). The CLI
// registers none; the last registration for a name wins.
func (c *Client) RegisterRPCHandler(name string, h RPCHandler) {
	c.mu.Lock()
	c.handlers[name] = h
	c.mu.Unlock()
}

// handleRPCRequest answers an incoming RPC request on its response topic, with
// RpcError::NoHandlerFound when no handler is registered (RpcHandlerRegistry::handle).
func (c *Client) handleRPCRequest(msg IncomingMessage) {
	var req struct {
		Request       json.RawMessage `json:"request"`
		RequestID     string          `json:"request_id"`
		RequestType   string          `json:"request_type"`
		ResponseTopic string          `json:"response_topic"`
	}
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		c.log("Error handling RPC request: Failed to deserialize request message: " + err.Error())
		return
	}
	c.mu.Lock()
	h := c.handlers[req.RequestType]
	c.mu.Unlock()
	var result any = map[string]string{"Err": "NoHandlerFound"}
	if h != nil {
		v, err := h(req.Request, msg.Source)
		if err != nil {
			result = map[string]any{"Err": map[string]string{"RequestDeserialization": err.Error()}}
		} else {
			result = map[string]any{"Ok": v}
		}
	}
	payload, err := json.Marshal(struct {
		Result      any    `json:"result"`
		RequestID   string `json:"request_id"`
		RequestType string `json:"request_type"`
	}{result, req.RequestID, req.RequestType})
	if err != nil {
		c.log("Error handling RPC request: Failed to serialize response message: " + err.Error())
		return
	}
	topic := req.ResponseTopic
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Send(ctx, OutgoingMessage{Payload: payload, Destination: msg.Source.ToEndpoint(), Topic: &topic}); err != nil {
		c.log("Failed to send response message")
	}
}

func (c *Client) subscribe(topic *string) (*subscription, func()) {
	s := &subscription{topic: topic, ch: make(chan IncomingMessage, subscriptionBuffer)}
	c.mu.Lock()
	c.subs[s] = struct{}{}
	c.mu.Unlock()
	return s, func() {
		c.mu.Lock()
		delete(c.subs, s)
		c.mu.Unlock()
	}
}

// Send is NoiseCryptoProvider::send: it performs a handshake when there is no session (or the
// session is older than the re-handshake interval), then encrypts the payload into a transport
// frame.
func (c *Client) Send(ctx context.Context, msg OutgoingMessage) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	dest := msg.Destination.ToEndpoint()
	key := dest.Key()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	state := c.sessions[key]
	shouldHandshake := state == nil
	if state != nil && state.shouldRehandshake(time.Now()) {
		c.log(fmt.Sprintf("Noise session with %s is older than %ds, re-handshaking", dest, int(rehandshakeInterval/time.Second)))
		delete(c.sessions, key)
		shouldHandshake = true
	}
	c.mu.Unlock()

	if shouldHandshake {
		if err := c.handshake(ctx, dest); err != nil {
			return err
		}
	}

	c.mu.Lock()
	state = c.sessions[key]
	if state == nil {
		c.mu.Unlock()
		return ErrHandshakeProtocol
	}
	frame, err := state.send(msg.Payload)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.sendRaw(ctx, Frame{Kind: FrameTransport, Transport: frame}, dest, msg.Topic); err != nil {
		// The destination may have gone away; tear the session down so the next send
		// re-handshakes instead of sending frames the peer cannot decrypt.
		c.log(fmt.Sprintf("%s is unreachable. Clearing cryptographic sessions.", dest))
		c.mu.Lock()
		delete(c.sessions, key)
		c.mu.Unlock()
		return err
	}
	return nil
}

func (c *Client) handshake(ctx context.Context, dest Endpoint) error {
	key := dest.Key()
	h, err := newHandshake(c.suite, true, c.rand)
	if err != nil {
		return err
	}
	start, err := h.writeStart()
	if err != nil {
		return err
	}
	w := make(chan []byte, 1)
	c.mu.Lock()
	c.waiters[key] = w
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.waiters[key] == w {
			delete(c.waiters, key)
		}
		c.mu.Unlock()
	}()

	if err := c.sendRaw(ctx, Frame{Kind: FrameHandshakeStart, Start: start}, dest, nil); err != nil {
		return err
	}
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()
	select {
	case finish := <-w:
		if h.readResponse(finish) != nil {
			c.log("Failed to read handshake response message")
			return ErrHandshakeProtocol
		}
	case <-timer.C:
		c.log(fmt.Sprintf("Noise handshake with %s timed out after %d seconds", dest, int(handshakeTimeout/time.Second)))
		return ErrHandshakeTimeout
	case <-ctx.Done():
		return ErrCancelled
	case <-c.done:
		return ErrClosed
	}
	c.mu.Lock()
	c.sessions[key] = h.transportState()
	c.mu.Unlock()
	c.log(fmt.Sprintf("Noise handshake with %s completed, session established", dest))
	return nil
}

// RPCError is the SDK RpcError returned in an Err result.
type RPCError struct {
	Variant string
	Detail  string
}

func (e *RPCError) Error() string {
	switch e.Variant {
	case "RequestDeserialization":
		return "Failed to read request: " + e.Detail
	case "RequestSerialization":
		return "Failed to serialize request: " + e.Detail
	case "ResponseDeserialization":
		return "Failed to read response: " + e.Detail
	case "ResponseSerialization":
		return "Failed to serialize response: " + e.Detail
	case "NoHandlerFound":
		return "Request could not be completed because no handler has been registered for"
	}
	return e.Variant
}

func parseRPCError(raw json.RawMessage) error {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &RPCError{Variant: s}
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) == nil {
		for k, v := range m {
			return &RPCError{Variant: k, Detail: v}
		}
	}
	return &RPCError{Variant: "ResponseDeserialization", Detail: string(raw)}
}

// Request is IpcClientExt::request: it sends an RpcRequestMessage to dest and waits for the
// matching response on its response topic. ctx bounds the whole request (the AbortSignal).
func (c *Client) Request(ctx context.Context, dest Endpoint, requestType string, request, response any) error {
	requestID := uuid.NewString()
	responseTopic := RPCResponseTopic + ":" + requestID
	payload, err := marshalRPCRequest(request, requestID, requestType, responseTopic)
	if err != nil {
		return fmt.Errorf("Failed to serialize request: %w", err)
	}

	sub, unsubscribe := c.subscribe(&responseTopic)
	defer unsubscribe()

	topic := RPCRequestTopic
	if err := c.Send(ctx, OutgoingMessage{Payload: payload, Destination: dest, Topic: &topic}); err != nil {
		return err
	}

	want := dest.ToEndpoint().Key()
	for {
		select {
		case <-ctx.Done():
			return ErrCancelled
		case <-c.done:
			return ErrClosed
		case msg := <-sub.ch:
			if msg.Source.ToEndpoint().Key() != want {
				c.log("Ignoring RPC response from a source other than the request destination")
				continue
			}
			var resp struct {
				Result map[string]json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal(msg.Payload, &resp); err != nil {
				return &RPCError{Variant: "ResponseDeserialization", Detail: err.Error()}
			}
			if e, ok := resp.Result["Err"]; ok {
				return parseRPCError(e)
			}
			ok, found := resp.Result["Ok"]
			if !found {
				return &RPCError{Variant: "ResponseDeserialization", Detail: "missing result"}
			}
			if response != nil {
				if err := json.Unmarshal(ok, response); err != nil {
					return &RPCError{Variant: "ResponseDeserialization", Detail: err.Error()}
				}
			}
			return nil
		}
	}
}

// marshalRPCRequest serializes an RpcRequestMessage like serde_json.
func marshalRPCRequest(request any, requestID, requestType, responseTopic string) ([]byte, error) {
	return json.Marshal(struct {
		Request       any    `json:"request"`
		RequestID     string `json:"request_id"`
		RequestType   string `json:"request_type"`
		ResponseTopic string `json:"response_topic"`
	}{request, requestID, requestType, responseTopic})
}

// DiscoverResponse is the response of the built-in DiscoverRequest.
type DiscoverResponse struct {
	Version string `json:"version"`
}

// Discover is ipcRequestDiscover: DiscoverRequest is a unit struct, serialized as null.
func (c *Client) Discover(ctx context.Context, dest Endpoint) (*DiscoverResponse, error) {
	var r DiscoverResponse
	if err := c.Request(ctx, dest, "DiscoverRequest", nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
