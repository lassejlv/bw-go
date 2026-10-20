package sshkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
)

// PEM handling: a port of pem-rfc7468 1.0 (RFC 7468 "strict" grammar) and the base64ct line
// reader it uses.

var errPEM = errors.New("pem: invalid encoding")

const (
	preBoundary  = "-----BEGIN "
	postBoundary = "-----END "
	boundaryEnd  = "-----"
	pemWrapWidth = 64 // pem_rfc7468::BASE64_WRAP_WIDTH
	minLineWidth = 4  // base64ct::MIN_LINE_WIDTH
)

type encapsulation struct {
	label string
	text  []byte // encapsulated (base64) text
}

func isLabelChar(c byte) bool { return (c >= 0x21 && c <= 0x2C) || (c >= 0x2E && c <= 0x7E) }
func isWsp(c byte) bool       { return c == '\t' || c == ' ' }

func stripPreamble(b []byte) ([]byte, error) {
	if bytes.HasPrefix(b, []byte(preBoundary)) {
		return b, nil
	}
	for len(b) > 0 {
		c, rest := b[0], b[1:]
		if c == 0 {
			return nil, errPEM
		}
		if c == '\n' && bytes.HasPrefix(rest, []byte(preBoundary)) {
			return rest, nil
		}
		b = rest
	}
	return nil, errPEM
}

func stripLeadingEOL(b []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(b, []byte("\n")):
		return b[1:], true
	case bytes.HasPrefix(b, []byte("\r\n")):
		return b[2:], true
	case bytes.HasPrefix(b, []byte("\r")):
		return b[1:], true
	}
	return nil, false
}

func stripTrailingEOL(b []byte) ([]byte, bool) {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return b[:len(b)-2], true
	case bytes.HasSuffix(b, []byte("\n")), bytes.HasSuffix(b, []byte("\r")):
		return b[:len(b)-1], true
	}
	return nil, false
}

func splitLabel(b []byte) (string, []byte, bool) {
	n := 0
	lastWasWsp := false
	for _, c := range b {
		if isLabelChar(c) {
			lastWasWsp = false
		} else if c == '-' {
			break
		} else if n != 0 && isWsp(c) {
			if lastWasWsp {
				return "", nil, false
			}
			lastWasWsp = true
		} else {
			return "", nil, false
		}
		n++
	}
	label, rest := string(b[:n]), b[n:]
	if !bytes.HasPrefix(rest, []byte(boundaryEnd)) {
		return "", nil, false
	}
	body, ok := stripLeadingEOL(rest[len(boundaryEnd):])
	if !ok {
		return "", nil, false
	}
	return label, body, true
}

// parseEncapsulation is Encapsulation::parse (and so pem_rfc7468::decode_label).
func parseEncapsulation(data []byte) (encapsulation, error) {
	data, err := stripPreamble(data)
	if err != nil {
		return encapsulation{}, err
	}
	if !bytes.HasPrefix(data, []byte(preBoundary)) {
		return encapsulation{}, errPEM
	}
	label, body, ok := splitLabel(data[len(preBoundary):])
	if !ok {
		return encapsulation{}, errPEM
	}
	if t, ok := stripTrailingEOL(body); ok {
		body = t
	}
	if !bytes.HasSuffix(body, []byte(boundaryEnd)) {
		return encapsulation{}, errPEM
	}
	body = body[:len(body)-len(boundaryEnd)]
	for _, s := range []string{label, postBoundary} {
		if !bytes.HasSuffix(body, []byte(s)) {
			return encapsulation{}, errPEM
		}
		body = body[:len(body)-len(s)]
	}
	text, ok := stripTrailingEOL(body)
	if !ok {
		return encapsulation{}, errPEM
	}
	return encapsulation{label: label, text: text}, nil
}

// lineWidth is Encapsulation::encapsulated_text_line_width (the position of the first EOL).
func (e encapsulation) lineWidth() int {
	if i := bytes.IndexAny(e.text, "\r\n"); i >= 0 {
		return i
	}
	return len(e.text)
}

func trimLineEnd(b []byte) []byte {
	if t, ok := stripTrailingEOL(b); ok {
		return t
	}
	return b
}

// decodeWrappedBase64 decodes standard padded base64 wrapped at exactly width characters per line
// (the last line may be shorter), like base64ct::Decoder::new_wrapped.
func decodeWrappedBase64(text []byte, width int) ([]byte, error) {
	if width < minLineWidth || len(text) == 0 {
		return nil, errPEM
	}
	var joined []byte
	rem := text
	for len(rem) > 0 {
		if len(rem) <= width {
			joined = append(joined, trimLineEnd(rem)...)
			break
		}
		after := rem[width:]
		var next []byte
		switch {
		case bytes.HasPrefix(after, []byte("\r\n")):
			next = after[2:]
		case after[0] == '\r' || after[0] == '\n':
			next = after[1:]
		default:
			return nil, errPEM
		}
		joined = append(joined, rem[:width]...)
		rem = next
	}
	for _, c := range joined {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, errPEM
		}
	}
	out, err := base64.StdEncoding.Strict().DecodeString(string(joined))
	if err != nil {
		return nil, errPEM
	}
	return out, nil
}

// decodePEMDocument is der::SecretDocument::from_pem: pem_rfc7468::decode_vec (64-column strict
// wrapping) and a check that the payload is exactly one DER SEQUENCE.
func decodePEMDocument(pem []byte) (string, []byte, error) {
	enc, err := parseEncapsulation(pem)
	if err != nil {
		return "", nil, err
	}
	der, err := decodeWrappedBase64(enc.text, pemWrapWidth)
	if err != nil {
		return "", nil, err
	}
	el, rest, err := readDER(der)
	if err != nil || el.tag != tagSequence || len(rest) != 0 {
		return "", nil, errPEM
	}
	return enc.label, der, nil
}

// rewrapPEM is import.rs rewrap_pem: re-wrap the base64 body of a single PEM block to 64
// characters per line. ok is false when the input is not a single well-formed block.
func rewrapPEM(pem string) (string, bool) {
	lines := rustLines(pem)
	i := 0
	for i < len(lines) && !strings.HasPrefix(lines[i], "-----BEGIN ") {
		i++
	}
	if i == len(lines) {
		return "", false
	}
	header := lines[i]
	var body strings.Builder
	footer := ""
	found := false
	for _, line := range lines[i+1:] {
		if strings.HasPrefix(line, "-----END ") {
			footer, found = line, true
			break
		}
		for _, f := range strings.FieldsFunc(line, unicode.IsSpace) {
			body.WriteString(f)
		}
	}
	if !found {
		return "", false
	}
	var out strings.Builder
	out.WriteString(header)
	out.WriteByte('\n')
	chars := []rune(body.String())
	for len(chars) > 0 {
		n := min(64, len(chars))
		out.WriteString(string(chars[:n]))
		out.WriteByte('\n')
		chars = chars[n:]
	}
	out.WriteString(footer)
	out.WriteByte('\n')
	return out.String(), true
}

// rustLines is str::lines: split on '\n', drop one trailing '\r' per line, no final empty line.
func rustLines(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// encodePEM is pem_rfc7468::encode_string with LF line endings and the given wrap width.
func encodePEM(label string, data []byte, width int) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.WriteString(preBoundary + label + boundaryEnd + "\n")
	for len(b64) > 0 {
		n := min(width, len(b64))
		sb.WriteString(b64[:n])
		sb.WriteByte('\n')
		b64 = b64[n:]
	}
	sb.WriteString(postBoundary + label + boundaryEnd + "\n")
	return sb.String()
}
