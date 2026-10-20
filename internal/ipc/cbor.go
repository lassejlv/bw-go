package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimal CBOR (RFC 8949) codec for the Noise frames, which the SDK serializes with ciborium via
// serde: structs are maps keyed by field name, externally tagged enum variants are single entry
// maps (newtype variants) or text strings (unit variants), Vec<u8> is an array of integers and
// serde_bytes buffers are byte strings. Integers always use the shortest encoding, like ciborium.

const (
	cborUint  = 0
	cborNeg   = 1
	cborBytes = 2
	cborText  = 3
	cborArray = 4
	cborMap   = 5
	cborOther = 7
)

func cborHead(buf []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(buf, m|byte(n))
	case n <= 0xff:
		return append(buf, m|24, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(buf, m|25), uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(buf, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(buf, m|27), n)
	}
}

func cborAppendText(buf []byte, s string) []byte {
	return append(cborHead(buf, cborText, uint64(len(s))), s...)
}

func cborAppendBytes(buf, b []byte) []byte {
	return append(cborHead(buf, cborBytes, uint64(len(b))), b...)
}

// cborAppendU8Array encodes a serde Vec<u8> (an array of small unsigned integers).
func cborAppendU8Array(buf, b []byte) []byte {
	buf = cborHead(buf, cborArray, uint64(len(b)))
	for _, v := range b {
		buf = cborHead(buf, cborUint, uint64(v))
	}
	return buf
}

// cborValue is a decoded item: uint64, int64 (negative integers), []byte, string, []any,
// map[string]any (text keys only), bool or nil.
type cborDecoder struct {
	b []byte
	i int
}

var errCborTruncated = errors.New("cbor: truncated input")

func cborDecode(b []byte) (any, error) {
	d := &cborDecoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.i != len(b) {
		return nil, errors.New("cbor: trailing data")
	}
	return v, nil
}

func (d *cborDecoder) head() (byte, uint64, error) {
	if d.i >= len(d.b) {
		return 0, 0, errCborTruncated
	}
	ib := d.b[d.i]
	d.i++
	major, info := ib>>5, ib&0x1f
	var n int
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	default:
		return 0, 0, fmt.Errorf("cbor: unsupported additional info %d", info)
	}
	if d.i+n > len(d.b) {
		return 0, 0, errCborTruncated
	}
	var v uint64
	for _, c := range d.b[d.i : d.i+n] {
		v = v<<8 | uint64(c)
	}
	d.i += n
	return major, v, nil
}

func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.b)-d.i) {
		return nil, errCborTruncated
	}
	out := d.b[d.i : d.i+int(n)]
	d.i += int(n)
	return out, nil
}

func (d *cborDecoder) value(depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("cbor: nesting too deep")
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case cborUint:
		return arg, nil
	case cborNeg:
		return -1 - int64(arg), nil
	case cborBytes:
		b, err := d.take(arg)
		return append([]byte(nil), b...), err
	case cborText:
		b, err := d.take(arg)
		return string(b), err
	case cborArray:
		if arg > uint64(len(d.b)) {
			return nil, errCborTruncated
		}
		out := make([]any, 0, arg)
		for range arg {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case cborMap:
		if arg > uint64(len(d.b)) {
			return nil, errCborTruncated
		}
		out := make(map[string]any, arg)
		for range arg {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errors.New("cbor: non-text map key")
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	case cborOther:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
	}
	return nil, fmt.Errorf("cbor: unsupported item (major %d)", major)
}

// cborByteSeq accepts a serde Vec<u8> as either an array of integers or a byte string.
func cborByteSeq(v any) ([]byte, error) {
	switch t := v.(type) {
	case []byte:
		return t, nil
	case []any:
		out := make([]byte, len(t))
		for i, e := range t {
			n, ok := e.(uint64)
			if !ok || n > 0xff {
				return nil, errors.New("cbor: invalid byte in array")
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	return nil, errors.New("cbor: expected bytes")
}
