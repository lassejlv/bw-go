package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Minimal CBOR (RFC 8949) codec used for COSE structures and DataEnvelope contents.
//
// Decoded value types:
//   - int64 for integers that fit, uint64 for larger unsigned integers
//   - []byte, string, []any, cborMap (ordered), cborTag, bool, nil (null), cborUndefined, float64,
//     cborSimple for other simple values.
//
// The encoder accepts the same types (plus int, uint8, uint16, uint32, int32 and cborRaw) and always
// produces definite-length, shortest-form encodings, which is what ciborium/coset emit.

type cborPair struct {
	K any
	V any
}

// cborMap is an ordered CBOR map.
type cborMap []cborPair

type cborTag struct {
	Num uint64
	Val any
}

type cborUndefined struct{}

type cborSimple uint8

// cborRaw is pre-encoded CBOR inserted verbatim by the encoder.
type cborRaw []byte

var errCBOR = errors.New("invalid CBOR encoding")

const cborMaxDepth = 64

// get returns the value of the first entry whose key equals k (int64/string keys).
func (m cborMap) get(k any) (any, bool) {
	for _, p := range m {
		if cborKeyEqual(p.K, k) {
			return p.V, true
		}
	}
	return nil, false
}

func cborKeyEqual(a, b any) bool {
	switch x := a.(type) {
	case int64:
		y, ok := b.(int64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case uint64:
		y, ok := b.(uint64)
		return ok && x == y
	}
	return false
}

// ---------- decoding ----------

type cborDecoder struct {
	b     []byte
	pos   int
	depth int
}

// cborDecode decodes exactly one CBOR data item; trailing bytes are an error.
func cborDecode(b []byte) (any, error) {
	d := &cborDecoder{b: b}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	if d.pos != len(b) {
		return nil, fmt.Errorf("%w: trailing data", errCBOR)
	}
	return v, nil
}

func (d *cborDecoder) byte() (byte, error) {
	if d.pos >= len(d.b) {
		return 0, fmt.Errorf("%w: unexpected end", errCBOR)
	}
	c := d.b[d.pos]
	d.pos++
	return c, nil
}

func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.b)-d.pos) {
		return nil, fmt.Errorf("%w: unexpected end", errCBOR)
	}
	out := d.b[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

// head reads the initial byte and argument. indefinite is true for additional info 31.
func (d *cborDecoder) head() (major byte, arg uint64, info byte, err error) {
	c, err := d.byte()
	if err != nil {
		return 0, 0, 0, err
	}
	major, info = c>>5, c&0x1f
	switch {
	case info < 24:
		return major, uint64(info), info, nil
	case info == 24:
		b, err := d.take(1)
		if err != nil {
			return 0, 0, 0, err
		}
		return major, uint64(b[0]), info, nil
	case info == 25:
		b, err := d.take(2)
		if err != nil {
			return 0, 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint16(b)), info, nil
	case info == 26:
		b, err := d.take(4)
		if err != nil {
			return 0, 0, 0, err
		}
		return major, uint64(binary.BigEndian.Uint32(b)), info, nil
	case info == 27:
		b, err := d.take(8)
		if err != nil {
			return 0, 0, 0, err
		}
		return major, binary.BigEndian.Uint64(b), info, nil
	case info == 31:
		return major, 0, info, nil
	default:
		return 0, 0, 0, fmt.Errorf("%w: reserved additional info", errCBOR)
	}
}

func (d *cborDecoder) isBreak() bool {
	return d.pos < len(d.b) && d.b[d.pos] == 0xff
}

func (d *cborDecoder) value() (any, error) {
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > cborMaxDepth {
		return nil, fmt.Errorf("%w: nesting too deep", errCBOR)
	}
	major, arg, info, err := d.head()
	if err != nil {
		return nil, err
	}
	indefinite := info == 31
	switch major {
	case 0:
		if indefinite {
			return nil, errCBOR
		}
		if arg <= math.MaxInt64 {
			return int64(arg), nil
		}
		return arg, nil
	case 1:
		if indefinite {
			return nil, errCBOR
		}
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: negative integer out of range", errCBOR)
		}
		return -1 - int64(arg), nil
	case 2, 3:
		var data []byte
		if indefinite {
			var buf bytes.Buffer
			for {
				if d.isBreak() {
					d.pos++
					break
				}
				cm, carg, cinfo, err := d.head()
				if err != nil {
					return nil, err
				}
				if cm != major || cinfo == 31 {
					return nil, fmt.Errorf("%w: bad string chunk", errCBOR)
				}
				chunk, err := d.take(carg)
				if err != nil {
					return nil, err
				}
				buf.Write(chunk)
			}
			data = buf.Bytes()
		} else {
			b, err := d.take(arg)
			if err != nil {
				return nil, err
			}
			data = append([]byte{}, b...)
		}
		if major == 2 {
			if data == nil {
				data = []byte{}
			}
			return data, nil
		}
		return string(data), nil
	case 4:
		var arr []any
		if indefinite {
			arr = []any{}
			for !d.isBreak() {
				v, err := d.value()
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			d.pos++
			return arr, nil
		}
		if arg > uint64(len(d.b)-d.pos) {
			return nil, fmt.Errorf("%w: array too long", errCBOR)
		}
		arr = make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 5:
		m := cborMap{}
		readPair := func() error {
			k, err := d.value()
			if err != nil {
				return err
			}
			v, err := d.value()
			if err != nil {
				return err
			}
			m = append(m, cborPair{k, v})
			return nil
		}
		if indefinite {
			for !d.isBreak() {
				if err := readPair(); err != nil {
					return nil, err
				}
			}
			d.pos++
			return m, nil
		}
		if arg > uint64(len(d.b)-d.pos) {
			return nil, fmt.Errorf("%w: map too long", errCBOR)
		}
		for i := uint64(0); i < arg; i++ {
			if err := readPair(); err != nil {
				return nil, err
			}
		}
		return m, nil
	case 6:
		if indefinite {
			return nil, errCBOR
		}
		v, err := d.value()
		if err != nil {
			return nil, err
		}
		return cborTag{Num: arg, Val: v}, nil
	default: // 7
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		case 23:
			return cborUndefined{}, nil
		case 25:
			return float64(halfToFloat32(uint16(arg))), nil
		case 26:
			return float64(math.Float32frombits(uint32(arg))), nil
		case 27:
			return math.Float64frombits(arg), nil
		case 31:
			return nil, fmt.Errorf("%w: unexpected break", errCBOR)
		default:
			return cborSimple(arg), nil
		}
	}
}

func halfToFloat32(h uint16) float32 {
	sign := uint32(h>>15) << 31
	exp := (h >> 10) & 0x1f
	frac := uint32(h & 0x3ff)
	switch exp {
	case 0:
		v := float32(math.Ldexp(float64(frac), -24))
		if sign != 0 {
			return -v
		}
		return v
	case 0x1f:
		return math.Float32frombits(sign | 0x7f800000 | frac<<13)
	default:
		return math.Float32frombits(sign | uint32(exp+112)<<23 | frac<<13)
	}
}

// ---------- encoding ----------

func cborEncode(v any) ([]byte, error) {
	var buf []byte
	return cborAppend(buf, v)
}

// cborMustEncode encodes values built internally from supported types.
func cborMustEncode(v any) []byte {
	b, err := cborEncode(v)
	if err != nil {
		panic(err)
	}
	return b
}

func cborHead(buf []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(buf, m|byte(n))
	case n <= math.MaxUint8:
		return append(buf, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(buf, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(buf, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(buf, m|27), n)
	}
}

func cborAppendInt(buf []byte, i int64) []byte {
	if i >= 0 {
		return cborHead(buf, 0, uint64(i))
	}
	return cborHead(buf, 1, uint64(-1-i))
}

func cborAppend(buf []byte, v any) ([]byte, error) {
	var err error
	switch x := v.(type) {
	case nil:
		return append(buf, 0xf6), nil
	case bool:
		if x {
			return append(buf, 0xf5), nil
		}
		return append(buf, 0xf4), nil
	case int:
		return cborAppendInt(buf, int64(x)), nil
	case int32:
		return cborAppendInt(buf, int64(x)), nil
	case int64:
		return cborAppendInt(buf, x), nil
	case uint8:
		return cborHead(buf, 0, uint64(x)), nil
	case uint16:
		return cborHead(buf, 0, uint64(x)), nil
	case uint32:
		return cborHead(buf, 0, uint64(x)), nil
	case uint64:
		return cborHead(buf, 0, x), nil
	case []byte:
		buf = cborHead(buf, 2, uint64(len(x)))
		return append(buf, x...), nil
	case string:
		buf = cborHead(buf, 3, uint64(len(x)))
		return append(buf, x...), nil
	case []any:
		buf = cborHead(buf, 4, uint64(len(x)))
		for _, e := range x {
			if buf, err = cborAppend(buf, e); err != nil {
				return nil, err
			}
		}
		return buf, nil
	case cborMap:
		buf = cborHead(buf, 5, uint64(len(x)))
		for _, p := range x {
			if buf, err = cborAppend(buf, p.K); err != nil {
				return nil, err
			}
			if buf, err = cborAppend(buf, p.V); err != nil {
				return nil, err
			}
		}
		return buf, nil
	case cborTag:
		buf = cborHead(buf, 6, x.Num)
		return cborAppend(buf, x.Val)
	case cborUndefined:
		return append(buf, 0xf7), nil
	case cborSimple:
		if x < 24 {
			return append(buf, 0xe0|byte(x)), nil
		}
		return append(buf, 0xf8, byte(x)), nil
	case float64:
		if f32 := float32(x); float64(f32) == x || math.IsNaN(x) {
			return binary.BigEndian.AppendUint32(append(buf, 0xfa), math.Float32bits(f32)), nil
		}
		return binary.BigEndian.AppendUint64(append(buf, 0xfb), math.Float64bits(x)), nil
	case cborRaw:
		return append(buf, x...), nil
	default:
		return nil, fmt.Errorf("cbor: unsupported type %T", v)
	}
}

// cborCanonicalMap encodes a map with integer keys using RFC 8949 §4.2.1 deterministic ordering
// (keys sorted by their encoded bytes), as used by RFC 9679 COSE key thumbprints.
func cborCanonicalMap(m cborMap) []byte {
	type enc struct{ k, v []byte }
	entries := make([]enc, len(m))
	for i, p := range m {
		entries[i] = enc{cborMustEncode(p.K), cborMustEncode(p.V)}
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].k, entries[j].k) < 0 })
	out := cborHead(nil, 5, uint64(len(entries)))
	for _, e := range entries {
		out = append(out, e.k...)
		out = append(out, e.v...)
	}
	return out
}

// ---------- JSON bridge ----------

// CBORToJSON converts a CBOR document (e.g. the content of an opened DataEnvelope, which the SDK
// serializes with serde/ciborium) into JSON, preserving map order. Byte strings become standard
// base64 strings, integer map keys become decimal strings, tags are dropped (their content is kept),
// and undefined becomes null.
func CBORToJSON(b []byte) ([]byte, error) {
	v, err := cborDecode(b)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeJSONValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeJSONValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil, cborUndefined:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return errors.New("cbor: cannot represent NaN/Inf in JSON")
		}
		b, _ := json.Marshal(x)
		buf.Write(b)
	case string:
		b, _ := json.Marshal(x)
		buf.Write(b)
	case []byte:
		b, _ := json.Marshal(base64.StdEncoding.EncodeToString(x))
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSONValue(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case cborMap:
		buf.WriteByte('{')
		for i, p := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			var key string
			switch k := p.K.(type) {
			case string:
				key = k
			case int64:
				key = strconv.FormatInt(k, 10)
			case uint64:
				key = strconv.FormatUint(k, 10)
			default:
				return fmt.Errorf("cbor: unsupported map key type %T for JSON", p.K)
			}
			kb, _ := json.Marshal(key)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeJSONValue(buf, p.V); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case cborTag:
		return writeJSONValue(buf, x.Val)
	case cborSimple:
		buf.WriteString("null")
	default:
		return fmt.Errorf("cbor: unsupported value %T", v)
	}
	return nil
}

// JSONToCBOR converts a JSON document into CBOR the way serde/ciborium would serialize the
// equivalent Rust value: objects become text-keyed maps (key order preserved), integers become
// CBOR integers, other numbers become floats, null becomes CBOR null.
func JSONToCBOR(j []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.UseNumber()
	v, err := readJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("json: trailing data")
	}
	return cborEncode(v)
}

func readJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := cborMap{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("json: invalid object key")
				}
				v, err := readJSONValue(dec)
				if err != nil {
					return nil, err
				}
				m = append(m, cborPair{k, v})
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := readJSONValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, errors.New("json: unexpected delimiter")
	case json.Number:
		s := t.String()
		if !strings.ContainsAny(s, ".eE") {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i, nil
			}
			if u, err := strconv.ParseUint(s, 10, 64); err == nil {
				return u, nil
			}
		}
		f, err := t.Float64()
		if err != nil {
			return nil, err
		}
		return f, nil
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("json: unexpected token %v", tok)
}
