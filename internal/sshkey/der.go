package sshkey

import (
	"bytes"
	"errors"
	"math/big"
)

// A small strict DER reader (the subset of the RustCrypto `der` crate the PKCS#8 / PKCS#5 /
// PKCS#1 / SEC1 decoders need).

var errDER = errors.New("der: invalid encoding")

const (
	tagInteger     = 0x02
	tagBitString   = 0x03
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30
)

type derElem struct {
	tag     byte
	content []byte
}

// readDER reads one TLV with DER length rules (definite, minimal) and returns the rest.
func readDER(b []byte) (derElem, []byte, error) {
	if len(b) < 2 {
		return derElem{}, nil, errDER
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return derElem{}, nil, errDER
	}
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n || b[2] == 0 {
			return derElem{}, nil, errDER
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		if l < 0x80 {
			return derElem{}, nil, errDER
		}
		hdr = 2 + n
	}
	if l < 0 || len(b)-hdr < l {
		return derElem{}, nil, errDER
	}
	return derElem{tag: tag, content: b[hdr : hdr+l]}, b[hdr+l:], nil
}

// derReader reads the elements of a constructed value in order.
type derReader struct{ b []byte }

func (r *derReader) finished() bool { return len(r.b) == 0 }

func (r *derReader) peekTag() (byte, bool) {
	if len(r.b) == 0 {
		return 0, false
	}
	return r.b[0], true
}

func (r *derReader) next() (derElem, error) {
	el, rest, err := readDER(r.b)
	if err != nil {
		return derElem{}, err
	}
	r.b = rest
	return el, nil
}

func (r *derReader) expect(tag byte) ([]byte, error) {
	el, err := r.next()
	if err != nil {
		return nil, err
	}
	if el.tag != tag {
		return nil, errDER
	}
	return el.content, nil
}

// optional reads the next element when it has the given tag.
func (r *derReader) optional(tag byte) ([]byte, bool, error) {
	if t, ok := r.peekTag(); !ok || t != tag {
		return nil, false, nil
	}
	c, err := r.expect(tag)
	return c, err == nil, err
}

// parseSequence parses a complete DER SEQUENCE (no trailing data) and returns a reader over it.
func parseSequence(b []byte) (*derReader, error) {
	el, rest, err := readDER(b)
	if err != nil || el.tag != tagSequence || len(rest) != 0 {
		return nil, errDER
	}
	return &derReader{el.content}, nil
}

func (r *derReader) sequence() (*derReader, error) {
	c, err := r.expect(tagSequence)
	if err != nil {
		return nil, err
	}
	return &derReader{c}, nil
}

// checkIntegerEncoding validates a DER INTEGER's content (non-empty, minimal).
func checkIntegerEncoding(c []byte) error {
	if len(c) == 0 {
		return errDER
	}
	if len(c) > 1 && ((c[0] == 0 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
		return errDER
	}
	return nil
}

// uint reads a non-negative INTEGER as big-endian magnitude bytes (der::asn1::UintRef: the sign
// byte is stripped).
func (r *derReader) uint() ([]byte, error) {
	c, err := r.expect(tagInteger)
	if err != nil {
		return nil, err
	}
	if err := checkIntegerEncoding(c); err != nil || c[0]&0x80 != 0 {
		return nil, errDER
	}
	if len(c) > 1 && c[0] == 0 {
		c = c[1:]
	}
	return c, nil
}

// smallUint reads a non-negative INTEGER that must fit in maxBits bits.
func (r *derReader) smallUint(maxBits int) (uint64, error) {
	c, err := r.uint()
	if err != nil {
		return 0, err
	}
	v := new(big.Int).SetBytes(c)
	if v.BitLen() > maxBits {
		return 0, errDER
	}
	return v.Uint64(), nil
}

func (r *derReader) oid() ([]byte, error) {
	c, err := r.expect(tagOID)
	if err != nil {
		return nil, err
	}
	if err := checkOID(c); err != nil {
		return nil, err
	}
	return c, nil
}

func checkOID(c []byte) error {
	if len(c) == 0 || c[len(c)-1]&0x80 != 0 {
		return errDER
	}
	start := true
	for _, b := range c {
		if start && b == 0x80 {
			return errDER
		}
		start = b&0x80 == 0
	}
	return nil
}

func oidEqual(a, b []byte) bool { return bytes.Equal(a, b) }

// Encoded OID contents.
var (
	oidEd25519      = []byte{0x2b, 0x65, 0x70}                                     // 1.3.101.112
	oidRSA          = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01} // 1.2.840.113549.1.1.1
	oidECPublicKey  = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}             // 1.2.840.10045.2.1
	oidP256         = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}       // 1.2.840.10045.3.1.7
	oidP384         = []byte{0x2b, 0x81, 0x04, 0x00, 0x22}                         // 1.3.132.0.34
	oidP521         = []byte{0x2b, 0x81, 0x04, 0x00, 0x23}                         // 1.3.132.0.35
	oidPBES2        = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d} // 1.2.840.113549.1.5.13
	oidPBKDF2       = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c} // 1.2.840.113549.1.5.12
	oidScrypt       = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b} // 1.3.6.1.4.1.11591.4.11
	oidHmacSHA1     = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07}       // 1.2.840.113549.2.7
	oidHmacSHA224   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08}
	oidHmacSHA256   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09}
	oidHmacSHA384   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a}
	oidHmacSHA512   = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b}
	oidAES128CBC    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02} // 2.16.840.1.101.3.4.1.2
	oidAES192CBC    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16}
	oidAES256CBC    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}
	oidAES128GCM    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06}
	oidAES256GCM    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e}
	derNullEncoding = []byte{tagNull, 0x00}
)

// algorithmIdentifier is spki::AlgorithmIdentifier { oid, parameters: Option<Any> }.
type algorithmIdentifier struct {
	oid    []byte
	params []byte // full TLV encoding of the parameters, nil when absent
}

func (r *derReader) algorithmIdentifier() (algorithmIdentifier, error) {
	seq, err := r.sequence()
	if err != nil {
		return algorithmIdentifier{}, err
	}
	oid, err := seq.oid()
	if err != nil {
		return algorithmIdentifier{}, err
	}
	var params []byte
	if !seq.finished() {
		before := seq.b
		if _, err := seq.next(); err != nil {
			return algorithmIdentifier{}, err
		}
		params = before[:len(before)-len(seq.b)]
	}
	if !seq.finished() {
		return algorithmIdentifier{}, errDER
	}
	return algorithmIdentifier{oid: oid, params: params}, nil
}

// privateKeyInfo is pkcs8::PrivateKeyInfo (RFC 5208 / RFC 5958 OneAsymmetricKey).
type privateKeyInfo struct {
	algorithm  algorithmIdentifier
	privateKey []byte // OCTET STRING contents
	publicKey  []byte // BIT STRING contents (including the unused-bits byte), nil when absent
}

// parsePrivateKeyInfo decodes a PrivateKeyInfo document (no trailing data allowed).
func parsePrivateKeyInfo(der []byte) (*privateKeyInfo, error) {
	seq, err := parseSequence(der)
	if err != nil {
		return nil, err
	}
	version, err := seq.smallUint(8)
	if err != nil || version > 1 {
		return nil, errDER
	}
	alg, err := seq.algorithmIdentifier()
	if err != nil {
		return nil, err
	}
	pk, err := seq.expect(tagOctetString)
	if err != nil {
		return nil, err
	}
	if _, _, err := seq.optional(0xa0); err != nil { // [0] IMPLICIT attributes
		return nil, err
	}
	pub, hasPub, err := seq.optional(0x81) // [1] IMPLICIT BIT STRING publicKey
	if err != nil {
		return nil, err
	}
	if hasPub {
		if len(pub) == 0 || pub[0] > 7 || (len(pub) == 1 && pub[0] != 0) {
			return nil, errDER
		}
	}
	if (version == 1) != hasPub {
		return nil, errDER
	}
	for !seq.finished() { // ignore any remaining (context-specific) extension fields
		el, err := seq.next()
		if err != nil || el.tag&0xc0 != 0x80 {
			return nil, errDER
		}
	}
	info := &privateKeyInfo{algorithm: alg, privateKey: pk}
	if hasPub {
		info.publicKey = pub
	}
	return info, nil
}
