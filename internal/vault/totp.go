package vault

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP generation mirroring the SDK (bitwarden-vault src/totp.rs), used by TotpService.getCode$.

// ErrTotpInvalidOtpauth / ErrTotpMissingSecret mirror TotpError.
var (
	ErrTotpInvalidOtpauth = errors.New("Invalid otpauth")
	ErrTotpMissingSecret  = errors.New("Missing secret")
)

const (
	base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	steamChars  = "23456789BCDFGHJKMNPQRTVWXY"
)

// TotpAlgorithm is the hash used for a TOTP.
type TotpAlgorithm int

const (
	TotpSHA1 TotpAlgorithm = iota
	TotpSHA256
	TotpSHA512
	TotpSteam
)

// TotpParams are the parsed TOTP parameters.
type TotpParams struct {
	Account   *string
	Issuer    *string
	Algorithm TotpAlgorithm
	Digits    int
	Period    int
	Secret    []byte
}

// TotpResponse mirrors the SDK TotpResponse.
type TotpResponse struct {
	Code   string `json:"code"`
	Period int    `json:"period"`
}

// decodeB32 mirrors the SDK's lenient base32 decoder (invalid characters are skipped, partial
// bytes dropped).
func decodeB32(s string) []byte {
	s = strings.ToUpper(s)
	var bits strings.Builder
	for _, c := range s {
		if i := strings.IndexRune(base32Chars, c); i >= 0 {
			fmt.Fprintf(&bits, "%05b", i)
		}
	}
	b := bits.String()
	out := make([]byte, 0, len(b)/8)
	for i := 0; i+8 <= len(b); i += 8 {
		v, _ := strconv.ParseUint(b[i:i+8], 2, 8)
		out = append(out, byte(v))
	}
	return out
}

// ParseTotp parses an otpauth:// URI, a steam:// key or a bare base32 secret.
func ParseTotp(key string) (*TotpParams, error) {
	key = strings.ToLower(key)
	switch {
	case strings.HasPrefix(key, "otpauth://"):
		u, err := url.Parse(key)
		if err != nil {
			return nil, ErrTotpInvalidOtpauth
		}
		p := &TotpParams{Algorithm: TotpSHA1, Digits: 6, Period: 30}
		path := u.EscapedPath()
		if dec, err := url.PathUnescape(path); err == nil {
			path = dec
		}
		if strings.HasPrefix(path, "/") {
			label := path[1:]
			if i := strings.Index(label, ":"); i >= 0 {
				iss, acc := strings.TrimSpace(label[:i]), strings.TrimSpace(label[i+1:])
				p.Issuer, p.Account = &iss, &acc
			} else {
				p.Account = &label
			}
		}
		q := map[string]string{}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			if pair == "" {
				continue
			}
			k, v, _ := strings.Cut(pair, "=")
			k, _ = url.QueryUnescape(k)
			v, _ = url.QueryUnescape(v)
			q[k] = v // last value wins (HashMap collect)
		}
		switch q["algorithm"] {
		case "sha256":
			p.Algorithm = TotpSHA256
		case "sha512":
			p.Algorithm = TotpSHA512
		}
		if d, err := strconv.ParseUint(q["digits"], 10, 32); err == nil {
			p.Digits = int(min(d, 10))
		}
		if per, err := strconv.ParseUint(q["period"], 10, 32); err == nil {
			p.Period = int(max(per, 1))
		}
		if iss, ok := q["issuer"]; ok {
			p.Issuer = &iss
		}
		secret, ok := q["secret"]
		if !ok {
			return nil, ErrTotpMissingSecret
		}
		p.Secret = decodeB32(secret)
		return p, nil
	case strings.HasPrefix(key, "steam://"):
		return &TotpParams{Algorithm: TotpSteam, Digits: 5, Period: 30, Secret: decodeB32(key[len("steam://"):])}, nil
	default:
		return &TotpParams{Algorithm: TotpSHA1, Digits: 6, Period: 30, Secret: decodeB32(key)}, nil
	}
}

// Code derives the code for the given time.
func (p *TotpParams) Code(t time.Time) string {
	counter := t.Unix() / int64(p.Period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	var h func() hash.Hash
	switch p.Algorithm {
	case TotpSHA256:
		h = sha256.New
	case TotpSHA512:
		h = sha512.New
	default:
		h = sha1.New
	}
	m := hmac.New(h, p.Secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := int(sum[len(sum)-1] & 15)
	bin := uint32(sum[off]&127)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	if p.Algorithm == TotpSteam {
		full := bin & 0x7fffffff
		var sb strings.Builder
		for i := 0; i < p.Digits; i++ {
			sb.WriteByte(steamChars[int(full)%len(steamChars)])
			full /= uint32(len(steamChars))
		}
		return sb.String()
	}
	mod := uint64(1)
	for i := 0; i < p.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", p.Digits, uint64(bin)%mod)
}

// GenerateTotp mirrors generate_totp: parse the key and derive the code at t (zero t = now).
func GenerateTotp(key string, t time.Time) (*TotpResponse, error) {
	p, err := ParseTotp(key)
	if err != nil {
		return nil, err
	}
	if t.IsZero() {
		t = time.Now()
	}
	return &TotpResponse{Code: p.Code(t), Period: p.Period}, nil
}
