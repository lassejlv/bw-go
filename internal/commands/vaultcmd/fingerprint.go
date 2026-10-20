package vaultcmd

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/crypto"
	"github.com/lassejlv/bw-go/internal/wordlist"
)

// Fingerprint mirrors LegacyCompatKeyService.getFingerprint: SHA-256 of the SPKI public key,
// HKDF-Expand (SHA-256, 32 bytes) with the fingerprint material (a user id) as info, then a phrase
// of EFF long word list words taken from the result as a big-endian number.
func Fingerprint(fingerprintMaterial string, publicKey []byte) ([]string, error) {
	if publicKey == nil {
		return nil, errors.New("Public key is required to generate a fingerprint.")
	}
	keyFingerprint := crypto.SHA256(publicKey)
	userFingerprint := crypto.HKDFExpand(keyFingerprint, fingerprintMaterial, 32)
	return hashPhrase(userFingerprint, 64)
}

// hashPhrase mirrors LegacyCompatKeyService.hashPhrase.
func hashPhrase(hash []byte, minimumEntropy float64) ([]string, error) {
	words := wordlist.EFFLongWordList
	entropyPerWord := math.Log(float64(len(words))) / math.Log(2)
	numWords := int(math.Ceil(minimumEntropy / entropyPerWord))
	entropyAvailable := float64(len(hash) * 4)
	if float64(numWords)*entropyPerWord > entropyAvailable {
		return nil, errors.New("Output entropy of hash function is too small")
	}
	phrase := make([]string, 0, numWords)
	n := new(big.Int).SetBytes(hash)
	size := big.NewInt(int64(len(words)))
	rem := new(big.Int)
	for ; numWords > 0; numWords-- {
		n.DivMod(n, size, rem)
		phrase = append(phrase, words[rem.Int64()])
	}
	return phrase, nil
}

// PwnedPasswordsAPI is the Have I Been Pwned range API (AuditService PwnedPasswordsApi).
var PwnedPasswordsAPI = "https://api.pwnedpasswords.com/range/"

var lineSplit = regexp.MustCompile(`\r?\n`)

// passwordLeaked mirrors AuditService.passwordLeaked (non-strict, padded): the k-anonymity range
// lookup. The HTTP status is not checked, like upstream. It returns the count as printed by
// `exposedNumber.toString()`.
func passwordLeaked(client *http.Client, password string) (string, error) {
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	hashStart, hashEnding := hash[:5], hash[5:]

	req, err := http.NewRequest("GET", PwnedPasswordsAPI+hashStart, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	for _, line := range lineSplit.Split(string(body), -1) {
		parts := strings.Split(line, ":")
		if parts[0] != hashEnding {
			continue
		}
		count := ""
		if len(parts) > 1 {
			count = parts[1]
		}
		return jsParseInt(count), nil
	}
	return "0", nil
}

// jsParseInt mirrors String(parseInt(s, 10)).
func jsParseInt(s string) string {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	sign := ""
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		if s[0] == '-' {
			sign = "-"
		}
		s = s[1:]
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return "NaN"
	}
	digits := strings.TrimLeft(s[:end], "0")
	if digits == "" {
		return "0"
	}
	return sign + digits
}
