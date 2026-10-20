package auth

import (
	"strings"
	"unicode/utf16"

	"github.com/lassejlv/bw-go/internal/zxcvbn"
)

// MaxPasswordStrengthLength mirrors MAX_PASSWORD_STRENGTH_LENGTH: longer inputs are truncated (in
// UTF-16 code units) before scoring.
const MaxPasswordStrengthLength = 256

// PasswordStrength mirrors PasswordStrengthService.getPasswordStrength(password, email,
// userInputs)?.score: the zxcvbn score with "bitwarden", "bit", "warden", the extra inputs and
// the words of the email's local part as user inputs. It returns nil for an empty password.
func PasswordStrength(password, email string, userInputs ...string) *int {
	if password == "" {
		return nil
	}
	inputs := []string{"bitwarden", "bit", "warden"}
	inputs = append(inputs, userInputs...)
	inputs = append(inputs, emailToUserInputs(email)...)
	seen := map[string]bool{}
	unique := inputs[:0]
	for _, in := range inputs {
		if !seen[in] {
			seen[in] = true
			unique = append(unique, in)
		}
	}
	units := utf16.Encode([]rune(password))
	if len(units) > MaxPasswordStrengthLength {
		units = units[:MaxPasswordStrengthLength]
	}
	score := zxcvbn.PasswordStrengthUTF16(units, unique).Score
	return &score
}

// emailToUserInputs mirrors PasswordStrengthService.emailToUserInputs: the trimmed, lower-cased
// local part split on every character outside [A-Za-z0-9] (empty parts kept, like String.split).
func emailToUserInputs(email string) []string {
	at := strings.Index(email, "@")
	if at < 0 {
		return nil
	}
	local := zxcvbn.ToLower(strings.TrimSpace(email[:at]))
	var out []string
	start := 0
	for i, r := range local {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9') {
			out = append(out, local[start:i])
			start = i + len(string(r))
		}
	}
	return append(out, local[start:])
}
