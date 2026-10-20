// Package wordlist exposes the EFF long word list used by Bitwarden for passphrases and
// fingerprint phrases (libs/common/src/platform/misc/wordlist.ts).
package wordlist

import (
	_ "embed"
	"strings"
)

//go:embed eff_long_wordlist.txt
var effLongWordListText string

// EFFLongWordList is EFF's Long Wordlist from https://www.eff.org/dice (7776 words), in the same
// order as the upstream EFFLongWordList array.
var EFFLongWordList = strings.Fields(effLongWordListText)
