package wordlist

import "testing"

func TestEFFLongWordList(t *testing.T) {
	if got := len(EFFLongWordList); got != 7776 {
		t.Fatalf("len = %d, want 7776", got)
	}
	if EFFLongWordList[0] != "abacus" || EFFLongWordList[7775] != "zoom" {
		t.Fatalf("unexpected first/last words %q %q", EFFLongWordList[0], EFFLongWordList[7775])
	}
	seen := map[string]bool{}
	for _, w := range EFFLongWordList {
		if w == "" || seen[w] {
			t.Fatalf("empty or duplicate word %q", w)
		}
		seen[w] = true
	}
}
