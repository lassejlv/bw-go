package auth

import (
	"strings"
	"testing"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/state"
)

func TestPasswordStrength(t *testing.T) {
	// getPasswordStrength(password, email).score computed with zxcvbn 4.4.2 under Node.js
	cases := []struct {
		pw, email string
		score     int
	}{
		{"lassevestergaard2024", "lasse.vestergaard@example.com", 3},
		{"lassevestergaard2024", "someone@example.com", 4},
		{"Vestergaard!Lasse", "lasse.vestergaard@example.com", 3},
		{"johnsmith1985", "john_smith@example.com", 2},
		{"bitwarden2024!", "x@y.z", 2},
		{"correct horse battery staple", "u@example.com", 4},
		{"Tr0ub4dour&3", "troubadour@example.com", 1},
	}
	for _, c := range cases {
		got := PasswordStrength(c.pw, c.email)
		if got == nil || *got != c.score {
			t.Errorf("%q / %q: got %v, want %d", c.pw, c.email, got, c.score)
		}
	}
	if PasswordStrength("", "a@b.c") != nil {
		t.Error("empty password must have no strength")
	}
	// only the first 256 code units are scored
	long := strings.Repeat("a", 256)
	if a, b := PasswordStrength(long, ""), PasswordStrength(long+"Zq8#xK2!pW", ""); *a != *b {
		t.Errorf("truncation: %d vs %d", *a, *b)
	}
	if got := strings.Join(emailToUserInputs(" John..Smith+tag@x.com"), "|"); got != "john||smith|tag" {
		t.Errorf("emailToUserInputs = %q", got)
	}
	if emailToUserInputs("no-at-sign") != nil {
		t.Error("expected no inputs without @")
	}
}

func intp(i int) *int { return &i }

func TestEvaluateMasterPasswordMinComplexity(t *testing.T) {
	p := &MasterPasswordPolicyResponse{MinComplexity: 3}
	if EvaluateMasterPassword(intp(2), "whatever", p) {
		t.Error("score 2 must fail minComplexity 3")
	}
	if !EvaluateMasterPassword(intp(3), "whatever", p) || !EvaluateMasterPassword(nil, "", p) {
		t.Error("score 3 (or no score) must pass minComplexity 3")
	}
	if !EvaluateMasterPassword(intp(0), "x", &MasterPasswordPolicyResponse{}) {
		t.Error("minComplexity 0 is not enforced")
	}
}

func TestWeakMasterPasswordForcesReset(t *testing.T) {
	t.Setenv("BITWARDENCLI_APPDATA_DIR", t.TempDir())
	a, err := app.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Store.Update(func(d *state.Data) error {
		d.ActiveUserID = "u1"
		d.Accounts = map[string]*state.Account{"u1": {UserID: "u1", Email: "lasse.vestergaard@example.com"}}
		return nil
	})
	policy := &MasterPasswordPolicyResponse{MinComplexity: 4, EnforceOnLogin: true}
	run := func(pw string) int {
		_ = a.UpdateAccount(func(acct *state.Account) error { acct.ForceSetPasswordReason = ForceSetPasswordNone; return nil })
		s := &Strategy{a: a, Kind: KindPassword, masterPassword: pw, userEnteredEmail: "lasse.vestergaard@example.com"}
		resp := &IdentityResponse{Token: &TokenResponse{MasterPasswordPolicy: policy}}
		if err := s.evaluateMasterPasswordIfRequired(resp, &AuthResult{UserID: "u1"}); err != nil {
			t.Fatal(err)
		}
		return a.ActiveAccount().ForceSetPasswordReason
	}
	// scores 3 only because the email's local part is a user input
	if got := run("lassevestergaard2024"); got != ForceSetPasswordWeakMasterPassword {
		t.Fatalf("weak password: reason %d", got)
	}
	if got := run("correct horse battery staple"); got != ForceSetPasswordNone {
		t.Fatalf("strong password: reason %d", got)
	}

	// with a two-factor response the reason is kept on the strategy for later
	s := &Strategy{a: a, Kind: KindPassword, masterPassword: "Tr0ub4dour&3", userEnteredEmail: "troubadour@example.com"}
	if err := s.evaluateMasterPasswordIfRequired(&IdentityResponse{TwoFactor: &TwoFactorResponse{MasterPasswordPolicy: policy}}, nil); err != nil {
		t.Fatal(err)
	}
	if s.forceReason != ForceSetPasswordWeakMasterPassword {
		t.Fatalf("two-factor force reason %d", s.forceReason)
	}
}
