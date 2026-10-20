package tools

import (
	"net/url"
	"strings"
	"unicode/utf16"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/generator"
)

// GenerateOptions are the raw `bw generate` options as given on the command line or in the
// `serve` query string. String options are nil when not provided.
type GenerateOptions struct {
	Uppercase     bool
	Lowercase     bool
	Number        bool
	Special       bool
	Passphrase    bool
	Capitalize    bool
	IncludeNumber bool
	// Ambiguous is the `--ambiguous` flag: avoid ambiguous characters.
	Ambiguous bool

	Length     *string
	Words      *string
	MinNumber  *string
	MinSpecial *string
	Separator  *string
}

// convertBooleanOption mirrors CliUtils.convertBooleanOption for string values.
func convertBooleanOption(v string) bool { return v == "" || strings.ToLower(v) == "true" }

// GenerateOptionsFromQuery parses `serve` query parameters (GET /generate).
func GenerateOptionsFromQuery(q url.Values) GenerateOptions {
	b := func(name string) bool {
		if !q.Has(name) {
			return false
		}
		return convertBooleanOption(q.Get(name))
	}
	s := func(name string) *string {
		if !q.Has(name) {
			return nil
		}
		v := q.Get(name)
		return &v
	}
	return GenerateOptions{
		Uppercase:     b("uppercase"),
		Lowercase:     b("lowercase"),
		Number:        b("number"),
		Special:       b("special"),
		Passphrase:    b("passphrase"),
		Capitalize:    b("capitalize"),
		IncludeNumber: b("includeNumber"),
		Ambiguous:     b("ambiguous"),
		Length:        s("length"),
		Words:         s("words"),
		MinNumber:     s("minNumber"),
		MinSpecial:    s("minSpecial"),
		Separator:     s("separator"),
	}
}

// normalizedGenerateOptions is the `Options` class of generate.command.ts.
type normalizedGenerateOptions struct {
	uppercase, lowercase, number, special bool
	length                                int
	passphrase                            bool
	separator                             string
	words                                 int
	capitalize, includeNumber             bool
	minNumber, minSpecial                 int
	ambiguous                             bool
}

func numberOption(v *string, def int) int {
	if v == nil {
		return def
	}
	return cli.ConvertNumberOption(*v, def)
}

func normalizeGenerateOptions(o GenerateOptions) normalizedGenerateOptions {
	defPw := generator.DefaultPasswordOptions()
	defPp := generator.DefaultPassphraseOptions()
	n := normalizedGenerateOptions{
		uppercase:     o.Uppercase,
		lowercase:     o.Lowercase,
		number:        o.Number,
		special:       o.Special,
		capitalize:    o.Capitalize,
		includeNumber: o.IncludeNumber,
		ambiguous:     o.Ambiguous,
		length:        numberOption(o.Length, defPw.Length),
		passphrase:    o.Passphrase,
		separator:     defPp.WordSeparator,
		words:         numberOption(o.Words, defPp.NumWords),
		minNumber:     numberOption(o.MinNumber, defPw.MinNumber),
		minSpecial:    numberOption(o.MinSpecial, defPw.MinSpecial),
	}
	if o.Separator != nil {
		n.separator = *o.Separator
	}
	if !n.uppercase && !n.lowercase && !n.special && !n.number {
		n.lowercase = true
		n.uppercase = true
		n.number = true
	}
	if n.length < 5 {
		n.length = 5
	}
	if n.words < 3 {
		n.words = 3
	}
	switch {
	case n.separator == "space":
		n.separator = " "
	case n.separator == "empty":
		n.separator = ""
	case len(utf16.Encode([]rune(n.separator))) > 1:
		n.separator = generator.FirstChar(n.separator)
	}
	return n
}

// shouldEnforcePolicies mirrors the upstream check: an active account with an access token.
func shouldEnforcePolicies(a *app.App) bool {
	if a == nil {
		return false
	}
	acct := a.ActiveAccount()
	return acct != nil && acct.AccessToken != ""
}

// generatorPolicy returns the password generator policies applying to the active account, read
// from the last sync (policies are not encrypted, so no vault key is needed).
func generatorPolicy(a *app.App) generator.GeneratorPolicy {
	acct := a.ActiveAccount()
	if acct == nil {
		return generator.GeneratorPolicy{}
	}
	return generator.CombinePolicies(generator.PoliciesFromState(acct.Vault.Policies, acct.Vault.Profile))
}

// Generate runs `bw generate` (GenerateCommand.run). When a user is logged in, the
// organization password generator policies from the last sync are enforced.
func Generate(a *app.App, opts GenerateOptions) *cli.Response {
	var policy *generator.GeneratorPolicy
	if shouldEnforcePolicies(a) {
		p := generatorPolicy(a)
		policy = &p
	}
	return generate(opts, policy)
}

func generate(opts GenerateOptions, policy *generator.GeneratorPolicy) *cli.Response {
	n := normalizeGenerateOptions(opts)
	pw := generator.PasswordOptions{
		Length:       n.length,
		Ambiguous:    !n.ambiguous,
		Uppercase:    n.uppercase,
		MinUppercase: 1,
		Lowercase:    n.lowercase,
		MinLowercase: 1,
		Number:       n.number,
		MinNumber:    n.minNumber,
		Special:      n.special,
		MinSpecial:   n.minSpecial,
	}
	pp := generator.PassphraseOptions{
		NumWords:      n.words,
		WordSeparator: n.separator,
		Capitalize:    n.capitalize,
		IncludeNumber: n.includeNumber,
	}
	typ := "password"
	if n.passphrase {
		typ = "passphrase"
	}
	if policy != nil {
		typ = policy.ResolveType(typ)
		if typ == "password" {
			pw = policy.Password.Enforce(pw)
		} else {
			pp = policy.Passphrase.Enforce(pp)
		}
	}

	var out string
	var err error
	if typ == "password" {
		out, err = generator.GeneratePassword(pw)
	} else {
		out, err = generator.GeneratePassphrase(pp)
	}
	if err != nil {
		return cli.Error(err)
	}
	return cli.Success(cli.NewString(out))
}

const generateHelp = "\n  Notes:\n\n" +
	"    Default options are `-uln --length 14`.\n\n" +
	"    Minimum `length` is 5.\n\n" +
	"    Minimum `words` is 3.\n\n" +
	"  Examples:\n\n" +
	"    bw generate\n" +
	"    bw generate -u -l --length 18\n" +
	"    bw generate -ulns --length 25\n" +
	"    bw generate -ul\n" +
	"    bw generate -p --separator _\n" +
	"    bw generate -p --words 5 --separator space\n" +
	"    bw generate -p --words 5 --separator empty\n"

func newGenerateCommand(a *app.App) *cobra.Command {
	var o GenerateOptions
	var length, words, minNumber, minSpecial, separator string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a password/passphrase.",
		Run: func(cmd *cobra.Command, args []string) {
			f := cmd.Flags()
			str := func(name, v string) *string {
				if !f.Changed(name) {
					return nil
				}
				return &v
			}
			o.Length = str("length", length)
			o.Words = str("words", words)
			o.MinNumber = str("minNumber", minNumber)
			o.MinSpecial = str("minSpecial", minSpecial)
			o.Separator = str("separator", separator)
			cli.Process(Generate(a, o), false)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&o.Uppercase, "uppercase", "u", false, "Include uppercase characters.")
	f.BoolVarP(&o.Lowercase, "lowercase", "l", false, "Include lowercase characters.")
	f.BoolVarP(&o.Number, "number", "n", false, "Include numeric characters.")
	f.BoolVarP(&o.Special, "special", "s", false, "Include special characters.")
	f.BoolVarP(&o.Passphrase, "passphrase", "p", false, "Generate a passphrase.")
	f.StringVar(&length, "length", "", "Length of the password.")
	f.StringVar(&words, "words", "", "Number of words.")
	f.StringVar(&minNumber, "minNumber", "", "Minimum number of numeric characters.")
	f.StringVar(&minSpecial, "minSpecial", "", "Minimum number of special characters.")
	f.StringVar(&separator, "separator", "", "Word separator.")
	f.BoolVarP(&o.Capitalize, "capitalize", "c", false, "Title case passphrase.")
	f.BoolVar(&o.IncludeNumber, "includeNumber", false, "Passphrase includes number.")
	f.BoolVar(&o.Ambiguous, "ambiguous", false, "Avoid ambiguous characters.")
	root.Examples(cmd, generateHelp)
	return cmd
}
