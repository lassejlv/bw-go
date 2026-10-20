// Package root builds the `bwgo` cobra command tree. Command packages register themselves from
// init() via Register, and main blank-imports them.
package root

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/version"
)

// Registrar adds commands to the root command.
type Registrar func(root *cobra.Command, a *app.App)

type entry struct {
	order int
	fn    Registrar
}

var registrars []entry

// Register queues a registrar. order controls the position in `bwgo --help` (lower first).
func Register(order int, fn Registrar) { registrars = append(registrars, entry{order, fn}) }

// Global flag values.
var (
	flagPretty, flagRaw, flagResponse, flagCleanExit, flagQuiet, flagNoInteraction bool
	flagSession                                                                    string
)

// ApplyGlobalFlags exports global flags to the environment like the Node CLI's option events.
func ApplyGlobalFlags() {
	set := func(on bool, name string) {
		if on {
			os.Setenv(name, "true")
		}
	}
	set(flagPretty, "BW_PRETTY")
	set(flagRaw, "BW_RAW")
	set(flagQuiet, "BW_QUIET")
	set(flagResponse, "BW_RESPONSE")
	set(flagCleanExit, "BW_CLEANEXIT")
	set(flagNoInteraction, "BW_NOINTERACTION")
	if flagSession != "" {
		os.Setenv("BW_SESSION", flagSession)
	}
}

const rootExamples = `
  Examples:

    bwgo login
    bwgo lock
    bwgo unlock myPassword321
    bwgo list --help
    bwgo list items --search google
    bwgo get item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bwgo get password google.com
    echo '{"name":"My Folder"}' | bwgo encode
    bwgo create folder eyJuYW1lIjoiTXkgRm9sZGVyIn0K
    bwgo edit folder c7c7b60b-9c61-40f2-8ccd-36c49595ed72 eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==
    bwgo delete item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bwgo archive item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bwgo generate -lusn --length 18
    bwgo config server https://bitwarden.example.com
    bwgo send -f ./file.ext
    bwgo send "text to send"
    echo "text to send" | bwgo send
    bwgo receive https://vault.bitwarden.com/#/send/rg3iuoS_Akm2gqy6ADRHmg/Ht7dYjsqjmgqUM3rjzZDSQ

  Tip: Managing and retrieving secrets for dev environments is easier with Bitwarden Secrets Manager. Learn more under https://bitwarden.com/products/secrets-manager/
`

// New builds the full command tree.
func New(a *app.App) *cobra.Command {
	// Keep upstream's command order in help output instead of sorting alphabetically.
	cobra.EnableCommandSorting = false
	// Run the root PersistentPreRun (global flags) even when a subcommand defines its own.
	cobra.EnableTraverseRunHooks = true
	root := &cobra.Command{
		Use:           "bwgo",
		Short:         "Bitwarden CLI (unofficial Go port)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("unknown command %q", args[0])
			}
			return nil
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) { ApplyGlobalFlags() },
		Run:              func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.Flags().BoolP("version", "v", false, "Show the version number.")
	pf := root.PersistentFlags()
	pf.BoolVar(&flagPretty, "pretty", false, "Format output. JSON is tabbed with two spaces.")
	pf.BoolVar(&flagRaw, "raw", false, "Return raw output instead of a descriptive message.")
	pf.BoolVar(&flagResponse, "response", false, "Return a JSON formatted version of response output.")
	pf.BoolVar(&flagCleanExit, "cleanexit", false, "Exit with a success exit code (0) unless an error is thrown.")
	pf.BoolVar(&flagQuiet, "quiet", false, "Don't return anything to stdout.")
	pf.BoolVar(&flagNoInteraction, "nointeraction", false, "Do not prompt for interactive user input.")
	pf.StringVar(&flagSession, "session", "", "Pass session key instead of reading from env.")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SuggestionsMinimumDistance = 2

	root.SetHelpFunc(renderHelp)
	Examples(root, rootExamples)

	sort.SliceStable(registrars, func(i, j int) bool { return registrars[i].order < registrars[j].order })
	for _, r := range registrars {
		r.fn(root, a)
	}
	keepFlagOrder(root)
	return root
}

// Execute runs the CLI and returns the exit code.
func Execute(a *app.App, args []string) int {
	root := New(a)
	root.SetArgs(args)
	cmd, err := root.ExecuteC()
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "unknown command") {
			cli.WriteLn(cli.RedBright("Invalid command: "+strings.Join(args, " ")), false, true)
			if len(args) > 0 {
				if hint := unknownCommandHint(root, args[0]); hint != "" {
					cli.WriteLn(hint, false, true)
				}
			}
			cli.WriteLn(cli.Err.Dim("See `"+root.Name()+" --help` for a list of available commands."), true, true)
		} else {
			cli.WriteLn(cli.RedBright("error: "+msg), false, true)
			cli.WriteLn(cli.Err.Dim("See `"+cmd.CommandPath()+" --help` for usage."), true, true)
		}
		return 1
	}
	return cli.ExitCode
}
