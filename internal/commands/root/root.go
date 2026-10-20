// Package root builds the `bw` cobra command tree. Command packages register themselves from
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

// Register queues a registrar. order controls the position in `bw --help` (lower first).
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
  Tip: Managing and retrieving secrets for dev environments is easier with Bitwarden Secrets Manager. Learn more under https://bitwarden.com/products/secrets-manager/

  Examples:

    bw login
    bw lock
    bw unlock myPassword321
    bw list --help
    bw list items --search google
    bw get item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bw get password google.com
    echo '{"name":"My Folder"}' | bw encode
    bw create folder eyJuYW1lIjoiTXkgRm9sZGVyIn0K
    bw edit folder c7c7b60b-9c61-40f2-8ccd-36c49595ed72 eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==
    bw delete item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bw archive item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bw generate -lusn --length 18
    bw config server https://bitwarden.example.com
    bw send -f ./file.ext
    bw send "text to send"
    echo "text to send" | bw send
    bw receive https://vault.bitwarden.com/#/send/rg3iuoS_Akm2gqy6ADRHmg/Ht7dYjsqjmgqUM3rjzZDSQ
`

// New builds the full command tree.
func New(a *app.App) *cobra.Command {
	// Keep upstream's command order in help output instead of sorting alphabetically.
	cobra.EnableCommandSorting = false
	// Run the root PersistentPreRun (global flags) even when a subcommand defines its own.
	cobra.EnableTraverseRunHooks = true
	root := &cobra.Command{
		Use:           "bw",
		Short:         "Bitwarden CLI",
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
	root.Flags().BoolP("version", "v", false, "output the version number")
	pf := root.PersistentFlags()
	pf.BoolVar(&flagPretty, "pretty", false, "Format output. JSON is tabbed with two spaces.")
	pf.BoolVar(&flagRaw, "raw", false, "Return raw output instead of a descriptive message.")
	pf.BoolVar(&flagResponse, "response", false, "Return a JSON formatted version of response output.")
	pf.BoolVar(&flagCleanExit, "cleanexit", false, "Exit with a success exit code (0) unless an error is thrown.")
	pf.BoolVar(&flagQuiet, "quiet", false, "Don't return anything to stdout.")
	pf.BoolVar(&flagNoInteraction, "nointeraction", false, "Do not prompt for interactive user input.")
	pf.StringVar(&flagSession, "session", "", "Pass session key instead of reading from env.")
	root.CompletionOptions.DisableDefaultCmd = true

	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		defaultHelp(cmd, args)
		if cmd == root {
			cli.WriteLn(rootExamples, true, false)
		}
	})

	sort.SliceStable(registrars, func(i, j int) bool { return registrars[i].order < registrars[j].order })
	for _, r := range registrars {
		r.fn(root, a)
	}
	return root
}

// Execute runs the CLI and returns the exit code.
func Execute(a *app.App, args []string) int {
	root := New(a)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "unknown command") {
			cli.WriteLn(cli.RedBright("Invalid command: "+strings.Join(args, " ")), false, true)
			cli.WriteLn("See --help for a list of available commands.", true, true)
		} else {
			cli.WriteLn(cli.RedBright("error: "+msg), true, true)
		}
		return 1
	}
	return cli.ExitCode
}

// Examples formats a help epilogue ("Notes"/"Examples" blocks) appended to a command's help.
func Examples(cmd *cobra.Command, text string) {
	def := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		def(c, args)
		if c == cmd {
			cli.WriteLn(text, true, false)
		}
	})
}
