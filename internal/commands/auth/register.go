package auth

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

const loginHelp = `
  Notes:

    See docs for valid ` + "`method`" + ` enum values.

    Pass ` + "`--raw`" + ` option to only return the session key.

  Examples:

    bw login
    bw login john@example.com myPassword321 --raw
    bw login john@example.com myPassword321 --method 1 --code 249213
    bw login --sso
`

const logoutHelp = `
  Examples:

    bw logout
`

const lockHelp = `
  Examples:

    bw lock
`

const unlockHelp = `
  Notes:

    After unlocking, any previous session keys will no longer be valid.

    Pass ` + "`--raw`" + ` option to only return the session key.

  Examples:

    bw unlock
    bw unlock myPassword321
    bw unlock myPassword321 --raw
`

const syncHelp = `
  Examples:

    bw sync
    bw sync -f
    bw sync --last
`

const configHelp = `
  Settings:

    server - On-premises hosted installation URL.

  Examples:

    bw config server
    bw config server https://bw.company.com
    bw config server bitwarden.com
    bw config server --api http://localhost:4000 --identity http://localhost:33656
`

const statusHelp = `

  Example return value:

    {
      "serverUrl": "https://bitwarden.example.com",
      "lastSync": "2020-06-16T06:33:51.419Z",
      "userEmail": "user@example.com,
      "userId": "00000000-0000-0000-0000-000000000000",
      "status": "locked"
    }

  Notes:

  ` + "`status`" + ` is one of:
    - ` + "`unauthenticated`" + ` when you are not logged in
    - ` + "`locked`" + ` when you are logged in and the vault is locked
    - ` + "`unlocked`" + ` when you are logged in and the vault is unlocked
`

// ssoNoValue is the --sso value when the flag is given without an identifier.
const ssoNoValue = "true"

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func init() {
	app.InteractiveUnlock = func(a *app.App) *cli.Response {
		return Unlock(a, "", UnlockOptions{})
	}

	root.Register(10, func(rootCmd *cobra.Command, a *app.App) {
		var o LoginOptions
		var sso string
		var check bool
		cmd := &cobra.Command{
			Use:   "login [email] [password]",
			Short: "Log into a user account.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				if check {
					cli.Process(LoginCheck(a), true)
					return
				}
				a.ExitIfAuthed()
				if cmd.Flags().Changed("sso") {
					v := sso
					if v == ssoNoValue {
						v = ""
					}
					o.Sso = &v
				}
				cli.Process(Login(a, argAt(args, 0), argAt(args, 1), o), true)
			},
		}
		f := cmd.Flags()
		f.StringVar(&o.Method, "method", "", "Two-step login method.")
		f.StringVar(&o.Code, "code", "", "Two-step login code.")
		f.StringVar(&sso, "sso", "", "Log in with Single-Sign On with optional organization identifier.")
		f.Lookup("sso").NoOptDefVal = ssoNoValue
		f.BoolVar(&o.APIKey, "apikey", false, "Log in with an Api Key.")
		f.StringVar(&o.PasswordEnv, "passwordenv", "", "Environment variable storing your password")
		f.StringVar(&o.PasswordFile, "passwordfile", "", "Path to a file containing your password as its first line")
		f.BoolVar(&check, "check", false, "Check login status.")
		root.Examples(cmd, loginHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(20, func(rootCmd *cobra.Command, a *app.App) {
		cmd := &cobra.Command{
			Use:   "logout",
			Short: "Log out of the current user account.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				a.ExitIfNotAuthed()
				cli.Process(Logout(a), false)
			},
		}
		root.Examples(cmd, logoutHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(30, func(rootCmd *cobra.Command, a *app.App) {
		cmd := &cobra.Command{
			Use:   "lock",
			Short: "Lock the vault and destroy active session keys.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				a.ExitIfNotAuthed()
				if acct := a.ActiveAccount(); acct != nil && acct.UsesKeyConnector {
					Logout(a)
					cli.Process(cli.Error("You cannot lock your vault because you are using Key Connector. "+
						"To protect your vault, you have been logged out."), true)
					return
				}
				cli.Process(Lock(a), false)
			},
		}
		root.Examples(cmd, lockHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(40, func(rootCmd *cobra.Command, a *app.App) {
		var o UnlockOptions
		var check bool
		cmd := &cobra.Command{
			Use:   "unlock [password]",
			Short: "Unlock the vault and return a new session key.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				a.ExitIfNotAuthed()
				if check {
					cli.Process(UnlockCheck(a), true)
					return
				}
				cli.Process(Unlock(a, argAt(args, 0), o), false)
			},
		}
		f := cmd.Flags()
		f.BoolVar(&check, "check", false, "Check lock status.")
		f.StringVar(&o.PasswordEnv, "passwordenv", "", "Environment variable storing your password")
		f.StringVar(&o.PasswordFile, "passwordfile", "", "Path to a file containing your password as its first line")
		root.Examples(cmd, unlockHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(50, func(rootCmd *cobra.Command, a *app.App) {
		var o SyncOptions
		cmd := &cobra.Command{
			Use:   "sync",
			Short: "Pull the latest vault data from server.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				a.ExitIfNotAuthed()
				cli.Process(Sync(a, o), false)
			},
		}
		cmd.Flags().BoolVarP(&o.Force, "force", "f", false, "Force a full sync.")
		cmd.Flags().BoolVar(&o.Last, "last", false, "Get the last sync date.")
		root.Examples(cmd, syncHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(60, func(rootCmd *cobra.Command, a *app.App) {
		cmd := &cobra.Command{
			Use:   "status",
			Short: "Show server, last sync, user information, and vault status.",
			Args:  cobra.ArbitraryArgs,
			Run: func(cmd *cobra.Command, args []string) {
				cli.Process(Status(a), false)
			},
		}
		root.Examples(cmd, statusHelp)
		rootCmd.AddCommand(cmd)
	})

	root.Register(70, func(rootCmd *cobra.Command, a *app.App) {
		var o ConfigOptions
		cmd := &cobra.Command{
			Use:   "config <setting> [value]",
			Short: "Configure CLI settings.",
			Args: func(cmd *cobra.Command, args []string) error {
				if len(args) < 1 {
					return errors.New("missing required argument 'setting'")
				}
				return nil
			},
			Run: func(cmd *cobra.Command, args []string) {
				cli.Process(Config(a, args[0], argAt(args, 1), o), false)
			},
		}
		f := cmd.Flags()
		f.StringVar(&o.WebVault, "web-vault", "", "Provides a custom web vault URL that differs from the base URL.")
		f.StringVar(&o.API, "api", "", "Provides a custom API URL that differs from the base URL.")
		f.StringVar(&o.Identity, "identity", "", "Provides a custom identity URL that differs from the base URL.")
		f.StringVar(&o.Icons, "icons", "", "Provides a custom icons service URL that differs from the base URL.")
		f.StringVar(&o.Notifications, "notifications", "", "Provides a custom notifications URL that differs from the base URL.")
		f.StringVar(&o.Events, "events", "", "Provides a custom events URL that differs from the base URL.")
		f.StringVar(&o.KeyConnector, "key-connector", "", "Provides the URL for your Key Connector server.")
		root.Examples(cmd, configHelp)
		rootCmd.AddCommand(cmd)
	})
}
