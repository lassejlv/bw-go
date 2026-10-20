package send

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

func init() {
	root.Register(300, func(rootCmd *cobra.Command, a *app.App) { rootCmd.AddCommand(sendCommand(a)) })
	// receive is accessible both at `bw receive` and `bw send receive`
	root.Register(310, func(rootCmd *cobra.Command, a *app.App) { rootCmd.AddCommand(receiveCommand(a)) })
}

// requireArgs returns a cobra Args validator reporting missing arguments like commander.
func requireArgs(names ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < len(names) {
			return fmt.Errorf("missing required argument '%s'", names[len(args)])
		}
		return nil
	}
}

// parentOpts are the options declared on `send` and read by its subcommands.
type parentOpts struct {
	password   string
	emails     emailsFlag
	fullObject bool
}

func (p *parentOpts) checkConflicts(cmd *cobra.Command) error {
	pw := cmd.Flags().Lookup("password")
	if pw != nil && pw.Changed && p.emails.set {
		return errors.New("option '--password <password>' cannot be used with option '--emails <emails>'")
	}
	return nil
}

func (p *parentOpts) passwordPtr(cmd *cobra.Command) *string {
	if f := cmd.Flags().Lookup("password"); f != nil && f.Changed {
		s := p.password
		return &s
	}
	return nil
}

func (p *parentOpts) emailList() []string {
	if !p.emails.set {
		return nil
	}
	return p.emails.emails
}

func sendCommand(a *app.App) *cobra.Command {
	po := &parentOpts{}
	var (
		file, hidden                       bool
		deleteInDays, maxAccessCount, name string
		notes                              string
	)
	cmd := &cobra.Command{
		Use:   "send <data>",
		Short: "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send",
		Long: "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send" +
			"\n\nArguments:\n  data  The data to Send. Specify as a filepath with the --file option",
		Args: requireArgs("data"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := po.checkConflicts(cmd); err != nil {
				return err
			}
			q := QuickOptions{File: file, DeleteInDays: deleteInDays, Hidden: hidden, Emails: po.emailList()}
			if cmd.Flags().Changed("name") {
				q.Name = &name
			}
			if cmd.Flags().Changed("notes") {
				q.Notes = &notes
			}
			encoded, resp := MakeSendJSON(args[0], q)
			if resp == nil {
				a.ExitIfLocked()
				opts := CreateOptions{Hidden: hidden, Password: po.passwordPtr(cmd), Emails: po.emailList(), FullObject: po.fullObject}
				if cmd.Flags().Changed("maxAccessCount") {
					opts.MaxAccessCount = &maxAccessCount
				}
				resp = Create(a, encoded, opts)
			}
			cli.Process(resp, false)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&file, "file", "f", false, "Specifies that <data> is a filepath")
	f.StringVarP(&deleteInDays, "deleteInDays", "d", "7", "The number of days in the future to set deletion date, defaults to 7. If a particular deletion date is mandated by enterprise policy that value will override this flag.")
	f.StringVarP(&maxAccessCount, "maxAccessCount", "a", "", "The amount of max possible accesses.")
	f.BoolVar(&hidden, "hidden", false, "Hide <data> in web by default. Valid only if --file is not set.")
	f.StringVarP(&name, "name", "n", "", "The name of the Send. Defaults to a guid for text Sends and the filename for files.")
	f.StringVar(&notes, "notes", "", "Notes to add to the Send.")
	// Declared on `send` and read by create/edit (commander: args.parent.opts()).
	pf := cmd.PersistentFlags()
	pf.StringVar(&po.password, "password", "", "optional password to access this Send. Can also be specified in JSON.")
	pf.Var(&po.emails, "emails", "optional emails to access this Send. Can also be specified in JSON.")
	pf.BoolVar(&po.fullObject, "fullObject", false, "Specifies that the full Send object should be returned rather than just the access url.")

	cmd.AddCommand(
		listCommand(a),
		templateCommand(),
		getCommand(a),
		receiveCommand(a),
		createCommand(a, po),
		editCommand(a, po),
		removePasswordCommand(a),
		deleteCommand(a),
	)
	return cmd
}

func receiveCommand(a *app.App) *cobra.Command {
	var opts ReceiveOptions
	cmd := &cobra.Command{
		Use:   "receive <url>",
		Short: "Access a Bitwarden Send from a url",
		Args:  requireArgs("url"),
		Run: func(cmd *cobra.Command, args []string) {
			cli.Process(Receive(a, args[0], opts), false)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.Password, "password", "", "Password needed to access the Send.")
	f.StringVar(&opts.PasswordEnv, "passwordenv", "", "Environment variable storing the Send's password")
	f.StringVar(&opts.PasswordFile, "passwordfile", "", "Path to a file containing the Sends password as its first line")
	f.BoolVar(&opts.Obj, "obj", false, "Return the Send's json object rather than the Send's content")
	f.StringVar(&opts.Output, "output", "", "Specify a file path to save a File-type Send to")
	root.Examples(cmd, "\nIf a password is required, the provided password is used or the user is prompted.\n")
	return cmd
}

func listCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all the Sends owned by you",
		Args:  cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfLocked()
			cli.Process(List(a, ""), false)
		},
	}
	root.Examples(cmd, "This is in the list command")
	return cmd
}

func templateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "template <object>",
		Short: "Get json templates for send objects",
		Long:  "Get json templates for send objects\n\nArguments:\n  object  Valid objects are: send.text, text, send.file, file",
		Args:  requireArgs("object"),
		Run: func(cmd *cobra.Command, args []string) {
			cli.Process(Template(args[0]), false)
		},
	}
}

func getCommand(a *app.App) *cobra.Command {
	var opts GetOptions
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get Sends owned by you.",
		Args:  requireArgs("id"),
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfLocked()
			cli.Process(Get(a, args[0], opts), false)
		},
	}
	cmd.Flags().StringVar(&opts.Output, "output", "", "Output directory or filename for attachment.")
	cmd.Flags().BoolVar(&opts.Text, "text", false, "Specifies to return the text content of a Send")
	root.Examples(cmd, `
  Id:

    Search term or Send's globally unique `+"`id`"+`.

    If raw output is specified and no output filename or directory is given for
    an attachment query, the attachment content is written to stdout.

  Examples:

    bw send get searchText
    bw send get id
    bw send get searchText --text
    bw send get searchText --file
    bw send get searchText --file --output ../Photos/photo.jpg
    bw send get searchText --file --raw
`)
	return cmd
}

func createCommand(a *app.App, po *parentOpts) *cobra.Command {
	var (
		file, text string
		hidden     bool
	)
	cmd := &cobra.Command{
		Use:   "create [encodedJson]",
		Short: "create a Send",
		Long:  "create a Send\n\nArguments:\n  encodedJson  JSON object to upload. Can also be piped in through stdin.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := po.checkConflicts(cmd); err != nil {
				return err
			}
			encoded := ""
			if len(args) > 0 {
				encoded = args[0]
			}
			opts := CreateOptions{
				File:       file,
				Hidden:     hidden,
				Password:   po.passwordPtr(cmd),
				Emails:     po.emailList(),
				FullObject: po.fullObject,
			}
			if cmd.Flags().Changed("text") {
				opts.Text = &text
			}
			a.ExitIfLocked()
			cli.Process(Create(a, encoded, opts), false)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "file to Send. Can also be specified in parent's JSON.")
	cmd.Flags().StringVar(&text, "text", "", "text to Send. Can also be specified in parent's JSON.")
	cmd.Flags().BoolVar(&hidden, "hidden", false, "text hidden flag. Valid only with the --text option.")
	root.Examples(cmd, "\nNote:\n  Options specified in JSON take precedence over command options\n")
	return cmd
}

func editCommand(a *app.App, po *parentOpts) *cobra.Command {
	var itemID string
	cmd := &cobra.Command{
		Use:   "edit [encodedJson]",
		Short: "edit a Send",
		Long:  "edit a Send\n\nArguments:\n  encodedJson  Updated JSON object to save. If not provided, encodedJson is read from stdin.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := po.checkConflicts(cmd); err != nil {
				return err
			}
			a.ExitIfLocked()
			encoded := ""
			if len(args) > 0 {
				encoded = args[0]
			}
			opts := EditOptions{ItemID: itemID, Emails: po.emailList()}
			if p := po.passwordPtr(cmd); p != nil {
				opts.Password = *p
			}
			cli.Process(Edit(a, encoded, opts), false)
			return nil
		},
	}
	cmd.Flags().StringVar(&itemID, "itemid", "", "Overrides the itemId provided in [encodedJson]")
	root.Examples(cmd, "\nNote:\n  You cannot update a File-type Send's file. Just delete and remake it\n")
	return cmd
}

func deleteCommand(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "delete a Send",
		Long:  "delete a Send\n\nArguments:\n  id  The id of the Send to delete.",
		Args:  requireArgs("id"),
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfLocked()
			cli.Process(Delete(a, args[0]), false)
		},
	}
}

func removePasswordCommand(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-password <id>",
		Short: "removes the saved password from a Send.",
		Long:  "removes the saved password from a Send.\n\nArguments:\n  id  The id of the Send to alter.",
		Args:  requireArgs("id"),
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfLocked()
			cli.Process(RemovePassword(a, args[0]), false)
		},
	}
}
