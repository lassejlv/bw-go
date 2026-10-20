package serve

import (
	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

const serveHelp = "\n  Notes:\n\n" +
	"    Default hostname is `localhost`.\n" +
	"    Use hostname `all` for no hostname binding.\n" +
	"    Default port is `8087`.\n\n" +
	"  Examples:\n\n" +
	"    bwgo serve\n" +
	"    bwgo serve --port 8080\n" +
	"    bwgo serve --hostname bwapi.mydomain.com --port 80\n"

func init() {
	root.Register(400, func(r *cobra.Command, a *app.App) { r.AddCommand(newServeCommand(a)) })
}

func newServeCommand(a *app.App) *cobra.Command {
	var o Options
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a RESTful API webserver.",
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfNotAuthed()
			if err := Run(a, o); err != nil {
				cli.WriteLn(cli.RedBright(err.Error()), true, true)
				cli.Exit(1)
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Hostname, "hostname", "", "The hostname to bind your API webserver to.")
	f.StringVar(&o.Port, "port", "", "The port to run your API webserver on.")
	f.BoolVar(&o.DisableOriginProtection, "disable-origin-protection", false,
		"If set, allows requests with origin header. Warning, this option exists for backwards compatibility reasons and exposes your environment to known CSRF attacks.")
	root.Examples(cmd, serveHelp)
	return cmd
}
