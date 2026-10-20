// Command bw is a Go port of the Bitwarden CLI (apps/cli in bitwarden/clients).
package main

import (
	"os"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"

	_ "github.com/lassejlv/bw-go/internal/commands/auth"
	_ "github.com/lassejlv/bw-go/internal/commands/importexport"
	_ "github.com/lassejlv/bw-go/internal/commands/send"
	_ "github.com/lassejlv/bw-go/internal/commands/serve"
	_ "github.com/lassejlv/bw-go/internal/commands/tools"
	_ "github.com/lassejlv/bw-go/internal/commands/vaultcmd"
	_ "github.com/lassejlv/bw-go/internal/commands/vaultedit"
)

func main() {
	a, err := app.New()
	if err != nil {
		cli.WriteLn(cli.RedBright(err.Error()), true, true)
		os.Exit(1)
	}
	os.Exit(root.Execute(a, os.Args[1:]))
}
