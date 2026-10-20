package tools

import (
	"encoding/base64"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

// Encode runs `bw encode`: base64 encodes piped stdin (EncodeCommand.run).
func Encode() *cli.Response {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return cli.BadRequest("No stdin was piped in.")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return cli.Error(err)
	}
	return EncodeInput(b)
}

// EncodeInput base64 encodes input as a string response.
func EncodeInput(input []byte) *cli.Response {
	return cli.Success(cli.NewString(base64.StdEncoding.EncodeToString(input)))
}

const encodeHelp = "\n  Notes:\n\n" +
	"    Use to create `encodedJson` for `create` and `edit` commands.\n\n" +
	"  Examples:\n\n" +
	"    echo '{\"name\":\"My Folder\"}' | bwgo encode\n"

func newEncodeCommand(_ *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encode",
		Short: "Base 64 encode stdin.",
		Run: func(cmd *cobra.Command, args []string) {
			cli.Process(Encode(), false)
		},
	}
	root.Examples(cmd, encodeHelp)
	return cmd
}
