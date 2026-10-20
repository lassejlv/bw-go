package tools

import (
	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/version"
)

// SdkVersion returns the version printed by `bw sdk-version`. This port has no Bitwarden SDK, so
// it reports the application version.
func SdkVersion() string { return version.Version }

func newSdkVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sdk-version",
		Short: "Print the SDK version.",
		Run: func(cmd *cobra.Command, args []string) {
			cli.WriteLn(SdkVersion(), true, false)
		},
	}
}
