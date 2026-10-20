// Package tools registers the generate, encode, update, completion and sdk-version commands
// (apps/cli/src/tools/generate.command.ts and apps/cli/src/commands/{encode,update,completion}).
package tools

import (
	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

func init() {
	root.Register(100, func(r *cobra.Command, a *app.App) { r.AddCommand(newSdkVersionCommand()) })
	root.Register(110, func(r *cobra.Command, a *app.App) { r.AddCommand(newGenerateCommand(a)) })
	root.Register(120, func(r *cobra.Command, a *app.App) { r.AddCommand(newEncodeCommand(a)) })
	root.Register(130, func(r *cobra.Command, a *app.App) { r.AddCommand(newUpdateCommand(a)) })
	root.Register(140, func(r *cobra.Command, a *app.App) { r.AddCommand(newCompletionCommand()) })
}
