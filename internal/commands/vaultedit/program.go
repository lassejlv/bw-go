package vaultedit

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

// Registration order relative to the other vault commands (vault.program.ts: list, get, create,
// edit, delete, restore, move, confirm, import, export, share, archive).
func init() {
	root.Register(220, func(r *cobra.Command, a *app.App) { r.AddCommand(createCommand(a)) })
	root.Register(230, func(r *cobra.Command, a *app.App) { r.AddCommand(editCommand(a)) })
	root.Register(240, func(r *cobra.Command, a *app.App) { r.AddCommand(deleteCommand(a)) })
	root.Register(250, func(r *cobra.Command, a *app.App) { r.AddCommand(restoreCommand(a)) })
	root.Register(260, func(r *cobra.Command, a *app.App) { r.AddCommand(shareCommand(a, "move", false)) })
	root.Register(270, func(r *cobra.Command, a *app.App) { r.AddCommand(confirmCommand(a)) })
	root.Register(280, func(r *cobra.Command, a *app.App) { r.AddCommand(shareCommand(a, "share", true)) })
	root.Register(290, func(r *cobra.Command, a *app.App) { r.AddCommand(archiveCommand(a)) })
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

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// validateObject mirrors VaultProgram.validateObject (case-sensitive, like Array.includes).
func validateObject(object string, valid []string) bool {
	for _, v := range valid {
		if v == object {
			return true
		}
	}
	cli.Process(cli.BadRequest(`Unknown object "`+object+`". Allowed objects are: `+strings.Join(valid, ", ")+"."), false)
	return false
}

// argumentsHelp formats commander's "Arguments:" section.
func argumentsHelp(description string, args ...[2]string) string {
	width := 0
	for _, a := range args {
		if len(a[0]) > width {
			width = len(a[0])
		}
	}
	var b strings.Builder
	b.WriteString(description + "\n\nArguments:")
	for _, a := range args {
		b.WriteString(fmt.Sprintf("\n  %-*s  %s", width, a[0], a[1]))
	}
	return b.String()
}

func createCommand(a *app.App) *cobra.Command {
	objects := []string{"item", "attachment", "folder", "org-collection"}
	var opts CreateOptions
	cmd := &cobra.Command{
		Use:   "create <object> [encodedJson]",
		Short: "Create an object in the vault.",
		Long: argumentsHelp("Create an object in the vault.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"encodedJson", "Encoded json of the object to create. Can also be piped into stdin."}),
		Args: requireArgs("object"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(CreateEncoded(a, args[0], argAt(args, 1), opts), false)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.File, "file", "", "Path to file for attachment.")
	f.StringVar(&opts.ItemID, "itemid", "", "Attachment's item id.")
	f.StringVar(&opts.OrganizationID, "organizationid", "", "Organization id for an organization object.")
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw create folder eyJuYW1lIjoiTXkgRm9sZGVyIn0K\n"+
		"    echo 'eyJuYW1lIjoiTXkgRm9sZGVyIn0K' | bw create folder\n"+
		"    bw create attachment --file ./myfile.csv --itemid 16b15b89-65b3-4639-ad2a-95052a6d8f66\n")
	return cmd
}

func editCommand(a *app.App) *cobra.Command {
	objects := []string{"item", "item-collections", "folder", "org-collection"}
	var opts EditOptions
	cmd := &cobra.Command{
		Use:   "edit <object> <id> [encodedJson]",
		Short: "Edit an object from the vault.",
		Long: argumentsHelp("Edit an object from the vault.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"id", "Object's globally unique `id`."},
			[2]string{"encodedJson", "Encoded json of the object to create. Can also be piped into stdin."}),
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(EditEncoded(a, args[0], args[1], argAt(args, 2), opts), false)
		},
	}
	cmd.Flags().StringVar(&opts.OrganizationID, "organizationid", "", "Organization id for an organization object.")
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw edit folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02 eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==\n"+
		"    echo 'eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==' | bw edit folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02\n"+
		"    bw edit item-collections 78307355-fd25-416b-88b8-b33fd0e88c82 WyI5NzQwNTNkMC0zYjMzLTRiOTgtODg2ZS1mZWNmNWM4ZGJhOTYiXQ==\n")
	return cmd
}

func deleteCommand(a *app.App) *cobra.Command {
	objects := []string{"item", "attachment", "folder", "org-collection"}
	var opts DeleteOptions
	cmd := &cobra.Command{
		Use:   "delete <object> <id>",
		Short: "Delete an object from the vault.",
		Long: argumentsHelp("Delete an object from the vault.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"id", "Object's globally unique `id`."}),
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(Delete(a, args[0], args[1], opts), false)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.ItemID, "itemid", "", "Attachment's item id.")
	f.StringVar(&opts.OrganizationID, "organizationid", "", "Organization id for an organization object.")
	f.BoolVarP(&opts.Permanent, "permanent", "p", false, "Permanently deletes the item instead of soft-deleting it (item only).")
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw delete item 7063feab-4b10-472e-b64c-785e2b870b92\n"+
		"    bw delete item 89c21cd2-fab0-4f69-8c6e-ab8a0168f69a --permanent\n"+
		"    bw delete folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02\n"+
		"    bw delete attachment b857igwl1dzrs2 --itemid 310d5ffd-e9a2-4451-af87-ea054dce0f78\n")
	return cmd
}

func restoreCommand(a *app.App) *cobra.Command {
	objects := []string{"item"}
	cmd := &cobra.Command{
		Use:   "restore <object> <id>",
		Short: "Restores an object from the trash or archive.",
		Long: argumentsHelp("Restores an object from the trash or archive.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"id", "Object's globally unique `id`."}),
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(Restore(a, args[0], args[1]), false)
		},
	}
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw restore item 7063feab-4b10-472e-b64c-785e2b870b92\n")
	return cmd
}

func archiveCommand(a *app.App) *cobra.Command {
	objects := []string{"item"}
	cmd := &cobra.Command{
		Use:   "archive <object> <id>",
		Short: "Archive an object from the vault.",
		Long: argumentsHelp("Archive an object from the vault.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"id", "Object's globally unique `id`."}),
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(Archive(a, args[0], args[1]), false)
		},
	}
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw archive item 7063feab-4b10-472e-b64c-785e2b870b92\n")
	return cmd
}

func shareCommand(a *app.App, name string, deprecated bool) *cobra.Command {
	desc := "Move an item to an organization."
	if deprecated {
		desc = "--DEPRECATED-- " + desc
	}
	cmd := &cobra.Command{
		Use:   name + " <id> <organizationId> [encodedJson]",
		Short: desc,
		Long: argumentsHelp(desc,
			[2]string{"id", "Object's globally unique `id`."},
			[2]string{"organizationId", "Organization's globally unique `id`."},
			[2]string{"encodedJson", "Encoded json of an array of collection ids. Can also be piped into stdin."}),
		Args: requireArgs("id", "organizationId"),
		Run: func(cmd *cobra.Command, args []string) {
			a.ExitIfLocked()
			cli.Process(MoveEncoded(a, args[0], args[1], argAt(args, 2)), false)
		},
	}
	help := "\n  Examples:\n\n" +
		"    bw " + name + " 4af958ce-96a7-45d9-beed-1e70fabaa27a " +
		"6d82949b-b44d-468a-adae-3f3bacb0ea32 WyI5NzQwNTNkMC0zYjMzLTRiOTgtODg2ZS1mZWNmNWM4ZGJhOTYiXQ==\n" +
		"    echo '[\"974053d0-3b33-4b98-886e-fecf5c8dba96\"]' | bw encode | " +
		"bw " + name + " 4af958ce-96a7-45d9-beed-1e70fabaa27a 6d82949b-b44d-468a-adae-3f3bacb0ea32\n"
	if deprecated {
		help += "\n--DEPRECATED See \"bw move\" for the current implementation--\n"
	}
	root.Examples(cmd, help)
	return cmd
}

func confirmCommand(a *app.App) *cobra.Command {
	objects := []string{"org-member"}
	var opts ConfirmOptions
	cmd := &cobra.Command{
		Use:   "confirm <object> <id>",
		Short: "Confirm an object to the organization.",
		Long: argumentsHelp("Confirm an object to the organization.",
			[2]string{"object", "Valid objects are: " + strings.Join(objects, ", ")},
			[2]string{"id", "Object's globally unique `id`."}),
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			if !validateObject(args[0], objects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(Confirm(a, args[0], args[1], opts), false)
		},
	}
	cmd.Flags().StringVar(&opts.OrganizationID, "organizationid", "", "Organization id for an organization object.")
	root.Examples(cmd, "\n  Examples:\n\n"+
		"    bw confirm org-member 7063feab-4b10-472e-b64c-785e2b870b92 --organizationid 310d5ffd-e9a2-4451-af87-ea054dce0f78\n")
	return cmd
}
