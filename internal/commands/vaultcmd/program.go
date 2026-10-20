package vaultcmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

func init() {
	root.Register(200, func(rootCmd *cobra.Command, a *app.App) { rootCmd.AddCommand(listCommand(a)) })
	root.Register(210, func(rootCmd *cobra.Command, a *app.App) { rootCmd.AddCommand(getCommand(a)) })
}

// ListObjects are the objects accepted by `bw list` (vault.program.ts listCommand).
var ListObjects = []string{"items", "folders", "collections", "org-collections", "org-members", "organizations"}

// GetObjects are the objects accepted by `bw get` (vault.program.ts getCommand).
var GetObjects = []string{
	"item", "username", "password", "uri", "totp", "notes", "exposed", "attachment", "folder",
	"collection", "org-collection", "organization", "template", "fingerprint", "send",
}

// requireArgs reports missing arguments like commander.
func requireArgs(names ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < len(names) {
			return fmt.Errorf("missing required argument '%s'", names[len(args)])
		}
		return nil
	}
}

// validateObject mirrors VaultProgram.validateObject (case-sensitive, like `includes`).
func validateObject(requested string, valid []string) bool {
	for _, o := range valid {
		if o == requested {
			return true
		}
	}
	cli.Process(cli.BadRequest(`Unknown object "`+requested+`". Allowed objects are: `+
		strings.Join(valid, ", ")+"."), false)
	return false
}

const listHelp = `
  Notes:

    Combining search with a filter performs a logical AND operation.

    Combining multiple filters performs a logical OR operation.

  Examples:

    bwgo list items
    bwgo list items --folderid 60556c31-e649-4b5d-8daf-fc1c391a1bf2
    bwgo list items --search google --folderid 60556c31-e649-4b5d-8daf-fc1c391a1bf2
    bwgo list items --url https://google.com
    bwgo list items --folderid null
    bwgo list items --organizationid notnull
    bwgo list items --folderid 60556c31-e649-4b5d-8daf-fc1c391a1bf2 --organizationid notnull
    bwgo list items --trash
    bwgo list items --archived
    bwgo list folders --search email
    bwgo list org-members --organizationid 60556c31-e649-4b5d-8daf-fc1c391a1bf2
`

const getHelp = `
  If raw output is specified and no output filename or directory is given for
  an attachment query, the attachment content is written to stdout.

  Examples:

    bwgo get item 99ee88d2-6046-4ea7-92c2-acac464b1412
    bwgo get password https://google.com
    bwgo get totp google.com
    bwgo get notes google.com
    bwgo get exposed yahoo.com
    bwgo get attachment b857igwl1dzrs2 --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --output ./photo.jpg
    bwgo get attachment photo.jpg --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --raw
    bwgo get folder email
    bwgo get template folder
`

func listCommand(a *app.App) *cobra.Command {
	var opts ListOptions
	cmd := &cobra.Command{
		Use:   "list <object>",
		Short: "List an array of objects from the vault.",
		Long: "List an array of objects from the vault.\n\nArguments:\n  object  Valid objects are: " +
			strings.Join(ListObjects, ", "),
		Args: requireArgs("object"),
		Run: func(cmd *cobra.Command, args []string) {
			object := args[0]
			if !validateObject(object, ListObjects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(List(a, object, opts), false)
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&opts.Search, "search", "", "Perform a search on the listed objects.")
	f.StringVar(&opts.URL, "url", "", "Filter items of type login with a url-match search.")
	f.StringVar(&opts.FolderID, "folderid", "", "Filter items by folder id.")
	f.StringVar(&opts.CollectionID, "collectionid", "", "Filter items by collection id.")
	f.StringVar(&opts.OrganizationID, "organizationid", "", "Filter items or collections by organization id.")
	f.BoolVar(&opts.Trash, "trash", false, "Filter items that are deleted and in the trash.")
	f.BoolVar(&opts.Archived, "archived", false, "Filter items that are archived.")
	root.Examples(cmd, listHelp)
	return cmd
}

func getCommand(a *app.App) *cobra.Command {
	var opts GetOptions
	cmd := &cobra.Command{
		Use:   "get <object> <id>",
		Short: "Get an object from the vault.",
		Long: "Get an object from the vault.\n\nArguments:\n  object  Valid objects are: " +
			strings.Join(GetObjects, ", ") + "\n  id      Search term or object's globally unique `id`.",
		Args: requireArgs("object", "id"),
		Run: func(cmd *cobra.Command, args []string) {
			object, id := args[0], args[1]
			if !validateObject(object, GetObjects) {
				return
			}
			a.ExitIfLocked()
			cli.Process(Get(a, object, id, opts), false)
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&opts.ItemID, "itemid", "", "Attachment's item id.")
	f.StringVar(&opts.Output, "output", "", "Output directory or filename for attachment.")
	f.StringVar(&opts.OrganizationID, "organizationid", "", "Organization id for an organization object.")
	root.Examples(cmd, getHelp)
	return cmd
}
