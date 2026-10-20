package importexport

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/features"
	"github.com/lassejlv/bw-go/internal/importcore"
	"github.com/lassejlv/bw-go/internal/importer"
	_ "github.com/lassejlv/bw-go/internal/importer/all" // every import format
	"github.com/lassejlv/bw-go/internal/importer/model"
	"github.com/lassejlv/bw-go/internal/syncer"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ImportOptions are the `bw import` options. OrganizationID is nil when --organizationid was not
// given (commander leaves it undefined).
type ImportOptions struct {
	Formats        bool
	OrganizationID *string
	KeyFile        string
	PasswordEnv    string
	PasswordFile   string
}

// ImportOptionsFromQuery parses `serve` query parameters.
func ImportOptionsFromQuery(q url.Values) ImportOptions {
	o := ImportOptions{
		KeyFile:      q.Get("keyfile"),
		PasswordEnv:  q.Get("passwordenv"),
		PasswordFile: q.Get("passwordfile"),
	}
	if q.Has("formats") {
		v := q.Get("formats")
		o.Formats = v == "" || strings.EqualFold(v, "true")
	}
	if q.Has("organizationid") {
		v := q.Get("organizationid")
		o.OrganizationID = &v
	}
	return o
}

// importPasswordPrompt is the prompt of ImportCommand.resolveImportPassword.
const importPasswordPrompt = "Import file password:"

// importMasterPasswordRequired is CliUtils.getPassword's BW_NOINTERACTION response.
const importMasterPasswordRequired = "Master password is required. Try again in interactive mode or provide a password file or environment variable."

// importGetPassword is CliUtils.getPassword (replaceable in tests).
var importGetPassword = cli.GetPassword

// importResolvePassword mirrors ImportCommand.resolveImportPassword.
func importResolvePassword(opts ImportOptions) (string, error) {
	pw, resp := importGetPassword("", opts.PasswordFile, opts.PasswordEnv, importPasswordPrompt)
	if resp != nil {
		if msg := resp.MessageText(); msg != importMasterPasswordRequired {
			return "", errors.New(msg) // e.g. a --passwordfile read error, thrown upstream
		}
		return "", errors.New(importer.MsgImportPasswordRequired)
	}
	return pw, nil
}

// importSync is the full sync run after a successful import (replaceable in tests).
var importSync = func(a *app.App) { _ = syncer.FullSync(a, true) }

// Import mirrors ImportCommand.run.
func Import(a *app.App, format, filePath string, opts ImportOptions) *cli.Response {
	var v *vault.Vault
	orgID := ""
	if opts.OrganizationID != nil {
		orgID = *opts.OrganizationID
		var err error
		if v, err = vault.Load(a); err != nil {
			return cli.Error(err)
		}
		org := v.Organization(orgID)
		if org == nil {
			return cli.BadRequest("You do not belong to an organization with the ID of " + orgID +
				". Check the organization ID and sync your vault.")
		}
		if !org.CanAccessImport() {
			return cli.BadRequest("You are not authorized to import into the provided organization.")
		}
	}

	if opts.Formats {
		return importList()
	}
	return importRun(a, v, format, filePath, orgID, opts)
}

// importList mirrors ImportCommand.list.
func importList() *cli.Response {
	list := strings.Join(importer.CLIFormatIDs(), "\n")
	return cli.Success(cli.NewMessage("Supported input formats:", list).SetRaw(list))
}

// importRun mirrors ImportCommand.import.
func importRun(a *app.App, v *vault.Vault, format, filePath, orgID string, opts ImportOptions) *cli.Response {
	if format == "" {
		return cli.BadRequest(importer.MsgFormatNotProvided)
	}
	if err := importer.CheckFileFormat(format); err != nil {
		return cli.BadRequest(err.Error())
	}
	if filePath == "" {
		return cli.BadRequest(importer.MsgFilepathNotProvided)
	}
	if v == nil {
		var err error
		if v, err = vault.Load(a); err != nil {
			return cli.Error(err)
		}
	}

	iopts := importer.Options{
		OrganizationID: orgID,
		PromptPassword: func() (string, error) { return importResolvePassword(opts) },
		Decryptor:      importcore.NewDecryptor(v.Keys()),
		Features:       importer.Features{NewItemTypes: features.Enabled(a, features.NewItemTypes)},
	}
	params := importer.ImportParams{
		OrganizationID:  orgID,
		RestrictedTypes: importcore.RestrictedTypes(v.RestrictedTypes()),
	}

	// SDK-backed importers (keepasskdbx) read the raw file and take their credentials up front.
	if f, ok := importer.LookupFormat(format); ok && f.SDK != nil {
		return importWithSDK(a, v, f, filePath, iopts, params, opts)
	}

	resolved, err := importer.ResolveFormat(format, filePath)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	imp, err := importer.New(resolved, iopts)
	if err != nil {
		return cli.BadRequest(err.Error())
	}

	contents, err := importer.ReadImportFile(format, filePath)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	if contents == "" {
		return cli.BadRequest(importer.MsgImportFileWasEmpty)
	}

	result, err := importer.Import(imp, contents, params)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	if err := importSubmit(a, v, result, orgID); err != nil {
		return cli.BadRequest(err.Error())
	}
	importSync(a)

	// Some items may have been skipped while the rest imported. Report which ones and why.
	if msg := importer.SkippedItemsMessage(result.Errors); msg != "" {
		return cli.Success(cli.NewMessage("Imported "+filePath, msg).SetRaw(msg))
	}
	return cli.Success(cli.NewMessageNull("Imported " + filePath))
}

// importWithSDK mirrors ImportCommand.importWithSdk + ImportService.importWithSdk.
func importWithSDK(a *app.App, v *vault.Vault, f importer.Format, filePath string, iopts importer.Options,
	params importer.ImportParams, opts ImportOptions) *cli.Response {
	file, err := importer.ReadImportFileBytes(filePath)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	if len(file) == 0 {
		return cli.BadRequest(importer.MsgImportFileWasEmpty)
	}

	// collectSdkCredentials
	switch f.SDK.CredentialKind {
	case importer.CredentialPassword, importer.CredentialPasswordWithKeyFile:
		password, err := importResolvePassword(opts)
		if err != nil {
			return cli.BadRequest(err.Error())
		}
		iopts.PromptPassword = func() (string, error) { return password, nil }
		if f.SDK.CredentialKind == importer.CredentialPasswordWithKeyFile && opts.KeyFile != "" {
			if iopts.KeyFile, err = importer.ReadKeyFile(opts.KeyFile); err != nil {
				return cli.BadRequest(err.Error())
			}
		}
	default:
		iopts.PromptPassword = nil
	}

	imp, err := importer.New(f.ID, iopts)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	bi, ok := imp.(importer.BinaryImporter)
	if !ok {
		return cli.BadRequest(fmt.Sprintf("No SDK importer registered for format '%s'.", f.ID))
	}
	result, err := bi.ParseBytes(file)
	if err != nil {
		return cli.BadRequest(err.Error())
	}
	// The SDK pipeline (ImportService.importWithSdk) skips the TS importers' checks ("nothing to
	// import", bad data); it only drops restricted item types. run() already rejected callers
	// without import permission for this org, so the unassigned-items guard cannot trigger.
	importer.DropRestrictedTypes(result, params.RestrictedTypes)
	if err := importSubmit(a, v, result, params.OrganizationID); err != nil {
		return cli.BadRequest(err.Error())
	}
	importSync(a)
	return cli.Success(cli.NewMessageNull(fmt.Sprintf("Imported %d item(s) from %s", len(result.Ciphers), filePath)))
}

// importSubmit encrypts the prepared result and posts it (handleIndividualImport /
// handleOrganizationalImport), mapping failures through handleServerError.
func importSubmit(a *app.App, v *vault.Vault, result *model.ImportResult, orgID string) error {
	path, body, err := importcore.BuildRequest(result, orgID, v.Keys(), v.UserID())
	if err == nil {
		err = a.API.Send("POST", path, body, true, nil, nil)
	}
	if err != nil {
		return importcore.ServerError(err, result)
	}
	return nil
}

const importHelp = `
 Examples:

    bw import --formats
    bw import bitwardencsv ./from/source.csv
    bw import keepass2xml keepass_backup.xml
    bw import --organizationid cf14adc3-aca5-4573-890a-f6fa231436d9 keepass2xml keepass_backup.xml
`

func init() {
	root.Register(275, func(rootCmd *cobra.Command, a *app.App) {
		var formats bool
		var orgID, keyFile, passwordEnv, passwordFile string
		cmd := &cobra.Command{
			Use:   "import [format] [input]",
			Short: "Import vault data from a file.",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) > 2 {
					return fmt.Errorf("too many arguments for 'import'. Expected 2 arguments but got %d.", len(args))
				}
				opts := ImportOptions{Formats: formats, KeyFile: keyFile, PasswordEnv: passwordEnv, PasswordFile: passwordFile}
				if cmd.Flags().Changed("organizationid") {
					opts.OrganizationID = &orgID
				}
				format, input := "", ""
				if len(args) > 0 {
					format = args[0]
				}
				if len(args) > 1 {
					input = args[1]
				}
				a.ExitIfLocked()
				cli.Process(Import(a, format, input, opts), false)
				return nil
			},
		}
		fl := cmd.Flags()
		fl.BoolVar(&formats, "formats", false, "List formats")
		fl.StringVar(&orgID, "organizationid", "", "ID of the organization to import to.")
		fl.StringVar(&keyFile, "keyfile", "", "Path to a key file used to unlock a KeePass (kdbx) database.")
		fl.StringVar(&passwordEnv, "passwordenv", "", "Environment variable storing the import file password.")
		fl.StringVar(&passwordFile, "passwordfile", "", "Path to a file containing the import file password as its first line.")
		root.Examples(cmd, importHelp)
		rootCmd.AddCommand(cmd)
	})
}
