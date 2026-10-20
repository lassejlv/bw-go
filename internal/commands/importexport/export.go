package importexport

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/lassejlv/bw-go/internal/api"
	"github.com/lassejlv/bw-go/internal/app"
	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
	"github.com/lassejlv/bw-go/internal/exporter"
	"github.com/lassejlv/bw-go/internal/vault"
)

// ExportOptions are the `bw export` options. Pointer fields are nil when the option was not given
// (commander leaves them undefined).
type ExportOptions struct {
	Output string
	Format *string
	// Password is the --password value.
	Password *string
	// PromptPassword is set when --password was given without a value (commander yields `true`):
	// the password is prompted for when the effective format is encrypted_json.
	PromptPassword bool
	OrganizationID *string
}

// ExportOptionsFromQuery parses `serve` query parameters.
func ExportOptionsFromQuery(q url.Values) ExportOptions {
	s := func(name string) *string {
		if !q.Has(name) {
			return nil
		}
		v := q.Get(name)
		return &v
	}
	return ExportOptions{
		Output:         q.Get("output"),
		Format:         s("format"),
		Password:       s("password"),
		OrganizationID: s("organizationid"),
	}
}

var exportGUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

// exportPromptPassword asks for the export password (inquirer password prompt on stderr).
var exportPromptPassword = func() (string, error) { return cli.PromptPassword("Export file password:") }

// exportNewService builds the export services for the active account.
var exportNewService = func(a *app.App, v *vault.Vault) *exporter.Service {
	return &exporter.Service{Vault: v, Kdf: v.Account().Kdf, API: exporter.APIClient{C: a.API}}
}

// Export mirrors ExportCommand.run.
func Export(a *app.App, opts ExportOptions) *cli.Response {
	v, err := vault.Load(a)
	if err != nil {
		return cli.Error(err)
	}
	if opts.OrganizationID == nil && v.PolicyAppliesToUser(vault.PolicyDisablePersonalVaultExport) {
		return cli.BadRequest("One or more organization policies prevents you from exporting your personal vault.")
	}

	// has password and format is 'json' => same behaviour as 'encrypted_json';
	// no format => 'csv'; otherwise the given format.
	passwordTruthy := opts.PromptPassword || (opts.Password != nil && *opts.Password != "")
	format := exporter.FormatCSV
	if passwordTruthy && opts.Format != nil && *opts.Format == exporter.FormatJSON {
		format = exporter.FormatEncryptedJSON
	} else if opts.Format != nil {
		format = *opts.Format
	}
	if !exporter.IsSupportedFormat(format) {
		return cli.BadRequest("'" + format + "' is not a supported export format. Supported formats: " +
			strings.Join(exporter.Formats, ", ") + ".")
	}
	if opts.OrganizationID != nil && !exportGUIDRe.MatchString(*opts.OrganizationID) {
		return cli.Error("`" + *opts.OrganizationID + "` is not a GUID.")
	}

	// A value-less --password (commander `true`) only means "prompt" for encrypted_json; for the
	// other formats the export services treat it like no password.
	password := ""
	if opts.Password != nil {
		password = *opts.Password
	}
	if format == exporter.FormatEncryptedJSON && opts.PromptPassword {
		p, err := exportPromptPassword()
		if err != nil {
			return cli.Error(err)
		}
		password = p
	}

	svc := exportNewService(a, v)
	var exp *exporter.ExportedVault
	if opts.OrganizationID == nil {
		exp, err = svc.GetExport(format, password)
	} else {
		exp, err = svc.GetOrganizationExport(*opts.OrganizationID, format, password, false)
	}
	if err != nil {
		return cli.Error(err)
	}

	if opts.OrganizationID != nil {
		exportCollectEvent(a, v, exportEventOrganizationClientExportedVault, opts.OrganizationID)
	} else {
		exportCollectEvent(a, v, exportEventUserClientExportedVault, nil)
	}
	return cli.SaveResultToFile(exp.Data, opts.Output, exp.FileName)
}

// Event types (EventType.User_ClientExportedVault / Organization_ClientExportedVault).
const (
	exportEventUserClientExportedVault         = 1007
	exportEventOrganizationClientExportedVault = 1602
)

// exportEventRequest mirrors EventRequest.
type exportEventRequest struct {
	Type           int     `json:"type"`
	CipherID       *string `json:"cipherId"`
	Date           string  `json:"date"`
	OrganizationID *string `json:"organizationId"`
}

// exportCollectEvent mirrors eventCollectionService.collect(eventType, null, true, orgId): the
// event is recorded only when the user belongs to an organization that uses events (and, for
// organization events, when that organization does) and is uploaded immediately. Upload failures
// are ignored.
func exportCollectEvent(a *app.App, v *vault.Vault, eventType int, organizationID *string) {
	var orgIDs []string
	for _, o := range v.Organizations() {
		if o.UseEvents {
			orgIDs = append(orgIDs, o.ID)
		}
	}
	if len(orgIDs) == 0 {
		return
	}
	if eventType != exportEventUserClientExportedVault {
		if organizationID == nil {
			return
		}
		found := false
		for _, id := range orgIDs {
			if id == *organizationID {
				found = true
			}
		}
		if !found {
			return
		}
	}
	req := []exportEventRequest{{Type: eventType, Date: cli.FormatDate(time.Now()), OrganizationID: organizationID}}
	_ = a.API.Send("POST", "/collect", req, true, nil, &api.RequestOptions{BaseURL: a.Urls().Events})
}

const exportHelp = `
  Notes:

    Valid formats are ` + "`csv`, `json`, `encrypted_json`" + ` and zip. Default format is ` + "`csv`" + `.

    If --raw option is specified and no output filename or directory is given, the
    result is written to stdout.

  Examples:

    bw export
    bw --raw export
    bw export myPassword321
    bw export myPassword321 --format json
    bw export --output ./exp/bw.csv
    bw export myPassword321 --output bw.json --format json
    bw export myPassword321 --organizationid 7063feab-4b10-472e-b64c-785e2b870b92
`

// exportPasswordNoValue is the NoOptDefVal of `--password` given without a value. The flag value
// reports type "bool" so cobra's usage shows neither a type nor the default (`--password password`).
const exportPasswordNoValue = "true"

// exportPasswordFlag is the pflag value of `--password [password]`.
type exportPasswordFlag struct{ value string }

func (p *exportPasswordFlag) String() string     { return p.value }
func (p *exportPasswordFlag) Set(s string) error { p.value = s; return nil }
func (p *exportPasswordFlag) Type() string       { return "bool" }

// exportRawArgs returns the raw command line (used to emulate commander's optional option value).
var exportRawArgs = func() []string { return os.Args[1:] }

// exportTakePasswordValue emulates commander's `--password [password]`: a value-less --password
// (pflag NoOptDefVal) consumes the following token as its value unless that token looks like an
// option. pflag has already moved that token into the positional args; it is removed from there.
func exportTakePasswordValue(raw, args []string) (string, []string, bool) {
	value, found := "", false
	for i := 0; i < len(raw); i++ {
		if raw[i] == "--" {
			break
		}
		if raw[i] != "--password" {
			continue
		}
		found = false
		if i+1 < len(raw) {
			next := raw[i+1]
			if !(len(next) > 1 && strings.HasPrefix(next, "-")) {
				value, found = next, true
				i++
			}
		}
	}
	if !found {
		return "", args, false
	}
	for j, a := range args {
		if a == value {
			rest := append(append([]string{}, args[:j]...), args[j+1:]...)
			return value, rest, true
		}
	}
	return "", args, false
}

func init() {
	root.Register(276, func(rootCmd *cobra.Command, a *app.App) {
		var output, format, orgID string
		var pw exportPasswordFlag
		cmd := &cobra.Command{
			Use:   "export",
			Short: "Export vault data to a CSV, JSON or ZIP file.",
			RunE: func(cmd *cobra.Command, args []string) error {
				f := cmd.Flags()
				opts := ExportOptions{Output: output}
				if f.Changed("format") {
					opts.Format = &format
				}
				if f.Changed("organizationid") {
					opts.OrganizationID = &orgID
				}
				if f.Changed("password") {
					if pw.value == exportPasswordNoValue {
						if v, rest, ok := exportTakePasswordValue(exportRawArgs(), args); ok {
							opts.Password, args = &v, rest
						} else {
							opts.PromptPassword = true
						}
					} else {
						v := pw.value
						opts.Password = &v
					}
				}
				if len(args) > 0 {
					return fmt.Errorf("too many arguments for 'export'. Expected 0 arguments but got %d.", len(args))
				}
				a.ExitIfLocked()
				cli.Process(Export(a, opts), false)
				return nil
			},
		}
		fl := cmd.Flags()
		fl.StringVar(&output, "output", "", "Output directory or filename.")
		fl.StringVar(&format, "format", "", "Export file format.")
		fl.Var(&pw, "password", "Use `password` to encrypt instead of your Bitwarden account encryption key. Only applies to the encrypted_json format.")
		fl.Lookup("password").NoOptDefVal = exportPasswordNoValue
		fl.StringVar(&orgID, "organizationid", "", "Organization id for an organization.")
		root.Examples(cmd, exportHelp)
		rootCmd.AddCommand(cmd)
	})
}
