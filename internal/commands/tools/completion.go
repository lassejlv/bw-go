package tools

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/commands/root"
)

var validShells = []string{"zsh"}

// Completion runs `bw completion --shell <shell>` (CompletionCommand.run) for the command tree
// rooted at rootCmd.
func Completion(rootCmd *cobra.Command, shell string) *cli.Response {
	if shell == "" {
		return cli.BadRequest("`shell` option was not provided.")
	}
	valid := false
	for _, s := range validShells {
		valid = valid || s == shell
	}
	if !valid {
		return cli.BadRequest("Unsupported shell.")
	}
	content := ""
	if shell == "zsh" {
		content = ZshCompletion("bw", rootCmd)
	}
	return cli.Success(cli.NewMessageNull(content))
}

// ZshCompletion renders the zsh completion script for a command tree.
func ZshCompletion(rootName string, rootCmd *cobra.Command) string {
	return strings.Join([]string{"#compdef _" + rootName + " " + rootName, "", renderCommandBlock(rootName, rootCmd)}, "\n")
}

// commandFlags returns the flags defined on cmd itself (not inherited), in definition order:
// persistent flags first, then local ones. The help flag is excluded.
func commandFlags(cmd *cobra.Command) []*pflag.Flag {
	var out []*pflag.Flag
	seen := map[string]bool{}
	inherited := cmd.InheritedFlags()
	visit := func(fs *pflag.FlagSet) {
		sorted := fs.SortFlags
		fs.SortFlags = false
		defer func() { fs.SortFlags = sorted }()
		fs.VisitAll(func(f *pflag.Flag) {
			if seen[f.Name] || f.Hidden || f.Name == "help" || inherited.Lookup(f.Name) == f {
				return
			}
			seen[f.Name] = true
			out = append(out, f)
		})
	}
	visit(cmd.PersistentFlags())
	visit(cmd.Flags())
	return out
}

func subcommands(cmd *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() {
			out = append(out, c)
		}
	}
	return out
}

func renderCommandBlock(name string, cmd *cobra.Command) string {
	commands := subcommands(cmd)
	options := commandFlags(cmd)
	hasOptions := len(options) > 0
	hasCommands := len(commands) > 0

	var args []string
	for _, o := range options {
		var aliases []string
		if o.Shorthand != "" {
			aliases = append(aliases, "-"+o.Shorthand)
		}
		aliases = append(aliases, "--"+o.Name)
		opts := strings.Join(aliases, ",")
		desc := "[" + strings.Replace(o.Usage, "'", `'"'"'`, 1) + "]"
		if len(aliases) > 1 {
			args = append(args, "'("+strings.Join(aliases, " ")+")'{"+opts+"}'"+desc+"'")
		} else {
			args = append(args, "'"+opts+desc+"'")
		}
	}
	args = append(args, `'(-h --help)'{-h,--help}'[output usage information]'`)
	if hasCommands {
		args = append(args, `"1: :->cmnds"`)
	}
	args = append(args, `"*::arg:->args"`)

	var parts []string
	if hasCommands {
		parts = append(parts, "local -a commands")
	}
	if hasOptions {
		parts = append(parts, "_arguments -C \\\n    "+strings.Join(args, " \\\n    "))
	}
	if hasCommands {
		var list, cases []string
		for _, c := range commands {
			list = append(list, `"`+c.Name()+":"+c.Short+`"`)
			cases = append(cases, strings.Join([]string{c.Name() + ")", "_" + name + "_" + c.Name(), ";;"}, "\n      "))
		}
		parts = append(parts, "case $state in\n"+
			"    cmnds)\n"+
			"      commands=(\n"+
			"        "+strings.Join(list, "\n        ")+"\n"+
			"      )\n"+
			"      _describe \"command\" commands\n"+
			"      ;;\n  esac\n\n"+
			"  case \"$words[1]\" in\n"+
			"    "+strings.Join(cases, "\n    ")+"\n  esac")
	}

	blocks := []string{"function _" + name + " {\n  " + strings.Join(parts, "\n\n  ") + "\n}"}
	if hasCommands {
		var sub []string
		for _, c := range commands {
			sub = append(sub, renderCommandBlock(name+"_"+c.Name(), c))
		}
		blocks = append(blocks, strings.Join(sub, "\n\n"))
	}
	return strings.Join(blocks, "\n\n")
}

const completionHelp = "\n  Notes:\n\n" +
	"    Valid shells are `zsh`.\n\n" +
	"  Examples:\n\n" +
	"    bw completion --shell zsh\n"

func newCompletionCommand() *cobra.Command {
	var shell string
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Generate shell completions.",
		Run: func(cmd *cobra.Command, args []string) {
			cli.Process(Completion(cmd.Root(), shell), false)
		},
	}
	cmd.Flags().StringVar(&shell, "shell", "", "Shell to generate completions for.")
	root.Examples(cmd, completionHelp)
	return cmd
}
