package root

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/lassejlv/bw-go/internal/cli"
	"github.com/lassejlv/bw-go/internal/version"
)

// helpAnnotation holds a command's Notes/Examples epilogue (set via Examples).
const helpAnnotation = "bwgo:help"

// commandGroups orders the root command list. Commands not listed fall into "Other".
var commandGroups = []struct {
	title    string
	commands []string
}{
	{"Session", []string{"login", "logout", "lock", "unlock", "sync", "status"}},
	{"Vault", []string{"list", "get", "create", "edit", "delete", "restore", "archive", "move", "confirm", "share"}},
	{"Import & export", []string{"import", "export"}},
	{"Send", []string{"send", "receive"}},
	{"Utilities", []string{"generate", "encode", "config", "completion", "update", "sdk-version"}},
	{"Server", []string{"serve"}},
}

// Examples attaches a Notes/Examples epilogue (upstream's `.on("--help")` text) to a command.
func Examples(cmd *cobra.Command, text string) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[helpAnnotation] = text
}

// renderHelp prints help for any command in the tree.
func renderHelp(c *cobra.Command, _ []string) {
	st := cli.Out
	width := st.Width()
	var b strings.Builder
	section := func(title string) { b.WriteString("\n  " + st.Bold(title) + "\n") }

	b.WriteString("\n")
	if !c.HasParent() {
		b.WriteString("  " + st.Bold(c.Name()) + "  " +
			st.Dim("Bitwarden CLI · unofficial Go port · v"+version.Version) + "\n")
	}
	desc, args := splitLong(c)
	if c.HasParent() && desc != "" {
		for _, l := range cli.Wrap(desc, width-4) {
			b.WriteString("  " + l + "\n")
		}
	}

	section("Usage")
	b.WriteString("    " + st.Dim("$ ") + usageLine(c) + "\n")

	if len(args) > 0 {
		section("Arguments")
		col := 0
		for _, a := range args {
			col = max(col, len(a[0]))
		}
		col += 3
		for _, a := range args {
			lines := cli.Wrap(a[1], max(width-4-col, 30))
			b.WriteString("    " + st.Accent(a[0]) + strings.Repeat(" ", col-len(a[0])) + lines[0] + "\n")
			for _, l := range lines[1:] {
				b.WriteString("    " + strings.Repeat(" ", col) + l + "\n")
			}
		}
	}

	if c.HasAvailableSubCommands() {
		if !c.HasParent() {
			writeGroupedCommands(&b, c, st, width)
		} else {
			section("Commands")
			writeCommandRows(&b, c.Commands(), st, width)
		}
	}

	c.InitDefaultHelpFlag()
	if h := c.Flags().Lookup("help"); h != nil {
		h.Usage = "Show help for this command."
	}
	if fs := c.LocalFlags(); fs.HasAvailableFlags() {
		if c.HasParent() {
			section("Options")
		} else {
			section("Global options")
		}
		writeFlagRows(&b, fs, st, width)
	}
	if c.HasParent() && c.InheritedFlags().HasAvailableFlags() {
		b.WriteString("\n  " + st.Dim("Global options (--raw, --pretty, --session, …): see `"+
			c.Root().Name()+" --help`") + "\n")
	}

	if text := c.Annotations[helpAnnotation]; text != "" {
		writeEpilogue(&b, text, st, width)
	}
	b.WriteString("\n")
	_, _ = io.WriteString(c.OutOrStdout(), b.String())
}

// splitLong separates a command's description from the commander-style "Arguments:" block that
// some commands keep in Long.
func splitLong(c *cobra.Command) (desc string, args [][2]string) {
	long := c.Long
	if long == "" {
		return c.Short, nil
	}
	desc = long
	if i := strings.Index(long, "\n\nArguments:"); i >= 0 {
		desc = long[:i]
		for _, line := range strings.Split(long[i+len("\n\nArguments:"):], "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			name, text, _ := strings.Cut(line, " ")
			args = append(args, [2]string{name, strings.TrimSpace(text)})
		}
	}
	return strings.TrimSpace(desc), args
}

func usageLine(c *cobra.Command) string {
	line := c.UseLine()
	if c.HasAvailableSubCommands() && (!c.Runnable() || !c.HasParent()) {
		line = c.CommandPath() + " <command>"
	} else if c.HasAvailableSubCommands() {
		line = strings.TrimSuffix(line, " [flags]") + " [command]"
	}
	if c.HasAvailableFlags() && !strings.Contains(line, "[options]") {
		line = strings.TrimSuffix(line, " [flags]") + " [options]"
	}
	return strings.Replace(line, "[flags]", "[options]", 1)
}

// keepFlagOrder lists options in definition order (like commander) instead of alphabetically.
func keepFlagOrder(c *cobra.Command) {
	c.Flags().SortFlags = false
	c.PersistentFlags().SortFlags = false
	for _, sub := range c.Commands() {
		keepFlagOrder(sub)
	}
}

func visibleCommands(cmds []*cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, c := range cmds {
		if c.IsAvailableCommand() && c.Name() != "help" {
			out = append(out, c)
		}
	}
	return out
}

func writeGroupedCommands(b *strings.Builder, root *cobra.Command, st cli.Style, width int) {
	byName := map[string]*cobra.Command{}
	cmds := visibleCommands(root.Commands())
	for _, c := range cmds {
		byName[c.Name()] = c
	}
	used := map[string]bool{}
	for _, g := range commandGroups {
		var rows []*cobra.Command
		for _, n := range g.commands {
			if c := byName[n]; c != nil {
				rows = append(rows, c)
				used[n] = true
			}
		}
		if len(rows) == 0 {
			continue
		}
		b.WriteString("\n  " + st.Bold(g.title) + "\n")
		writeCommandRows(b, rows, st, width)
	}
	var other []*cobra.Command
	for _, c := range cmds {
		if !used[c.Name()] {
			other = append(other, c)
		}
	}
	if len(other) > 0 {
		b.WriteString("\n  " + st.Bold("Other") + "\n")
		writeCommandRows(b, other, st, width)
	}
}

func writeCommandRows(b *strings.Builder, cmds []*cobra.Command, st cli.Style, width int) {
	nameColumn := 14
	for _, c := range visibleCommands(cmds) {
		nameColumn = max(nameColumn, len(c.Name())+2)
	}
	for _, c := range visibleCommands(cmds) {
		desc := strings.TrimSpace(c.Short)
		deprecated := strings.HasPrefix(desc, "--DEPRECATED--")
		if deprecated {
			desc = strings.TrimSpace(strings.TrimPrefix(desc, "--DEPRECATED--")) + " (deprecated)"
		}
		name := c.Name()
		lines := cli.Wrap(desc, width-6-nameColumn)
		pad := strings.Repeat(" ", max(nameColumn-len(name), 1))
		if deprecated {
			b.WriteString("    " + st.Dim(name+pad+lines[0]) + "\n")
		} else {
			b.WriteString("    " + st.Accent(name) + pad + lines[0] + "\n")
		}
		for _, l := range lines[1:] {
			b.WriteString("    " + strings.Repeat(" ", nameColumn) + l + "\n")
		}
	}
}

// flagPlaceholders are upstream's value names where they differ from the flag name.
var flagPlaceholders = map[string]string{
	"api": "url", "events": "url", "icons": "url", "identity": "url", "key-connector": "url",
	"notifications": "url", "web-vault": "url", "minNumber": "count", "minSpecial": "count",
	"sso": "identifier", "maxAccessCount": "amount", "deleteInDays": "days",
}

func flagLabel(f *pflag.Flag, st cli.Style) (plain, styled string) {
	name := "--" + f.Name
	if f.Shorthand != "" {
		name = "-" + f.Shorthand + ", " + name
	} else {
		name = "    " + name
	}
	arg := ""
	if f.Value.Type() != "bool" {
		ph := f.Name
		if p, ok := flagPlaceholders[f.Name]; ok {
			ph = p
		}
		if f.NoOptDefVal != "" {
			arg = " [" + ph + "]"
		} else {
			arg = " <" + ph + ">"
		}
	}
	return name + arg, st.Accent(name) + st.Dim(arg)
}

func writeFlagRows(b *strings.Builder, fs *pflag.FlagSet, st cli.Style, width int) {
	fs.SortFlags = false
	type row struct{ plain, styled, usage string }
	var rows []row
	col := 0
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		p, s := flagLabel(f, st)
		rows = append(rows, row{p, s, f.Usage})
		col = max(col, len(p))
	})
	col = min(col, max(30, width*2/5)) + 3
	for _, r := range rows {
		lines := cli.Wrap(r.usage, max(width-4-col, 30))
		if len(r.plain)+3 > col {
			b.WriteString("    " + r.styled + "\n")
			for _, l := range lines {
				b.WriteString("    " + strings.Repeat(" ", col) + l + "\n")
			}
			continue
		}
		b.WriteString("    " + r.styled + strings.Repeat(" ", col-len(r.plain)) + lines[0] + "\n")
		for _, l := range lines[1:] {
			b.WriteString("    " + strings.Repeat(" ", col) + l + "\n")
		}
	}
}

// writeEpilogue renders upstream's free-form "Notes:/Examples:" help text: headings in bold,
// example command lines prefixed with a dim "$", and prose wrapped to the terminal width.
func writeEpilogue(b *strings.Builder, text string, st cli.Style, width int) {
	last, pending := "", false // last: "heading", "example", "prose" or "tip"
	for _, raw := range strings.Split(strings.Trim(text, "\n"), "\n") {
		line := strings.TrimRight(raw, " ")
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "" {
			pending = last != ""
			continue
		}
		gap := func() {
			if pending && last != "heading" {
				b.WriteString("\n")
			}
		}
		switch {
		case isHeading(trimmed, indent):
			b.WriteString("\n  " + st.Bold(strings.TrimSuffix(trimmed, ":")) + "\n")
			last = "heading"
		case strings.HasPrefix(trimmed, "Tip:"):
			b.WriteString("\n")
			for _, l := range cli.Wrap(trimmed, width-4) {
				b.WriteString("  " + st.Dim(l) + "\n")
			}
			last = "tip"
		case isExampleCommand(trimmed):
			gap()
			b.WriteString("    " + st.Dim("$ ") + trimmed + "\n")
			last = "example"
		default:
			if last == "" {
				b.WriteString("\n")
			} else {
				gap()
			}
			pad := strings.Repeat(" ", max(indent, 4))
			for _, l := range cli.Wrap(trimmed, width-len(pad)) {
				b.WriteString(pad + l + "\n")
			}
			last = "prose"
		}
		pending = false
	}
}

func isHeading(trimmed string, indent int) bool {
	return indent <= 2 && strings.HasSuffix(trimmed, ":") && len(trimmed) <= 40 &&
		!strings.ContainsAny(trimmed, "`{}\"")
}

func isExampleCommand(trimmed string) bool {
	return strings.HasPrefix(trimmed, "bwgo ") || trimmed == "bwgo" ||
		strings.HasPrefix(trimmed, "echo ") || strings.Contains(trimmed, "| bwgo ")
}

// unknownCommandHint suggests close matches for a mistyped command.
func unknownCommandHint(root *cobra.Command, name string) string {
	if s := root.SuggestionsFor(name); len(s) > 0 {
		return fmt.Sprintf("Did you mean %s?", strings.Join(s, " or "))
	}
	return ""
}
