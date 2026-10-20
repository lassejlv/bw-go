package cli

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// Style applies ANSI styling for human-facing output (help, prompts, hints). It is a no-op when
// the target stream is not a terminal or NO_COLOR is set, so piped and machine-readable output
// is never affected.
type Style struct{ f *os.File }

// Out styles text written to stdout; Err styles text written to stderr.
var (
	Out = Style{os.Stdout}
	Err = Style{os.Stderr}
)

func (s Style) wrap(open, close, text string) string {
	if text == "" || !colorEnabled(s.f) {
		return text
	}
	return "\x1b[" + open + "m" + text + "\x1b[" + close + "m"
}

// Enabled reports whether styling is active for the stream.
func (s Style) Enabled() bool { return colorEnabled(s.f) }

// Bold renders text in bold.
func (s Style) Bold(t string) string { return s.wrap("1", "22", t) }

// Dim renders secondary text.
func (s Style) Dim(t string) string { return s.wrap("2", "22", t) }

// Accent renders text in the accent colour (cyan).
func (s Style) Accent(t string) string { return s.wrap("36", "39", t) }

// Green renders text in green.
func (s Style) Green(t string) string { return s.wrap("32", "39", t) }

// Red renders text in bright red.
func (s Style) Red(t string) string { return s.wrap("91", "39", t) }

// Width returns the terminal width of the stream, capped for readability.
func (s Style) Width() int {
	const def, max = 100, 110
	w, _, err := term.GetSize(int(s.f.Fd()))
	if err != nil || w <= 0 {
		return def
	}
	if w > max {
		return max
	}
	return w
}

// VisibleLen returns the printed width of s, ignoring ANSI escape sequences.
func VisibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			if r == 'm' {
				esc = false
			}
		case r == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// Wrap breaks text into lines of at most width visible characters (words longer than width are
// kept whole).
func Wrap(text string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	for _, para := range strings.Split(text, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if VisibleLen(line)+1+VisibleLen(w) > width {
				lines = append(lines, line)
				line = w
			} else {
				line += " " + w
			}
		}
		lines = append(lines, line)
	}
	return lines
}
