package cli

import (
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// ExitCode is the process exit code set by Process; main exits with it.
var ExitCode = 0

// Exit flushes nothing and exits immediately (process.exit equivalent).
var Exit = os.Exit

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

func colorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" && os.Getenv("FORCE_COLOR") != "0" {
		return true
	}
	return isTTY(f)
}

// Colors (chalk bright variants).
func colorize(code, s string, f *os.File) string {
	if !colorEnabled(f) {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[39m"
}

// RedBright colors s for stderr output.
func RedBright(s string) string { return colorize("91", s, os.Stderr) }

// GreenBright colors s for stdout output.
func GreenBright(s string) string { return colorize("92", s, os.Stdout) }

// YellowBright colors s for stdout output.
func YellowBright(s string) string { return colorize("93", s, os.Stdout) }

// WriteLn writes s to stdout (or stderr). A final line omits the trailing newline when the stream
// is not a TTY, matching the Node CLI so `$(bw ...)` captures exact values.
func WriteLn(s string, finalLine, toStderr bool) {
	f := os.Stdout
	if toStderr {
		f = os.Stderr
	}
	if finalLine && (runtime.GOOS == "windows" || !isTTY(f)) {
		f.WriteString(s)
	} else {
		f.WriteString(s + "\n")
	}
}

func envTrue(name string) bool { return os.Getenv(name) == "true" }

// Process prints a response following the global output flags and sets the exit code. When
// exitImmediately is true the process exits.
func Process(r *Response, exitImmediately bool) {
	if r == nil {
		r = Success(nil)
	}
	if !r.Success {
		if !envTrue("BW_QUIET") {
			if envTrue("BW_RESPONSE") {
				WriteLn(ToJSON(r), true, false)
			} else {
				msg := r.MessageText()
				if Err.Enabled() {
					msg = "✗ " + msg
				}
				WriteLn(RedBright(msg), true, true)
			}
		}
		code := 1
		if os.Getenv("BW_CLEANEXIT") != "" {
			code = 0
		}
		if exitImmediately {
			Exit(code)
		}
		ExitCode = code
		return
	}

	if envTrue("BW_RESPONSE") {
		WriteLn(ToJSON(r), true, false)
	} else if r.Data != nil {
		var out *string
		set := func(s string) { out = &s }
		switch d := r.Data.(type) {
		case *TemplateResponse:
			set(ToJSON(d.Template))
		case *StringResponse:
			if d.Data != nil {
				set(*d.Data)
			}
		case *ListResponse:
			set(ToJSON(d.Data))
		case *MessageResponse:
			if m := messageText(d); m != nil {
				set(*m)
			}
		case *FileResponse:
			// Files are only meaningful to `serve`.
		default:
			set(ToJSON(d))
		}
		if out != nil && !envTrue("BW_QUIET") {
			WriteLn(*out, true, false)
		}
	}
	if exitImmediately {
		Exit(0)
	}
	ExitCode = 0
}

func messageText(m *MessageResponse) *string {
	if envTrue("BW_RAW") {
		return m.Raw
	}
	out := ""
	if m.Title != nil {
		if m.NoColor {
			out = *m.Title
		} else if Out.Enabled() {
			out = GreenBright("✓ " + *m.Title)
		} else {
			out = *m.Title
		}
	}
	if m.Message != nil {
		if m.Title != nil {
			out += "\n"
		}
		out += *m.Message
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return &out
}
