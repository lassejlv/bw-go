package serve

import (
	"fmt"
	"io"
	"os"
)

// logger mirrors the CLI's ConsoleLogService as configured by the service container: info
// messages are filtered out unless BITWARDENCLI_DEBUG is "true" and go to stdout (console.log),
// or to stderr when BW_RESPONSE is "true"; warnings always go to stderr (console.warn).
type logger struct {
	stdout, stderr io.Writer
}

var defaultLogger = &logger{stdout: os.Stdout, stderr: os.Stderr}

func (l *logger) info(msg string) {
	if os.Getenv("BITWARDENCLI_DEBUG") != "true" {
		return
	}
	w := l.stdout
	if os.Getenv("BW_RESPONSE") == "true" {
		w = l.stderr
	}
	fmt.Fprintln(w, msg)
}

func (l *logger) warning(msg string) { fmt.Fprintln(l.stderr, msg) }

func (l *logger) error(msg string) { fmt.Fprintln(l.stderr, msg) }
