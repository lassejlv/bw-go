package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// CanInteract reports whether prompting is allowed.
func CanInteract() bool { return os.Getenv("BW_NOINTERACTION") != "true" }

// StdinIsTTY reports whether stdin is an interactive terminal (nothing piped in).
func StdinIsTTY() bool { return isTTY(os.Stdin) }

// ReadStdin returns piped stdin, or "" when stdin is a terminal.
func ReadStdin() (string, error) {
	if isTTY(os.Stdin) {
		return "", nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func resolvePath(input string) (string, error) {
	if input == "" {
		return "", errors.New("You must specify a file path.")
	}
	p := filepath.Clean(input)
	if !strings.ContainsRune(p, os.PathSeparator) {
		wd, _ := os.Getwd()
		p = filepath.Join(wd, p)
	}
	return p, nil
}

// ReadFile reads a file relative to the working directory.
func ReadFile(input string) ([]byte, error) {
	p, err := resolvePath(input)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// ReadFirstLine reads the first line of a file (used for --passwordfile).
func ReadFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// SaveFile writes data to output (or cwd/defaultFileName) and returns the absolute path.
func SaveFile(data []byte, output, defaultFileName string) (string, error) {
	var p string
	mkdir := false
	if output != "" {
		osOutput := filepath.Clean(output)
		if strings.HasSuffix(output, "/") || strings.HasSuffix(output, string(os.PathSeparator)) {
			osOutput += string(os.PathSeparator)
		}
		if !strings.ContainsRune(osOutput, os.PathSeparator) {
			wd, _ := os.Getwd()
			p = filepath.Join(wd, osOutput)
		} else {
			mkdir = true
			if strings.HasSuffix(osOutput, string(os.PathSeparator)) {
				p = filepath.Join(osOutput, defaultFileName)
			} else {
				p = osOutput
			}
		}
	} else {
		wd, _ := os.Getwd()
		p = filepath.Join(wd, defaultFileName)
	}
	p, _ = filepath.Abs(p)
	if mkdir {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", fmt.Errorf("Cannot save file to %s", p)
	}
	return p, nil
}

// SaveResultToFile writes to stdout when --raw is set and no output is given, otherwise to a file.
func SaveResultToFile(data []byte, output, defaultFileName string) *Response {
	if output == "" && os.Getenv("BW_RAW") == "true" {
		os.Stdout.Write(data)
		return Success(nil)
	}
	p, err := SaveFile(data, output, defaultFileName)
	if err != nil {
		return Error(err)
	}
	return Success(NewMessageNull("Saved " + p).SetRaw(p))
}

// stdinReader is shared by all prompts so buffered input is not lost between consecutive prompts
// when stdin is piped.
var stdinReader = bufio.NewReader(os.Stdin)

func promptLabel(message string) string {
	return Err.Accent("?") + " " + Err.Bold(message) + " "
}

// PromptInput asks for a line of text on stderr.
func PromptInput(message string) (string, error) {
	fmt.Fprint(os.Stderr, promptLabel(message))
	return PromptInputRaw()
}

// PromptPassword asks for a hidden value on stderr.
func PromptPassword(message string) (string, error) {
	fmt.Fprint(os.Stderr, promptLabel(message))
	if !isTTY(os.Stdin) {
		return PromptInputRaw()
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr, Err.Dim("[hidden]"))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PromptInputRaw reads a line from stdin without printing anything.
func PromptInputRaw() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// PromptSelect shows a numbered list and returns the chosen index.
func PromptSelect(message string, choices []string) (int, error) {
	fmt.Fprintln(os.Stderr, Err.Accent("?")+" "+Err.Bold(message))
	for i, c := range choices {
		fmt.Fprintf(os.Stderr, "  %s %s\n", Err.Dim(fmt.Sprintf("%d)", i+1)), c)
	}
	for {
		fmt.Fprint(os.Stderr, "  "+Err.Dim(fmt.Sprintf("Choose 1-%d:", len(choices)))+" ")
		ans, err := PromptInputRaw()
		if err != nil {
			return -1, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(ans))
		if err == nil && n >= 1 && n <= len(choices) {
			return n - 1, nil
		}
		for i, c := range choices {
			if strings.EqualFold(strings.TrimSpace(ans), c) {
				return i, nil
			}
		}
		if ans == "" && err == nil {
			if _, peekErr := stdinReader.Peek(1); peekErr == io.EOF {
				return -1, io.EOF
			}
		}
	}
}

// GetPassword resolves a password from the argument, --passwordfile, --passwordenv or a prompt.
// It returns a non-nil *Response on failure.
func GetPassword(password, passwordFile, passwordEnv, promptMessage string) (string, *Response) {
	if promptMessage == "" {
		promptMessage = "Master password:"
	}
	if password == "" {
		if passwordFile != "" {
			p, err := ReadFirstLine(passwordFile)
			if err != nil {
				return "", Error(err)
			}
			password = p
		} else if passwordEnv != "" {
			if v := os.Getenv(passwordEnv); v != "" {
				password = v
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Provided passwordenv %s is not set\n", passwordEnv)
			}
		}
	}
	if password == "" {
		if CanInteract() {
			p, err := PromptPassword(promptMessage)
			if err != nil {
				return "", Error(err)
			}
			password = p
		} else {
			return "", BadRequest("Master password is required. Try again in interactive mode or provide a password file or environment variable.")
		}
	}
	return password, nil
}

// ConvertNumberOption parses an integer option like parseInt, falling back to def.
func ConvertNumberOption(v string, def int) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	end := 0
	for end < len(v) && (v[end] >= '0' && v[end] <= '9' || (end == 0 && (v[end] == '-' || v[end] == '+'))) {
		end++
	}
	n, err := strconv.Atoi(v[:end])
	if err != nil {
		return def
	}
	return n
}

// ContainsFold reports whether s contains substr case-insensitively.
func ContainsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
