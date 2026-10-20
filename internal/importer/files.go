package importer

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Zip entries the CLI extracts (ImportCommand.import).
const (
	OnePassword1puxEntry = "export.data"
	ProtonPassZipEntry   = "Proton Pass/data.json"
)

// ReadImportFile mirrors how ImportCommand.import reads `filepath` for a text importer:
//   - format "1password1pux" and a path ending in ".1pux": the "export.data" zip entry;
//   - format "protonpass" and a path ending in ".zip": the "Proton Pass/data.json" zip entry;
//   - anything else: the whole file decoded as UTF-8 (invalid bytes become U+FFFD, a BOM is kept
//     and later stripped by the parsers that care).
//
// The suffix checks are case-sensitive, like upstream. Error messages follow Node's fs errors
// (e.g. "ENOENT: no such file or directory, open 'x.csv'"). The caller must still reject an empty
// result with MsgImportFileWasEmpty.
func ReadImportFile(format, path string) (string, error) {
	switch {
	case format == "1password1pux" && strings.HasSuffix(path, ".1pux"):
		return readZipEntry(path, OnePassword1puxEntry)
	case format == "protonpass" && strings.HasSuffix(path, ".zip"):
		return readZipEntry(path, ProtonPassZipEntry)
	}
	data, err := readFileNode(path)
	if err != nil {
		return "", err
	}
	return ToValidUTF8(data), nil
}

// ReadImportFileBytes mirrors ImportCommand.importWithSdk's CliUtils.readBinaryFile for SDK-backed
// formats (keepasskdbx). Upstream reports any failure as "Could not read file: <path>".
func ReadImportFileBytes(path string) ([]byte, error) {
	data, err := readFileNode(path)
	if err != nil {
		return nil, fmt.Errorf("Could not read file: %s", path)
	}
	return data, nil
}

// ReadKeyFile reads the --keyfile argument (CliUtils.readBinaryFile; errors propagate unchanged).
func ReadKeyFile(path string) ([]byte, error) { return readFileNode(path) }

// ReadImportFileContents mirrors the web client's readImportFileContents (services/
// read-import-file-contents.ts) for callers that have a file name and its bytes: 1pux and
// ProtonPass zip extraction (case-insensitive extension match) plus LastPass HTML exports, whose
// CSV is taken from the first <pre> element. The CLI itself uses ReadImportFile instead.
func ReadImportFileContents(format, name string, data []byte) (string, error) {
	lower := strings.ToLower(name)
	if format == "1password1pux" && strings.HasSuffix(lower, ".1pux") {
		return ExtractZipEntry(data, OnePassword1puxEntry)
	}
	if format == "protonpass" && strings.HasSuffix(lower, ".zip") {
		return ExtractZipEntry(data, ProtonPassZipEntry)
	}
	text := ToValidUTF8(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))) // FileReader.readAsText strips a BOM
	if format == "lastpasscsv" && strings.HasSuffix(lower, ".html") {
		return ExtractLastPassHTMLContent(text)
	}
	return text, nil
}

// ExtractLastPassHTMLContent returns the text of the first <pre> element of a LastPass HTML export.
func ExtractLastPassHTMLContent(html string) (string, error) {
	var b Base
	pre := b.ParseHtml(html).QuerySelector("pre")
	if pre == nil {
		return "", errors.New("LastPass html export has no <pre> content")
	}
	return pre.TextContent(), nil
}

// ExtractZipEntry returns the UTF-8 decoded contents of entry in the zip archive data.
func ExtractZipEntry(data []byte, entry string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", errors.New("Can't find end of central directory : is this a zip file ? If it is, see https://stuk.github.io/jszip/documentation/howto/read_zip.html")
	}
	for _, f := range zr.File {
		if f.Name != entry {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			return "", err
		}
		return ToValidUTF8(b), nil
	}
	// Upstream's CLI never settles in this case (a TypeError inside a then-callback); the web
	// client reports this message.
	return "", fmt.Errorf("Zip entry not found: %s", entry)
}

func readZipEntry(path, entry string) (string, error) {
	data, err := readFileNode(path)
	if err != nil {
		return "", err
	}
	return ExtractZipEntry(data, entry)
}

// resolveFilePath is CliUtils.resolveFilePath: path.join(input), made absolute against the cwd
// only when it has no separator.
func resolveFilePath(input string) (string, error) {
	if input == "" {
		return "", errors.New("You must specify a file path.")
	}
	p := filepath.Clean(input)
	if !strings.ContainsRune(p, filepath.Separator) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		p = filepath.Join(wd, p)
	}
	return p, nil
}

func readFileNode(input string) ([]byte, error) {
	p, err := resolveFilePath(input)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nodeFSError(err, p)
	}
	return data, nil
}

// nodeFSError formats err like Node's fs.readFile errors.
func nodeFSError(err error, p string) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("ENOENT: no such file or directory, open '%s'", p)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("EACCES: permission denied, open '%s'", p)
	}
	if fi, statErr := os.Stat(p); statErr == nil && fi.IsDir() {
		return errors.New("EISDIR: illegal operation on a directory, read")
	}
	return err
}
