package importer

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Constructor builds an importer for one format id.
type Constructor func(opts Options) Importer

var (
	regMu        sync.RWMutex
	constructors = map[string]Constructor{}
	formatsByID  = func() map[string]Format {
		m := make(map[string]Format, len(formatTable))
		for _, f := range formatTable {
			m[f.ID] = f
		}
		return m
	}()
)

// Register associates a constructor with a format id. Call it from init() in the importer's
// package. It panics on duplicate registration. Ids outside the upstream table are allowed (e.g.
// the "bitwardenpasswordprotected" alias that getImporter accepts) but are not listed by Formats.
func Register(id string, ctor Constructor) {
	regMu.Lock()
	defer regMu.Unlock()
	if ctor == nil {
		panic("importer: nil constructor for " + id)
	}
	if _, dup := constructors[id]; dup {
		panic("importer: duplicate registration of " + id)
	}
	constructors[id] = ctor
}

// IsImplemented reports whether a Go importer is registered for id.
func IsImplemented(id string) bool {
	regMu.RLock()
	defer regMu.RUnlock()
	_, ok := constructors[id]
	return ok
}

// New mirrors ImportService.getImporter: it returns the importer for format with the options
// applied. Errors:
//   - *NotImplementedError for an upstream format id whose Go port does not exist yet;
//   - an error with the CLI message "Proper importer type required." for unknown ids.
func New(format string, opts Options) (Importer, error) {
	regMu.RLock()
	ctor, ok := constructors[format]
	regMu.RUnlock()
	if ok {
		return ctor(opts), nil
	}
	if f, known := formatsByID[format]; known {
		return nil, &NotImplementedError{Format: f}
	}
	return nil, fmt.Errorf("%s", MsgProperImporterTypeRequired)
}

// Formats returns every upstream format in importOptions order (a copy).
func Formats() []Format {
	out := make([]Format, len(formatTable))
	copy(out, formatTable)
	return out
}

// LookupFormat returns the format for id (ImportService.getImportOption).
func LookupFormat(id string) (Format, bool) {
	f, ok := formatsByID[id]
	return f, ok
}

// CLIFormatIDs returns the ids `bw import --formats` lists: formats that accept a file, sorted by
// id with JavaScript string comparison (code-unit order).
func CLIFormatIDs() []string {
	var ids []string
	for _, f := range formatTable {
		if len(f.AcceptedFileTypes) > 0 {
			ids = append(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// UnimplementedFormats returns the upstream format ids that have no registered Go importer,
// excluding direct-only formats (no accepted file types) that the CLI rejects anyway.
func UnimplementedFormats() []Format {
	var out []Format
	for _, f := range formatTable {
		if len(f.AcceptedFileTypes) == 0 || f.ID == "keeper" {
			continue
		}
		if !IsImplemented(f.ID) {
			out = append(out, f)
		}
	}
	return out
}

// CheckFileFormat mirrors the first checks of ImportCommand.import: a format without accepted file
// types signs in to the vendor instead, which the CLI cannot do.
func CheckFileFormat(format string) error {
	if f, ok := formatsByID[format]; ok && len(f.AcceptedFileTypes) == 0 {
		return fmt.Errorf("%s", strings.ReplaceAll(MsgImportDirectOnlyError, "$FORMAT$", f.Name))
	}
	return nil
}

// ResolveFormat mirrors ImportCommand.import's handling of the unified "keeper" id: the CLI infers
// keepercsv/keeperjson from the file extension. Other ids are returned unchanged.
func ResolveFormat(format, filepath string) (string, error) {
	if format != "keeper" {
		return format, nil
	}
	lower := strings.ToLower(filepath)
	switch {
	case strings.HasSuffix(lower, ".csv"):
		return "keepercsv", nil
	case strings.HasSuffix(lower, ".json"):
		return "keeperjson", nil
	}
	return "", fmt.Errorf("Cannot determine Keeper file type. Use a .csv or .json file.")
}
