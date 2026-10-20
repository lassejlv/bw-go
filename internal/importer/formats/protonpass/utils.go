package protonpass

import (
	"regexp"
	"strings"

	"github.com/lassejlv/bw-go/internal/importer"
)

// jsWhitespaceRun is /\s+/ (JavaScript's \s: Unicode whitespace plus line terminators and BOM).
var jsWhitespaceRun = regexp.MustCompile(`[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]+`)

// processNames is protonpass-import-utils.ts processNames ("" stands for null).
func processNames(fullname, firstname, middlename, lastname string) (mappedFirstName, mappedMiddleName, mappedLastName string) {
	mappedFirstName = firstname
	mappedMiddleName = middlename
	mappedLastName = lastname

	if fullname != "" {
		parts := jsWhitespaceRun.Split(importer.JSTrim(fullname), -1)

		// Assign parts to first, middle, and last name based on the number of parts
		if parts[0] != "" {
			mappedFirstName = parts[0]
		} else {
			mappedFirstName = firstname
		}
		if len(parts) > 1 {
			mappedLastName = parts[len(parts)-1]
		} else {
			mappedLastName = lastname
		}
		if len(parts) > 2 {
			mappedMiddleName = strings.Join(parts[1:len(parts)-1], " ")
		} else {
			mappedMiddleName = middlename
		}
	}

	return mappedFirstName, mappedMiddleName, mappedLastName
}
