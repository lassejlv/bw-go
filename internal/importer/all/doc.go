// Package all links every importer into the binary. Import it for side effects:
//
//	import _ "github.com/lassejlv/bw-go/internal/importer/all"
//
// Each importer package gets its own file here (one blank import per file) so that importers can
// be added in parallel without editing a shared list.
package all
