package all

import (
	"testing"

	"github.com/lassejlv/bw-go/internal/importer"
)

func TestRegistered(t *testing.T) {
	for _, id := range []string{"bitwardencsv", "bitwardenjson", "bitwardenpasswordprotected", "chromecsv", "edgecsv",
		"operacsv", "vivaldicsv", "bravecsv", "arccsv", "firefoxcsv", "lastpasscsv", "passboltcsv", "keepass2xml"} {
		if !importer.IsImplemented(id) {
			t.Errorf("%s is not registered", id)
		}
	}
	for _, f := range importer.UnimplementedFormats() {
		if _, err := importer.New(f.ID, importer.Options{}); err == nil {
			t.Errorf("%s: expected a not-implemented error", f.ID)
		}
	}
}
