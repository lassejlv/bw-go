package firefox

import (
	"reflect"
	"testing"

	"github.com/lassejlv/bw-go/internal/importer/importertest"
)

// Ported from libs/importer/src/importers/firefox-csv-importer.spec.ts (spec-data/firefox-csv).

const simplePasswordData = `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://example.com","foo","bar",,"","{d61e37fa-2bc4-469a-bd66-41fd3b0005e0}","1612345678900","1612345678900","1612345678900"`

const firefoxAccountsData = `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"chrome://FirefoxAccounts","xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","{""version"":1,""accountData"":{""scopedKeys"":{""https://identity.mozilla.com/apps/oldsync"":{""kid"":""xxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxx"",""k"":""xxxx"",""kty"":""xxx""}},""kSync"":""xxxx"",""kXCS"":""xxxx"",""kExtSync"":""xxxx"",""kExtKbHash"":""xxxx""}}","Firefox Accounts credentials",,"{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}","xxxxxxxxxxxxx","xxxxxxxxxxxxx","xxxxxxxxxxxxx"
"https://example.com","foo","bar",,"","{d61e37fa-2bc4-469a-bd66-41fd3b0005e0}","1612345678900","1612345678900","1612345678900"
`

func TestFirefoxCsvImporter(t *testing.T) {
	for title, csv := range map[string]string{
		"should parse password":                  simplePasswordData,
		`should skip "chrome://FirefoxAccounts"`: firefoxAccountsData,
	} {
		t.Run(title, func(t *testing.T) {
			r := importertest.Parse(t, New(importertest.Options()), csv)
			if !r.Success || len(r.Ciphers) != 1 {
				t.Fatalf("%s", importertest.Dump(r))
			}
			c := r.Ciphers[0]
			if c.Name != "example.com" || c.Login.Username != "foo" || c.Login.Password != "bar" ||
				!reflect.DeepEqual(importertest.URIs(c), []string{"https://example.com"}) || c.Notes != "" {
				t.Fatalf("%s", importertest.Dump(c))
			}
		})
	}
}
