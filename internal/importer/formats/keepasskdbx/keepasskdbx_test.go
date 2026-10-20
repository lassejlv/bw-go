package keepasskdbx

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/importertest"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

// Ported from the tests in sdk-internal crates/bitwarden-importers/src/importers/kdbx.rs (built with
// writer_test.go instead of keepass's save_kdbx4), plus libs/importer/src/sdk/importers/
// kdbx-sdk-importer.spec.ts (error mapping) and reads of the keepass-rs test databases in testdata/
// (MIT, see testdata/LICENSE-keepass-rs.txt).

const testPassword = "test-password"

func strp(s string) *string { return &s }

func newImporter(password *string, keyFile []byte, orgID string) importer.BinaryImporter {
	opts := importertest.Options()
	opts.OrganizationID = orgID
	if password != nil {
		pw := *password
		opts.PromptPassword = func() (string, error) { return pw, nil }
	}
	opts.KeyFile = keyFile
	return New(opts).(importer.BinaryImporter)
}

// buildDB is build_db: a KDBX 4 file protected by testPassword.
func buildDB(t testing.TB, root tGroup) []byte {
	return buildKDBX(t, tDB{root: root}, writeOptions{password: strp(testPassword)})
}

func parseBytes(t testing.TB, data []byte) *model.ImportResult {
	t.Helper()
	r, err := newImporter(strp(testPassword), nil, "").ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	return r
}

func root(entries []tEntry, groups ...tGroup) tGroup {
	return tGroup{uuid: 1, name: "Root", entries: entries, groups: groups}
}

func TestMapsStandardFieldsAndGroupToFolder(t *testing.T) {
	data := buildDB(t, root(nil, tGroup{uuid: 2, name: "Social", entries: []tEntry{{uuid: 10, fields: []tField{
		{"Title", "GitHub", false},
		{"UserName", "octocat", false},
		{"Password", "hunter2", true},
		{"URL", "https://github.com", false},
		{"Notes", "my note", false},
		{"otp", "JBSWY3DPEHPK3PXP", false},
	}}}}))
	r := parseBytes(t, data)
	if !r.Success || len(r.Ciphers) != 1 {
		t.Fatalf("%s", importertest.Dump(r))
	}
	c := r.Ciphers[0]
	if c.Type != model.CipherTypeLogin || c.Name != "GitHub" || c.Notes != "my note" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	if c.Login.Username != "octocat" || c.Login.Password != "hunter2" || c.Login.Totp != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("%s", importertest.Dump(c.Login))
	}
	if got := importertest.URIs(c); len(got) != 1 || got[0] != "https://github.com" {
		t.Fatalf("uris %v", got)
	}
	if len(c.Fields) != 0 {
		t.Fatalf("fields %s", importertest.Dump(c.Fields))
	}
	if len(r.Folders) != 1 || r.Folders[0].Name != "Social" {
		t.Fatalf("folders %s", importertest.Dump(r.Folders))
	}
	if len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("relationships %v", r.FolderRelationships)
	}
	if c.CreationDate == nil || c.RevisionDate == nil {
		t.Fatal("dates not set")
	}
}

func TestNestedGroupsBecomeFolderPaths(t *testing.T) {
	data := buildDB(t, root(nil, tGroup{uuid: 2, name: "Parent", groups: []tGroup{
		{uuid: 3, name: "Child", entries: []tEntry{{uuid: 10, fields: []tField{{"Title", "Nested", false}}}}},
	}}))
	r := parseBytes(t, data)
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	if strings.Join(names, "|") != "Parent|Parent/Child" {
		t.Fatalf("folders %v", names)
	}
	if len(r.FolderRelationships) != 1 || r.FolderRelationships[0] != (model.Relationship{0, 1}) {
		t.Fatalf("relationships %v", r.FolderRelationships)
	}
}

func TestBlankGroupNameAndEntriesOrder(t *testing.T) {
	data := buildDB(t, root(
		[]tEntry{{uuid: 10, fields: []tField{{"Title", "  ", false}, {"UserName", " ", false}}}},
		tGroup{uuid: 2, name: " ", entries: []tEntry{{uuid: 11, fields: []tField{{"Title", "A", false}}}},
			groups: []tGroup{{uuid: 3, name: "Sub", entries: []tEntry{{uuid: 12, fields: []tField{{"Title", "B", false}}}}}}},
	))
	r := parseBytes(t, data)
	if len(r.Ciphers) != 3 || r.Ciphers[0].Name != "--" || r.Ciphers[0].Login.Username != "" || r.Ciphers[1].Name != "A" || r.Ciphers[2].Name != "B" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers))
	}
	if len(r.Folders) != 2 || r.Folders[0].Name != "-" || r.Folders[1].Name != "-/Sub" {
		t.Fatalf("%s", importertest.Dump(r.Folders))
	}
	want := []model.Relationship{{1, 0}, {2, 1}}
	if importertest.Dump(r.FolderRelationships) != importertest.Dump(want) {
		t.Fatalf("relationships %v", r.FolderRelationships)
	}
}

func TestProtectedStringsAreHiddenFieldsPlainAreText(t *testing.T) {
	data := buildDB(t, root([]tEntry{{uuid: 10, fields: []tField{
		{"Title", "Custom", false},
		{"PlainField", "plain value", false},
		{"SecretField", "secret value", true},
		{"BlankField", "   ", false},
	}}}))
	c := parseBytes(t, data).Ciphers[0]
	importertest.AssertCustomFieldsStructure(t, c.Fields,
		importertest.F("PlainField", "plain value", model.FieldTypeText),
		importertest.F("SecretField", "secret value", model.FieldTypeHidden),
	)
}

func TestProtectedValuesAcrossHistoryKeepStreamInSync(t *testing.T) {
	// History entries consume the inner stream although they are not imported.
	for _, opts := range []writeOptions{{password: strp(testPassword)}, {password: strp(testPassword), kdbx3: true}} {
		data := buildKDBX(t, tDB{root: root([]tEntry{
			{uuid: 10, fields: []tField{{"Title", "First", false}, {"Password", "p1", true}},
				history: []tEntry{{uuid: 10, fields: []tField{{"Password", "old-password", true}}}}},
			{uuid: 11, fields: []tField{{"Title", "Second", false}, {"Password", "p2", true}}},
		})}, opts)
		r := parseBytes(t, data)
		if len(r.Ciphers) != 2 || r.Ciphers[0].Login.Password != "p1" || r.Ciphers[1].Login.Password != "p2" {
			t.Fatalf("kdbx3=%v %s", opts.kdbx3, importertest.Dump(r.Ciphers))
		}
	}
}

func TestTimeOtpBase32MapsTotp(t *testing.T) {
	data := buildDB(t, root([]tEntry{{uuid: 10, fields: []tField{
		{"Title", "Entry with OTP", false},
		{"TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", true},
	}}}))
	c := parseBytes(t, data).Ciphers[0]
	if c.Login.Totp != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("totp %q", c.Login.Totp)
	}
	for _, f := range c.Fields {
		if f.Name == "TimeOtp-Secret-Base32" {
			t.Fatal("TimeOtp field kept as custom field")
		}
	}
}

func TestTimeOtpNonDefaultSettingsBuildOtpauthURI(t *testing.T) {
	data := buildDB(t, root([]tEntry{{uuid: 10, fields: []tField{
		{"Title", "Custom OTP", false},
		{"TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP", true},
		{"TimeOtp-Period", "60", false},
		{"TimeOtp-Length", "8", false},
		{"TimeOtp-Algorithm", "HMAC-SHA-256", false},
	}}}))
	c := parseBytes(t, data).Ciphers[0]
	if c.Login.Totp != "otpauth://totp/Imported?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60" {
		t.Fatalf("totp %q", c.Login.Totp)
	}
	if len(c.Fields) != 0 {
		t.Fatalf("fields %s", importertest.Dump(c.Fields))
	}
}

func TestTimeOtpSecretEncodingsConvertToBase32(t *testing.T) {
	// "Hello" encodes to the Base32 secret "JBSWY3DP".
	for _, tc := range [][2]string{
		{"TimeOtp-Secret-Base64", "SGVsbG8="},
		{"TimeOtp-Secret-Hex", "48656c6c6f"},
		{"TimeOtp-Secret", "Hello"},
		{"TimeOtp-Secret-Base32", "jbsw y3dp"},
	} {
		data := buildDB(t, root([]tEntry{{uuid: 10, fields: []tField{{"Title", "Encoded OTP", false}, {tc[0], tc[1], true}}}}))
		if got := parseBytes(t, data).Ciphers[0].Login.Totp; got != "JBSWY3DP" {
			t.Errorf("field %s: totp %q", tc[0], got)
		}
	}
}

func TestTotpEdgeCases(t *testing.T) {
	e := newEntry()
	e.set("otp", "key=ABC&key=x", false)
	if got := buildTotp(e); got != "ABC&key=x" {
		t.Fatalf("otp %q", got)
	}
	e = newEntry()
	e.set("TimeOtp-Secret-Base32", "AB", false) // non-zero trailing bits
	e.set("TimeOtp-Secret", "Hello", false)
	if got := buildTotp(e); got != "" {
		t.Fatalf("malformed base32 must give no totp, got %q", got)
	}
	e = newEntry()
	e.set("TimeOtp-Secret-Hex", "48656c6c6f", false)
	e.set("TimeOtp-Period", " 30 ", false)
	e.set("TimeOtp-Length", "6", false)
	e.set("TimeOtp-Algorithm", "hmac-sha-512", false)
	if got := buildTotp(e); got != "otpauth://totp/Imported?secret=JBSWY3DP&algorithm=SHA512" {
		t.Fatalf("totp %q", got)
	}
	e = newEntry()
	e.set("TimeOtp-Secret-Hex", "48656c6c6f", false)
	e.set("TimeOtp-Algorithm", "HMAC-SHA-1", false)
	if got := buildTotp(e); got != "JBSWY3DP" {
		t.Fatalf("totp %q", got)
	}
}

func TestWrongPasswordIsWrongCredentials(t *testing.T) {
	data := buildDB(t, root([]tEntry{{uuid: 10, fields: []tField{{"Title", "Secret", false}}}}))
	_, err := newImporter(strp("incorrect"), nil, "").ParseBytes(data)
	if err != ErrWrongCredentials || err.Error() != importer.MsgInvalidFilePassword {
		t.Fatalf("err %v", err)
	}
	// KDBX 3.1 has no header HMAC: a wrong key fails on the stream start bytes / padding.
	data = buildKDBX(t, tDB{root: root(nil)}, writeOptions{password: strp(testPassword), kdbx3: true})
	if _, err := newImporter(strp("incorrect"), nil, "").ParseBytes(data); err != ErrWrongCredentials {
		t.Fatalf("kdbx3 err %v", err)
	}
}

func TestNonKdbxInputIsInvalidFormat(t *testing.T) {
	_, err := newImporter(strp(testPassword), nil, "").ParseBytes([]byte("not a kdbx file"))
	if err != ErrInvalidFormat || err.Error() != importer.MsgKdbxWrongFileType {
		t.Fatalf("err %v", err)
	}
	if _, err := newImporter(strp(""), nil, "").ParseBytes(readFixture(t, "broken_random_data.kdbx")); err != ErrInvalidFormat {
		t.Fatalf("err %v", err)
	}
}

func TestInputOverSizeLimitIsRejected(t *testing.T) {
	if _, err := parseKdbx(make([]byte, maxKdbxSize), strp(""), nil, false); err == ErrFileTooLarge {
		t.Fatal("exactly the limit must be accepted")
	}
	_, err := newImporter(strp(""), nil, "").ParseBytes(make([]byte, maxKdbxSize+1))
	if err != ErrFileTooLarge || err.Error() != importer.MsgKdbxFileTooLarge {
		t.Fatalf("err %v", err)
	}
}

func TestCorruptIsCorruptOrUnsupported(t *testing.T) {
	data := buildDB(t, root(nil))
	for _, d := range [][]byte{data[:40], data[:len(data)-10], readFixture(t, "broken_kdbx_version.kdbx")} {
		_, err := newImporter(strp(testPassword), nil, "").ParseBytes(d)
		if err != ErrCorruptOrUnsupported || err.Error() != importer.MsgKdbxCorruptOrOutdated {
			t.Fatalf("err %v", err)
		}
	}
	// Flipping a byte of the header breaks the header hash.
	bad := append([]byte(nil), data...)
	bad[20] ^= 1
	if _, err := newImporter(strp(testPassword), nil, "").ParseBytes(bad); err != ErrCorruptOrUnsupported {
		t.Fatalf("err %v", err)
	}
}

func TestPromptPasswordErrorIsReturned(t *testing.T) {
	want := errors.New(importer.MsgImportPasswordRequired)
	opts := importertest.Options()
	opts.PromptPassword = func() (string, error) { return "", want }
	_, err := New(opts).(importer.BinaryImporter).ParseBytes(buildDB(t, root(nil)))
	if err != want {
		t.Fatalf("err %v", err)
	}
	// Without a password source the key is empty: wrong credentials.
	if _, err := newImporter(nil, nil, "").ParseBytes(buildDB(t, root(nil))); err != ErrWrongCredentials {
		t.Fatalf("err %v", err)
	}
}

func dbWithRecycleBin(t testing.TB, enabled string) []byte {
	return buildKDBX(t, tDB{
		root:              root(nil, tGroup{uuid: 2, name: "Trash", entries: []tEntry{{uuid: 10, fields: []tField{{"Title", "in trash", false}}}}}),
		recycleBinEnabled: enabled,
		recycleBinUUID:    2,
	}, writeOptions{password: strp(testPassword)})
}

func TestRecycleBinGroupIsSkippedWhenEnabled(t *testing.T) {
	r := parseBytes(t, dbWithRecycleBin(t, "True"))
	if len(r.Ciphers) != 0 || len(r.Folders) != 0 {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestRecycleBinUUIDIsIgnoredWhenDisabled(t *testing.T) {
	for _, enabled := range []string{"False", ""} {
		r := parseBytes(t, dbWithRecycleBin(t, enabled))
		if len(r.Folders) != 1 || r.Folders[0].Name != "Trash" || len(r.Ciphers) != 1 || r.Ciphers[0].Name != "in trash" {
			t.Fatalf("enabled=%q %s", enabled, importertest.Dump(r))
		}
	}
	// An unparsable boolean is a corrupt database.
	if _, err := newImporter(strp(testPassword), nil, "").ParseBytes(dbWithRecycleBin(t, "yes")); err != ErrCorruptOrUnsupported {
		t.Fatalf("err %v", err)
	}
}

func TestDuplicateEntryUUIDIsCorrupt(t *testing.T) {
	data := buildDB(t, root([]tEntry{{uuid: 10}, {uuid: 10}}))
	if _, err := newImporter(strp(testPassword), nil, "").ParseBytes(data); err != ErrCorruptOrUnsupported {
		t.Fatalf("err %v", err)
	}
}

func TestGroupDepthLimit(t *testing.T) {
	build := func(depth int) tGroup {
		g := tGroup{uuid: 200, name: "leaf"}
		for i := 0; i < depth; i++ {
			g = tGroup{uuid: i + 1000, name: "g", groups: []tGroup{g}}
		}
		return g
	}
	// depth 256 below root is allowed, 257 is not (MAX_GROUP_DEPTH).
	r := parseBytes(t, buildDB(t, root(nil, build(255))))
	if len(r.Folders) != 256 {
		t.Fatalf("folders %d", len(r.Folders))
	}
	if _, err := newImporter(strp(testPassword), nil, "").ParseBytes(buildDB(t, root(nil, build(256)))); err != ErrCorruptOrUnsupported {
		t.Fatalf("err %v", err)
	}
}

func TestOrganizationImportUsesCollections(t *testing.T) {
	data := buildDB(t, root(nil, tGroup{uuid: 2, name: "Shared", entries: []tEntry{{uuid: 10, fields: []tField{{"Title", "x", false}}}}}))
	r, err := newImporter(strp(testPassword), nil, "org-id").ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Folders) != 0 || len(r.Collections) != 1 || r.Collections[0].Name != "Shared" || r.Collections[0].OrganizationID != "org-id" ||
		len(r.CollectionRelationships) != 1 || r.CollectionRelationships[0] != (model.Relationship{0, 0}) {
		t.Fatalf("%s", importertest.Dump(r))
	}
}

func TestKDBX3AndVariants(t *testing.T) {
	db := tDB{root: root([]tEntry{{uuid: 10, fields: []tField{{"Title", "T", false}, {"Password", "secret", true}, {"Extra", "hidden", true}}}})}
	for name, o := range map[string]writeOptions{
		"kdbx3":          {password: strp(testPassword), kdbx3: true},
		"kdbx4 argon2d":  {password: strp(testPassword), argon2: true},
		"kdbx4 chacha20": {password: strp(testPassword), chachaOuter: true},
	} {
		r := parseBytes(t, buildKDBX(t, db, o))
		c := r.Ciphers[0]
		if c.Login.Password != "secret" || len(c.Fields) != 1 || c.Fields[0].Value != "hidden" || c.Fields[0].Type != model.FieldTypeHidden {
			t.Fatalf("%s: %s", name, importertest.Dump(c))
		}
	}
}

func TestKeyFileFormats(t *testing.T) {
	raw32 := seq(32, 7)
	hex64 := []byte(strings.ToUpper(hex.EncodeToString(raw32)))
	xmlV1 := []byte(`<?xml version="1.0" encoding="UTF-8"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>` +
		"BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY=" + `</Data></Key></KeyFile>`)
	xmlV2 := []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"00000000\">\n\t\t\t" +
		"0708090A 0B0C0D0E 0F101112 13141516\n\t\t\t1718191A 1B1C1D1E 1F202122 23242526\n\t\t</Data>\n\t</Key>\n</KeyFile>\n")
	for name, kf := range map[string][]byte{"32-byte": raw32, "64-hex": hex64, "xml v1": xmlV1, "xml v2": xmlV2} {
		if got := parseKeyFile(kf); string(got) != string(raw32) {
			t.Errorf("%s: key %x", name, got)
		}
	}
	arbitrary := []byte("any file contents")
	if got := parseKeyFile(arbitrary); string(got) != string(sha256Sum(arbitrary)) {
		t.Errorf("hashed key %x", got)
	}
	// A database protected by password + key file (one form) opens with every equivalent form.
	data := buildKDBX(t, tDB{root: root([]tEntry{{uuid: 10, fields: []tField{{"Title", "K", false}}}})},
		writeOptions{password: strp(testPassword), keyFile: raw32})
	for name, kf := range map[string][]byte{"32-byte": raw32, "64-hex": hex64, "xml v1": xmlV1, "xml v2": xmlV2} {
		r, err := newImporter(strp(testPassword), kf, "").ParseBytes(data)
		if err != nil || r.Ciphers[0].Name != "K" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := newImporter(strp(testPassword), nil, "").ParseBytes(data); err != ErrWrongCredentials {
		t.Errorf("missing key file: %v", err)
	}
	if _, err := newImporter(strp(testPassword), arbitrary, "").ParseBytes(data); err != ErrWrongCredentials {
		t.Errorf("wrong key file: %v", err)
	}
}

func TestSanitizeURI(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com":           "https://github.com",
		"http://keepass.info/":         "http://keepass.info/",
		"github.com":                   "https://github.com",
		"www.example.com/path":         "https://www.example.com/path",
		"example.com:8080":             "https://example.com:8080",
		"localhost:3000":               "https://localhost:3000",
		"192.168.1.1":                  "http://192.168.1.1",
		"10.0.0.1:8080/admin":          "http://10.0.0.1:8080/admin",
		"ftp://files.example":          "ftp://files.example",
		"ssh://host.example":           "ssh://host.example",
		"mailto:user@example.com":      "https://mailto:user@example.com",
		"$":                            "https://$",
		"http://":                      "https://http://",
		"androidapp://com.example.app": "androidapp://com.example.app",
		"file:///etc/hosts":            "https://file:///etc/hosts",
		"https://exa mple.com":         "https://https://exa mple.com",
	} {
		if got := sanitizeURI(in); got != want {
			t.Errorf("sanitizeURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArgon2AgainstReference(t *testing.T) {
	salt := []byte("somesalt")
	for _, tc := range []struct {
		mode    int
		version uint32
		want    string
	}{
		// phc-winner-argon2 test.c vectors (t=2, m=2^16 KiB, p=1, "password", "somesalt").
		{argon2i, argon2Version10, "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694"},
		{argon2i, argon2Version13, "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0"},
		{argon2id, argon2Version13, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"},
	} {
		got, err := argon2Key(argon2Params{mode: tc.mode, version: tc.version, time: 2, memory: 1 << 16, lanes: 1, salt: salt, password: []byte("password")})
		if err != nil || hex.EncodeToString(got) != tc.want {
			t.Errorf("mode %d v%x: %x %v", tc.mode, tc.version, got, err)
		}
	}
	// Multi-lane Argon2id matches x/crypto.
	got, _ := argon2Key(argon2Params{mode: argon2id, version: argon2Version13, time: 3, memory: 256, lanes: 4, salt: salt, password: []byte("pw")})
	if want := argon2.IDKey([]byte("pw"), salt, 3, 256, 4, 32); string(got) != string(want) {
		t.Errorf("argon2id lanes=4: %x != %x", got, want)
	}
	if _, err := argon2Key(argon2Params{mode: argon2d, version: argon2Version13, time: 1, memory: 8, lanes: 2, salt: salt}); err == nil {
		t.Error("memory below 8*lanes must fail")
	}
}

// --- keepass-rs databases ---------------------------------------------------------------------

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeepassRsDatabases(t *testing.T) {
	type expect struct {
		ciphers int
		folders string
		first   [3]string // name, username, password of the first cipher
	}
	cases := []struct {
		file, password, keyFile string
		want                    expect
	}{
		{"test_db_with_password.kdbx", "demopass", "", expect{6, "General|General/Subgroup|Internet", [3]string{"Sample Entry", "User Name", "Password"}}},
		{"test_db_kdbx3_with_attachments.kdbx", "demopass", "", expect{2, "", [3]string{"first", "", ""}}},
		{"test_db_kdbx3_with_chacha20_protected_fields.kdbx", "password", "", expect{1, "IntelliJ Platform", [3]string{"IntelliJ Platform DB — 7c2d7f7f-81a9-418a-8ecf-9b2687c21daa", "", "admin"}}},
		{"test_db_with_keyfile.kdbx", "-", "test_key.key", expect{1, "", [3]string{"Test key", "jdoe", "1234"}}},
		{"test_db_with_keyfile_xml.kdbx", "-", "test_key_xml.key", expect{6, "Some group|Some group/Empty Sub-Group of group|Some group/Sub-Group 2 of group|Another group", [3]string{"Test", "tester", "testing"}}},
		{"test_db_kdbx4_with_password_argon2.kdbx", "demopass", "", expect{2, "", [3]string{"Test", "user", "pass"}}},
		{"test_db_kdbx4_with_password_argon2id.kdbx", "demopass", "", expect{2, "", [3]string{"Test", "user", "pass"}}},
		{"test_db_kdbx4_with_password_aes.kdbx", "demopass", "", expect{1, "", [3]string{"ASDF", "ghj", "klmno"}}},
		{"test_db_kdbx4_with_password_argon2_twofish.kdbx", "demopass", "", expect{1, "", [3]string{"test", "test", "test"}}},
		{"test_db_kdbx4_with_password_argon2_chacha20.kdbx", "demopass", "", expect{1, "", [3]string{"test", "test", "test"}}},
		{"test_db_kdbx4_with_password_argon2id_twofish.kdbx", "demopass", "", expect{1, "", [3]string{"test", "test", "test"}}},
		{"test_db_kdbx4_with_password_argon2id_chacha20.kdbx", "demopass", "", expect{1, "", [3]string{"test", "test", "test"}}},
		{"test_db_kdbx4_with_keyfile.kdbx", "-", "test_key.key", expect{1, "", [3]string{"Test", "user", "pass"}}},
		{"test_db_kdbx4_with_keyfile_v2.kdbx", "demopass", "test_db_kdbx4_with_keyfile_v2.keyx", expect{1, "", [3]string{"secret", "", "secret"}}},
		{"test_db_kdbx4_with_keyfile_v2_alt.kdbx", "demopass", "test_db_kdbx4_with_keyfile_v2_alt.keyx", expect{2, "General|Windows|Network|Internet|eMail|Homebanking", [3]string{"Sample Entry", "User Name", "Password"}}},
		{"test_db_kdb_with_password.kdb", "foobar", "", expect{5, "General|General/Windows|General/Network|General/Internet|General/eMail|General/Homebanking|Backup|depth0|depth0/depth1.1|depth0/depth1.1/depth2|depth0/depth1.2", [3]string{"foo", "bar", "zEZ9endy9zHu0jZMNNvl"}}},
		// The recycle bin (enabled, with a deleted entry) is skipped.
		{"test_db_kdbx4_with_password_deleted_entry.kdbx", "demopass", "", expect{2, "", [3]string{"Test", "user", "pass"}}},
		{"test_db_kdbx41_with_password_aes.kdbx", "demopass", "", expect{4, "Group with tags|Group that was moved", [3]string{"entry with no quality check", "jdoe", "hunter2"}}},
		{"test_db_kdbx41_features.kdbx", "demopass", "", expect{2, "DumbDangler", [3]string{"tagged-entry-41", "graffiti", "orisitart"}}},
		{"test_db_few_rounds.kdbx", "demopass", "", expect{1, "", [3]string{"test entry", "jdoe", "hunter2"}}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var pw *string
			if tc.password != "-" {
				pw = strp(tc.password)
			}
			var kf []byte
			if tc.keyFile != "" {
				kf = readFixture(t, tc.keyFile)
			}
			r, err := newImporter(pw, kf, "").ParseBytes(readFixture(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, f := range r.Folders {
				names = append(names, f.Name)
			}
			c := r.Ciphers[0]
			if len(r.Ciphers) != tc.want.ciphers || strings.Join(names, "|") != tc.want.folders ||
				c.Name != tc.want.first[0] || c.Login.Username != tc.want.first[1] || c.Login.Password != tc.want.first[2] {
				t.Fatalf("got %d ciphers, folders %q, first %q/%q/%q", len(r.Ciphers), strings.Join(names, "|"), c.Name, c.Login.Username, c.Login.Password)
			}
			if pw != nil {
				if _, err := newImporter(strp(tc.password+"x"), kf, "").ParseBytes(readFixture(t, tc.file)); err != ErrWrongCredentials {
					t.Fatalf("wrong password: %v", err)
				}
			}
		})
	}
}

func TestKeepassRsTotpAndCustomFields(t *testing.T) {
	r, err := newImporter(strp("test"), nil, "").ParseBytes(readFixture(t, "test_db_kdbx4_with_totp_entry.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Ciphers[0].Login.Totp; got != "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC" {
		t.Fatalf("totp %q", got)
	}
	r, err = newImporter(strp("demopass"), nil, "").ParseBytes(readFixture(t, "test_db_with_password.kdbx"))
	if err != nil {
		t.Fatal(err)
	}
	c := r.Ciphers[0]
	importertest.AssertCustomFieldsStructure(t, c.Fields, importertest.F("custom attribute", "data for custom attribute", model.FieldTypeText))
	if c.Notes != "Notes" || importertest.URIs(c)[0] != "http://keepass.info/" {
		t.Fatalf("%s", importertest.Dump(c))
	}
	// KeePass 1.x "Meta-Info" entries are imported like any other entry (the crate keeps them),
	// and the "$" URL is sanitized to https://$.
	r, err = newImporter(strp("foobar"), nil, "").ParseBytes(readFixture(t, "test_db_kdb_with_password.kdb"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Ciphers[1].Name != "Meta-Info" || importertest.URIs(r.Ciphers[1])[0] != "https://$" {
		t.Fatalf("%s", importertest.Dump(r.Ciphers[1]))
	}
}

func TestRegistration(t *testing.T) {
	imp, err := importer.New("keepasskdbx", importertest.Options())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := imp.(importer.BinaryImporter); !ok {
		t.Fatal("not a BinaryImporter")
	}
}
