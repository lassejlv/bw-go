# internal/importer — `bw import`

Go port of `libs/importer` (plus the Rust SDK importers) for `bw import`. Upstream reference:

- `libs/importer/src/importers/**` — one TypeScript class per format
- `libs/importer/src/importers/base-importer.ts` — shared helpers → `base.go`
- `libs/importer/src/models/import-options.ts` — format table → `formats_table.go`
- `libs/importer/src/services/import.service.ts` — post-processing → `service.go`
- `apps/cli/src/tools/import.command.ts` — CLI command (lives elsewhere; see the last section)
- `sdk-internal/crates/bitwarden-importers` — KeePass kdbx (SDK-backed in upstream)

## Layout

| Package | Contents |
| --- | --- |
| `internal/importer` | `Base` (BaseImporter), `Importer`/`BinaryImporter`, `Options`, `Decryptor`, registry (`Register`, `New`, `Formats`, `LookupFormat`, `CLIFormatIDs`, `ResolveFormat`, `CheckFileFormat`), service post-processing (`Import`, `Prepare`, `SetImportTarget`, `ServerError`, `SkippedItemsMessage`), file reading (`ReadImportFile`, `ReadImportFileBytes`, `ReadKeyFile`, `ReadImportFileContents`, `ExtractZipEntry`), JS-compat helpers (`JSTrim`, `Len16`, `ParseInt`, `ParseJSDate`, `GetHostname`, lenient JSON types), messages (`Msg*`) |
| `internal/importer/model` | `CipherView` and all nested views, `FolderView`, `CollectionView`, `ImportResult`, enums |
| `internal/importer/papa` | PapaParse 5.5.3 port (verified against papaparse on 40k fuzzed inputs) |
| `internal/importer/dom` | XML/HTML DOM with `QuerySelector`/`QuerySelectorAll`, `TextContent`, `GetAttribute`, ... |
| `internal/importer/importertest` | Test helpers (`Parse`, `ReadFile`, `AssertCustomFieldsExist/Structure`, `Dump`, ...) |
| `internal/importer/formats/<name>` | One package per upstream importer file (or family) |
| `internal/importer/all` | One file per importer package containing only a blank import; the CLI imports `all` |
| `internal/importer/testdata/extract-spec-data.mjs` | Converts upstream spec-data `.ts` modules into plain files |

## How to add an importer

The contract, in order:

1. **Create `internal/importer/formats/<name>/<name>.go`** (`package <name>`), porting exactly one
   upstream file (see `Source` in `formats_table.go`; families sharing a base class, e.g.
   `onepassword-csv-importer.ts` → mac/win, `keeper-importer.ts` → csv/json, go in one package).
2. **Embed `importer.Base`** and construct it with `importer.NewBase(opts)`.
3. **Implement `Parse(data string) (*model.ImportResult, error)`** (or `ParseBytes([]byte)` for
   binary formats — keepasskdbx). Return a result with `Success=false` (and `ErrorMessage`) wherever
   TS returns such a result; return an `error` only where TS *throws*. Wrap JSON syntax errors with
   `importer.NewSyntaxError` (or use `importer.UnmarshalJSONLenient`) so they become "Data is not
   formatted correctly...".
4. **Register every format id it serves from `init()`**: `importer.Register("<id>", New)`. The ids
   must match `getImporterInstance` in `import.service.ts` (several ids may share one importer).
   Feature flags (`configService.getFeatureFlag`) come from `opts.Features`; the password prompt
   from `opts.PromptPassword`; the KeePass key file from `opts.KeyFile`.
5. **Add `internal/importer/all/<name>.go`** containing only
   `package all` + `import _ "github.com/lassejlv/bw-go/internal/importer/formats/<name>"`. Do not edit other files.
6. **Port the `.spec.ts` tests** to `<name>_test.go`. Put spec-data in
   `formats/<name>/testdata/` (extract with
   `bun internal/importer/testdata/extract-spec-data.mjs <spec-data.ts> <dir>`; short CSVs can be
   inlined as Go raw strings). Use `importertest.Options()` to silence CSV warnings.
7. Run `go build ./internal/importer/... && go vet ./internal/importer/... && go test ./internal/importer/...`.

### Worked example (the real `formats/firefox/firefox.go`)

TypeScript:

```ts
export class FirefoxCsvImporter extends BaseImporter implements Importer {
  parse(data: string): Promise<ImportResult> {
    const result = new ImportResult();
    const results = this.parseCsv(data, true);
    if (results == null) { result.success = false; return Promise.resolve(result); }
    results
      .filter((value) => value.url !== "chrome://FirefoxAccounts")
      .forEach((value) => {
        const cipher = this.initLoginCipher();
        const url = this.getValueOrDefault(value.url, this.getValueOrDefault(value.hostname));
        cipher.name = this.getValueOrDefault(this.nameFromUrl(url), "--");
        cipher.login.username = this.getValueOrDefault(value.username);
        cipher.login.password = this.getValueOrDefault(value.password);
        cipher.login.uris = this.makeUriArray(url);
        this.cleanupCipher(cipher);
        result.ciphers.push(cipher);
      });
    result.success = true;
    return Promise.resolve(result);
  }
}
```

Go:

```go
package firefox

import (
	"github.com/lassejlv/bw-go/internal/importer"
	"github.com/lassejlv/bw-go/internal/importer/model"
)

func init() { importer.Register("firefoxcsv", New) }

type Importer struct{ importer.Base }

func New(opts importer.Options) importer.Importer { return &Importer{Base: importer.NewBase(opts)} }

func (i *Importer) Parse(data string) (*model.ImportResult, error) {
	result := model.NewImportResult()
	results := i.ParseCsv(data, nil) // parseCsv(data, true)
	if results == nil {
		result.Success = false
		return result, nil
	}
	for _, value := range results {
		if value.Get("url") == "chrome://FirefoxAccounts" {
			continue
		}
		cipher := i.InitLoginCipher()
		url := i.GetValueOrDefault(value.Get("url"), i.GetValueOrDefault(value.Get("hostname")))
		cipher.Name = i.GetValueOrDefault(i.NameFromUrl(url), "--")
		cipher.Login.Username = i.GetValueOrDefault(value.Get("username"))
		cipher.Login.Password = i.GetValueOrDefault(value.Get("password"))
		cipher.Login.Uris = i.MakeUriArray(url)
		i.CleanupCipher(cipher)
		result.Ciphers = append(result.Ciphers, cipher)
	}
	result.Success = true
	return result, nil
}
```

plus `internal/importer/all/firefox.go`:

```go
package all

import _ "github.com/lassejlv/bw-go/internal/importer/formats/firefox"
```

### Translation cheat sheet

| TypeScript | Go |
| --- | --- |
| `this.helper(...)` | `i.Helper(...)` (methods of the embedded `importer.Base`) |
| `null` / `undefined` string | `""` (all optional model strings are plain `string`) |
| `new CipherView()` | `model.NewCipherView()` (all nested views allocated, like TS) |
| `new ImportResult()` | `model.NewImportResult()` |
| `result.folderRelationships.push([a, b])` | `append(..., model.Relationship{a, b})` |
| `this.organization` / `this.organizationId` | `i.Organization()` / `i.OrganizationID` |
| `this.parseCsv(data, true, opts)` | `i.ParseCsv(data, &importer.CsvOptions{...})` → `[]importer.Record` or nil |
| `this.parseCsv(data, false, opts)` | `i.ParseCsvRows(data, opts)` → `[][]string` or nil |
| `value.field`, `value["a b"]` | `value.Get("field")` (`""` when missing) |
| `value.field != null`, `hasOwnProperty` | `value.Lookup("field")` / `value.Has("field")` |
| `Object.keys(value)` / `Object.values` | `value.Keys()` / `value.Values()` (JS key order) |
| `value.__parsed_extra` | `value.Extra` |
| papaparse options | `importer.CsvOptions{Delimiter, QuoteChar, EscapeChar: &s, SkipEmptyLines: importer.SkipEmptyLines/SkipEmptyLinesGreedy, TransformHeader, Comments}` |
| `a \|\| b` on strings | explicit `if a != "" { ... }` |
| `this.makeUriArray(str)` / `(arr)` | `i.MakeUriArray(str)` / `i.MakeUriArray(arr...)` |
| `this.getValueOrDefault(x)` / `(x, "--")` | `i.GetValueOrDefault(x)` / `i.GetValueOrDefault(x, "--")` |
| `this.processKvp(c, k, v, FieldType.Hidden)` | `i.ProcessKvp(c, k, v, model.FieldTypeHidden)` |
| `this.processFolder(r, name, false)` | `i.ProcessFolder(r, name, false)` |
| `CardView.getCardBrandByPatterns(n)` | `i.GetCardBrand(n)` / `model.GetCardBrandByPatterns(n)` |
| `this.parseXml(data)` → `Document` | `i.ParseXml(data)` → `*dom.Node` or nil |
| `this.parseHtml(data)` | `i.ParseHtml(data)` |
| `el.querySelector(sel)` / `querySelectorAll` | `el.QuerySelector(sel)` / `el.QuerySelectorAll(sel)` (CSS subset: type, `*`, `#id`, `.class`, `[attr]`, `[attr="v"]` and `~= ^= $= *= \|=`, descendant, `>`, `+`, `~`, `,`) |
| `this.querySelectorDirectChild(el, sel)` | `i.QuerySelectorDirectChild(el, sel)` or `el.QuerySelectorDirectChild(sel)` |
| `el.textContent` / `el.getAttribute("x")` | `el.TextContent()` / `el.GetAttribute("x")` (value, ok) or `el.Attr("x")` |
| `el.attributes.X.value`, `el.tagName`, `el.children`, `el.parentNode` | `el.GetAttribute("X")`, `el.TagName()`, `el.Children()`, `el.Parent` |
| `JSON.parse(data)` | decode into structs using `importer.JSONString`, `*importer.JSONString` (null-aware), `importer.JSONNumber`, `importer.JSONBool`, via `importer.UnmarshalJSONLenient` |
| `str.trim()`, `/\s/` | `importer.JSTrim`, `importer.IsJSSpace`, `importer.RemoveJSWhitespace` |
| `str.length`, `substring` (UTF-16) | `importer.Len16`, `importer.Substring16` |
| `parseInt(x, 10)` | `importer.ParseInt(x)` → `(n, ok)`; `ok=false` is NaN |
| `new Date(s)` / `Date.parse` | `importer.ParseJSDate(s)` (port of V8's DateParser, local time where V8 uses it) |
| `this.parseDateString(s)` / `formatDateString(d)` | `i.ParseDateString(s)` / `i.FormatDateString(&t)` |
| `Utils.getHostname(u)` | `importer.GetHostname(u)` (tldts 7.4.2 port) |
| `Utils.newGuid()` | `importer.NewGuid()` |
| `import_ssh_key(pem, pw)` (sdk-internal) | `importer.ImportSSHKey(pem, pw)` — a hook; see "Still needed" |
| `new ImportRecordError(id, reason)` | `append(result.Errors, model.ImportRecordError{ID: id, Reason: model.ImportRecordErrorReason...})` |
| `this.logService.warning(...)` | handled by `ParseCsv`; otherwise `i.Warn` |

Conventions: keep upstream names (`parseSecureNoteMapping` → `parseSecureNoteMapping`), keep the
statement order (folder/relationship indexes depend on it), keep error strings verbatim.

## Implemented formats

`bitwardencsv`, `bitwardenjson` (+ alias `bitwardenpasswordprotected`: unencrypted,
account-encrypted via `Options.Decryptor`, password-protected), `chromecsv`, `edgecsv`, `operacsv`,
`vivaldicsv`, `bravecsv`, `arccsv`, `firefoxcsv`, `lastpasscsv`, `passboltcsv`, `keepass2xml`.
`importer.UnimplementedFormats()` lists the rest; `importer.New` returns `*NotImplementedError`
("The \"x\" import format (Name) is not supported by this CLI yet.") for them.

Bitwarden JSON details: account-encrypted exports need `Options.Decryptor` (user key, org keys and
`DecryptExportCipher`). `bitwarden.LegacyDecryptor{AccountKeys: keys}` decrypts field-level
EncString items itself (verified against upstream's V1 test vector) but returns
`bitwarden.ErrBlobCipher` for v2 blob items (`"data"`), which need the vault package. Password-
protected exports derive their key with `crypto.MakeMasterKey` + `crypto.StretchKey` and the file's
KDF parameters (bounds-checked first, before prompting). `bitwarden.NewUpgradePasswordProtectedImporter`
is the web-only "upgrade" variant (sets `ImportResult.ErrorKey`).

## What the import command must do

Mirror `apps/cli/src/tools/import.command.ts` + `ImportService.import`:

1. `--organizationid`: the organization must exist in state, else
   ``You do not belong to an organization with the ID of <id>. Check the organization ID and sync your vault.``;
   it must allow import (`canAccessImport`), else
   `You are not authorized to import into the provided organization.`
2. `--formats`: respond with `MessageResponse("Supported input formats:", strings.Join(importer.CLIFormatIDs(), "\n"))`, `raw` = the same list.
3. Missing format → `importer.MsgFormatNotProvided`; `importer.CheckFileFormat(format)` (direct-only
   formats); missing path → `importer.MsgFilepathNotProvided`.
4. Password source (for `PromptPassword`): `--passwordfile`, `--passwordenv`, else an interactive
   prompt `Import file password:`; with `BW_NOINTERACTION` and no source fail with
   `importer.MsgImportPasswordRequired`. Only call it lazily (importers prompt only when needed).
5. Build `importer.Options{OrganizationID, PromptPassword, KeyFile (from --keyfile via
   importer.ReadKeyFile, kdbx only), Decryptor, Features{NewItemTypes: server feature flag
   "pm-32009-new-item-types"}}`.
6. **SDK formats** (`f, _ := importer.LookupFormat(format); f.SDK != nil`, i.e. `keepasskdbx`):
   `importer.ReadImportFileBytes(path)` (empty → `importer.MsgImportFileWasEmpty`), the importer is a
   `importer.BinaryImporter`; call `ParseBytes`, then `importer.Prepare(result, ImportParams{...,
   CanAccessImportExport: true})`, encrypt and post as below, full sync, and respond
   `Imported <n> item(s) from <path>` (n = number of ciphers). Map kdbx failures to
   `MsgInvalidFilePassword`, `MsgKdbxWrongFileType`, `MsgKdbxCorruptOrOutdated`, `MsgKdbxFileTooLarge`.
7. **Text formats**: `format, err = importer.ResolveFormat(format, path)` (the unified `keeper` id);
   `imp, err := importer.New(format, opts)` (unknown id → `Proper importer type required.`);
   `contents, err := importer.ReadImportFile(format, path)` (zip extraction for `.1pux`/ProtonPass
   `.zip`, UTF-8 decoding, Node-style fs errors); empty → `importer.MsgImportFileWasEmpty`.
8. `result, err := importer.Import(imp, contents, importer.ImportParams{OrganizationID: orgID,
   RestrictedTypes: <cipher types restricted by the RestrictedItemTypes policy>})`. Upstream's CLI
   passes no import target and leaves `CanAccessImportExport` false, so an organization import whose
   items are not all assigned to a collection fails with `File contains unassigned items.`.
   Any error → `Response.badRequest(err.Error())`.
9. Encrypt and POST:
   - **Individual** (`organizationID == ""`): encrypt every cipher with the user key (generating a
     cipher key as the vault normally does), each folder name with the user key, then
     `POST /ciphers/import`:
     ```json
     {
       "ciphers": [ /* CipherRequest, exactly as for POST /ciphers */ ],
       "folders": [ { "name": "2.<enc name>", "id": "<folder.ID, omitted when empty>" } ],
       "folderRelationships": [ { "key": <cipher index>, "value": <folder index> } ]
     }
     ```
   - **Organization**: set `OrganizationID` on every cipher, encrypt ciphers with the org key,
     folder names with the **user** key (upstream does this), collection names with the org key, then
     `POST /ciphers/import-organization?organizationId=<orgId>`:
     ```json
     {
       "ciphers": [ /* CipherRequest with organizationId */ ],
       "collections": [ { "name": "2.<enc name>", "id": "<collection.ID or null>", "externalId": "<or null>", "groups": [], "users": [] } ],
       "collectionRelationships": [ { "key": <cipher index>, "value": <collection index> } ],
       "folders": [ { "name": "2.<enc>", "id": "<optional>" } ],
       "folderRelationships": [ { "key": <cipher index>, "value": <folder index> } ]
     }
     ```
   Model conventions to respect while encrypting: `""` means null for every optional string (emit
   `null`, do not encrypt an empty string; `Name` is always encrypted); `CleanupCipher` already set
   `Login = nil` for non-login ciphers; send only the nested view matching `Type`; `Reprompt`,
   `Favorite`, `Fields` (with `LinkedID`), `PasswordHistory` (max 5), `Fido2Credentials`,
   `ArchivedDate` and `Uris[].Match` (nil → null) map 1:1 to the request.
10. A 400 with `validationErrors` → `importer.ServerError(message, []importer.ValidationError{...in
    server order...}, result)`; otherwise the server message.
11. On success start a full sync and respond `MessageResponse("Imported " + path, null)`; when
    `result.Errors` is non-empty use `importer.SkippedItemsMessage(result.Errors)` as the message
    (and `raw`).

## Still needed from other packages

- **Vault**: an `importer.Decryptor` implementation (user/org keys from the unlocked session +
  `DecryptExportCipher` handling blob/v2 ciphers), `CipherView` → `CipherRequest` encryption, and the
  import request types above. Until then `bitwarden.LegacyDecryptor` covers legacy exports.
- **SSH key import** (`importer.ImportSSHKey`), needed by the 1pux and Keeper JSON ports: a port of
  `sdk-internal/crates/bitwarden-ssh/src/import.rs` (PKCS#1/PKCS#8/OpenSSH, encrypted keys) that
  assigns the hook from `init()`; `golang.org/x/crypto/ssh` is available without a go.mod change.
- **KeePass kdbx** (`keepasskdbx`): a Go port of `crates/bitwarden-importers/src/importers/kdbx.rs`
  (KDBX 3.1/4 parsing, AES/ChaCha20/Twofish, AES-KDF/Argon2d/Argon2id, Salsa20/ChaCha20 inner
  streams, key files) implementing `BinaryImporter`. `golang.org/x/crypto` already provides
  twofish, chacha20, salsa20 and argon2id, but not Argon2d (KDBX 4's default), which needs a small
  port or a new go.mod dependency.

## Known, deliberate deviations

- HTML is parsed by a small lenient parser (no html5 tree construction: no implied
  `<html>/<head>/<body>` and only common implied end tags). Selectors cover the importers' needs.
- XML is parsed with `encoding/xml` in strict mode (namespaces are not resolved; type selectors match
  local names). The encoding declaration is ignored (the input is already a string), like DOMParser.
- `ReadImportFile` reports a missing zip entry as `Zip entry not found: <entry>` (upstream's CLI
  never settles in that case).
- JavaScript's `null` vs `""` distinction is not kept in the model (see above).
