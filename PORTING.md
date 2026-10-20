# Porting notes

Go port of `apps/cli` from https://github.com/bitwarden/clients, with the v2 encryption, SSH key
and KeePass (kdbx) pieces ported from the Rust SDK at https://github.com/bitwarden/sdk-internal.

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/bwgo` | entry point (`bwgo` binary); blank-imports every command package |
| `internal/crypto` | SymmetricKey, EncString, EncArrayBuffer (EncryptBytes/DecryptBytes), KDF, HKDF, RSA |
| `internal/state` | JSON state file (`data-go.json` in the Node CLI's app data dir), `Store.Load` / `Store.Update` |
| `internal/api` | HTTP client: `Send/Get/Post/Put/Delete`, identity token, token refresh, `ErrorResponse`, environment URLs |
| `internal/app` | `App` service container, BW_SESSION handling (`SetUserKey`, `UserKey`, `Lock`, `Logout`), auth guards |
| `internal/cli` | `Response` model, `Process` (output rules of BaseProgram.processResponse), prompts, file helpers |
| `internal/commands/root` | cobra root, global flags, help renderer (`help.go`), `root.Register(order, fn)`, `root.Examples(cmd, text)` |
| `internal/commands/*` | one package per command group, each registering itself from `init()` |
| `internal/vault` | vault domain: server models, decryption/encryption, keys, CLI response/export JSON shapes |
| `internal/importer` | all `bw import` formats (port of libs/importer + SDK kdbx); see internal/importer/README.md |

## Conventions

* Each command's logic lives in an exported function returning `*cli.Response` (so `serve` can call
  it); the cobra `Run` only parses flags, runs guards (`a.ExitIfLocked()` etc.) and calls
  `cli.Process(resp, false)`.
* JSON output must match the Node CLI: same property names and order (Go struct field order),
  `null` where Node emits `null`, omitted where Node leaves `undefined`. Dates are emitted with
  `cli.Date` formatting (`2006-01-02T15:04:05.000Z`).
* Server JSON is decoded with Go's case-insensitive `encoding/json`, so PascalCase and camelCase
  responses both work.
* Error/success messages are copied verbatim from the TypeScript source.
* Environment flags follow the Node CLI: `BW_SESSION`, `BW_RAW`, `BW_PRETTY`, `BW_RESPONSE`,
  `BW_QUIET`, `BW_NOINTERACTION`, `BW_CLEANEXIT`, `BW_CLIENTID`, `BW_CLIENTSECRET`,
  `BITWARDENCLI_APPDATA_DIR`.

## Encryption versions

Both v1 accounts (AES-256-CBC-HMAC user key, EncString type 2) and v2 accounts (COSE user key,
EncString type 7 / XChaCha20-Poly1305, data envelopes for blob ciphers and sends, signed public
keys) are supported. v2 primitives are ported from the Rust SDK (`bitwarden/sdk-internal`,
crates/bitwarden-crypto); code outside `internal/crypto` must never assume a key length or
EncString type.

## Session model

Login/unlock generates a random 64-byte session key, exported as base64 in `BW_SESSION`. The user
key is stored in state encrypted with it (`Account.ProtectedUserKey`). Commands needing the vault
decrypt it via `App.UserKey()`. `lock` clears it.
