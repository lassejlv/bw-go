# bw-go

An unofficial Go port of the [Bitwarden CLI](https://github.com/bitwarden/clients/tree/main/apps/cli)
(`bw`). It aims to behave like the official Node.js CLI — same commands, options, messages and
JSON output — while shipping as a single static binary.

> **Not affiliated with or endorsed by Bitwarden, Inc.** "Bitwarden" is a trademark of Bitwarden,
> Inc. For production use, prefer the [official CLI](https://bitwarden.com/help/cli/).

> **Status: experimental.** Every command is ported and covered by unit tests and fake-server
> tests built from the upstream source, but it has **not yet been tested against a real Bitwarden
> or Vaultwarden server**. Try it with a throwaway account before trusting it with your vault.

## Install

The binary is called `bwgo`, so it can sit next to the official `bw` on your `PATH`:

```sh
go install github.com/lassejlv/bw-go/cmd/bwgo@latest
```

Make sure `$(go env GOPATH)/bin` (usually `~/go/bin`) is on your `PATH`. Run the same command again
to update.

Or build from source:

```sh
git clone https://github.com/lassejlv/bw-go && cd bw-go
go build ./cmd/bwgo
```

Requires Go 1.27+.

## Usage

The commands mirror the official CLI, so its [documentation](https://bitwarden.com/help/cli/)
applies — just run `bwgo` instead of `bw`:

```sh
bwgo config server https://vault.example.com   # optional, defaults to bitwarden.com
bwgo login
export BW_SESSION="..."                         # printed by login/unlock
bwgo list items --search github
bwgo get password github.com
bwgo generate -lusn --length 24
bwgo serve --port 8087
```

State is stored in `data-go.json` inside the official CLI's data directory (or
`BITWARDENCLI_APPDATA_DIR`), so it does not touch the official CLI's `data.json`.

## What's included

- **All commands:** `login` (password, API key, SSO, two-step login, new-device verification,
  Key Connector), `logout`, `lock`, `unlock`, `sync`, `status`, `config`, `list`, `get`, `create`,
  `edit`, `delete`, `restore`, `archive`, `move`/`share`, `confirm`, `import`, `export`, `send`,
  `receive`, `generate`, `encode`, `update`, `completion`, `serve`.
- **v1 and v2 encryption accounts.** v2 (COSE / XChaCha20-Poly1305, data envelopes, signed public
  keys) is ported from Bitwarden's Rust SDK and checked against the SDK's test vectors.
- **All file import formats** upstream supports (~70, including 1Password 1pux/1pif, KeePass
  `.kdbx` with `--keyfile`, LastPass, Keeper, Dashlane, Proton Pass and Bitwarden's own formats).
- **Server feature flags** read from the server's `/config`, like upstream. Override one with
  `BW_FEATURE_<flag>=true|false`.

## Differences from the official CLI

- Not ported: biometric unlock, trusted-device / admin-approval SSO decryption (rejected with an
  explanation, as upstream does), remembered two-step tokens, and the "direct" 1Password /
  LastPass / Keeper sign-in imports.
- `bw serve`: attachments are only accepted as uploads (never read from the server's disk),
  `/unlock` ignores password-file/env options, and a failed unlock keeps an unlocked vault unlocked.
- Imports that drop policy-restricted item types keep the remaining items' folder and collection
  assignments correct (upstream can misassign them).
- `export --password=true` means "prompt for a password" (the flag library cannot take an
  optional value the way upstream's does).
- Minor: name sorting approximates the browser's collation, URI regex matching uses Go's regex
  engine, and a few rare error messages are worded slightly differently.

See [PORTING.md](PORTING.md) for the code layout and porting conventions.

## License

GPL-3.0, as a derivative of
[bitwarden/clients](https://github.com/bitwarden/clients) and
[bitwarden/sdk-internal](https://github.com/bitwarden/sdk-internal) (both GPL-3.0). See
[LICENSE](LICENSE). Test fixtures from [keepass-rs](https://github.com/sseemayer/keepass-rs) are
MIT-licensed; see `internal/importer/formats/keepasskdbx/testdata/LICENSE-keepass-rs.txt`.
