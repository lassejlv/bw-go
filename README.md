# bw-go

Unofficial Go port of the [Bitwarden CLI](https://github.com/bitwarden/clients/tree/main/apps/cli). `bwgo` follows the official `bw` commands, options, messages, and JSON, and ships as one static binary.

Bitwarden is a trademark of Bitwarden, Inc. This project is not affiliated with or endorsed by Bitwarden. For a vault you rely on, use the [official CLI](https://bitwarden.com/help/cli/).

**Experimental.** Every command is ported and covered by unit tests and fake-server tests taken from the upstream source. It has not been tested against a live Bitwarden or Vaultwarden server. Use a throwaway account until you have.

## Install

The binary is `bwgo`, so it can sit next to the official `bw` on your `PATH`.

```sh
go install github.com/lassejlv/bw-go/cmd/bwgo@latest
```

`$(go env GOPATH)/bin` (usually `~/go/bin`) needs to be on your `PATH`. Run the same command again to update.

From a checkout:

```sh
go build -o bwgo ./cmd/bwgo
```

Requires Go 1.27+.

## Quick start

Command behavior matches the official CLI. Its [documentation](https://bitwarden.com/help/cli/) applies; run `bwgo` where it says `bw`.

```sh
# Self-hosted or Vaultwarden. Skip this line for bitwarden.com.
bwgo config server https://vault.example.com

bwgo login
# When login unlocks the vault it prints a session key. Export it:
export BW_SESSION="..."

bwgo sync
bwgo list items --search github
bwgo get password github.com
```

`lock` drops the key. `unlock` prints a new one. `unlock --raw` prints only the key:

```sh
export BW_SESSION="$(bwgo unlock --raw)"
```

`bwgo --help` lists commands. `bwgo <command> --help` lists that command's options.

## Commands

| | Command | What it does |
| --- | --- | --- |
| Account | `login` | Password, API key, SSO, two-step login, new-device verification, Key Connector |
| | `logout` `lock` `unlock` | End the session, lock the vault, or unlock and print a session key |
| | `sync` `status` `config` | Pull the vault, show login state, set the server and other settings |
| Read | `list` `get` | Search the vault and print an item, password, or other object |
| Write | `create` `edit` `delete` | Add, change, or remove vault objects |
| | `restore` `archive` | Bring an object back, or archive it |
| | `move` `share` `confirm` | Move or share into an organization, or confirm an item |
| Files | `import` `export` | Import a file, or export CSV, JSON, or ZIP |
| Send | `send` `receive` | Create a Send, or open one from its URL |
| Other | `generate` `encode` | Passwords and passphrases, or base64-encode stdin |
| | `update` `completion` | Check for updates, or print a shell completion script |
| | `serve` | Local REST API on port 8087 |

`serve` exposes the same command logic over HTTP. The default port is 8087.

## Session and data

`login` and `unlock` create a random 64-byte session key and print it as base64. The user key stays on disk encrypted with that session key. Later commands read `BW_SESSION` (or `--session`) to decrypt it. `lock` clears the protected key.

Global flags match the official CLI and can also be set in the environment: `--pretty` (`BW_PRETTY`), `--raw` (`BW_RAW`), `--response` (`BW_RESPONSE`), `--quiet` (`BW_QUIET`), `--nointeraction` (`BW_NOINTERACTION`), `--cleanexit` (`BW_CLEANEXIT`). API-key login reads `BW_CLIENTID` and `BW_CLIENTSECRET`.

State is `data-go.json` in the official CLI's data directory, so this port leaves `data.json` alone. Override the directory with `BITWARDENCLI_APPDATA_DIR`.

| OS | Default directory |
| --- | --- |
| macOS | `~/Library/Application Support/Bitwarden CLI` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/Bitwarden CLI` |
| Windows | `%APPDATA%\Bitwarden CLI` |

Failed organization event uploads are retried from `events-go.json` in that same directory.

Server feature flags come from the server's `/config`. Override one with `BW_FEATURE_<flag>=true` or `false`.

## What this port covers

- **v1 and v2 accounts.** v1 is AES-256-CBC-HMAC. v2 is COSE / XChaCha20-Poly1305, data envelopes, and signed public keys, ported from Bitwarden's Rust SDK and checked against the SDK's test vectors.
- **Import formats** the official CLI supports (about 70), including 1Password 1pux/1pif, KeePass `.kdbx` with `--keyfile`, LastPass, Keeper, Dashlane, Proton Pass, and Bitwarden's own formats.
- **Biometric unlock** through the Bitwarden desktop app when the server enables `biometrics-sdk-ipc`. On macOS and Linux, `bwgo` can talk to the desktop socket directly, so the desktop proxy binary is optional.
- **Organization policies** the official CLI enforces, including Send controls and the master-password strength check (a zxcvbn 4.4.2 port).
- **Event logging** for organizations that record views and exports.

## Differences

Same limits as the official CLI:

- Trusted-device and admin-approval SSO decryption is rejected with an explanation.
- Remembered two-step tokens are unsupported.
- Direct 1Password, LastPass, and Keeper sign-in imports are unsupported.

Left to other Bitwarden clients:

- Account migrations that raise a too-low KDF or rotate an account to v2 encryption.

Specific to this port:

- `serve` accepts attachments only as uploads. It does not read attachment files from disk on behalf of the caller.
- `serve`'s `/unlock` ignores password-file and password-env options. A failed unlock leaves an already-unlocked vault unlocked.
- `export --password=true` prompts for a password. The flag library has no equivalent of upstream's optional value.
- An import that drops policy-restricted item types keeps folder and collection assignments on the items it keeps.
- Name sorting approximates browser collation. URI matching uses Go's `regexp`. A few rare error strings differ in wording.

[PORTING.md](PORTING.md) describes the package layout and the rules for keeping JSON output aligned with the Node CLI.

## Development

```sh
go test ./...
go build -o bwgo ./cmd/bwgo
```

The version string tracks the upstream CLI release this port targets (`bwgo --version`). Override it with `-ldflags "-X github.com/lassejlv/bw-go/internal/version.Version=..."`.

## License

GPL-3.0, as a derivative of [bitwarden/clients](https://github.com/bitwarden/clients) and [bitwarden/sdk-internal](https://github.com/bitwarden/sdk-internal). See [LICENSE](LICENSE).

KeePass test fixtures from [keepass-rs](https://github.com/sseemayer/keepass-rs) are MIT-licensed. See `internal/importer/formats/keepasskdbx/testdata/LICENSE-keepass-rs.txt`.
