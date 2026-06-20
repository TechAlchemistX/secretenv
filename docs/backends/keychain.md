# macOS Keychain

- **Type:** `keychain`
- **CLI required:** `security` (ships with every macOS)
- **URI scheme:** `<instance-name>:///<service>/<account>`
- **Platform:** macOS only. `secretenv doctor` reports `keychain-<instance>` as CliMissing on Linux/Windows
- **Tested:** macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `keychain` backend. New here? See the [overview](/).

The macOS Keychain is the OS's native credential store via the built-in `security` CLI. Requires no external service account or API token.

## When to pick this

- **Solo dev machines:** zero-infrastructure, passwords encrypted at rest by the OS
- **App development:** store API keys, credentials, certificates locally
- **Paired with `local` registry:** `local://…/aliases.toml` points at `keychain://…` entries
- **macOS only:** non-macOS hosts cannot use this backend

## Configuration

```toml
[backends.keychain-default]
type = "keychain"
```

All fields are optional. No credential configuration needed.

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"keychain"` |
| `keychain_path` | No | Absolute path to the keychain file. Defaults to the user's login keychain. Example: `/Users/you/Library/Keychains/team.keychain-db`. |
| `kind` | No | `"generic-password"` (default) or `"internet-password"`. Selects which `security` subcommand family wraps `get` / `set` / `delete`. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. Keychain operations are local (sub-100ms); this field is for symmetry with cloud backends. |

### Multiple keychains

```toml
[backends.keychain-default]
type = "keychain"
kind = "generic-password"

[backends.keychain-team]
type           = "keychain"
kind           = "generic-password"
keychain_path  = "/Users/you/Library/Keychains/team.keychain-db"
```

Each instance targets a distinct keychain file; the URI scheme picks which.

## URI Format

```
keychain-default:///com.acme.prod/stripe-key
└──────────────┘    └───────────┘ └────────┘
instance name       service       account
```

The two path segments map to `security`'s `-s <service>` and `-a <account>` arguments. Both are required. A URI with one segment or three segments is rejected.

### Slashes in service or account

If a service name contains a literal `/` (e.g., `com.acme/subteam`), percent-encode it as `%2F` (case-insensitive):

```
keychain-default:///com.acme%2Fsubteam/stripe-key
```

Only `%2F` is decoded, no general percent-escape handling.

### `kind`: generic-password vs internet-password

| `kind` | Use case |
|---|---|
| `generic-password` (default) | API keys, tokens, shared secrets. Keychain Access calls these "application passwords". |
| `internet-password` | Protocol+host-scoped credentials (HTTP basic-auth, SMB shares). Extra attributes (protocol, port) not surfaced in v0.13. |

Most use cases want `generic-password`. Pick `internet-password` only if items were created through Keychain Access → Add Password or by an app.

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

The Keychain has no user-level auth surface like cloud backends. Access is gated by:

1. **Lock state.** The login keychain unlocks automatically when you log in. Custom keychains you manage via `security unlock-keychain`.
2. **Per-item ACL.** Set at item creation. See ACL setup below.

### Locked-keychain remediation

If `secretenv doctor` reports `NotAuthenticated`, unlock with:

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
# prompts for keychain password
```

### ACL setup for automation

Items created through Keychain Access.app default to "Confirm before allowing", which breaks automation. For automation-friendly items, set "Always allow" via `-T`:

```bash
security add-generic-password \
    -s myapp -a stripe-key \
    -w "sk_test_…" \
    -T /usr/local/bin/secretenv \
    -T /bin/zsh \
    ~/Library/Keychains/login.keychain-db
```

Or allow any process (simpler for solo dev): add `-A` instead of `-T` flags.

## The `list()` limitation: registry patterns

**The keychain backend does not implement `list()` as a registry source.** The `security` CLI offers no safe list-by-prefix operation. `security dump-keychain` requires per-item confirmation and dumps every credential, a security footgun.

### What this means

- **Keychain cannot host an alias registry.** Aliases cannot point `sources = [...]` at a keychain URI.
- **Keychain URIs are alias TARGETS only.** Put keychain entries on the right-hand side; host the registry on `local`, `aws-ssm`, `aws-secrets`, `vault`, or another backend.

Recommended shape:

```toml
# ~/.config/secretenv/config.toml

[registries.default]
sources = ["local-main:///Users/you/.config/secretenv/aliases.toml"]

[backends.local-main]
type = "local"

[backends.keychain-default]
type = "keychain"
```

```toml
# /Users/you/.config/secretenv/aliases.toml, the registry

stripe-key = "keychain-default:///com.acme.prod/stripe-key"
db-url     = "keychain-default:///com.acme.prod/db-url"
api-token  = "keychain-default:///com.acme.prod/api-token"
```

## doctor Output

Healthy (unlocked, configured keychain exists):

```
keychain-default                                              (keychain)
  ✓ security (macOS system)
  ✓ authenticated  keychain=login.keychain-db
```

Locked:

```
keychain-default                                              (keychain)
  ✓ security (macOS system)
  ✗ not authenticated, keychain is locked
      → run: security unlock-keychain ~/Library/Keychains/login.keychain-db
```

Non-macOS:

```
keychain-default                                              (keychain)
  ✗ CLI 'security' not found
      → the 'security' tool ships with macOS; non-macOS hosts cannot use this backend
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Not implemented. The Keychain has no version-history API. Items are overwritten in place on `set` with no audit trail.

## Limitations

- **Stdin discipline.** Every `security` invocation sets `stdin: Stdio::null()` to prevent hangs on locked keychains.
- **`set` argv exposure.** `security add-*-password -w <value>` passes the value through argv. On macOS's single-UID model, `ps -ww` is visible only to the same UID. We accept this and don't gate behind an opt-in flag (unlike `op_unsafe_set`). `tracing::warn!` at `set` time records the exposure for audit.
- **Multi-user macOS.** Machines with multiple active UIDs don't get additional `set` protection. Avoid `registry set` against keychain on shared machines.

## Examples

### Solo dev, single keychain

```toml
[backends.keychain-default]
type = "keychain"

[backends.local-main]
type = "local"

[registries.default]
sources = ["local-main:///Users/you/.config/secretenv/aliases.toml"]
```

```bash
security add-generic-password -s myapp -a stripe-key -w "sk_test_123" -T /usr/local/bin/secretenv
secretenv doctor
secretenv run -- npm start
```

### Multiple keychains

```toml
[backends.keychain-personal]
type = "keychain"
kind = "generic-password"

[backends.keychain-work]
type           = "keychain"
kind           = "generic-password"
keychain_path  = "/Users/you/Library/Keychains/work.keychain-db"
```

```toml
# aliases.toml

personal-stripe-key = "keychain-personal:///personal.app/stripe"
work-api-key        = "keychain-work:///company.internal/api-key"
```

## Troubleshooting

**"keychain is locked"**
Run `security unlock-keychain ~/Library/Keychains/login.keychain-db`.

**"Item not found" on a custom keychain**
Verify the keychain file exists at `keychain_path`. If missing, recreate with `security create-keychain` or use the login keychain (omit `keychain_path`).

**"Permission denied" or "ACL mismatch"**
The item's ACL is set to "Confirm before allowing". Edit in Keychain Access.app to always allow, or recreate with `-T /usr/local/bin/secretenv` or `-A` at creation.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Local file backend](local.md), recommended registry host when keychain is the secret target
- [macOS Keychain documentation](https://www.unix.com/man-page/osx/1/security/), the authoritative CLI reference
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
