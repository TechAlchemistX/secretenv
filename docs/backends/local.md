# Local File

**Type:** `local`
**CLI required:** None (filesystem only)
**URI scheme:** `<instance-name>:///path/to/file.toml`
**Platform:** all (macOS, Linux, Windows)
**Tested:** SecretEnv v0.13.0 (2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `local` backend — the only backend that needs no CLI. New here? See the [overview](/).

The local backend reads secret values directly from a flat TOML file on disk. Use it for solo developers who want zero-infrastructure local workflow, or as a **registry document** pointing at other backends (most commonly the macOS Keychain).

## When to pick this

- **Solo development:** zero external service, no credentials, filesystem only
- **Local registry document:** point aliases at Keychain / Vault / other backends
- **Air-gapped environments:** all secrets on disk, no network required
- **Testing SecretEnv:** quick setup without infrastructure

## Configuration

```toml
[backends.local]
type = "local"
```

No credential fields, no remote service, no authentication. Just `std::fs`.

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"local"` |

### Multiple instances

You can configure multiple `local` instances if you want different files referenced as separate backends:

```toml
[backends.local-personal]
type = "local"

[backends.local-team]
type = "local"
```

The instance name (`local-personal`, `local-team`) becomes the URI scheme.

## URI Format

```
local:///Users/yourname/.config/secretenv/local-registry.toml
└────┘   └──────────────────────────────────────────────────┘
instance  absolute path to TOML file
```

The path must be absolute. The file at the path must be a flat TOML key-value document — keys at top level only, values either scalar (raw secret values) or URI strings (when the file serves as a registry document).

**Verify your setup with:** `secretenv doctor` — green output means SecretEnv can read the file.

### File Format

Two common patterns:

**As a registry document (recommended):**

```toml
# ~/.config/secretenv/local-registry.toml

stripe-key  = "keychain-default:///myapp/stripe-key"
dev-db-url  = "keychain-default:///myapp/dev-db-url"
api-key     = "keychain-default:///myapp/api-key"
```

**As raw secrets (not recommended):**

```toml
# ~/.config/secretenv/secrets-local.toml

STRIPE_KEY    = "sk_test_…"
DATABASE_URL  = "postgres://localhost/mydb"
API_TOKEN     = "abc123…"
```

The registry-document pattern is **strongly recommended** — it aliases secrets from other backends. Storing actual secret values in a flat file is what `.env` already does poorly. Prefer routing through Keychain or any cloud backend instead.

## Authentication

None. The backend reads from the filesystem with the current user's permissions.

If a file is unreadable (permissions, missing), `secretenv doctor` reports it cleanly.

## doctor Output

Healthy (file readable):

```
local                                                            (local)
  ✓ filesystem access
  ✓ /Users/alice/.config/secretenv/local-registry.toml — readable
```

File missing or unreadable:

```
local                                                            (local)
  ✓ filesystem access
  ✗ /Users/alice/.config/secretenv/local-registry.toml — not readable
      → check the path exists and you have read permissions
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Supported via `git log --follow`. `secretenv registry history <alias>` shells out to `git log` against the registry file and returns one entry per commit, with the short SHA as `version`, the ISO-8601 author timestamp, and the author name/email as `actor`. The file must be inside a git repository; a clear error is returned if it is not tracked. The fragment is rejected before the git call fires.

## Limitations

- **Plaintext on disk if storing raw secrets.** `chmod 600` and exclude from cloud-syncing backups. Strongly prefer the registry-document pattern.
- **No write protection.** Anyone with write access to the file can change values; no signing or verification.
- **TOML parse errors are fatal.** A malformed file fails the whole resolve, not just the affected alias.

## Examples

### Solo dev with local + keychain

```toml
# ~/.config/secretenv/config.toml

[backends.local-main]
type = "local"

[backends.keychain-default]
type = "keychain"

[registries.default]
sources = ["local-main:///Users/you/.config/secretenv/aliases.toml"]
```

```toml
# ~/.config/secretenv/aliases.toml — the registry

stripe-key  = "keychain-default:///myapp/stripe-key"
db-url      = "keychain-default:///myapp/db-url"
api-token   = "keychain-default:///myapp/api-token"
```

```bash
secretenv run -- npm start
```

### Development environment with literal defaults

```toml
# ~/Projects/myapp/.env.local.toml

DATABASE_URL = "postgres://localhost:5432/myapp"
REDIS_URL    = "redis://localhost:6379"
DEBUG        = "true"
```

```toml
# ~/.config/secretenv/config.toml

[backends.local-dev]
type = "local"

[registries.default]
sources = ["local-dev:///Users/you/Projects/myapp/.env.local.toml"]
```

## Troubleshooting

**"file is not readable"**
Check the file path is correct (must be absolute). Verify permissions: `chmod 600 ~/.config/secretenv/aliases.toml`. Verify the file exists: `ls -la /absolute/path/to/file.toml`.

**"failed to parse TOML"**
The file is readable but the TOML syntax is invalid. Check for missing quotes on values, missing `=` signs, or unclosed brackets.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how aliases resolve
- [macOS Keychain backend](keychain.md) — the typical pair for `local`-as-registry
- [AWS SSM backend](aws-ssm.md) — alternative: cloud-native parameter store
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
