# Local File

- **Type:** `local`
- **CLI required:** None (filesystem only)
- **URI scheme:** `<instance-name>:///path/to/file.toml`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** SecretEnv v0.19.0

> SecretEnv injects secrets as environment variables. This page covers the `local` backend, the only one needing no CLI. New here? See the [overview](/).

Read secrets from a TOML file on disk. Best for solo development (zero infrastructure) or as a registry document pointing at other backends.

## When to pick this

- **Solo development**, no external service, no credentials
- **Local registry**, alias to Keychain, Vault, or other backends
- **Air-gapped setups**, all secrets on disk, no network
- **Quick testing**, minimal setup

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

Configure multiple `local` instances to reference different files:

```toml
[backends.local-personal]
type = "local"

[backends.local-team]
type = "local"
```

## URI Format

```
local:///Users/yourname/.config/secretenv/local-registry.toml
└────┘   └──────────────────────────────────────────────────┘
instance  absolute path to TOML file
```

Path must be absolute. File must be a flat TOML key-value document (top-level keys only; values are scalars or URIs).

**Verify:** `secretenv doctor`. Green output means SecretEnv can read the file.

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

**Strongly prefer the registry-document pattern.** It aliases from other backends. Storing actual secrets in flat files defeats the point; use Keychain or a cloud backend instead.

## Authentication

None. Reads the file with the current user's permissions. Unreadable files are reported cleanly by `secretenv doctor`.

## doctor Output

Healthy (file readable):

```
local                                                            (local)
  ✓ filesystem access
  ✓ /Users/alice/.config/secretenv/local-registry.toml, readable
```

File missing or unreadable:

```
local                                                            (local)
  ✓ filesystem access
  ✗ /Users/alice/.config/secretenv/local-registry.toml, not readable
      → check the path exists and you have read permissions
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Supported via `git log --follow` on the registry file. Returns one entry per commit with short SHA (version), ISO-8601 timestamp, and author name/email. File must be git-tracked; clear error if not.

## Limitations

- **Plaintext if storing raw secrets.** Use `chmod 600` and exclude from cloud backups
- **No write protection.** Writable file = writable secrets (no signing)
- **Parse errors are fatal.** Malformed TOML fails all aliases, not just one

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
# ~/.config/secretenv/aliases.toml, the registry

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

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how aliases resolve
- [macOS Keychain backend](keychain.md), the typical pair for `local`-as-registry
- [AWS SSM backend](aws-ssm.md), alternative: cloud-native parameter store
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
