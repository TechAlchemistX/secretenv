# Bitwarden Secrets Manager

**Type:** `bitwarden-sm`
**CLI required:** [`bws`](https://bitwarden.com/help/secrets-manager-cli/) (Bitwarden Secrets Manager CLI v2+)
**URI scheme:** `<instance-name>://<uuid>[#json-key=<field>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `bws 2.0.0` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `bitwarden-sm` backend. New here? See the [main README](../../README.md).

[Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) is Bitwarden's developer/CI secrets product — machine-account access tokens, project-scoped secrets keyed by UUID. It is **a distinct product from Bitwarden Password Manager** (`bw` CLI). The backend wraps `bws` v2+ only; human-readable aliases live in the SecretEnv registry layer because `bws secret get` accepts UUIDs only (no key-name lookup), and Bitwarden allows duplicate key names within a project.

## When to pick this

- **You use Bitwarden:** native integration, no new service account type
- **Multi-environment CI:** machine accounts scoped per project suit dev/staging/prod separation
- **Zero-infrastructure local:** machine accounts with no internal PKI required
- **EU/self-hosted Bitwarden:** set `bitwarden_server_url` to your deployment

## Configuration

```toml
[backends.bws-prod]
type = "bitwarden-sm"
bitwarden_project_id = "abcdef01-2345-6789-abcd-ef0123456789"
# Optional fields: bitwarden_server_url, bitwarden_access_token_env
```

For EU cloud or self-hosted:

```toml
[backends.bws-prod]
type                 = "bitwarden-sm"
bitwarden_project_id = "abcdef01-2345-6789-abcd-ef0123456789"
bitwarden_server_url = "https://vault.bitwarden.eu"   # EU cloud
# bitwarden_server_url = "https://bws.company.com"    # self-hosted
```

For multiple machine accounts:

```toml
[backends.bws-prod]
type                       = "bitwarden-sm"
bitwarden_project_id       = "abcdef01-..."
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_PROD"

[backends.bws-staging]
type                       = "bitwarden-sm"
bitwarden_project_id       = "12345678-..."
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_STAGING"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"bitwarden-sm"` |
| `bitwarden_project_id` | Yes | Project UUID this instance scopes to. Find via the web UI or `bws project list`. |
| `bitwarden_server_url` | No | Override the Bitwarden server URL. Defaults to US cloud (`https://vault.bitwarden.com`). Set for EU cloud or self-hosted. |
| `bitwarden_access_token_env` | No | Name of the env var holding the machine-account access token. Defaults to `BWS_ACCESS_TOKEN`. Use to keep multiple instances scoped to different machine accounts without collision. |
| `bitwarden_bin` | No | Override the `bws` binary path. Defaults to `"bws"` (PATH lookup). |
| `bitwarden_unsafe_set` | No | Defense-in-depth opt-in for argv-based `set` / `delete`. Defaults to `false` (both refused). |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

## URI Format

```
bws-prod://abcdef0123456789abcdef0123456789
└─────┘   └──────────────────────────────┘
instance  UUID (36-char hyphenated or 32-char simple)
```

The path is the secret's UUID. `bws` accepts both the canonical hyphenated form (`8-4-4-4-12`, 36 chars) and the 32-char simple form (no hyphens). The wrapper normalizes both to lowercase.

### Why UUID, not key-name

- `bws secret get` accepts UUID only; there is no `--key` lookup mode.
- Bitwarden allows duplicate key names within a project, making key-name URIs ambiguous.
- Human-readable aliases live in the SecretEnv registry: `stripe-live → bws-prod://abcdef...`.

### `#json-key=<field>` fragment

When the secret's value is JSON, extract a top-level scalar:

```toml
db_password = "bws-prod://abcdef0123456789abcdef0123456789#json-key=password"
db_username = "bws-prod://abcdef0123456789abcdef0123456789#json-key=username"
```

The fragment is recognized on `get` only. `set`, `delete`, `list`, and `history` reject any fragment.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Bitwarden Secrets Manager uses **machine accounts** (not user logins). Issue an access token in the web UI:

1. Open the [Bitwarden web vault](https://vault.bitwarden.com/) → **Secrets Manager → Machine Accounts → New machine account**.
2. Grant `read` (or `read-write`) on the projects this instance will access.
3. Generate an **Access Token** (shape: `0.<uuid>.<base64>:<base64>`).
4. Export it (no surrounding quotes — see below):

   ```bash
   export BWS_ACCESS_TOKEN=0.abc...:xyz...    # NO QUOTES
   ```

There is **no interactive `bws login` flow** — `bws` is purely env-var-driven. The wrapper sources the token from your shell at command time and sets `BWS_ACCESS_TOKEN` on the child process env only; it is never logged or written to argv.

### Critical: no surrounding quotes

`bws` v2 doesn't strip surrounding double-quotes from `BWS_ACCESS_TOKEN`. If you export `BWS_ACCESS_TOKEN="..."` (literal quotes), the quote characters become part of the token bytes, decryption fails, and you get the misleading "Cipher MAC doesn't match". Re-export bare. Verify with:

```bash
echo "len=${#BWS_ACCESS_TOKEN}"
# A clean token is 94 chars; quoted reads 96.
```

## RBAC and project scoping

Bitwarden Secrets Manager scopes access at the **project** level. Machine accounts are granted `read` or `read-write` per project:

- `get` / `list` / `check`: `read` on the project.
- `set` / `delete`: `read-write` on the project (and `bitwarden_unsafe_set = true`).

Manage via the web UI; SecretEnv does not provision machine accounts or tokens.

## doctor Output

Healthy state:

```
bws-prod                                                  (bitwarden-sm)
  ✓ bws CLI 2.0.0
  ✓ authenticated  server=https://vault.bitwarden.com  projects=3
```

Missing access token:

```
bws-prod                                                  (bitwarden-sm)
  ✓ bws CLI 2.0.0
  ✗ not authenticated
      → run: export BWS_ACCESS_TOKEN=0.<machine-uuid>.<base64>:<base64>  (no quotes)
```

## Fragment directives

| Directive | Effect | Example |
|---|---|---|
| `json-key=<field>` | Extract top-level JSON field | `bws-prod://uuid#json-key=password` |

Other fragments are rejected with an enumerated error.

## History API support

Not implemented. Bitwarden Secrets Manager surfaces revision timestamps in the web UI (`revisionDate` field), but the CLI exposes no `secret history` subcommand. `secretenv registry history <alias>` returns the trait-default "not implemented" until the vendor exposes version metadata via CLI.

## Limitations

- **`set` disabled by default.** `bws secret edit --value <value>` passes the value through argv. Set `bitwarden_unsafe_set = true` to enable; only do so after reading the threat model. Recommended alternative: provision via the web UI.
- **`delete` is gated alongside `set`.** Both are destructive write operations; the gate flag applies to both.
- **`set` updates only, never creates.** A UUID can only refer to an existing secret. Provision secrets via the web UI (or `bws secret create` outside SecretEnv), obtain the UUID, then add it to the registry.
- **UUID addressing only.** Alias via registry.
- **No secret history via CLI.** History is available in the web UI only.
- **Free-tier limits apply.** Free tier caps at 2 projects and 2 machine accounts per organization.

## Examples

### Single instance, US cloud

```toml
[backends.bws-prod]
type                 = "bitwarden-sm"
bitwarden_project_id = "abcdef01-2345-6789-abcd-ef0123456789"

[registries.default]
sources = ["bws-prod://abcdef0123456789abcdef0123456789"]
```

```bash
export BWS_ACCESS_TOKEN=0.machine-uuid.base64:mac
secretenv doctor
secretenv run -- npm start
```

### Multi-project setup

```toml
[backends.bws-payments]
type                       = "bitwarden-sm"
bitwarden_project_id       = "11111111-..."
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_PAYMENTS"

[backends.bws-platform]
type                       = "bitwarden-sm"
bitwarden_project_id       = "22222222-..."
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_PLATFORM"

[registries.payments]
sources = ["bws-payments://abc..."]

[registries.platform]
sources = ["bws-platform://def..."]
```

```bash
export BWS_ACCESS_TOKEN_PAYMENTS=0.pay-uuid...
export BWS_ACCESS_TOKEN_PLATFORM=0.plat-uuid...
secretenv run --registry platform -- npm start
```

### Self-hosted Bitwarden

```toml
[backends.bws-internal]
type                       = "bitwarden-sm"
bitwarden_project_id       = "33333333-..."
bitwarden_server_url       = "https://bws.company.com"
bitwarden_access_token_env = "BWS_INTERNAL_TOKEN"
```

## Troubleshooting

**"Cipher MAC doesn't match"**
Your `BWS_ACCESS_TOKEN` contains surrounding quotes. Export bare: `export BWS_ACCESS_TOKEN=0.uuid...` (no `"..."` wrapper). Verify with `echo "len=${#BWS_ACCESS_TOKEN}"` — should be 94 chars, not 96.

**"set is disabled by default"**
You hit the defense-in-depth gate. Either provision the secret via the Bitwarden web UI (preferred) or set `bitwarden_unsafe_set = true` and review the threat model. Per-invocation warnings appear in `secretenv --verbose` output.

**"URI path must be a Bitwarden UUID"**
The path is neither 36-char hyphenated nor 32-char simple UUID format. Get the UUID from `bws secret list --output json | jq -r '.[].id'`.

**"doctor returns projects=0"**
Your token is authenticated but scoped to zero projects. Grant the machine account access to a project in the web UI, or verify you exported the correct token (token from a different organization finds no projects in yours).

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc.
- [1Password backend](1password.md) — alternative: personal vault + team vaults
- [Vault backend](vault.md) — alternative: HashiCorp's general-purpose secrets engine
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
