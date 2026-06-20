# Bitwarden Secrets Manager

- **Type:** `bitwarden-sm`
- **CLI required:** [`bws`](https://bitwarden.com/help/secrets-manager-cli/)
- **CLI version:** Bitwarden Secrets Manager CLI v2+
- **URI scheme:** `<instance-name>://<uuid>[#json-key=<field>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `bws 2.0.0` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `bitwarden-sm` backend. New here? See the [overview](/).

Bitwarden Secrets Manager is Bitwarden's developer/CI secrets product (distinct from Password Manager). Machine-account tokens grant project-scoped access. This backend wraps `bws` v2+ only; `bws secret get` accepts UUIDs only (no key-name lookup), so human-readable aliases live in the SecretEnv registry layer.

## When to pick this

- **Bitwarden already in use:** native integration, no new service account type
- **Multi-environment CI:** per-project machine accounts for env separation
- **EU or self-hosted:** configurable server URL

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
| `bitwarden_project_id` | Yes | Project UUID (from web UI or `bws project list`). |
| `bitwarden_server_url` | No | Override server URL. Default: US cloud. Set for EU or self-hosted. |
| `bitwarden_access_token_env` | No | Env var name for machine-account token. Default: `BWS_ACCESS_TOKEN`. |
| `bitwarden_bin` | No | Override `bws` binary path. Default: `"bws"` (PATH lookup). |
| `bitwarden_unsafe_set` | No | Opt into argv-based `set` / `delete`. Default `false` (both gated). |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

## URI Format

```
bws-prod://abcdef0123456789abcdef0123456789
└─────┘   └──────────────────────────────┘
instance  UUID (36-char hyphenated or 32-char simple)
```

The path is the secret's UUID (36-char hyphenated or 32-char simple form, normalized to lowercase).

### Why UUID only

- No key-name lookup mode in `bws secret get`.
- Bitwarden allows duplicate key names; aliases via SecretEnv registry (`stripe-live → bws-prod://abcdef...`).

### `#json-key=<field>` fragment

When the secret's value is JSON, extract a top-level scalar:

```toml
db_password = "bws-prod://abcdef0123456789abcdef0123456789#json-key=password"
db_username = "bws-prod://abcdef0123456789abcdef0123456789#json-key=username"
```

The fragment is recognized on `get` only. `set`, `delete`, `list`, and `history` reject any fragment.

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Bitwarden Secrets Manager uses **machine accounts** (not user logins). Issue an access token in the web UI:

1. Open the [Bitwarden web vault](https://vault.bitwarden.com/) → **Secrets Manager → Machine Accounts → New machine account**.
2. Grant `read` (or `read-write`) on the projects this instance will access.
3. Generate an **Access Token** (shape: `0.<uuid>.<base64>:<base64>`).
4. Export it (no surrounding quotes, see below):

   ```bash
   export BWS_ACCESS_TOKEN=0.abc...:xyz...    # NO QUOTES
   ```

No interactive login flow exists. `bws` is purely env-var-driven. The token is set on the child process env only; never logged or on argv.

### Critical: no surrounding quotes

`bws` v2 doesn't strip surrounding quotes. If you export `BWS_ACCESS_TOKEN="..."`, the quotes become part of the token, causing "Cipher MAC doesn't match". Export bare. Verify:

```bash
echo "len=${#BWS_ACCESS_TOKEN}"  # Clean: 94 chars; quoted: 96
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

Not implemented. Revision timestamps are in the web UI, but the CLI has no `secret history` subcommand.

## Limitations

- **`set` gated by default:** argv-based (`bws secret edit --value <value>`). Set `bitwarden_unsafe_set = true` only after reading the threat model; prefer web UI.
- **`delete` gated with `set`:** both destructive; same flag controls both.
- **`set` updates only:** provision new secrets via web UI, obtain UUID, then add to registry.
- **UUID-only addressing:** human-readable names via registry.
- **No CLI history:** web UI only.
- **Free-tier limits:** 2 projects + 2 machine accounts per organization.

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
Your `BWS_ACCESS_TOKEN` contains surrounding quotes. Export bare: `export BWS_ACCESS_TOKEN=0.uuid...` (no `"..."` wrapper). Verify with `echo "len=${#BWS_ACCESS_TOKEN}"`. Should be 94 chars, not 96.

**"set is disabled by default"**
You hit the defense-in-depth gate. Either provision the secret via the Bitwarden web UI (preferred) or set `bitwarden_unsafe_set = true` and review the threat model. Per-invocation warnings appear in `secretenv --verbose` output.

**"URI path must be a Bitwarden UUID"**
The path is neither 36-char hyphenated nor 32-char simple UUID format. Get the UUID from `bws secret list --output json | jq -r '.[].id'`.

**"doctor returns projects=0"**
Your token is authenticated but scoped to zero projects. Grant the machine account access to a project in the web UI, or verify you exported the correct token (token from a different organization finds no projects in yours).

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key`, `#version`, etc.
- [1Password backend](1password.md), alternative: personal vault + team vaults
- [Vault backend](vault.md), alternative: HashiCorp's general-purpose secrets engine
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
