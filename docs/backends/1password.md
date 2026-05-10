# 1Password

**Type:** `1password`
**CLI required:** [`op`](https://developer.1password.com/docs/cli/get-started/) (1Password CLI v2)
**URI scheme:** `<instance>://vault/item/field`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `op 2.34.0` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `1password` backend. New here? See the [overview](/).

1Password is a password manager and secret store used by engineering teams for credential centralization, audit logging, and fine-grained access control. The `op` CLI is 1Password's official integration surface, supporting both interactive authentication via the desktop app and non-interactive service accounts for CI/CD environments.

## When to pick this

- **Team credential sharing:** 1Password vaults scale across teams; fine-grained access control per vault
- **Audit trails:** Every access is logged; compliance audits see who accessed what
- **Desktop integration:** Interactive biometric authentication via the 1Password app (no token management)
- **CI/CD service accounts:** 1Password supports scoped service accounts for non-interactive automation

## Configuration

```toml
[backends.1password-work]
type       = "1password"
op_account = "company.1password.com"  # optional — omit for single-account setups
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"1password"` |
| `op_account` | No | Account domain (e.g., `company.1password.com`). Required when multiple 1Password accounts are signed in |
| `op_unsafe_set` | No | Allow `set` operation (default `false`). See Limitations below. |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

### Multiple Accounts

```toml
[backends.1password-work]
type       = "1password"
op_account = "company.1password.com"

[backends.1password-personal]
type       = "1password"
op_account = "personal.1password.com"
```

## URI Format

```
1password-work://Engineering/Prod DB/password
└──────────────┘  └─────────┘ └────────┘ └───────┘
instance name    vault       item       field
```

URIs have exactly three path segments: vault name, item name, and field label. Common fields for Login items: `username`, `password`. For API Credential items: use the field label configured in 1Password.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

**Local development:** Interactive biometric authentication via the 1Password desktop app. The `op` CLI communicates with the app over a local socket. No token management required — open the app and authenticate once.

**CI/CD:** Use a service account token. This is 1Password's official mechanism for non-interactive environments:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

Service accounts are created in the 1Password admin console. Scope them to specific vaults — never grant access to all vaults for CI credentials.

## doctor Output

Healthy state:

```
1password-work                                              (1password)
  ✓ op CLI v2.34.0
  ✓ authenticated  account=company.1password.com
```

Not authenticated:

```
1password-work                                              (1password)
  ✓ op CLI v2.34.0
  ✗ not authenticated
      → open 1Password app and sign in, or set OP_SERVICE_ACCOUNT_TOKEN for CI
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Not implemented. The 1Password CLI does not expose a per-item version-history subcommand, so historical revisions cannot be retrieved programmatically.

## Limitations

- **Set operation requires opt-in.** `op item edit` passes the field value through subprocess argv (visible in `/proc/<pid>/cmdline` on multi-user Linux hosts). This is a 1Password CLI limitation (no stdin-fed form for field edits). The backend refuses `set` by default; operators acknowledge the exposure by setting `op_unsafe_set = true` under `[backends.<instance>]`.
- **No auto-create:** `secretenv registry set` modifies a single field within an existing item; it does not create new items. Create the item manually in the 1Password app or via `op item create` first.
- **Sections and nested fields:** v0.13 supports flat three-segment URIs only (`vault/item/field`). Nested sections are not supported.

## Examples

### Single vault, local development

```toml
[backends.1password-personal]
type       = "1password"

[registries.default]
sources = ["1password-personal://Personal/MyApp/api_token"]
```

```bash
secretenv run -- npm start
```

### Multi-vault with corporate account

```toml
[backends.1password-corp]
type       = "1password"
op_account = "company.1password.com"

[registries.prod]
sources = ["1password-corp://Engineering/Production/api_key"]
```

Deploy with: `secretenv run --registry prod -- ./deploy.sh`

### Registry document stored in 1Password

A 1Password note item with TOML-formatted content (one alias per line):

```toml
stripe-key = "1password-corp://Shared/Stripe/secret-key"
db-url     = "vault-eng://secret/prod/db"
```

Reference it as the registry source:

```bash
secretenv run --registry '1password-corp://Shared/Registry/notesPlain' -- npm start
```

## Troubleshooting

**"item not found in vault"**
Verify the vault name, item name, and field label match exactly. Use `op item list --vault Engineering` to list items in a vault, then `op item get "Item Name"` to inspect fields.

**"You are not signed in"**
For local dev: open the 1Password app and sign in. For CI: set `OP_SERVICE_ACCOUNT_TOKEN` in your environment.

**"refused set operation" (when op_unsafe_set is false)**
Enable `op_unsafe_set = true` in `[backends.1password-<instance>]` if you need to modify fields. Confirm your host is single-user or audited before doing so.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [1Password CLI documentation](https://developer.1password.com/docs/cli) — `op` command reference
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
