# 1Password

- **Type:** `1password`
- **CLI required:** [`op`](https://developer.1password.com/docs/cli/get-started/)
- **CLI version:** 1Password CLI v2
- **URI scheme:** `<instance>://vault/item/field`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `op 2.34.0` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets as environment variables. This page covers the `1password` backend. New here? See the [overview](/).

1Password is a team password manager with audit logging and access control. The `op` CLI supports both interactive (desktop app) and non-interactive (service accounts) authentication.

## When to pick this

- **Team sharing**, fine-grained access control per vault
- **Audit trails**, every access logged for compliance
- **Desktop integration**, biometric auth via 1Password app (no token management)
- **CI/CD automation**, scoped service accounts

## Configuration

```toml
[backends.1password-work]
type       = "1password"
op_account = "company.1password.com"  # optional, omit for single-account setups
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

URIs require exactly three segments: vault, item, and field. Common fields for Login items: `username`, `password`. API Credential items: use the configured field label.

**Verify:** `secretenv doctor`. Green output means ready to run.

## Authentication

**Local development:** Biometric via the 1Password desktop app. The `op` CLI communicates over a local socket. Open the app and authenticate once; no token management needed.

**CI/CD:** Use a service account token (1Password's official non-interactive method):

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

Create service accounts in the 1Password admin console. Scope to specific vaults only, never all vaults.

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

Not implemented. The `op` CLI lacks a per-item history subcommand for programmatic retrieval.

## Limitations

- **Set requires opt-in.** `op item edit` passes values via argv (visible in `/proc/<pid>/cmdline` on multi-user Linux); this is a 1Password CLI limitation. Disabled by default; enable with `op_unsafe_set = true`
- **No auto-create.** `registry set` edits existing items only; create items manually first via 1Password app or `op item create`
- **No nested fields.** v0.13 supports flat three-segment URIs only (`vault/item/field`)

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

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [1Password CLI documentation](https://developer.1password.com/docs/cli), `op` command reference
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
