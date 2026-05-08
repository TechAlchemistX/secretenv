# Keeper

**Type:** `keeper`
**CLI required:** [`keeper` (Commander)](https://docs.keeper.io/en/keeperpam/commander-cli) v17+ — `pip install keepercommander`
**URI scheme:** `<instance-name>:///<record-uid-or-title>[#field=<name>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `keeper Commander 17.2.13` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `keeper` backend. New here? See the [main README](../../README.md).

Keeper is an enterprise password manager and secrets vault. Unlike other backends, Keeper requires a one-time persistent-login setup before non-interactive use. After setup, the `keeper` CLI provides interactive shell access and one-shot commands. This backend wraps the one-shot path.

## When to pick this

- **Enterprise password vault:** team password sharing, fine-grained record permissions
- **Persistent-login workflows:** machine-bound device tokens for non-interactive use
- **Compliance auditing:** Keeper Vault tracks access via the web UI
- **Existing Keeper deployments:** native integration without a new credential type

## Important — persistent-login setup required

**Before adding a Keeper instance to `config.toml`, set up persistent login:**

```bash
keeper shell
# At the `My Vault>` prompt:
this-device register
this-device persistent-login on
quit

# Verify:
keeper --batch-mode login-status
# Expected: "Logged in"
```

This writes a device token to `~/.keeper/config.json`. The backend reads it automatically on every invocation.

## Configuration

```toml
[backends.keeper-prod]
type                      = "keeper"
# keeper_config_path     = "~/.keeper/config.json"   # optional — override default
# keeper_unsafe_set      = false                     # optional — opt-in for set()
# keeper_list_max_records = 500                      # optional — cap for list()
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"keeper"` |
| `keeper_config_path` | No | Path to `config.json` holding the device token. Defaults to `~/.keeper/config.json`. Must be mode 0600 or stricter; permissive modes are rejected. |
| `keeper_unsafe_set` | No | Default `false`. When `false`, `set()` bails with a UI pointer. When `true`, opts into argv-based `set()` — **the Keeper CLI has no stdin form**, so argv exposure via `ps -ww` is unavoidable. |
| `keeper_list_max_records` | No | Optional cap on `list()` per-record enumeration. Default unset (no cap). When set, stops after N records, bounding heap + rate-limit pressure on large vaults. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Multi-account setups

```toml
[backends.keeper-personal]
type               = "keeper"
keeper_config_path = "~/.keeper/personal.json"

[backends.keeper-enterprise]
type               = "keeper"
keeper_config_path = "~/.keeper/enterprise.json"
```

Each config file needs its own persistent-login setup.

## URI Format

```
keeper-prod:///STRIPE_API_KEY
└──────────┘    └────────────┘
instance name   record UID or title
```

The path segment is the record identifier — either a 22-character base64url UID or a record title. The Keeper CLI resolves both.

### Field-selection fragment

By default, `get` returns the **password field**:

```
keeper-prod:///STRIPE_API_KEY#field=api_key
```

`#field=<name>` selects a custom field or typed field. Matching is case-insensitive. Priority: custom-field label → typed-field label → typed-field type name.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

All auth flows through the persistent-login **device token** in `~/.keeper/config.json` (or `keeper_config_path`). The master password is never read by this backend.

Verify persistent login:

```bash
keeper --batch-mode login-status
# → "Logged in"

keeper --batch-mode whoami
# → user info, including server region
```

Keeper accounts are region-sharded (US, EU, AU, CA, JP, GOV). If your account lives in a non-US region, regenerate the config with `keeper --server EU shell → this-device register → persistent-login on`.

## doctor Output

Healthy:

```
keeper-prod                                                     (keeper)
  ✓ keeper Commander v17.2.13
  ✓ authenticated  user=you@example.com
```

Not authenticated (device token missing or stale):

```
keeper-prod                                                     (keeper)
  ✓ keeper Commander v17.2.13
  ✗ not authenticated
      → run: keeper shell → this-device register → persistent-login on
```

## Fragment directives

| Directive | Effect | Example |
|---|---|---|
| `field=<name>` | Select a custom or typed field (case-insensitive) | `keeper-prod:///MyRecord#field=api_key` |
| (no fragment) | Default to the `password` field | `keeper-prod:///MyRecord` |

Other fragments are rejected with a specific error.

## History API support

Not implemented. Keeper records have per-version history in the Vault UI (Vault → record → `...` → "Record History") and the REST API, but the `keeper` CLI (v17.2.13) has no per-record history subcommand. Use the Vault UI to view record history.

## Limitations

- **Set is gated by default.** `keeper_unsafe_set = true` is required because the Keeper CLI has no stdin form for field values. argv exposure via `ps -ww` is unavoidable when opted in.
- **Device token is a trust boundary.** `~/.keeper/config.json` contains long-lived auth. Protect it (`chmod 600` is the default) and the parent directory (`chmod 700 ~/.keeper`).
- **Large vault enumeration is sequential.** `list()` runs one `keeper get` per record. 1000+ records can take several seconds; use `keeper_list_max_records` to cap.

## Examples

### Single vault

```toml
[backends.keeper-prod]
type = "keeper"

[registries.default]
sources = ["keeper-prod:///REGISTRY"]
```

### Multi-vault by config file

```toml
[backends.keeper-personal]
type               = "keeper"
keeper_config_path = "~/.keeper/personal.json"

[backends.keeper-work]
type               = "keeper"
keeper_config_path = "~/.keeper/work.json"
```

### As registry source

Keeper record `REGISTRY` holds:

```json
{
  "stripe_key": "keeper-prod:///STRIPE_API_KEY",
  "db_url": "vault-prod:///secret/db",
  "api_token": "keeper-prod:///API_TOKEN"
}
```

Then: `secretenv run --registry keeper-prod:///REGISTRY -- npm start`

## Troubleshooting

**"not authenticated — invalid master password"**
Persistent login is not set up. Follow the [setup section](#important--persistent-login-setup-required) above.

**"record not found"**
The record UID or title doesn't exist in the vault. Verify with `keeper --batch-mode list` or `keeper shell → search`.

**"set() is gated behind keeper_unsafe_set = true"**
The Keeper CLI has no stdin form for field values. Either opt in via config (`keeper_unsafe_set = true` + `tracing::warn!` on every use) or use the Keeper Vault UI for writes.

## See Also

- [`secretenv doctor`](../../README.md#operational-health-secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc. on other backends
- [Keeper CLI reference](https://docs.keeper.io/en/keeperpam/commander-cli) — authoritative Keeper docs
- [All backends](README.md) — pick a different backend
- [Main README](../../README.md) — overview + workflows
