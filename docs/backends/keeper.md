# Keeper

- **Type:** `keeper`
- **CLI required:** [`keeper` (Commander)](https://docs.keeper.io/en/keeperpam/commander-cli)
- **CLI version:** v17+
- **URI scheme:** `<instance-name>:///<record-uid-or-title>[#field=<name>]`
- **Platform:** all (macOS, Linux, Windows)
- **Tested:** `keeper Commander 17.2.13` on macOS Darwin 25.4 (SecretEnv v0.19.0)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `keeper` backend. New here? See the [overview](/).

Keeper is an enterprise password manager and secrets vault requiring a one-time persistent-login setup for non-interactive use. This backend wraps the `keeper` CLI one-shot command path.

## When to pick this

- **Enterprise password vault:** fine-grained record permissions, team sharing, audit trails
- **Non-interactive CI:** persistent-login device tokens enable automation
- **Existing Keeper deployments:** native integration

## Important: persistent-login setup required

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
# keeper_config_path     = "~/.keeper/config.json"   # optional, override default
# keeper_unsafe_set      = false                     # optional, opt-in for set()
# keeper_list_max_records = 500                      # optional, cap for list()
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"keeper"` |
| `keeper_config_path` | No | Path to device-token file. Defaults to `~/.keeper/config.json` (mode 0600+ required). |
| `keeper_unsafe_set` | No | Opt into argv-based `set()` (unavoidable `ps -ww` exposure). Default `false`. |
| `keeper_list_max_records` | No | Cap on `list()` enumeration per vault size. Default: no limit. |
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

The path is the record identifier: 22-character UID or title (Keeper CLI resolves both).

### Field-selection fragment

By default, `get` returns the **password field**:

```
keeper-prod:///STRIPE_API_KEY#field=api_key
```

`#field=<name>` selects a custom field or typed field. Matching is case-insensitive. Priority: custom-field label → typed-field label → typed-field type name.

**Verify your setup with:** `secretenv doctor`. Green output means you're ready to run `secretenv run -- <your command>`.

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

Not implemented. The `keeper` CLI (v17.2.13) has no per-record history subcommand. View history via the Vault UI (Vault → record → `...` → "Record History").

## Limitations

- **`set` gated by default:** no stdin form available; argv exposure unavoidable. Set `keeper_unsafe_set = true` only if needed.
- **Device token is sensitive:** protect `~/.keeper/config.json` (mode 0600) and its parent directory (mode 0700).
- **Slow enumeration:** `list()` is sequential (one CLI call per record). Cap with `keeper_list_max_records` for large vaults.

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

**"not authenticated, invalid master password"**
Persistent login is not set up. Follow the [setup section](#important-persistent-login-setup-required) above.

**"record not found"**
The record UID or title doesn't exist in the vault. Verify with `keeper --batch-mode list` or `keeper shell → search`.

**"set() is gated behind keeper_unsafe_set = true"**
The Keeper CLI has no stdin form for field values. Either opt in via config (`keeper_unsafe_set = true` + `tracing::warn!` on every use) or use the Keeper Vault UI for writes.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor), health checks for all backends
- [Alias registry concepts](../reference/registry.md), how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md), `#json-key`, `#version`, etc. on other backends
- [Keeper CLI reference](https://docs.keeper.io/en/keeperpam/commander-cli), authoritative Keeper docs
- [All backends](README.md), pick a different backend
- [Overview](/), overview + workflows
