# Keeper

**Type:** `keeper`
**CLI required:** [`keeper` (Keeper Commander)](https://docs.keeper.io/en/keeperpam/commander-cli) v17+ — `pip install keepercommander`
**URI scheme:** `<instance-name>:///<record-uid-or-title>` with optional `#field=<name>` fragment
**Platform:** cross-platform (macOS, Linux, Windows)

Keeper is an enterprise password manager and secrets vault. The `keeper` CLI (Keeper Commander) wraps the Keeper API and ships with a full interactive shell plus one-shot subcommand invocation. This backend wraps the one-shot path with `--batch-mode`.

## Important — persistent-login is a prerequisite

**Unlike every other SecretEnv backend, Keeper requires a one-time setup before any non-interactive invocation works.** The CLI does not persist session state across one-shot invocations by default — each `keeper <cmd>` would prompt for the master password interactively.

Set up persistent login **before** adding a Keeper instance to `config.toml`:

```bash
keeper shell
# At the `My Vault>` prompt:
this-device register
this-device persistent-login on
quit

# Verify:
keeper --batch-mode login-status
# Expected output: "Logged in"
```

This writes a device token to `~/.keeper/config.json`. The backend reads through that token automatically.

If persistent login isn't set up, `doctor` reports `not authenticated` with a hint pointing back at this setup; nothing hangs, nothing prompts.

---

## Configuration

```toml
[backends.keeper-prod]
type = "keeper"                                      # required
# All fields below are optional.
# keeper_config_path = "/home/ci/.keeper/config.json"  # override ~/.keeper/config.json
# keeper_unsafe_set  = false                         # opt-in gate for set() — default false
# timeout_secs       = 15                            # default: DEFAULT_GET_TIMEOUT (30 s)
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"keeper"` |
| `keeper_folder` | No | Reserved for future short-form URI scoping. Currently accepted but unused. |
| `keeper_config_path` | No | Path to the Keeper Commander `config.json` holding the persisted device token. Defaults to `~/.keeper/config.json` (the CLI's own default). Useful for multi-account setups where you keep separate config files per account. |
| `keeper_unsafe_set` | No | Default `false`. When `false`, `set()` bails with a pointer at the Keeper Vault UI. When `true`, opts into argv-based `set()` via `record-add`/`record-update` — **the Keeper CLI has no stdin form for field values**, so argv exposure via `ps -ww` is unavoidable. Matches the 1Password `op_unsafe_set` precedent (see `docs/backends/1password.md`). |
| `timeout_secs` | No | Per-instance fetch deadline. Default `DEFAULT_GET_TIMEOUT` (30 s). Keeper API latencies are typically sub-second but authoritative-source fetches can spike during peak. |

### Multi-account setups

Keeper Commander supports one active account per config file. For multiple Keeper accounts on one machine, keep a separate config file per account and route via `keeper_config_path`:

```toml
[backends.keeper-personal]
type               = "keeper"
keeper_config_path = "~/.keeper/personal.json"

[backends.keeper-enterprise]
type               = "keeper"
keeper_config_path = "~/.keeper/enterprise.json"
```

Each config file needs its own persistent-login setup (`keeper --config ~/.keeper/personal.json shell` → `this-device register` → `persistent-login on`).

---

## URI Format

### Standard form (single segment)

```
keeper-prod:///STRIPE_API_KEY
└──────────┘    └────────────┘
instance name   record UID or title
```

The path segment IS the record identifier. The Keeper CLI's `get <target>` subcommand accepts **either**:

- A 22-character base64url record UID (`keeper-prod:///kF3aBcDeFgHiJkLmNoPqRs`)
- A record title (`keeper-prod:///STRIPE_API_KEY`)

No disambiguation is needed — the CLI resolves both. Titles that collide with UIDs (22 chars, matching charset) are vanishingly unlikely but technically ambiguous; prefer UIDs for scripted pipelines.

### Field-selection fragment

By default, `get` returns the record's **password field** (the most common case for a secrets-manager record):

```
keeper-prod:///STRIPE_API_KEY
```

To read a custom field or a different typed field, append `#field=<name>`:

```
keeper-prod:///STRIPE_API_KEY#field=api_key      # custom field named "api_key"
keeper-prod:///MY_SERVER#field=login             # typed "login" field (username)
keeper-prod:///MY_SERVER#field=url               # typed "url" field
```

Field-name matching is **case-insensitive** — `#field=api_key` matches a label `API_KEY`. Priority order: custom-field label match → typed-field label match → typed-field type name match.

Fragments other than `#field=<name>` are rejected with a specific error at URI-parse time; the v0.2.1 canonical fragment vocabulary (`#version=5` etc.) does not apply to Keeper.

### Folder-path URIs

**Not currently supported.** Keeper records live in folders, but the URI format is a single segment. If your record title isn't globally unique, either rename it or reference it by UID. Future enhancement (v0.8.x+) could add `keeper_folder` as a scoping hint.

---

## Authentication

All authentication flows through the persistent-login **device token** in `~/.keeper/config.json` (or the file named by `keeper_config_path`). The master password is **never** read by this backend.

### Verifying persistent login works

```bash
keeper --batch-mode login-status
# → "Logged in"

keeper --batch-mode whoami --format=json
# → {"user":"you@example.com","server":"US",...}
```

If `login-status` says anything other than "Logged in", run through the [setup section](#important--persistent-login-is-a-prerequisite) above.

### Server region

Keeper accounts are region-sharded (US, EU, AU, CA, JP, GOV). The persistent-login device token is bound to the region where you created it. If your account lives in EU, your `keeper shell` invocations must use `--server EU` OR your config file must record the region — the CLI handles both paths.

v0.8 does **not** expose a per-instance server override. If your backend's `config.json` was created against the wrong region, regenerate it with `keeper --server EU shell → this-device register → persistent-login on`.

### Token rotation

Device tokens are long-lived but revocable. `keeper` CLI → `My Vault>` → `device-list` shows every active device; `device-action --action revoke --device <id>` invalidates one. After revocation, re-run `this-device register + persistent-login on` on the affected machine.

---

## `set()` discipline — argv exposure

The Keeper CLI has **no stdin form** for field values. `record-add` and `record-update` pass field values on argv, which is visible to same-UID processes via `ps -ww` and may persist in process-accounting logs.

### Default: `set()` bails

Without `keeper_unsafe_set = true` in the instance config, any `set()` call surfaces:

```
keeper backend '<instance>': set() is gated behind `keeper_unsafe_set = true`
because the `keeper` CLI has no stdin form for field values — `record-add`
and `record-update` pass the value on argv, which is visible to same-UID
processes via `ps -ww`. Opt in explicitly in your config.toml, or set the
value through the Keeper Vault UI (URI '<uri>').
```

This matches 1Password's `op_unsafe_set` precedent (v0.4 Phase 3): dangerous-by-default CLIs require an explicit opt-in before SecretEnv routes writes through them.

### Opt-in: `keeper_unsafe_set = true`

```toml
[backends.keeper-ci]
type              = "keeper"
keeper_unsafe_set = true
```

With the flag set, `set()`:

1. Probes existence: `keeper --batch-mode get <target> --format=detail`. Exit 0 → record exists (use `record-update`); non-zero with "not found" → new record (use `record-add`).
2. New record: `keeper --batch-mode record-add -t <title> -rt login password=<value>`.
3. Existing record: `keeper --batch-mode record-update -r <uid> password=<value>`.

A `tracing::warn!` fires on every `set()` call, naming the instance + URI + argv-exposure mechanism. Operators running in multi-user contexts or on hosts with sensitive process-accounting see a clear trail.

### Threat-model guidance

- **Single-user personal workstation:** opt-in is typically fine. Same-UID exposure is bounded by process lifetime (~seconds) and doesn't persist beyond it on default configurations.
- **Shared CI host / multi-tenant compute:** do NOT opt in. Use the Keeper Vault UI or Keeper Commander's interactive `keeper shell` for writes. Leave `set()` gated.
- **Production compute plane:** SecretEnv is a developer tool, not a production secret-delivery mechanism. Keeper writes on production hosts are out of scope regardless of `keeper_unsafe_set`.

---

## `list()` — registry-source semantics

Keeper's `list()` uses the **Pattern A bulk model**: each vault record becomes one alias; the record's password field serves as the alias target URI. Mirrors Doppler + Infisical.

```bash
# Keeper vault with URI-valued records:
#   STRIPE_KEY        → "aws-ssm-prod:///stripe-key" (in password field)
#   DB_URL            → "vault-dev:///secret/db"     (in password field)
#   SEGMENT_WRITE_KEY → "1password-private://Private/seg/password"

[registries.default]
sources = ["keeper-prod:///UNUSED_MARKER"]

[backends.keeper-prod]
type = "keeper"
```

The URI's record segment (`UNUSED_MARKER`) is **ignored by `list()`** — the bulk list enumerates the whole vault. Using a recognizable placeholder makes the intent obvious in your config.

### Implementation note: sequential get()

`keeper list --format=json` returns record metadata only (no field values), so the backend follows up with one `keeper get --format=password --unmask` per record to hydrate the target URI. This is sequential to respect per-token rate limits. For large vaults (1000+ records), `list()` latency can be several seconds.

---

## `history()` — unsupported via CLI

**Keeper records HAVE per-version history** — the Keeper Vault UI shows it under Record → `...` → "Record History", and the REST API exposes it. The `keeper` CLI (v17.2.13) does **not** expose a per-record history subcommand. Commander's `keeper history` command is input-line history for the interactive shell, **not** record version history.

Until the CLI adds `keeper record-history <uid>` or equivalent, `history()` returns:

```
keeper backend '<instance>': history is not supported — the `keeper` CLI
(v17.2.13) has no per-record version-history subcommand; record version
history IS available in the Keeper Vault UI (Vault → record → '...' →
'Record History'). URI '<uri>'
```

A future CLI release that adds the subcommand can flip this to a native implementation in a patch.

---

## Response parsing gotchas

- **`get --format=password` trailing newline.** The CLI writes the password followed by exactly one `\n`. The backend strips it; your consumer sees the raw value.
- **`get --format=json` returns a typed record.** Top-level object with `fields` + `custom` arrays. Each array entry is `{"type": ..., "label": ..., "value": [<string>]}`. Single-valued fields are normalized to a length-1 array.
- **`list --format=json` is an array.** Top-level `[<record>, ...]`. Each record object has `title`, `record_uid`, `type`, and nested arrays. The backend extracts just `title`; all other fields are dropped by serde.
- **`--unmask` is mandatory on reads.** Without it, the CLI replaces hidden-field values with `********` in the output. Every `get` in this backend passes `--unmask`.
- **`--batch-mode` is mandatory on every invocation.** Without it, an expired persistent-login token surfaces as an interactive password prompt that hangs the backend indefinitely.

---

## Security notes

- **Master password is NEVER read by this backend.** Auth flows through the `~/.keeper/config.json` device token. The file is written with mode 0600 by Commander itself.
- **`--batch-mode` on every invocation.** Prevents interactive prompts from hanging the backend.
- **Argv discipline:** `get` / `delete` / `list` pass the record identifier on argv (record titles are not secrets). `set` passes the **value** on argv — gated behind `keeper_unsafe_set = true`, `tracing::warn!` on every invocation.
- **Response bodies are secret-bearing.** `get --format=password` stdout IS the secret. `list --format=json` stdout is metadata only, but the follow-up `get` calls inside `list()` fetch values. Errors never interpolate stdout; `tracing` fields never include the value.
- **Config file is a trust boundary.** `~/.keeper/config.json` contains a long-lived device token equivalent to persistent auth. Protect the file (`chmod 600` is the Commander default) and the parent directory (`chmod 700 ~/.keeper`).
- **Backup considerations.** If you back up `~/.keeper/`, the device token travels with the backup. Store encrypted.

---

## doctor Output

Healthy:

```
keeper-prod                                             (keeper)
  ✓ v17.2.13
  ✓ authenticated  user=you@example.com server=US auth=persistent-login
```

Not authenticated (persistent login not set up, or token revoked):

```
keeper-prod                                             (keeper)
  ✓ v17.2.13
  ✗ not authenticated
      → set up persistent login: 'keeper shell' → 'this-device register' → 'this-device persistent-login on' → 'quit'
```

CLI missing:

```
keeper-prod                                             (keeper)
  ✗ CLI 'keeper' not found
      → pip install keepercommander  OR  https://docs.keeper.io/en/keeperpam/commander-cli
```

---

## Related

- [Fragment directives](../fragment-vocabulary.md) — `#field=<name>` for Keeper; the v0.2.1 canonical `#version=N` vocabulary is rejected by this backend since Keeper has no per-record history CLI surface.
- [`docs/registry.md`](../registry.md) — how alias → URI resolution works end-to-end.
- [`docs/security.md`](../security.md) — cross-backend threat-model notes (argv discipline, stdin-fed writes, trust boundaries).
- [`docs/backends/1password.md`](1password.md) — `op_unsafe_set` precedent that `keeper_unsafe_set` mirrors.
- [Keeper Commander docs](https://docs.keeper.io/en/keeperpam/commander-cli) — authoritative CLI reference.
- [Keeper record history](https://docs.keeper.io/en/user-guides/record-history) — where record version history lives (UI + REST, not CLI).
