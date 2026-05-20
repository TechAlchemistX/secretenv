# `secretenv registry migrate`

`secretenv registry migrate` moves an alias's secret value from one backend to
another **in a single operation** — read the value from the current backend,
write it to the destination, then atomically flip the registry pointer so the
alias resolves to the new location. No repo touches a backend URI directly, so
a migration never requires a code change in any consuming project.

This page is the operator-facing reference. The design rationale lives in the
[Registry](./registry.md) concept page; the threat model is in
[`security.md`](../security.md).

---

## Command

```
secretenv registry migrate <ALIAS> <DEST_URI>
              [--dry-run]
              [--yes | -y]
              [--from <SOURCE_URI>]
              [--delete-source]
              [--json]
              [--registry <name|uri>]
```

| Argument / flag | Default | Effect |
|---|---|---|
| `<ALIAS>` | (required) | The registry alias to migrate. Must already exist in the active registry. |
| `<DEST_URI>` | (required) | The destination backend URI (e.g. `vault-prod:///secret/payments/stripe`). Must be a direct backend URI — not a `secretenv://` alias. The destination backend instance must be configured in `config.toml`. |
| `--dry-run` | off | Plan-only mode. Runs the source/destination probes, prints the migration plan, and exits **without any mutation**. Use this first on every migration. |
| `--yes` / `-y` | off | Skip the top-level confirmation prompt. **Does not** skip the `--delete-source` confirmation (see below). |
| `--from <SOURCE_URI>` | (inferred) | Override the source URI. By default the source is the alias's current registry pointer; `--from` is for recovery flows where the pointer was already flipped but the value still lives in the old backend. |
| `--delete-source` | off | After a successful migration, delete the value from the source backend. Opt-in and separately confirmed — see [`--delete-source`](#delete-source-opt-in-cleanup). |
| `--json` | off | Emit a machine-readable `MigrateReport` to stdout instead of the human progress output. For CI consumption. |
| `--registry <name|uri>` | active registry | Select which registry to operate on. Same semantics as `secretenv run --registry`. |

---

## The migration transaction

A migration is a **three-step transaction** with an optional fourth cleanup step:

1. **Read** — fetch the value from the source backend.
2. **Write** — write the value to the destination backend.
3. **Pointer flip** — rewrite the registry document so the alias points at the
   destination URI. **This is the commit point.**
4. **Source delete** *(optional)* — only when `--delete-source` is passed and
   separately confirmed.

The commit point is step 3. Before it, nothing the operator depends on has
changed — the alias still resolves to the source. After it, the alias resolves
to the destination.

### What is NOT atomic

The pointer flip itself is implemented as read-modify-write of the registry
document (`list` → mutate → `set`). It is **not** atomic at the storage layer:
a concurrent `secretenv registry set` against the same registry instance can
race it. The window is one round-trip and registry mutations are rare,
operator-driven events — but if you script migrations, **serialize them**
against a single registry instance. A content-addressed (`cas_set`) protocol
is planned for a later release.

---

## Dry run

Always dry-run a migration first. `--dry-run` probes both ends and prints the
plan with zero mutation:

```
$ secretenv registry migrate stripe-key vault-prod:///secret/payments/stripe --dry-run

secretenv migrate (dry-run):
  alias:        stripe-key
  source type:  1password
  dest type:    vault

Probes:
  1password-work       ok
  vault-prod           ok (probed)

Dry-run complete. No changes made. Remove --dry-run to execute.
```

The **probe line** for the destination distinguishes two cases:

- `ok (probed)` — the backend ran a real write-permission probe and it passed.
  Only HashiCorp Vault does this in the current release (`vault token
  capabilities`).
- `ok (no probe available for this backend)` — the backend has no cheap
  permission probe; the dry-run cannot pre-verify write access. The real write
  in a non-dry-run will surface any permission failure.

A destination probe that **definitively** fails (e.g. Vault returns a `deny`
capability) aborts the dry-run — and a real migration — before any read.

---

## Confirmation prompts

By default `migrate` prompts once before doing anything:

```
About to migrate stripe-key:
  from: 1password-work://Payments/Stripe/api_key
  to:   vault-prod://secret/payments/stripe

This will read the current value from the source and write it to the destination.
The registry pointer will be updated on success.
The source value will NOT be deleted.

Continue? [y/N]
```

`--yes` skips this top-level prompt.

---

## `--delete-source`: opt-in cleanup

By default a migration **leaves the source value in place**. The success
message prints a copy-paste cleanup command:

```
Migration complete.
  alias:           stripe-key
  probe / read / write / flip ms: 84 / 341 / 92 / 121
  source value still present. To remove it:
    op item edit "Stripe" "api_key=" --vault "Payments"
```

To delete the source value as part of the migration, pass `--delete-source`.
This triggers a **second confirmation** that fires **even when `--yes` is
set** — destructive cleanup is never silent:

```
  4/4  About to permanently delete 1password-work://Payments/Stripe/api_key.
       This cannot be undone.
       Continue? [y/N]
```

The second prompt fires **after** the pointer-flip commit. If you decline it,
the migration is already complete — the alias resolves to the destination —
and the source value simply remains for you to clean up manually. Declining is
not an error; the command still exits 0.

If the source delete itself fails (after a successful commit), the migration
is still complete. The outcome is reported as a cleanup failure, and the
copy-paste cleanup command is printed so you can retry by hand.

---

## Partial failure

If the destination **write** fails, nothing was committed — the source is
untouched and the alias still resolves to it. Re-run when the destination is
healthy.

If the **pointer flip** fails *after* a successful destination write, the
value now exists in **both** backends. `migrate` does **not** auto-roll-back by
deleting the destination — automatic destructive recovery is never performed.
Instead it prints the manual recovery options:

```
Error: migration partially failed.

  Step 1/3  Read from source:           OK
  Step 2/3  Write to destination:        OK
  Step 3/3  Registry pointer update:     FAILED

IMPORTANT: The value has been written to vault-prod://secret/payments/stripe.
           The registry still points at the original source.
           The value now exists in TWO backends.

To complete the migration:
  secretenv registry set stripe-key vault-prod:///secret/payments/stripe

To roll back (delete from destination):
  VAULT_ADDR=https://vault.example.com vault kv delete secret/payments/stripe
```

You decide whether to complete or roll back. The recovery block is printed to
your terminal only — it is never emitted to logs or telemetry.

---

## Per-backend write capability

A migration's destination must be a backend that can be written to.

- **Native destinations** (13 backends) — `local`, `aws-ssm`, `aws-secrets`,
  `vault`, `gcp`, `azure`, `keychain`, `doppler`, `infisical`, `cf-kv`,
  `openbao`, `conjur` — accept migrations with no extra configuration.
- **Gated destinations** (`1password`, `bitwarden-sm`, and `keeper` for
  writes) — refuse to be a migration destination unless you opt in via the
  backend's `*_unsafe_set` config flag (`op_unsafe_set`,
  `bitwarden_unsafe_set`, `keeper_unsafe_set`). These backends' CLIs pass the
  value through process arguments, a known exposure on multi-user hosts; the
  flag is your explicit acknowledgement. Without it, `migrate` fails fast with
  a clear message naming the flag, before reading the source value.

Some destination backends require the destination container to **already
exist** — for example AWS Secrets Manager and GCP Secret Manager will not
auto-create a secret, and 1Password will not auto-create an item. Create the
empty destination first, then migrate into it.

---

## JSON output

`--json` emits a machine-readable report to stdout:

```json
{
  "alias": "stripe-key",
  "source_backend_type": "1password",
  "dest_backend_type": "vault",
  "outcome": "success",
  "phase_durations_ms": {
    "probe_ms": 84,
    "read_ms": 341,
    "write_ms": 92,
    "pointer_flip_ms": 121
  },
  "delete_source": false,
  "probe_results": [
    { "instance": "1password-work", "status": "ok" },
    { "instance": "vault-prod", "status": "ok (probed)" }
  ],
  "transaction_id": "0192f3a1c4d27e80a1b2c3d4e5f60718"
}
```

Source and destination **URI bodies are never emitted** to JSON — only the
backend *type* strings. The cleanup hint (which contains URI path components)
is terminal-only and is likewise absent from JSON. This keeps `--json` output
safe to pipe into a log aggregator.

`outcome` is one of `success`, `dry-run`, `source-delete-failed-post-commit`,
or `partial-failure-pointer-flip`.

---

## Examples

```sh
# Always dry-run first.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --dry-run

# Execute, with the top-level prompt.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url

# Non-interactive (CI). Top-level prompt skipped; still safe — no deletion.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --yes

# Migrate and clean up the source (second confirmation still fires).
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --delete-source

# Recovery: the pointer was already flipped but the value is still in the old
# backend — point --from at the stale source explicitly.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url \
  --from vault-old:///secret/db-url

# Machine-readable result.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --yes --json
```
