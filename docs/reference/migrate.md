# `secretenv registry migrate`

`secretenv registry migrate` moves an alias's secret value from one backend to
another **in a single operation**: read the value from the current backend,
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
| `<DEST_URI>` | (required) | The destination backend URI (e.g. `vault-prod:///secret/payments/stripe`). Must be a direct backend URI, not a `secretenv://` alias. The destination backend instance must be configured in `config.toml`. |
| `--dry-run` | off | Plan-only mode. Runs the source/destination probes, prints the migration plan, and exits **without any mutation**. Use this first on every migration. |
| `--yes` / `-y` | off | Skip the top-level confirmation prompt. **Does not** skip the `--delete-source` confirmation (see below). |
| `--from <SOURCE_URI>` | (inferred) | Override the source URI. By default the source is the alias's current registry pointer; `--from` is for recovery flows where the pointer was already flipped but the value still lives in the old backend. |
| `--delete-source` | off | After a successful migration, delete the value from the source backend. Opt-in and separately confirmed. See [`--delete-source`](#opt-in-source-cleanup). |
| `--json` | off | Emit a machine-readable `MigrateReport` as JSON to **stdout**. For CI consumption. Without `--json`, the human progress + summary output goes to **stderr** (so `2>/dev/null` suppresses it). |
| `--registry <name|uri>` | active registry | Select which registry to operate on. Same semantics as `secretenv run --registry`. |

---

## The migration transaction

A migration is a **three-step transaction** with an optional fourth cleanup step:

1. **Read**: fetch the value from the source backend.
2. **Write**: write the value to the destination backend.
3. **Pointer flip**: rewrite the registry document so the alias points at the
   destination URI. **This is the commit point.**
4. **Source delete** *(optional)*: only when `--delete-source` is passed and
   separately confirmed.

The commit point is step 3. Before it, nothing the operator depends on has
changed. The alias still resolves to the source. After it, the alias resolves
to the destination.

### What is NOT atomic

The pointer flip is a read-modify-write (`list` → mutate → `set`), not atomic at the storage layer. Concurrent `secretenv registry set` calls against the same registry instance can race it. The window is one round-trip and mutations are rare, operator-driven events. But if you script migrations, **serialize them** against a single registry instance. A content-addressed (`cas_set`) protocol is planned for a later release.

---

## Dry run

Always dry-run first. `--dry-run` probes both ends with zero mutation:

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

The **probe line** distinguishes two cases:

- `ok (probed)`: the backend ran a real write-permission probe (e.g. `vault token capabilities`). Only Vault does this currently.
- `ok (no probe available for this backend)`: no cheap permission probe; the real write will surface any failure.

A **definitive** probe failure (e.g. Vault returns `deny`) aborts before any read.

---

## Confirmation prompts

By default, one prompt before any mutation:

```
About to migrate stripe-key:
  from: 1password-work://Payments/Stripe/api_key
  to:   vault-prod:///secret/payments/stripe

This will read the current value from the source and write it to the destination.
The registry pointer will be updated on success.
The source value will NOT be deleted.

Continue? [y/N]
```

`--yes` skips this top-level prompt.

---

## Opt-in source cleanup

By default migrations **leave the source value in place** and print a copy-paste cleanup command. To delete the source as part of the migration, pass `--delete-source`. This triggers a **second confirmation** even when `--yes` is set. Destructive cleanup is never silent:

```
  4/4  About to permanently delete 1password-work://Payments/Stripe/api_key.
       This cannot be undone.
       Continue? [y/N]
```

The second prompt fires **after** the pointer-flip commit. Declining leaves the migration complete (alias already resolves to destination) but the source value remains for manual cleanup. Not an error; exits 0.

If source delete fails post-commit, migration is still complete. The outcome is reported as a cleanup failure with a copy-paste cleanup command for manual retry.

---

## Partial failure

If the destination **write** fails, nothing is committed: source untouched, alias still resolves to it. Re-run when the destination is healthy.

If the **pointer flip** fails after a successful write, the value exists in **both** backends. `migrate` does **not** auto-roll-back. Automatic destructive recovery never happens. Instead it prints manual recovery options:

```
Error: migration partially failed.

  Step 1/3  Read from source:           OK
  Step 2/3  Write to destination:        OK
  Step 3/3  Registry pointer update:     FAILED

IMPORTANT: The value has been written to vault-prod:///secret/payments/stripe.
           The registry still points at the original source.
           The value now exists in TWO backends.

To complete the migration:
  secretenv registry set stripe-key vault-prod:///secret/payments/stripe

To roll back (delete from destination):
  VAULT_ADDR=https://vault.example.com vault kv delete secret/payments/stripe
```

You decide whether to complete or roll back. The recovery block is terminal-only; never emitted to logs or telemetry.

---

## Per-backend write capability

A migration's destination must support writes.

- **Native destinations** (12 backends), `local`, `aws-ssm`, `aws-secrets`, `vault`, `gcp`, `azure`, `keychain`, `doppler`, `infisical`, `cf-kv`, `openbao`, `conjur`, accept migrations with no extra configuration.
- **Gated destinations** (`1password`, `bitwarden-sm`, `keeper`), require explicit opt-in via `*_unsafe_set` flags (`op_unsafe_set`, `bitwarden_unsafe_set`, `keeper_unsafe_set`). Their CLIs pass values through process arguments, a known multi-user host exposure. Without the flag, `migrate` fails fast, before reading the source.

Some destination backends require the container to **already exist** (e.g. AWS Secrets Manager, GCP Secret Manager). Create the empty destination first, then migrate into it.

---

## JSON output

Machine-readable report to stdout:

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

Source and destination **URI bodies never appear in JSON**: only backend *type* strings. The cleanup hint (which contains URI paths) is terminal-only. This keeps `--json` safe to pipe into a log aggregator.

`outcome` is one of `success`, `dry-run`, `source-delete-failed-post-commit`, or `partial-failure-pointer-flip`.

---

## Examples

```sh
# Always dry-run first.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --dry-run

# Execute, with the top-level prompt.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url

# Non-interactive (CI). Top-level prompt skipped; still safe, no deletion.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --yes

# Migrate and clean up the source (second confirmation still fires).
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --delete-source

# Recovery: the pointer was already flipped but the value is still in the old
# backend. Point --from at the stale source explicitly.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url \
  --from vault-old:///secret/db-url

# Machine-readable result.
secretenv registry migrate db-url aws-ssm-prod:///prod/db-url --yes --json
```
