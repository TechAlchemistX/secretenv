# The Three-File Model — Deep Reference

The README has the summary. This page is the deep reference: full schemas, validation rules, lifecycle, ownership boundaries, and the exact resolution flow.

The three files:

| # | File | Lives where | Owner | Lifecycle |
|---|---|---|---|---|
| 1 | `secretenv.toml` | Repo root | Developer | Committed; changes when secret *requirements* change |
| 2 | `~/.config/secretenv/config.toml` | Machine XDG config dir | Each developer (or platform team via profiles) | Per-machine; rarely changes after initial setup |
| 3 | Alias registry document | Inside a backend you control | Platform / security team | Mutable; changes when secrets migrate or aliases are renamed |

---

## File 1 — Project Manifest (`secretenv.toml`)

### Discovery
- Walked **upward** from CWD
- Stops at version-control sentinel: `.git`, `.hg`, `.svn`, or `.secretenv-root`
- Falls back to filesystem root if no sentinel found (v0.1 compatibility for non-VCS projects)
- The sentinel boundary prevents a hostile parent directory from hijacking resolution when you `cd` into a project repo

### Schema

```toml
[secrets]
ENV_VAR_NAME = { from = "secretenv://alias-name" }   # alias reference
ENV_VAR_NAME = { default = "literal-value" }         # static default
```

**Validation:**
- Two value shapes only — `{ from = "..." }` or `{ default = "..." }`
- `from` URIs MUST be `secretenv://` or `secretenv:///` (direct backend URIs are a hard error)
- `default` values are arbitrary strings, injected as-is
- Both `from` and `default` in the same entry: error
- Unknown fields: error (TOML `deny_unknown_fields`)
- Control characters in URIs (NUL + ASCII <0x20 except tab): error
- Bidirectional-override Unicode (U+202E etc.): warning (defense-in-depth)
- Empty manifest: parses successfully (no secrets to inject)

### Order preservation
Entries are stored in `IndexMap` — declaration order is preserved. `doctor` and `resolve` output reflects manifest order.

### Lifecycle
- **Created** when setting up secrets for a new project
- **Committed** to git alongside other project config
- **Modified** only when the project's secret requirements change (new env var needed, old one retired)
- **Never modified** when the location of a secret changes — that's the registry's job

---

## File 2 — Machine Config (`~/.config/secretenv/config.toml`)

### Discovery
- `--config <path>` flag, OR
- `$XDG_CONFIG_HOME/secretenv/config.toml`, OR
- `~/.config/secretenv/config.toml` (XDG default)
- Missing file: empty config (non-fatal)

### Schema

```toml
# Named registries — cascade source lists
[registries.<name>]
sources = ["<backend-uri>", ...]   # first-match-wins lookup

# Named backend instances — credentials and routing
[backends.<instance-name>]
type = "<backend-type>"            # identifies factory (aws-ssm, 1password, vault, ...)
# ... backend-specific fields ...
```

### Validation
- `[registries.<name>]` requires `sources` — non-empty list of backend URIs
- `[backends.<instance>]` requires `type` — must match a registered backend factory
- Backend-specific fields validated by each factory (the core stays blind to backend semantics)
- Profile auto-merge: 1 MiB hard cap per profile file

### Profile merge
On load, `<config-dir>/profiles/*.toml` files are merged in alphabetical order. **User's config always wins** where keys overlap. Profiles only fill gaps. This makes profiles safe for organizational distribution — a bad profile cannot silently override a developer's intentional override.

### Lifecycle
- **Created** via `secretenv setup <uri>` (interactive wizard) OR `secretenv profile install <name>` (pre-configured distribution) OR hand-edited
- **Updated** when backend topology changes — typically rare after initial setup
- **Per-machine** — never committed; each developer / CI runner has their own
- **Credentials** for backends are owned by the machine (AWS profiles in `~/.aws`, 1Password account via `op signin`, etc.); this file just *names* them

---

## File 3 — Alias Registry Document

### Where it lives
Inside any backend you already control. Examples:
- `aws-ssm-platform:///secretenv/org-registry` (AWS SSM SecureString)
- `1password-work://secretenv/org-registry` (1Password item)
- `vault-prod://secret/secretenv/registry` (Vault KV v2)
- `local:///Users/alice/.config/secretenv/registry.toml` (local file)
- Any of the 15 supported backends

### Schema

**TOML format** (for `local`, `1password` backends — flat key-value):

```toml
stripe-key      = "1password-work://payments/stripe/api_key"
db-url          = "aws-ssm-dev:///myapp/dev/db_url"
datadog-api-key = "1password-work://engineering/datadog/api_key"
```

**JSON format** (for cloud backends storing as a single secret value — aws-ssm, aws-secrets, gcp, azure, vault, openbao, conjur, bitwarden-sm):

```json
{
  "stripe-key": "1password-work://payments/stripe/api_key",
  "db-url": "aws-ssm-dev:///myapp/dev/db_url"
}
```

### Validation
- Every value must parse as a valid backend URI
- Every URI's scheme must match a configured backend instance
- Chained aliases are forbidden — registry values cannot be `secretenv://...`
- Writes use `BTreeMap` ordering (alphabetical) — diffs are clean and reproducible

### Cascade

A named registry can list multiple `sources`. They form a **first-match-wins cascade**:

```toml
[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",       # source 0 — checked first
  "aws-ssm-platform:///secretenv/org-registry",  # source 1 — fallback
]
```

- Lookup walks layers 0 → N, returns first hit
- Later layers are read-only fallbacks (no merging at entry level)
- `sources[0]` is the single write target for `registry set` / `unset`
- To write to a non-source-0 layer, pass a direct URI to `--registry`

### Lifecycle
- **Created** via the first `secretenv registry set <alias> <uri>` against an empty path
- **Updated** when a secret migrates between backends, or when an alias is renamed
- **Owner** is whoever owns the host backend — typically the platform / security team
- **Scoping:**
  - Org-wide registry: shared across all teams (e.g., `aws-ssm-platform:///secretenv/org-registry`)
  - Team-specific registry: scoped to a team, can shadow org defaults
  - Cascading: stack registries to layer team overrides on top of org defaults

---

## Resolution Flow (full)

When you run `secretenv run --registry dev -- npm start`:

### Phase 1 — Registry selection

```
1. Explicit --registry <name-or-uri> flag    (highest precedence)
2. SECRETENV_REGISTRY=<name-or-uri> env var
3. [registries.default] in machine config
4. Hard error                                 (no implicit assumption)
```

If the value contains `://`, it's treated as a direct URI (single source, no cascade). Otherwise it's a name lookup against `[registries.<name>]`.

### Phase 2 — Registry document loading

For each source URI in the cascade:
- Call the matching backend's `list()` method
- Parse the result as a `Vec<(alias, target-uri)>` map
- Build a layered `AliasMap` (one layer per source, in declaration order)

**All sources must succeed.** If any `list()` fails (CLI missing, NotAuth, network), the entire resolve errors. This is deliberate — fails-fast prevents silent fallthrough that would mask environment problems.

Each target URI is validated: parses, scheme matches a configured backend, no chained aliases.

### Phase 3 — Manifest resolution

For each entry in `secretenv.toml`'s `[secrets]` section:
- If `from = "secretenv://alias"`: look up `alias` in the AliasMap (first-match-wins across cascade layers); get the target URI
- If `default = "..."`: use the literal value

Result: a `Vec<ResolvedSecret>` in manifest declaration order.

### Phase 4 — Secret fetching

For each `ResolvedSecret`:
- If `Default`: inject inline (no backend call)
- If `Uri`: call `backend.get(target-uri)` — **all fetches run in parallel**

**Failure modes:**
- Single failure: error returned with full context (alias, URI, operation)
- Multiple failures: aggregated into one report — operators see every broken alias in one pass

If `--dry-run`: skip fetching, print resolution map (`KEY ← <uri>` and `KEY = <value>`), exit 0.

### Phase 5 — Inject and exec

- Merge fetched values + static defaults into the env map
- On Unix: `exec()` replaces the current process (inherits TTY, stdio, signals; secrets exist briefly in the heap before exec discards it)
- On non-Unix: spawn child, wait, propagate exit code (secrets zeroed via `zeroize::Zeroizing` on drop)

---

## What this decoupling solves (in detail)

### Secrets-in-config problem
Without decoupling, every dev's `.env` contains both values and paths:
```
STRIPE_KEY=sk_live_abc123...                         # secret value
DB_URL=mydb.prod.us-east-1.rds.amazonaws.com         # infrastructure path
```
Both leak. Both go stale. Both are hard to rotate.

With decoupling: `secretenv.toml` declares names only (safe to commit); the registry stores pointers only (safe to keep in any backend); secrets are fetched at runtime (always fresh).

### Topology hiding
Without: new engineer reading the repo learns "Stripe is in 1Password account X, vault path Y, AWS account Z" — infrastructure topology leaks via code review.

With: repo contains alias names; actual paths are in a registry that lives behind backend access controls. Reading the repo teaches you nothing about backend topology.

### Team vs org scoping
Without: teams either bake env-specific logic into code, or maintain separate repos / branches per environment.

With: one `secretenv.toml` per repo. Registry cascade routes the same alias names to env-specific backends. Environments change *how they're configured* (different registry), not *what the code knows*.

### Credential portability
Without: migrating Stripe from 1Password to Vault means decrypting in 1Password, encrypting in Vault, updating every repo, re-inviting every team member.

With: secrets already live in both backends (you put them there using your existing tools). One `secretenv registry set` updates the alias pointer. Every repo picks it up on the next run.

### Offboarding
Without: departing engineer still has local `.env` files; revocation is manual and error-prone per backend.

With: revoke access to the registry backend. Engineer can no longer resolve any alias. Single operation covers every repo simultaneously.

---

## See also

- [Overview](/) — overview + workflows
- [Full CLI reference](cli-reference-full.md)
- [Threat model](../security.md) — full security comparison
- [Fragment vocabulary](fragment-vocabulary.md) — URI fragment grammar
