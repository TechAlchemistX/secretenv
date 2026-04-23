# Doppler

**Type:** `doppler`
**CLI required:** [`doppler`](https://docs.doppler.com/docs/install-cli) v3+
**URI scheme:** `<instance-name>:///<project>/<config>/<secret>` or `<instance-name>:///<secret>` (short form, when config supplies defaults)
**Platform:** cross-platform (macOS, Linux, Windows)

Doppler is a SaaS secrets manager. The `doppler` CLI wraps the Doppler API with a clean `secrets get / set / delete / download` surface and resolves auth from one of three sources (in CLI's own precedence order): an explicit `DOPPLER_TOKEN` env var, the OS-keychain entry `doppler login` drops, or an instance-scoped token passed through secretenv's `doppler_token` config field.

---

## Configuration

```toml
[backends.doppler-prod]
type = "doppler"                                     # required
# All fields below are optional.
# doppler_project = "acme"                           # short-form URI default
# doppler_config  = "prd"                            # short-form URI default
# doppler_token   = "dp.st.prd.…"                    # override $DOPPLER_TOKEN
# timeout_secs    = 15                               # default: DEFAULT_GET_TIMEOUT
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"doppler"` |
| `doppler_project` | No | Default project if the URI omits the `<project>` segment (short form). See [URI Format](#uri-format). |
| `doppler_config` | No | Default Doppler config (Doppler calls environments "configs" — `dev`/`stg`/`prd`). Pairs with `doppler_project`: both-or-neither. |
| `doppler_token` | No | Per-instance override for `$DOPPLER_TOKEN`. Passed to the `doppler` subprocess via the `DOPPLER_TOKEN` environment variable — **never** via the `--token` argv flag (argv is visible to same-UID processes via `ps -ww`). Lets one machine address multiple Doppler accounts via different `[backends.<instance>]` blocks. |
| `timeout_secs` | No | Per-instance fetch deadline. Default: `DEFAULT_GET_TIMEOUT` (30 s). Doppler API latencies are typically sub-second; bump this only if you've seen intermittent timeouts during incidents. |

### Short-form URI defaults

`doppler_project` and `doppler_config` are **both-or-neither**. Setting only one triggers a factory-time error with a pointer at the other field — the alternative would be a confusing "missing config" error surfacing at every short-form `get()` instead of at config-load time.

```toml
[backends.doppler-prod]
type             = "doppler"
doppler_project  = "acme"
doppler_config   = "prd"
```

With the defaults set, `doppler-prod:///STRIPE_API_KEY` resolves to project=`acme`, config=`prd`, secret=`STRIPE_API_KEY`.

Without them, every URI must carry all three segments: `doppler-prod:///acme/prd/STRIPE_API_KEY`.

### Multiple Doppler accounts

```toml
[backends.doppler-acme]
type           = "doppler"
doppler_token  = "dp.st.prd.ACME_TOKEN"              # scoped to acme workplace

[backends.doppler-side-project]
type           = "doppler"
doppler_token  = "dp.st.prd.SIDE_TOKEN"              # different workplace entirely
```

Each instance gets its own token. `doppler-acme:///…` and `doppler-side-project:///…` URIs route through independent auth.

---

## URI Format

### Full form (three segments)

```
doppler-prod:///acme/prd/STRIPE_API_KEY
└──────────┘    └──┘ └─┘ └────────────┘
instance name   proj cfg secret name
```

Every segment must be non-empty. `<project>` and `<config>` must exist in Doppler (the backend surfaces a clear error if they don't). `<secret>` follows Doppler's naming rules (see [Secret names](#secret-names) below).

### Short form (one segment)

```
doppler-prod:///STRIPE_API_KEY
└──────────┘    └────────────┘
instance name   secret name
```

Valid only when the instance config sets **both** `doppler_project` and `doppler_config`. The backend resolves project/config from defaults and the URI's sole segment as the secret name.

If defaults aren't set, a short-form URI errors locally **before** any `doppler` subprocess runs, with a message pointing at both fields.

### Invalid segment counts

`doppler-prod:///acme/STRIPE_API_KEY` (two segments) and `doppler-prod:///acme/prd/nested/STRIPE_API_KEY` (four segments) are rejected with a specific error. If you need a secret whose name contains `/`, Doppler does not support that character — use underscores.

### Fragment directives

**None in v0.6.** URIs carrying a `#` fragment are rejected at `get` / `set` / `delete` / `list` / `history` time. Reserved for v0.7+ if we introduce per-URI format directives.

### Secret names

Doppler enforces `[A-Z_][A-Z0-9_]*` (all-caps, underscores, cannot start with a digit). `STRIPE_API_KEY` works; `stripe-api-key` gets rejected by the Doppler API. The backend doesn't auto-uppercase — you'll see the raw API validation error.

---

## Authentication

Precedence (highest wins):

1. **`doppler_token` config field** — instance-scoped, passed via `DOPPLER_TOKEN` env to every subprocess.
2. **`$DOPPLER_TOKEN` env var** — inherits from the parent shell.
3. **`doppler login` keychain entry** — the CLI's built-in OS-keychain credential.

### Token types

Doppler issues three token shapes; the backend doesn't care which you use — it passes whatever's configured through to the CLI, which handles the type-specific behavior itself:

| Type | Shape | Scope | Use case |
|---|---|---|---|
| **CLI / personal** | `dp.ct.*` | User-scoped (all projects the user can access) | Your workstation after `doppler login`. Interactive use, exploration. |
| **Service token** | `dp.st.<config>.*` | **Project + config locked** at mint time | CI pipelines. One token = one `secretenv-validation/prd` scope. |
| **Service account** | `dp.sa.*` | Workplace-scoped | Automation that needs access to multiple projects; grant project-level perms separately. |

### Minting a service token

Scoped to least privilege — one project + one config:

1. Doppler dashboard → your project → "Access" tab → "Service Tokens".
2. "Generate Service Token".
3. **Config:** pick `prd` (or whichever single config).
4. **Access:** "Read" for CI inject-only workloads; "Read / Write" only if your automation mutates secrets.
5. Copy the token (shown once). Store somewhere encrypted — the Doppler dashboard won't show it again.

In your SecretEnv config:

```toml
[backends.doppler-ci]
type           = "doppler"
doppler_token  = "dp.st.prd.YOUR_SERVICE_TOKEN"       # or export DOPPLER_TOKEN in CI
```

> **Storing the token in `config.toml`.** `doppler_token` is a credential. Putting it in a file anyone can read is a risk comparable to committing an AWS access key. Prefer `$DOPPLER_TOKEN` in your environment (CI provider secret store, `direnv` with a `.envrc` that doesn't get committed, 1Password CLI's shell helpers, etc.). Use `doppler_token` in `config.toml` only when you need per-instance routing that an env var can't express (e.g. two Doppler workplaces on the same machine).

### Service-token scope mismatch

Service tokens are locked to a project + config at mint time. If a URI addresses a **different** project or config, the CLI errors with a shape like:

```
Doppler Error: Unexpected HTTP response 401 Unauthorized
```

The backend surfaces the Doppler CLI's stderr verbatim. Double-check your token's scope matches the URI you're reading.

---

## `list()` — registry-source semantics

Unlike most backends (where the registry is a single secret whose value is a JSON/TOML alias→URI map), Doppler's `list()` uses the **entire Doppler config** as the alias map. Each Doppler secret becomes one alias; the secret's value is the alias target URI.

```toml
# Doppler: project=registry-central, config=prd
STRIPE_KEY = "aws-ssm-prod:///stripe-key"
DB_URL     = "vault-dev:///secret/db"
SEGMENT_WRITE_KEY = "doppler-prod:///api-keys/prd/SEGMENT_WRITE_KEY"
```

Configuring this as a registry source:

```toml
[registries.default]
sources = ["doppler-registry:///registry-central/prd/UNUSED_MARKER"]

[backends.doppler-registry]
type = "doppler"
```

The URI's secret segment (`UNUSED_MARKER`) is **ignored by `list()`** — a list targets the whole project+config, not a single secret. Using a recognizable placeholder makes the intent obvious in your config.

### Synthetic-key filter

`doppler secrets download` injects three auto-generated entries describing the config itself: `DOPPLER_PROJECT`, `DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT`. The backend **filters every key starting with `DOPPLER_`** out of the list before returning — a regression here would add three meaningless "aliases" to every registry-list caller.

**Side effect:** if a user secret in the Doppler config starts with `DOPPLER_` (which the Doppler CLI accepts — the `DOPPLER_` prefix isn't hard-reserved), it's filtered out of the alias map too. Do not name registry entries with the `DOPPLER_` prefix. Scalar secret URIs (targets of aliases pointing INTO Doppler) are unaffected — only entries in the list() output are filtered.

---

## `history()` — unsupported via CLI

Doppler has per-secret version history in the Dashboard and REST API, but the `doppler` CLI (v3.76.0 at time of writing) does **not** expose a `secrets versions` subcommand. Since the backend-wraps-CLI pattern is load-bearing (see [backend template](https://github.com/TechAlchemistX/secretenv/blob/main/docs/backends/template.md) — Doppler spec Q4), `history()` returns:

```
doppler backend '<instance>': history is not supported — the `doppler`
CLI (v3.76.0) has no per-secret version-history subcommand; version
history IS available in the Doppler Dashboard and REST API.
```

If a future Doppler CLI release adds `doppler secrets versions`, the backend can flip to a native implementation in a patch. For now, open the secret in the Dashboard to view its version history.

---

## Response parsing gotchas

- **`secrets get --plain` trailing newline.** The CLI writes the value with exactly one `\n` appended. The backend strips it; your consumer sees the raw value.
- **`secrets download --format json --no-file` is a JSON OBJECT.** Top-level `{ "SECRET_NAME": "value", ... }`, not an array. The backend parses it directly as `HashMap<String, String>`.
- **Auto-injected `DOPPLER_*` keys.** `download` always includes `DOPPLER_PROJECT`, `DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT`. See [Synthetic-key filter](#synthetic-key-filter).
- **Rate limits.** Doppler's API enforces per-token rate limits; cascade resolvers that fan out across many aliases can throttle. The SecretEnv cascade resolves serially, so this isn't a v0.6 concern.

---

## Security notes

- **Stdin-fed `set`.** `doppler secrets set <NAME> --no-interactive` reads the value from child stdin; the value **never** touches argv. Locked by a stdin-fragment canary in unit tests.
- **Token via env, never argv.** `DOPPLER_TOKEN` is set on the subprocess environment — never passed as `--token <value>`. A unit canary test (`token_travels_via_env_not_argv`) locks this: if a regression adds `--token` to argv, the strict-mock's declared argv shape diverges and the test fails with `strict-mock-no-match`.
- **`list()` response is secret-bearing.** `doppler secrets download --format json` returns every value in the config. The backend parses the body into a `HashMap<String,String>` and discards values immediately (list-of-aliases returns `(name, target_uri)` pairs where `target_uri` IS the value — so values do leave the backend, but they're alias-target URIs, not credential bodies). Do not configure a Doppler project as a registry source unless every entry's value is a URI.
- **Error messages never quote secret bodies.** Every `bail!` includes instance name + URI.raw + the CLI's stderr, never the body of the secret being read. The CLI's own stderr format doesn't include values for the operations this backend uses.

---

## doctor Output

Healthy:

```
doppler-prod                                            (doppler)
  ✓ v3.76.0
  ✓ authenticated  account=alice-mbp token-type=cli workplace=TechAlchemist
```

Not authenticated (expired `doppler login` session, no `DOPPLER_TOKEN`):

```
doppler-prod                                            (doppler)
  ✓ v3.76.0
  ✗ not authenticated
      → run: doppler login  OR  export DOPPLER_TOKEN=<your-token>
```

CLI missing:

```
doppler-prod                                            (doppler)
  ✗ CLI 'doppler' not found
      → brew install dopplerhq/cli/doppler  OR  https://docs.doppler.com/docs/install-cli
```

---

## Related

- [Fragment directives](../fragment-vocabulary.md) — why `#version=` etc. are rejected by Doppler (currently none supported).
- [`docs/registry.md`](../registry.md) — how alias → URI resolution works end-to-end.
- [`docs/security.md`](../security.md) — threat-model notes (argv discipline, stdin-fed writes).
- [Doppler CLI reference](https://docs.doppler.com/docs/cli) — authoritative CLI docs.
- [Doppler service tokens](https://docs.doppler.com/docs/service-tokens) — minting + scoping guide.
