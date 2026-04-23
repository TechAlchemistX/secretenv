# Infisical

**Type:** `infisical`
**CLI required:** [`infisical`](https://infisical.com/docs/cli/overview) v0.43+
**URI scheme:** `<instance-name>:///<project-id>/<env>/<secret>` (full) or `<instance-name>:///<secret>` (short, when config supplies defaults). Nested folders fold into middle segments: `<project-id>/<env>/<folder1>/<folder2>/<secret>`.
**Platform:** cross-platform (macOS, Linux, Windows)

Infisical is an open-source secrets manager, available both as a hosted SaaS (`app.infisical.com`) and as a self-hostable service. Teams frequently pick Infisical when they want a Doppler-like developer experience without SaaS lock-in. The `infisical` CLI wraps the Infisical API with a clean `secrets get / set / delete` surface and resolves auth from one of three sources: an explicit `INFISICAL_TOKEN` env var, the local cache `infisical login` drops, or an instance-scoped token passed through secretenv's `infisical_token` config field.

---

## Configuration

```toml
[backends.infisical-prod]
type = "infisical"                                       # required
# All fields below are optional.
# infisical_project_id  = "abc-123"                      # short-form URI default
# infisical_environment = "prod"                         # short-form URI default (dev/staging/prod by default)
# infisical_secret_path = "/api"                         # default folder path within the env
# infisical_token       = "st.xxx.yyy"                   # override $INFISICAL_TOKEN
# infisical_domain      = "https://infisical.acme.com"   # self-hosted instance URL
# timeout_secs          = 15                             # default: DEFAULT_GET_TIMEOUT
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"infisical"` |
| `infisical_project_id` | No | Default project UUID if the URI omits the `<project-id>` segment (short form). See [URI Format](#uri-format). Pairs with `infisical_environment`: both-or-neither. |
| `infisical_environment` | No | Default environment slug (Infisical's default envs are `dev`/`staging`/`prod`, but projects may add custom slugs). |
| `infisical_secret_path` | No | Default folder path within the environment. Infisical supports nested folders (`/`, `/api`, `/api/stripe`). Defaults to `/` when unset. |
| `infisical_token` | No | Per-instance override for `$INFISICAL_TOKEN`. Passed to the `infisical` subprocess via the `INFISICAL_TOKEN` environment variable — **never** via the `--token` argv flag (argv is visible to same-UID processes via `ps -ww`). |
| `infisical_domain` | No | Self-hosted Infisical instance URL. Passed via `INFISICAL_API_URL` env var — never the `--domain` argv flag. Default: `https://app.infisical.com/api` (hosted SaaS). |
| `timeout_secs` | No | Per-instance fetch deadline. Default: `DEFAULT_GET_TIMEOUT` (30 s). Infisical API latencies are typically sub-second; bump this only if you've seen intermittent timeouts during incidents. |

### Short-form URI defaults

`infisical_project_id` and `infisical_environment` are **both-or-neither**. Setting only one triggers a factory-time error pointing at the other field — the alternative would be a confusing "missing config" error surfacing at every short-form `get()` instead of at config-load time.

```toml
[backends.infisical-prod]
type                  = "infisical"
infisical_project_id  = "abc-123"
infisical_environment = "prod"
```

With the defaults set, `infisical-prod:///STRIPE_API_KEY` resolves to project=`abc-123`, env=`prod`, path=`/`, secret=`STRIPE_API_KEY`.

Without them, every URI must carry at least the project + env segments: `infisical-prod:///abc-123/prod/STRIPE_API_KEY`.

### Self-hosted vs SaaS

One config, one CLI, two target shapes:

```toml
# SaaS (hosted at app.infisical.com — the default)
[backends.infisical-saas]
type = "infisical"

# Self-hosted
[backends.infisical-internal]
type             = "infisical"
infisical_domain = "https://infisical.acme.com"
```

The `infisical` CLI is shape-identical against both surfaces — only the API URL differs. The `infisical_domain` field points the subprocess at your instance via the `INFISICAL_API_URL` environment variable; no `--domain` flag ever lands on argv (same hardening discipline as the token).

### Multiple Infisical accounts

```toml
[backends.infisical-acme]
type             = "infisical"
infisical_token  = "st.xxx.ACME_TOKEN"

[backends.infisical-side-project]
type             = "infisical"
infisical_token  = "st.xxx.SIDE_TOKEN"
```

Each instance gets its own token. `infisical-acme:///…` and `infisical-side-project:///…` URIs route through independent auth.

---

## URI Format

### Full form (three or more segments)

```
infisical-prod:///abc-123/prod/STRIPE_API_KEY
└────────────┘    └─────┘ └──┘ └────────────┘
instance name     project env  secret name
```

Every segment must be non-empty. `<project-id>` is Infisical's UUID identifier — visible in the project settings URL or via the dashboard. `<env>` is the environment slug (`dev`/`staging`/`prod` or a custom slug).

### Folder-path folding (four or more segments)

Infisical organizes secrets under a filesystem-like folder tree inside each environment. The URI folds folder components in as middle segments between `<env>` and `<secret>`:

```
infisical-prod:///abc-123/prod/api/stripe/STRIPE_API_KEY
                              └────────┘
                              folds to path=/api/stripe
```

This URI resolves to project=`abc-123`, env=`prod`, **path=`/api/stripe`**, secret=`STRIPE_API_KEY`. The backend splits on `/`, takes the first two non-empty segments as project + env, the last as secret name, and joins the middle with `/` to form the folder path. If there are no middle segments, path defaults to `/`.

### Short form (one segment)

```
infisical-prod:///STRIPE_API_KEY
└────────────┘    └────────────┘
instance name     secret name
```

Valid only when the instance config sets **both** `infisical_project_id` and `infisical_environment`. The backend resolves project + env + path from defaults and the URI's sole segment as the secret name.

If defaults aren't set, a short-form URI errors locally **before** any `infisical` subprocess runs, with a message pointing at both fields.

### Invalid segment counts

`infisical-prod:///abc-123/STRIPE_API_KEY` (two segments) is ambiguous — could be project/secret, env/secret, or folder/secret — and rejected with a specific error. Use full form with all segments or short form with only the secret name.

### Fragment directives

**None in v0.7.** URIs carrying a `#` fragment are rejected at `get` / `set` / `delete` / `list` / `history` time. Reserved for later if per-URI directives become useful.

### Secret names

Infisical's API accepts most characters in secret names but the standard shape is `[A-Z_][A-Z0-9_]*` (all-caps, underscores). The backend doesn't enforce — it passes whatever you give it through the URI directly.

---

## Authentication

Precedence (highest wins):

1. **`infisical_token` config field** — instance-scoped, passed via `INFISICAL_TOKEN` env to every subprocess.
2. **`$INFISICAL_TOKEN` env var** — inherits from the parent shell.
3. **`infisical login` local cache** — the CLI's built-in credential store.

### Token types

Infisical issues several token shapes; the backend doesn't care which you use — it passes whatever's configured through to the CLI, which handles the type-specific behavior itself:

| Type | Shape | Scope | Use case |
|---|---|---|---|
| **User login** | Cached via `infisical login` | User-scoped (all projects the user can access) | Your workstation after browser-based login. Interactive use, exploration. |
| **Service token** | `st.*` | Project + env + path locked at mint time | CI pipelines. Least-privilege per pipeline. |
| **Machine identity** | Access token via identity exchange | Scoped per identity's policies | Production automation; supports mTLS, AWS IAM, and other credential-exchange flows. |

### Minting a service token

Scoped to least privilege — one project + one environment + one path:

1. Infisical dashboard → your project → "Access Control" → "Service Tokens".
2. Click "Create service token".
3. **Environments:** pick `prod` (or whichever single env).
4. **Secret path:** `/` for project-wide read, or a subtree like `/api` for narrower scope.
5. **Permissions:** "Read" for inject-only workloads; "Read + Write" only if your automation mutates secrets.
6. Copy the token (shown once). Store somewhere encrypted — the dashboard won't show it again.

In your SecretEnv config:

```toml
[backends.infisical-ci]
type             = "infisical"
infisical_token  = "st.xxx.yyy.YOUR_SERVICE_TOKEN"       # or export INFISICAL_TOKEN in CI
```

> **Storing the token in `config.toml`.** `infisical_token` is a credential. Putting it in a file anyone can read is a risk comparable to committing an AWS access key. Prefer `$INFISICAL_TOKEN` in your environment (CI provider secret store, `direnv` with an uncommitted `.envrc`, 1Password CLI's shell helpers, etc.). Use `infisical_token` in `config.toml` only when you need per-instance routing that a single env var can't express (e.g. two Infisical instances on the same machine).

### Self-hosted domain trust

`infisical_domain` accepts any URL — including ones that look legitimate but aren't. Double-check the domain before committing it to `config.toml` or sharing a registry that references it; a malicious domain receives every token and URI your backend routes through. Pin to an HTTPS URL with a cert you trust.

---

## `set()` discipline — temp-file, not argv

The `infisical` CLI at v0.43.77 accepts values for `set` in exactly two ways:

1. **Positional `secretName=secretValue` pairs** on argv — rejected here because argv is visible to same-UID processes via `ps -ww`.
2. **`--file <path>`** pointing at a .env or YAML file — **used here**.

There is no stdin form. The backend:

1. Creates a `NamedTempFile` under `$TMPDIR` (mode 0600 on Unix).
2. Writes `NAME=VALUE\n` to it and `fsync`s.
3. Spawns `infisical secrets set --file <tempfile> --type shared …`.
4. On return (success OR failure), explicitly drops the `NamedTempFile` handle, which auto-unlinks the file.

The value never appears on argv. A unit canary test confirms this: it installs a strict mock with no rules, calls `set()` with a recognizable canary string, and asserts the canary is absent from the mock's observed-argv diagnostic.

**Exposure window:** the temp file exists on disk for roughly the duration of the `infisical secrets set` subprocess (typically a few hundred milliseconds). The file is readable only by the current UID (mode 0600). Same-UID processes CAN read it during that window; this is an inherent property of the `--file` interface. If your threat model cares about same-UID adversaries, keep `infisical_unsafe_set` out of your workflow and mutate secrets through the dashboard.

### `--type shared` is mandatory

The CLI's `--type` flag on `set` and `delete` defaults to `personal`. Personal-scoped secrets are user-specific overrides of shared (project-wide) secrets, NOT the project's canonical values. Omitting `--type shared` would:

- On `set`: write to your personal override, leaving project-shared untouched (confusing silent no-op from teammates' perspective).
- On `delete`: attempt to delete your personal override — if none exists, the shared secret isn't touched and the command silently succeeds.

The backend passes `--type shared` explicitly on every `set` and `delete`. A unit drift-catch test asserts the argv shape diverges from a `--type`-less form, locking the invariant against accidental removal.

---

## `list()` — registry-source semantics

Unlike most backends (where the registry is a single secret whose value is a JSON/TOML alias→URI map), Infisical's `list()` uses the **entire Infisical environment + path** as the alias map. Each Infisical secret becomes one alias; the secret's value is the alias target URI.

```toml
# Infisical: project=abc-123, env=prod, path=/registry
STRIPE_KEY        = "aws-ssm-prod:///stripe-key"
DB_URL            = "vault-dev:///secret/db"
SEGMENT_WRITE_KEY = "infisical-prod:///abc-123/prod/api/SEGMENT_WRITE_KEY"
```

Configuring this as a registry source:

```toml
[registries.default]
sources = ["infisical-registry:///abc-123/prod/registry/UNUSED_MARKER"]

[backends.infisical-registry]
type = "infisical"
```

The URI's secret segment (`UNUSED_MARKER`) is **ignored by `list()`** — a list targets the whole project+env+path scope, not a single secret. Using a recognizable placeholder makes the intent obvious in your config.

### Defense-in-depth on response body

`infisical secrets --output json` returns an array shaped
`[{"secretKey":"NAME","secretValue":"VAL", …}, …]` covering every secret in the scope. The backend parses via a Rust struct that declares only the `secretKey` field — serde silently drops `secretValue` and every other field. The parsed `Vec` carries names only; values never materialize in our types and cannot accidentally land in log/error/Debug output. Defense-in-depth on top of the "return names only" contract.

---

## `history()` — unsupported via CLI

Infisical has per-secret version history in the Dashboard and REST API, but the `infisical` CLI (v0.43.77 at time of writing) does **not** expose a `secrets versions` subcommand. Since the backend-wraps-CLI pattern is load-bearing (see [backend template](../../kb/wiki/backends/template.md)), `history()` returns:

```
infisical backend '<instance>': history is not supported — the `infisical`
CLI (v0.43.77) has no per-secret version-history subcommand; version
history IS available in the Infisical Dashboard and REST API.
```

If a future Infisical CLI release adds `infisical secrets versions`, the backend can flip to a native implementation in a patch. For now, open the secret in the dashboard to view its version history.

---

## Response parsing gotchas

- **`secrets get --plain` trailing newline.** The CLI writes the value with exactly one `\n` appended. The backend strips it; your consumer sees the raw value.
- **`secrets --plain` is deprecated on list.** The CLI marks `--plain` deprecated on the `secrets` (list) subcommand at v0.43.77; the backend uses `--output json` which is the forward-compatible shape.
- **`--output json` on list returns a JSON ARRAY.** Top-level `[{"secretKey":"…","secretValue":"…"}, …]`, not an object. The backend parses into a name-only struct as described above.
- **Folder-path normalization.** Infisical paths always start with `/`; the backend normalizes (prepending `/` if the URI path somehow doesn't, though URI parsing enforces the leading slash).
- **Rate limits.** Infisical's SaaS enforces per-token rate limits; self-hosted instances are capped by your own infrastructure. Cascade resolvers that fan out across many aliases can throttle; the SecretEnv cascade resolves serially, so this isn't typically a concern.

---

## Security notes

- **`set()` via `--file` temp-file.** Mode 0600 under `$TMPDIR`, unlinked on drop (RAII guard, regardless of spawn exit code). Value never on argv. See [`set()` discipline](#set-discipline--temp-file-not-argv).
- **Token via env, never argv.** `INFISICAL_TOKEN` is set on the subprocess environment — never passed as `--token <value>`. A unit canary test (`token_travels_via_env_not_argv`) locks this: if a regression adds `--token` to argv, the strict-mock's declared argv shape diverges and the test fails with `strict-mock-no-match`.
- **Domain via env, never argv.** `infisical_domain` travels via `INFISICAL_API_URL`, not `--domain` on argv. Symmetric to the token discipline — keeps the `infisical` subprocess command-line shape uniform across self-hosted and SaaS deployments.
- **`list()` response is secret-bearing.** `infisical secrets --output json` returns every value in the scope. The struct we parse into declares only the `secretKey` field — serde drops `secretValue` silently. Values leave the backend only as alias targets (URIs), not credential bodies. Do not configure an Infisical env+path as a registry source unless every entry's value is a URI.
- **`--type shared` on set + delete.** Locked by drift-catch tests to prevent silent scope corruption under the CLI's `personal` default.
- **Error messages never quote secret bodies.** Every `bail!` includes instance name + URI.raw + the CLI's stderr, never the body of the secret being read.

---

## doctor Output

Healthy (user-login auth against SaaS):

```
infisical-prod                                          (infisical)
  ✓ infisical version 0.43.77
  ✓ authenticated  auth=user-login domain=https://app.infisical.com/api
```

Healthy (token-auth against a self-hosted instance):

```
infisical-prod                                          (infisical)
  ✓ infisical version 0.43.77
  ✓ authenticated  auth=token domain=https://infisical.acme.com
```

Not authenticated (no cached login, no `INFISICAL_TOKEN`):

```
infisical-prod                                          (infisical)
  ✓ infisical version 0.43.77
  ✗ not authenticated
      → run: infisical login  OR  export INFISICAL_TOKEN=<your-token>  (domain: https://app.infisical.com/api)
```

CLI missing:

```
infisical-prod                                          (infisical)
  ✗ CLI 'infisical' not found
      → brew install infisical/get-cli/infisical  OR  https://infisical.com/docs/cli/overview
```

---

## Related

- [Fragment directives](../fragment-vocabulary.md) — why `#version=` etc. are rejected by Infisical (currently none supported).
- [`docs/registry.md`](../registry.md) — how alias → URI resolution works end-to-end.
- [`docs/security.md`](../security.md) — threat-model notes (argv discipline, temp-file writes).
- [Infisical CLI reference](https://infisical.com/docs/cli/overview) — authoritative CLI docs.
- [Infisical service tokens](https://infisical.com/docs/documentation/platform/token) — minting + scoping guide.
- [Self-hosting Infisical](https://infisical.com/docs/self-hosting/overview) — running your own instance.
