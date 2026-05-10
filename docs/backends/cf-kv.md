# Cloudflare Workers KV

**Type:** `cf-kv`
**CLI required:** [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/) 4.x — `npm install -g wrangler` OR `brew install cloudflare/cloudflare/wrangler`
**URI scheme:** `<instance-name>:///<namespace-id>/<key>` (or `<instance-name>:///<key>` when `cf_kv_default_namespace_id` is configured)
**Platform:** all (macOS, Linux, Windows)
**Tested:** `wrangler 4.85.0` on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `cf-kv` backend. New here? See the [overview](/).

Cloudflare Workers KV is a globally-distributed, eventually-consistent key-value store designed for low-latency reads from Cloudflare Workers. This backend wraps the `wrangler` CLI for read, write, list, and delete operations. Auth flows through `wrangler login` (OAuth) or `CLOUDFLARE_API_TOKEN`.

## When to pick this

- **Cloudflare Workers already deployed:** native integration, no new service
- **Global edge caching:** KV is replicated to Cloudflare's edge; reads are fast from anywhere
- **Flat key-value model:** simple key namespaces, no folder scoping (use naming conventions or multiple namespaces)
- **Low-cost, pay-as-you-go:** no upfront secrets infrastructure to manage

## Configuration

```toml
[backends.cf-kv-prod]
type                          = "cf-kv"
cf_kv_default_namespace_id    = "c554de8d89644f3d85f21933e7aea910"  # optional
cf_kv_list_prefix             = "registry/"                          # optional
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"cf-kv"` |
| `cf_kv_default_namespace_id` | No | Namespace UUID for single-segment URIs. When unset, two-segment form required. Find via `wrangler kv namespace list`. |
| `cf_kv_list_prefix` | No | Prefix filter for `list()` (e.g., `registry/` to enumerate only keys starting with that prefix). Enables single-namespace scalar + registry mixing. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Single-namespace mixing via `cf_kv_list_prefix`

To hold both scalars and registry aliases in one namespace:

```toml
[backends.cf-kv-prod]
type                          = "cf-kv"
cf_kv_default_namespace_id    = "c554de8d89644f3d85f21933e7aea910"
cf_kv_list_prefix             = "registry/"
```

Store registry aliases under `registry/alias-name` (e.g., `registry/STRIPE_KEY` → `aws-ssm-prod:///stripe`). Scalar secrets at the top level stay invisible to `list()` but accessible via direct `get()`.

## URI Format

```
cf-kv-prod:///c554de8d89644f3d85f21933e7aea910/STRIPE_KEY
└──────────┘   └──────────────────────────────┘ └─────────┘
instance name  namespace ID (or default)       key name
```

Two-segment form: `<namespace-id>/<key>`. Single-segment form (one segment) requires `cf_kv_default_namespace_id` in config. The namespace ID is the stable UUID-shaped identifier from `wrangler kv namespace list` — **not** the Worker-local binding name.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

Two equivalent paths:

**OAuth (interactive, recommended for developer machines):**

```bash
wrangler login
# Opens a browser; grant scopes including Workers KV Storage.
# wrangler caches the token at ~/.config/.wrangler/config/default.toml.
```

**API token (CI / headless):**

Mint a token at `dashboard.cloudflare.com → My Profile → API Tokens` with the `Workers KV Storage:Edit` template (or `Read` for read-only). Export:

```bash
export CLOUDFLARE_API_TOKEN=<your-token>
```

Wrangler picks up the env var transparently — no further config required.

## doctor Output

Healthy:

```
cf-kv-prod                                                       (cf-kv)
  ✓ wrangler CLI v4.85.0
  ✓ authenticated  email=alice@acme.com  auth=wrangler
```

Not authenticated (no OAuth or API token):

```
cf-kv-prod                                                       (cf-kv)
  ✓ wrangler CLI v4.85.0
  ✗ not authenticated
      → run: wrangler login  OR  export CLOUDFLARE_API_TOKEN=<token>
```

## Fragment directives

No fragment directives. Any `#...` fragment is rejected at URI-parse time.

## History API support

Not implemented. Workers KV has no per-key version history — overwrites simply replace the previous value. If you need versioning, encode it in the key name (e.g., `STRIPE_KEY/v3`).

## Limitations

- **Flat namespace.** KV stores all keys at the same level; no folder scoping. Use `cf_kv_list_prefix` to separate scalar + registry keys via naming convention.
- **Eventually consistent.** KV replicates globally with a slight delay. Immediate strong consistency is not available.
- **Rate limits.** Cloudflare KV enforces per-account rate limits (~1200 req / 5 min default). `list()` with large namespaces can throttle; request a limit increase if needed.
- **Safe set form (no `_unsafe_set` flag).** `set` writes a mode-0600 tempfile and passes `--path <tempfile>`; the value never appears on argv.

## Examples

### Single namespace with default

```toml
[backends.cf-kv-prod]
type                          = "cf-kv"
cf_kv_default_namespace_id    = "c554de8d89644f3d85f21933e7aea910"

[registries.default]
sources = ["cf-kv-prod:///registry/REGISTRY"]
```

```bash
secretenv run -- npm start
```

### Two-namespace pattern (recommended)

Store scalars in one namespace, registry aliases in another:

```toml
[backends.cf-kv-prod]
type = "cf-kv"

[registries.default]
sources = ["cf-kv-prod:///<registry-namespace-uuid>/REGISTRY"]
```

Registry namespace holds URI-valued aliases; scalars live in a separate namespace addressed by URI.

### As registry source

KV namespace holds:

```
registry/stripe_key  →  "cf-kv-prod:///<secrets-ns>/STRIPE_KEY"
registry/db_url      →  "vault-prod:///secret/db"
```

Then: `secretenv run --registry cf-kv-prod:///<registry-ns>/registry -- npm start`

## Troubleshooting

**"Error: code 10009: key not found"**
The key doesn't exist in the namespace. Verify with `wrangler kv key list --namespace-id <id> --remote`. Double-check you're using the **namespace ID** (UUID, from `wrangler kv namespace list`), not the binding name.

**"Error: 429 Too Many Requests"**
Hit the account-wide rate limit. Either request a Cloudflare rate-limit increase, or scope the registry to a smaller namespace with bounded entry count.

**"✗ not authenticated"**
OAuth token expired or `CLOUDFLARE_API_TOKEN` not set. Quickest fix: `wrangler logout && wrangler login` OR `export CLOUDFLARE_API_TOKEN=<token>`.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc. on other backends
- [Cloudflare Workers KV docs](https://developers.cloudflare.com/workers/wrangler/commands/#kv) — authoritative KV reference
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
