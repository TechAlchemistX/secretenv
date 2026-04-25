# Cloudflare Workers KV

**Type:** `cf-kv`
**CLI required:** [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/) 4.x — `npm install -g wrangler` OR `brew install cloudflare/cloudflare/wrangler`
**URI scheme:** `<instance-name>:///<namespace-id>/<key>` (or `<instance-name>:///<key>` when `cf_kv_default_namespace_id` is configured)
**Platform:** cross-platform (macOS, Linux, Windows)

Cloudflare Workers KV is a globally-distributed, eventually-consistent key-value store designed for low-latency reads from Cloudflare Workers (or any HTTPS client). SecretEnv wraps the official `wrangler` CLI for read, write, list, and delete operations against the remote KV namespace. The backend never touches your wrangler-cached OAuth token; auth flows entirely through `wrangler login` (OAuth) or the `CLOUDFLARE_API_TOKEN` env var that wrangler picks up automatically.

## Authentication

Two equivalent paths — pick one:

**OAuth (interactive, recommended for developer machines):**

```bash
wrangler login
# Opens a browser; grant the requested scopes including Workers KV Storage.
# wrangler caches the token at ~/.config/.wrangler/config/default.toml.
```

**API token (CI / headless servers):**

Mint a token at `dashboard.cloudflare.com → My Profile → API Tokens` with the `Workers KV Storage:Edit` template (or `Read` for read-only registry use). Export:

```bash
export CLOUDFLARE_API_TOKEN=<your-token>
```

Wrangler picks up `CLOUDFLARE_API_TOKEN` transparently — no further config required.

## URI format

Two forms are accepted, controlled by config:

```
cf-kv-<instance>:///<namespace-id>/<key>      # always works
cf-kv-<instance>:///<key>                     # requires cf_kv_default_namespace_id
```

The **namespace ID** is the UUID-shaped identifier Cloudflare assigns when you create a namespace; it is stable across Workers and accounts. Find it via `wrangler kv namespace list`. The **binding name** (the `binding:` field in `wrangler.toml`) is per-Worker-script-local and is intentionally NOT used here — namespace IDs are portable, binding names aren't.

The **key** is an arbitrary string; SecretEnv passes it verbatim to wrangler, which URL-encodes internally.

Two-segment URIs always override the configured default namespace. Single-segment URIs require `cf_kv_default_namespace_id` to be set in `config.toml` and are otherwise rejected with a clear local error before any subprocess.

No fragment vocabulary is supported in v0.9. Any `#…` fragment is rejected before subprocess.

## Configuration

```toml
[backends.cf-kv-prod]
type = "cf-kv"

# Optional: namespace ID used when a URI has only one path segment.
# Leave unset to require the explicit two-segment form on every URI.
cf_kv_default_namespace_id = "c554de8d89644f3d85f21933e7aea910"

# Optional: per-instance read/write deadline (seconds). Default 30.
timeout_secs = 15
```

Multiple instances against multiple Cloudflare accounts work via standard SecretEnv multi-instance config; wrangler's account scope follows the OAuth login or `CLOUDFLARE_ACCOUNT_ID` env var.

## Operations

### `get` — fast remote read

```bash
secretenv get my_alias --yes
# Resolves to:  wrangler kv key get <key> --namespace-id <id> --remote --text
```

The `--text` flag tells wrangler to decode the stored value as UTF-8 (default is binary-safe but breaks pipelines for string values). SecretEnv strips the single trailing newline wrangler adds.

### `set` — tempfile via `--path`, no opt-in gate

`wrangler kv key put <key> <value>` exposes the value on argv (visible to same-UID processes via `ps -ww`). To avoid this, SecretEnv writes the value to a `mode-0600` tempfile and passes `--path <tempfile>` instead:

```
wrangler kv key put <key> --namespace-id <id> --remote --path <tempfile>
```

The tempfile is unlinked immediately after wrangler exits (RAII via `tempfile::NamedTempFile`). No `_unsafe_set` opt-in is required because the tempfile path is strictly safer than argv: there is no `ps -ww` exposure, and the same-UID file-system race window is bounded by the 0600 mode and the immediate unlink.

Wrangler 4.x prints an info banner naming the key and namespace ID. The backend nulls stdout on `set()` so even a future regression that includes the value in the banner cannot reach SecretEnv's error-message capture.

### `delete` — strict, not idempotent

```
wrangler kv key delete <key> --namespace-id <id> --remote
```

Mirrors the `aws-secrets` precedent: missing keys bail with a clear "not found" error rather than silently no-opping. Wrangler's interactive confirmation prompt is bypassed because the subprocess runs without a TTY.

### `list` — Pattern A bulk model

`wrangler kv key list --namespace-id <id> --remote` returns a JSON array of `{"name": "..."}` entries (metadata only). For each name, the backend runs a sequential `get --text` to hydrate the value. The result is a `(name, value)` pair list suitable for use as a SecretEnv registry source — store each alias name as a key whose value is the alias's target URI.

Sequential, not parallel: Cloudflare's KV API has account-wide rate limits (~1200 req/5min by default). Sequential fan-out is the polite default; large-namespace deployments can request a rate-limit increase.

Per-key failures (non-zero exit, non-UTF-8 body, IO error) are skipped with a `tracing::warn!` per skip and a summary count. The downstream alias map is therefore at most as large as the namespace, never larger; a registry-source caller sees a shorter map than the namespace actually holds when keys are dropped.

### `history` — unsupported

Workers KV has no per-key version history. Overwrites simply replace the previous value. SecretEnv's `history` override bails with a pointer suggesting you encode versioning in the key name (e.g. `STRIPE_KEY/v3`).

## Security posture

- Every `wrangler` invocation goes through `Command::args([...])` with individual `&str` — never `sh -c`, never `format!` into a shell string.
- `set()` value flows through a mode-0600 tempfile in the OS tempdir; never argv.
- `set()` subprocess `Stdio::null()`s stdout to suppress wrangler's info banner from any future regression that might include the value.
- Response bodies for `get` are secret-bearing. Errors never interpolate stdout; tracing fields never include values.
- The OAuth token cached by `wrangler login` lives in `~/.config/.wrangler/config/default.toml` (wrangler-managed); SecretEnv never reads or writes it.
- API tokens passed via `CLOUDFLARE_API_TOKEN` env var follow the same posture as Doppler / Infisical / Vault tokens — env-var-preferred over config-baked.

## Multi-account configuration

Two Cloudflare accounts work cleanly via wrangler's `--config <wrangler.toml>` plus `CLOUDFLARE_ACCOUNT_ID`:

```toml
[backends.cf-kv-prod]
type = "cf-kv"
cf_kv_default_namespace_id = "abc123…"

[backends.cf-kv-staging]
type = "cf-kv"
cf_kv_default_namespace_id = "def456…"
# OAuth-cached account doesn't need pinning; API-token auth uses the
# token's bound account.
```

If both accounts use OAuth, wrangler's cached token only covers one account. The second instance must use a `CLOUDFLARE_API_TOKEN` env var scoped to the other account — set it via your shell init or a per-process wrapper.

## Doctor output

```
$ secretenv doctor
backend cf-kv-prod (cf-kv): Ok
  cli_version =  ⛅️ wrangler 4.85.0
  identity = email=alice@acme.com auth=wrangler
```

The identity reports the email associated with the OAuth token (or the API token's bound user). Account-name and account-ID details are visible via `wrangler whoami` directly; SecretEnv keeps `doctor` lean by parsing only the email line.

## `set()` opt-in posture vs other backends

cf-kv ships **safe-by-default** for writes — no opt-in flag required. This is a deliberate departure from `1password` and `keeper`, which gate writes behind a `*_unsafe_set = true` config flag because their CLIs have no stdin or filesystem-input form for values (the value MUST land on argv, visible to same-UID processes via `ps -ww`).

| Backend | `set()` posture | Why |
|---|---|---|
| `local` | Safe by default | Writes to a TOML file with explicit perms |
| `aws-ssm`, `aws-secrets`, `gcp`, `azure`, `vault` | Safe by default | CLIs accept value via stdin or `--file` |
| `doppler`, `infisical` | Safe by default | `doppler secrets set --file -`, `infisical secrets set --file <path>` |
| **`cf-kv`** | **Safe by default** | `wrangler kv key put --path <tempfile>` — mode-0600 tempfile + RAII unlink |
| `1password` | Opt-in via `op_unsafe_set = true` | `op item edit` puts value on argv with no stdin alternative |
| `keeper` | Opt-in via `keeper_unsafe_set = true` | `keeper record-add/-update` puts value on argv with no stdin alternative |
| `keychain` | Safe by default | `security add-generic-password` accepts `-w` argv but SecretEnv uses `-w` only with the value, NOT logging it |

The cf-kv tempfile path is strictly safer than argv: there is no `ps -ww` exposure, mode 0600 bounds the same-UID file-system race window, and RAII unlink immediately after wrangler exits keeps the disk-resident lifetime to seconds. No opt-in is required because no exposure mechanism exists to opt into.

## Multi-namespace worked example

cf-kv namespaces are flat — there's no folder/path scoping like Doppler's `dev/registry/` or Infisical's `/registry`. If you want to use cf-kv for **both** scalar secret storage AND a SecretEnv alias registry, use **two namespaces**: one for scalar secrets, one for URI-valued aliases. The registry-source resolver bails on the first non-URI value it sees, so mixing types in a single namespace breaks `secretenv registry list` immediately.

```toml
# ~/.config/secretenv/config.toml

[registries.default]
# The REGISTRY namespace holds ONLY URI-valued aliases.
sources = ["cf-kv-prod:///abc123…/REGISTRY_MARKER"]

[backends.cf-kv-prod]
type = "cf-kv"
# The SECRETS namespace holds scalar values addressed via secretenv.toml.
# Two-segment URIs in alias values point HERE for actual secret reads.
cf_kv_default_namespace_id = "def456…"
```

Then in your alias registry namespace (the one in `[registries.default]`), seed entries like:

```bash
# Each KV key in the registry namespace IS one alias; each value
# IS the full backend URI for the secret behind that alias.
echo -n 'cf-kv-prod:///def456…/STRIPE_KEY' | wrangler kv key put \
  --namespace-id abc123… --remote --path /dev/stdin stripe_key

echo -n 'aws-ssm-prod:///stripe-webhook-secret' | wrangler kv key put \
  --namespace-id abc123… --remote --path /dev/stdin webhook_secret
```

The registry can point at any mix of backends; cf-kv just provides the alias-store layer. `secretenv registry list` enumerates the alias namespace; `secretenv get stripe_key` resolves through whatever URI the alias holds.

## Troubleshooting

**`✗ not authenticated  run: wrangler login OR export CLOUDFLARE_API_TOKEN`**
OAuth token expired or never set up. Quickest fix:

```bash
wrangler logout && wrangler login
# OR
export CLOUDFLARE_API_TOKEN=<token>  # token needs Workers KV Storage:Edit scope
```

**`Error: code 10009: key not found`**
The key doesn't exist in the namespace. Verify with `wrangler kv key list --namespace-id <id> --remote`. Double-check you're using the **namespace ID** (UUID-shaped, from `wrangler kv namespace list`), NOT the binding name (which is per-Worker-script-local).

**`Error: 429 Too Many Requests`**
Cloudflare KV's account-wide rate limit (~1200 req / 5 min default) has been hit, typically by a `secretenv registry list` against a namespace with many keys (each key triggers a sequential `get`). Either request a rate-limit increase from Cloudflare, or scope the registry to a smaller dedicated namespace with bounded entry count.

**Wrong account / multi-account confusion**
`wrangler whoami` shows the active account. To switch:

```bash
# OAuth path:
wrangler logout && wrangler login
# Token path:
export CLOUDFLARE_API_TOKEN=<token-for-other-account>
# Or scope per-instance via wrapper script that exports CLOUDFLARE_ACCOUNT_ID.
```

**`Error: Resource location: remote / Writing the value "..." ...` showing in stderr**
wrangler's info banner. Not an error — the operation succeeded. SecretEnv suppresses this banner from `set()` output by nulling stdout; you'll see it only when running `wrangler` directly.

## Limitations and roadmap

- **No per-key version history.** Use key naming conventions or a separate audit-log key. Cloudflare may add this; SecretEnv will follow.
- **No `bulk get` / `bulk put` use.** Wrangler's `bulk` subcommands are open-beta in 4.x; SecretEnv waits for GA before opting in. Until then, `list()` does sequential per-key fetches.
- **Namespace metadata not exposed.** KV keys can have associated metadata (small JSON blob alongside the value). v0.9 ignores metadata; future `#metadata` fragment support is a possibility if there's user demand.
- **Account-wide rate limits.** Cloudflare KV defaults to ~1200 requests / 5 min. Large-namespace `list()` fan-out can hit this; consider requesting a rate-limit increase or using a dedicated registry namespace with bounded entry count.

## Pointers

- [Workers KV concepts](https://developers.cloudflare.com/workers/runtime-apis/kv/)
- [wrangler kv command reference](https://developers.cloudflare.com/workers/wrangler/commands/#kv)
- [Cloudflare API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
