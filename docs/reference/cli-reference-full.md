# SecretEnv CLI Reference (Full)

Complete per-flag reference for SecretEnv v0.18.0. The README has the compact summary; this page is the deep reference for every command, every flag, every exit code.

---

## Global

```bash
secretenv [--config <path>] <command> [command-options]
```

| Flag | Default | Description |
|---|---|---|
| `--config <path>` | `$XDG_CONFIG_HOME/secretenv/config.toml` (or `~/.config/secretenv/config.toml`) | Path to the machine config file. Used by every subcommand. |

### Environment variables

| Var | Effect |
|---|---|
| `SECRETENV_REGISTRY=<name-or-uri>` | Registry override. Disambiguates name vs URI by presence of `://`. Primary CI mechanism. |
| `SECRETENV_PROFILE_URL=<base-url>` | Override the default profile fetch base (`https://secretenv.io/profiles`). For self-hosted / air-gapped orgs. |
| `RUST_LOG=secretenv=<level>` | Structured logging level. Default `secretenv=warn`. Set to `secretenv=debug` or `secretenv=trace` for diagnostics. |

---

## `secretenv run`

Execute a command with secrets injected as environment variables.

```bash
secretenv run [--registry <name-or-uri>] [--dry-run] [--verbose]
              [--redact] [--no-redact --i-know] [--redact-token <token>]
              [--otel-include-error-detail]
              -- <command> [args...]
```

| Flag | Description |
|---|---|
| `--registry <name-or-uri>` | Override active registry. Name looks up `[registries.<name>]` in config; URI is used directly with no cascade. |
| `--dry-run` | Print resolution map (`KEY ← <uri>` for fetched, `KEY = <value>` for static defaults) and exit. No backend invoked, no credentials needed. Exit 0 on successful resolution. |
| `--verbose` | Emit per-secret fetch progress to stderr. |
| `--redact` | Force pipe-based stdout/stderr redaction even when stdin is a TTY. PTY-bound programs may misbehave; use only when confirmed safe. Mutually exclusive with `--no-redact`. |
| `--no-redact` | Disable runtime stdout/stderr redaction. Falls back to the pre-v0.14 `exec()` path. Requires `--i-know` on non-TTY parents. Mutually exclusive with `--redact`. |
| `--i-know` | Acknowledge the audit consequences of `--no-redact` on a non-TTY parent. Required by `--no-redact`. On a TTY parent an additional interactive prompt fires regardless. |
| `--redact-token <token>` | Override the substitution token. Default is `[redacted:<alias-name>]`. |
| `--otel-include-error-detail` | Include scrubbed backend stderr text on the `secretenv.backend.error.message` OTel span attribute on failed fetches. Default off. |

**Behavior:**
- Walks upward from CWD to find `secretenv.toml`; stops at VCS sentinel (`.git`/`.hg`/`.svn`/`.secretenv-root`) or filesystem root.
- Resolves the registry, then the manifest, then fetches all secrets in parallel.
- **All-or-nothing:** if any required alias fails to resolve, the child process never starts. Partial environments are never injected.
- On Unix: replaces the current process via `exec()` (inherits TTY, stdio, signals).
- On non-Unix: spawns child, waits, propagates exit code.

**Exit codes:**
- 0: child exited 0 (or, on Unix, exec succeeded)
- 1: configuration error (manifest invalid, registry not found, backend not configured)
- 2: backend resolution error (alias unresolved, backend NotAuth, etc.)
- N: child's exit code (when not exec'd)

---

## `secretenv resolve`

Metadata-only lookup for a single alias. No secret value fetched.

```bash
secretenv resolve <alias> [--registry <name-or-uri>] [--json]
```

Output: alias name, env-var binding (if any, reverse-looked from manifest), resolved backend URI, cascade-layer source, backend auth status.

---

## `secretenv get`

Fetch and print a single secret. Confirmation-gated by default.

```bash
secretenv get <alias> [--registry <name-or-uri>] [--yes|-y]
```

| Flag | Description |
|---|---|
| `--yes`, `-y` | Skip the interactive "about to print the secret value" confirmation prompt. |

Prints the raw secret value to stdout. Use with care; piping to `pbcopy` or `wl-copy` is the common pattern.

---

## `secretenv registry`

Alias CRUD + history + onboarding helpers.

### `registry list`

```bash
secretenv registry list [--registry <name-or-uri>]
```

Lists all aliases in the active (or specified) registry, with their backend URIs, grouped by source layer (cascade-aware). Shadowed entries marked.

### `registry get`

```bash
secretenv registry get <alias> [--registry <name-or-uri>]
```

Prints the backend URI an alias resolves to. No secret value.

### `registry set`

```bash
secretenv registry set <alias> <backend-uri> [--registry <name-or-uri>]
```

Adds or updates an alias. Validates URI parses and target backend is configured. Writes go to `sources[0]` of the active registry. To write to a specific source, pass a direct URI to `--registry`.

### `registry unset`

```bash
secretenv registry unset <alias> [--registry <name-or-uri>]
```

Removes an alias from the registry.

### `registry history`

```bash
secretenv registry history <alias> [--registry <name-or-uri>] [--json]
```

Shows version history (most-recent-first) for a secret. Outputs human table (VERSION / TIMESTAMP / ACTOR / DESCRIPTION columns) or JSON. Backends without a native history API return an error when history is requested. The error message varies by backend: the trait default says "not implemented"; per-backend overrides that wrap a CLI with no history subcommand say "not supported".

History is supported by: `local` (where backed by git), `aws-ssm`, `vault` (KV v2).

History is not supported by: `1password`, `keychain`, `gcp`, `azure`, `aws-secrets`, `doppler`, `infisical`, `keeper`, `cf-kv`, `openbao`, `conjur`, `bitwarden-sm`.

### `registry migrate`

```bash
secretenv registry migrate <alias> <dest-uri>
  [--registry <name-or-uri>]
  [--dry-run]
  [--yes|-y]
  [--from <source-uri>]
  [--delete-source]
  [--json]
```

Migrate an alias's value from its current backend to a new one. Reads the current value via the registry pointer, writes it to the destination, then atomically flips the registry pointer to the destination URI. The source value is NOT deleted by default.

| Flag | Description |
|---|---|
| `--dry-run` | Plan-only mode. Runs source/destination probes, prints the migration plan, exits without mutation. |
| `--yes`, `-y` | Skip the top-level confirmation prompt. The `--delete-source` extra confirmation still fires even under this flag. |
| `--from <source-uri>` | Override the inferred source URI. Used for recovery flows where the registry already points at the destination but the value is still in the old backend. |
| `--delete-source` | After a successful migrate, delete the source value via the source backend's delete operation. Subject to a separate confirmation gate even under `--yes`. |
| `--json` | Emit machine-readable JSON to stdout instead of the human-formatted progress and summary. |

### `registry invite`

```bash
secretenv registry invite [--registry <name-or-uri>] [--invitee <identifier>] [--json]
```

Generates an onboarding snippet (config.toml fragment + IAM grant command) for a new collaborator. Invitee defaults to `<INVITEE>` placeholder.

---

## `secretenv profile`

Distributed config-fragment overlay system.

```bash
secretenv profile install   <name> [--url <url>]
secretenv profile list      [--json]
secretenv profile update    [<name>]
secretenv profile uninstall <name>
```

| Subcommand | Description |
|---|---|
| `install <name>` | Fetches the profile from `--url <url>` if given, else from `${SECRETENV_PROFILE_URL:-https://secretenv.io/profiles}/<name>.toml`. Hard cap 1 MiB. Writes to `<config-dir>/profiles/<name>.toml` + sidecar `<name>.meta.json` (source URL, ETag, install timestamp). |
| `list` | Show installed profiles (NAME / INSTALLED / SOURCE). |
| `update [<name>]` | Re-fetches one (or all) profiles using ETag for conditional re-fetch. Reports `up-to-date` or `refreshed`. |
| `uninstall <name>` | Removes profile `.toml` + sidecar metadata. |

**Merge semantics:** profiles are loaded after the user's `config.toml`. **User config always wins** where keys overlap. Profiles only fill gaps. Profiles are processed alphabetically.

---

## `secretenv setup`

Bootstrap a fresh `config.toml`.

```bash
secretenv setup <registry-uri>
  [--region <r>]                       # aws-ssm / aws-secrets
  [--profile <p>]                      # aws-ssm / aws-secrets
  [--account <a>]                      # 1password
  [--vault-address <url>]              # vault
  [--vault-namespace <ns>]             # vault enterprise
  [--gcp-project <p>]                  # gcp
  [--gcp-impersonate-service-account <e>]  # gcp
  [--azure-vault-url <url>]            # azure
  [--azure-tenant <t>]                 # azure
  [--azure-subscription <s>]           # azure
  [--force]
  [--skip-doctor]
```

| Flag | Description |
|---|---|
| `--force` | Overwrite existing config.toml without prompting. |
| `--skip-doctor` | Skip the post-write `secretenv doctor` health check. |

Backend-specific flags map to fields in the generated `[backends.<instance>]` block.

---

## `secretenv doctor`

Health check across all configured backends.

```bash
secretenv doctor [--json] [--fix] [--extensive]
```

| Flag | Description |
|---|---|
| `--json` | Machine-readable output. Status variants: `ok`, `not_authenticated`, `cli_missing`, `error`. Suitable for CI gates and monitoring probes. |
| `--fix` | For each `not_authenticated` backend, run canonical remediation CLI interactively (`aws sso login`, `op signin`, `gcloud auth login`, `az login`, `vault login`). Re-checks after. |
| `--extensive` | Level-3 deep probe: attempts `list()` against each registry source, counts aliases, reports permission scope. |
| `--trace` | Capture OTel spans emitted during the doctor pass into a local in-memory exporter and render them as a chronologically-sorted table. No OTLP collector required — useful for operator observability without standing up infrastructure. |

**Three levels:**
- **L1** — CLI installed (e.g., `aws --version` exits 0)
- **L2** — Backend authenticated (e.g., `aws sts get-caller-identity` succeeds)
- **L3** — Can read registry source (counts aliases). `--extensive` only.

Default is L1 + L2. All checks run concurrently with a 5-second per-check timeout. Exit code is non-zero if any backend reports anything other than `ok` (after remediation if `--fix` was passed). L3 failures report but don't change exit code.

---

## `secretenv completions`

Generate shell completion scripts.

```bash
secretenv completions <bash|zsh|fish> [--output <path>]
```

| Flag | Description |
|---|---|
| `--output <path>` | Write to file with mode 0o644. If omitted, prints to stdout. TTY detection shows install hints. |

---

## `secretenv redact`

Post-hoc redaction: scrub secret values out of an existing file or stream.

```bash
secretenv redact <path>
  [--registry <name-or-uri>]
  [--alias <name>[,<name>...]]
  [--in-place]
  [--backup <suffix>]
  [--dry-run]
  [--allow-foreign-owner]
  [--redact-token <token>]
```

| Flag | Description |
|---|---|
| `--registry <name-or-uri>` | Registry selection — same semantics as `secretenv run --registry`. |
| `--alias <name>` | Restrict the tainted set to these alias names. Repeatable; comma-separated values also accepted. Default: every alias resolvable from the active manifest and registry cascade. |
| `--in-place` | Rewrite the file in place (atomic rename). Without this flag, the scrubbed output is written to stdout and the original file is untouched. |
| `--backup <suffix>` | With `--in-place`, keep a backup of the original at `<path><suffix>` (e.g. `--backup=.bak`). Requires `--in-place`. |
| `--dry-run` | Count matches without writing any output. Mutually exclusive with `--in-place`. |
| `--allow-foreign-owner` | Bypass the foreign-owner refusal that fires when the target file's UID differs from the caller's effective UID. |
| `--redact-token <token>` | Override the substitution token. Default is `[redacted:<alias-name>]`. |

**Behavior:** Resolves every alias's current value from the active registry, builds a tainted set, and rewrites the file replacing any occurrence with the substitution token. All-or-nothing — a single unresolvable alias aborts before writing. Symlinks are refused (`O_NOFOLLOW`); special files (devices, sockets) are refused. Files owned by a different UID are refused unless `--allow-foreign-owner` is passed.

---

## `secretenv mcp`

Model Context Protocol (MCP) server operations.

### `mcp serve`

```bash
secretenv mcp serve [--allow-mutations <never|confirm|always>] [--confirm-via <auto|elicitation|tty|notification|none>]
```

Run the MCP server over stdio until the transport closes. Honors the disable sentinel — if present and unexpired, exits with a clear stderr message before binding.

| Flag | Description |
|---|---|
| `--allow-mutations <mode>` | Per-launch override for `[mcp].allow_mutations`. Values: `never`, `confirm`, `always`. Takes precedence over the value in `config.toml`. |
| `--confirm-via <surface>` | Per-launch override for `[mcp].confirm_via`. Values: `auto`, `elicitation`, `tty`, `notification`, `none`. |

### `mcp disable`

```bash
secretenv mcp disable [--duration <duration>]
```

Disable the MCP server by writing the sentinel file. Subsequent `mcp serve` invocations exit immediately until the sentinel is removed (`mcp enable`) or, when `--duration` was given, the embedded expiry has passed.

| Flag | Description |
|---|---|
| `--duration <duration>` | Optional auto-expiry — e.g. `30m`, `2h`, `1d`. Without this flag the disable is indefinite. |

### `mcp enable`

```bash
secretenv mcp enable
```

Re-enable the MCP server by removing the disable sentinel. No-op if the sentinel is already absent.

### `mcp setup`

```bash
secretenv mcp setup [--ide <key>] [--list-ides] [--binary <path>] [--write] [--force] [--merge] [--check-overrides]
```

Emit a paste-ready MCP-client config block for a supported IDE, or write the config file directly.

| Flag | Description |
|---|---|
| `--ide <key>` | Which IDE to render for. Required unless `--list-ides` or `--check-overrides` is given. |
| `--list-ides` | Print supported IDE keys and their config-file paths, then exit. |
| `--binary <path>` | Absolute path to the `secretenv` binary the IDE will spawn. Default: `secretenv` (relies on the IDE's `$PATH`). |
| `--write` | Write the rendered config to the target file. Default is stdout. |
| `--force` | With `--write`, overwrite the target file even if it already exists. Mutually exclusive with `--merge`. |
| `--merge` | With `--write`, splice the SecretEnv MCP entry into the existing file in place. Supported for JSON-shaped IDE configs. Mutually exclusive with `--force`. |
| `--check-overrides` | Read-only scan: check every supported IDE's config file for SecretEnv MCP argv overrides and flag any that would be vetoed by `[mcp].allow_cli_overrides`. Mutually exclusive with all other flags. |

### `mcp audit tail`

```bash
secretenv mcp audit tail [--lines <n>] [--path <path>]
```

Print the last N audit-log entries (default 50) in chronological order. Output is one JSON object per line.

| Flag | Description |
|---|---|
| `--lines <n>` | How many entries to print. Default: 50. |
| `--path <path>` | Path to the audit-log file. Default is the XDG state-dir location `mcp serve` writes to. |

---

## URI grammar

```
<scheme>://[<authority>]/<path>[#<fragment>]
```

- **Scheme:** alphanumeric + `_`/`-`, must start with alphanumeric. The scheme is your **named instance** (e.g., `aws-ssm-prod`, `1password-work`, `vault-eng`).
- **Authority:** SecretEnv URIs have no authority — the "host" position is empty. This produces the triple-slash form `<scheme>:///<path>` for paths beginning with `/`.
- **Path:** Non-empty. Control characters (NUL + ASCII <0x20 except tab) are rejected at parse time.
- **Fragment:** Optional `key=value[,key=value]*` directive map. Common directives: `json-key=<field>` (extract JSON field from response), `version=<n>` (pin version, where supported). See [fragment-vocabulary.md](fragment-vocabulary.md).

**Special scheme:** `secretenv://` is reserved for alias references in the project manifest.

---

## File formats

### `secretenv.toml` (project manifest)

```toml
[secrets]
KEY = { from = "secretenv://alias-name" }   # alias reference
KEY = { default = "literal-value" }         # static default
```

Two value shapes only. Direct backend URIs are a hard error.

### `~/.config/secretenv/config.toml` (machine config)

```toml
[registries.<name>]
sources = ["<backend-uri>", ...]   # cascade; first-match-wins

[backends.<instance-name>]
type = "<backend-type>"
# backend-specific fields
```

### Profile (`<config-dir>/profiles/<name>.toml`)

Same shape as machine config — `[registries.*]` + `[backends.*]` blocks. Auto-merged on every load. User config wins on key collision.

### Registry document (stored in any backend)

TOML or JSON, depending on backend. Flat `alias-name → backend-uri` map.

```toml
stripe-key = "1password-work://payments/stripe/api_key"
db-url     = "aws-ssm-dev:///myapp/dev/db_url"
```

---

For workflow guidance, see the [overview](/). For the threat model + security posture: [security.md](../security.md).
