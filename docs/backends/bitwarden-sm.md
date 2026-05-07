# Bitwarden Secrets Manager

**Type:** `bitwarden-sm`
**CLI required:** `bws` (Bitwarden Secrets Manager CLI v1+)
**URI scheme:** `<instance-name>://<uuid>[#json-key=<field>]`

[Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) is the developer/CI product from Bitwarden — machine-account access tokens, project-scoped secrets, designed for application/CI consumption rather than personal vault use.

> **Two products, two CLIs.** Bitwarden ships **Bitwarden Password Manager** (CLI `bw`, master-password vault items) and **Bitwarden Secrets Manager** (CLI `bws`, machine-account access tokens). They are distinct products with distinct data models. This backend wraps **Secrets Manager only** (`bws`). The backend type is `bitwarden-sm`, leaving the bare `bitwarden` namespace open for a future Password Manager wrapper. If you have `bw` installed and were expecting that, you want a different (not-yet-shipped) backend — check the roadmap.

Unlike Vault / OpenBao's KV-mount-and-path model, Bitwarden Secrets Manager uses a **flat per-project secret table**: every secret is a row keyed by a server-generated UUID, owned by a project. The wrapper addresses secrets by UUID directly because (1) `bws secret get` accepts only UUIDs — there is no `--key` lookup mode, and (2) the server allows duplicate KEY names within a project, so key-name addressing would be ambiguous. Human-readable aliases live in the SecretEnv registry layer.

---

## Install

```bash
brew install bitwarden-secrets-manager       # macOS
```

Linux and Windows binaries are linked from the [Bitwarden Secrets Manager CLI docs](https://bitwarden.com/help/secrets-manager-cli/). Verify:

```bash
bws --version          # → bws 2.0.0 (or newer)
```

`secretenv doctor` requires `bws` major version >= 1.

---

## Authentication

Bitwarden Secrets Manager uses **machine accounts** (not user logins). Issue an access token in the web UI:

1. Open the [Bitwarden web vault](https://vault.bitwarden.com/) and switch to your organization.
2. Navigate to **Secrets Manager → Machine Accounts → New machine account**.
3. Grant the machine account `read` (or `read-write`) on the projects this SecretEnv instance will touch.
4. Generate an **Access Token**. The token has the shape `0.<machine-account-uuid>.<base64>:<base64>`.
5. Export it in your shell:

   ```bash
   export BWS_ACCESS_TOKEN='0.abc...:xyz...'
   ```

There is **no interactive `bws login` flow** — `bws` is purely env-var-driven, which makes the wrapper simpler than 1Password (no session-key juggling) and constrains the doctor surface to "is `BWS_ACCESS_TOKEN` set, and does it work."

The wrapper sources the token from the operator shell at command time and sets `BWS_ACCESS_TOKEN` on each child process env only. The token VALUE is never written to argv, never to the registry doc, never logged. `secretenv doctor` echoes only the env-var NAME and the project COUNT — never the token itself.

---

## Configuration

```toml
[backends.bws-prod]
type = "bitwarden-sm"
# All other fields optional — US cloud + BWS_ACCESS_TOKEN env var are the defaults.
```

For non-default cloud regions or self-hosted Bitwarden:

```toml
[backends.bws-prod]
type = "bitwarden-sm"
bitwarden_server_url = "https://vault.bitwarden.eu"           # EU cloud
# bitwarden_server_url = "https://bitwarden.company.com"       # self-hosted
```

For multi-instance setups where each Bitwarden organization needs its own access token:

```toml
[backends.bws-prod]
type = "bitwarden-sm"
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_PROD"

[backends.bws-staging]
type = "bitwarden-sm"
bitwarden_access_token_env = "BWS_ACCESS_TOKEN_STAGING"
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"bitwarden-sm"`. |
| `bitwarden_server_url` | No | Override the Bitwarden server URL. Default is the US cloud (`https://vault.bitwarden.com`). When unset, the wrapper actively REMOVES `BWS_SERVER_URL` from the child env so the CLI's built-in default applies — even if the operator's parent shell has `BWS_SERVER_URL` exported globally. |
| `bitwarden_access_token_env` | No | Name of the env var holding the machine-account access token. Defaults to `BWS_ACCESS_TOKEN`. Use this to keep multiple instances scoped to different machine accounts without env-var collision. Must match the POSIX env-var-name shape (`[A-Za-z_][A-Za-z0-9_]*`); invalid names are rejected at config-parse time. |
| `bitwarden_unsafe_set` | No | Defense-in-depth opt-in. Default `false`: `set` and `delete` REFUSE because `bws` exposes the secret value on argv. Set `true` to enable both. See "Why `set` is disabled by default" below. |
| `bitwarden_bin` | No | Override the `bws` binary path. Defaults to `"bws"` (resolved via `$PATH`). Primarily a test hook. |
| `timeout_secs` | No | Per-instance fetch timeout in seconds. Defaults to 30. |

---

## URI shape

```
bitwarden-sm-<instance>://<uuid>[#json-key=<field>]
```

Examples:

```
bws-prod://abcdef0123456789abcdef0123456789
bws-prod://abcdef0123456789abcdef0123456789#json-key=password
```

The path is the secret's UUID. `bws` accepts (and emits) the **canonical hyphenated form** (`8-4-4-4-12`, 36 chars including hyphens — what you get when you copy from the web UI or `bws secret list`); the wrapper also accepts the 32-char "simple" form (no hyphens) for operators round-tripping data through systems that strip hyphens. Mixed case is normalized to lowercase. Anything else is rejected at URI-parse time with a clear error.

### Why UUID, not key-name

- `bws secret get` accepts UUID only — no `--key` lookup mode.
- Bitwarden allows duplicate KEY names within a project. A key-name URI would be ambiguous.
- A key-name URI would force a `bws secret list` round-trip on every fetch (latency + ambiguity).
- Human-readable aliases are exactly what the SecretEnv registry layer is for: `secretenv://stripe-live → bitwarden-sm://abcdef...`.

### `#json-key=<field>` fragment

When the secret's `value` is itself a JSON-encoded object (a common pattern for grouped credentials):

```toml
# Secret value at <uuid>: {"username":"alice","password":"hunter2","host":"db.internal"}
[backends.bws-prod]
type = "bitwarden-sm"

# Registry alias map:
db_password = "bws-prod://abcdef0123456789abcdef0123456789#json-key=password"
```

`secretenv get db_password` returns `hunter2`. Same fragment shape as `aws-secrets`, `openbao`, and `conjur`. Only `get` accepts the fragment; `set` / `delete` / `list` / `history` reject it.

---

## Storage model

Bitwarden Secrets Manager secrets are JSON envelopes:

```json
{
  "object": "secret",
  "id": "abcdef0123456789abcdef0123456789",
  "key": "STRIPE_LIVE_KEY",
  "value": "sk_live_xyz...",
  "note": "",
  "projectId": "11112222333344445555666677778888",
  "creationDate": "2026-05-05T12:00:00Z",
  "revisionDate": "2026-05-05T12:00:00Z"
}
```

The wrapper extracts the `value` field. The other fields are ignored at runtime; `note`, `key`, etc. live for the operator's own benefit in the web UI.

### Why `set` is disabled by default

`bws` v2.0.0 has **no stdin path** for `secret create` or `secret edit`. The value is on argv via `--value <VALUE>` (or as the second positional for `create`), which means it's visible in `/proc/<pid>/cmdline` to any process running as the same UID. There is no `-`/`/dev/stdin` sentinel and no `--value-file` flag.

The wrapper refuses both `set` and `delete` by default with:

```
bitwarden-sm backend '<instance>': set is disabled by default because `bws`
exposes the secret value on argv (visible via /proc/<pid>/cmdline). To enable, set:

  [backends.<instance>]
  bitwarden_unsafe_set = true

Recommended alternative: provision the secret via the Bitwarden web UI, then
reference its UUID from this registry. See docs/backends/bitwarden-sm.md.
```

To enable, set `bitwarden_unsafe_set = true` per-instance. Same defense-in-depth precedent established by 1Password (`op_unsafe_set`), OpenBao (`bao_unsafe_set`), and Conjur (`conjur_unsafe_set`). When the gate is open, the wrapper emits a per-invocation `tracing::warn!` so `secretenv --verbose` surfaces the choice as a runtime breadcrumb.

**`delete` is gated alongside `set`** because the threat model is "destructive write operations from a wrapped CLI" — not argv-leak risk specifically. Splitting the gate would proliferate flags without changing the operator mental model.

### `set` updates only — never creates

The URI is a UUID, which can only refer to a secret that already exists. So `secretenv set <alias>` always invokes `bws secret edit --value <value> <uuid>` — never `bws secret create`. Secret provisioning is an out-of-band operator workflow:

1. Operator creates the secret in the web UI (or via a one-shot `bws secret create` script outside SecretEnv).
2. Web UI returns the new secret's UUID.
3. Operator adds the UUID to the SecretEnv registry: `secretenv registry set <alias> bitwarden-sm-prod://<uuid>`.

This separation matches Bitwarden's own intended workflow: long-lived secrets are managed in the UI, applications consume them by reference.

---

## Server URLs

| Environment | Set `bitwarden_server_url` to |
|---|---|
| US cloud (default) | (omit — leave field unset) |
| EU cloud | `https://vault.bitwarden.eu` |
| Self-hosted | your server's public URL, e.g. `https://bitwarden.company.com` |

The wrapper omits `BWS_SERVER_URL` from the child env when no override is configured, so `bws`'s built-in US-cloud default applies. This survives a host where the operator's parent shell has `BWS_SERVER_URL` set globally to something else — useful when running smoke tests against a known-good cloud instance from a workstation pre-configured for self-hosted.

### Security note — `bitwarden_server_url` forwards your access token

`bitwarden_server_url` accepts any URL the operator configures and the wrapper forwards `BWS_ACCESS_TOKEN` to whatever server is at that URL on the next `secretenv doctor` / `get` / `set`. This is the intended behavior for legitimate self-hosted and EU deployments, but it also means a typo-squatted or attacker-supplied URL pasted into a starter config or pull-request template hands the access token to the attacker. Validate the URL before pasting it into a config you commit:

- Compare the URL letter-by-letter against the value in your Bitwarden web UI's organization settings.
- Prefer hard-coded constants (`https://vault.bitwarden.com`, `https://vault.bitwarden.eu`) over copy-paste from chat / tickets / templates.
- Treat any change to `bitwarden_server_url` in a code review with the same scrutiny as a change to an `aws-secrets` `region` or a `vault` `address` — wrong target servers can exfiltrate the token without any other code change.

The wrapper enforces a control-character check on the URL but does not restrict the scheme, host, or TLD; that remains the operator's responsibility.

TLS trust is delegated to the system CA bundle the `bws` binary loads at runtime — typically the platform default (macOS Keychain trust roots, Linux `/etc/ssl/certs/`). On corporate networks with TLS-intercepting proxies that install a private CA, `bws` will quietly trust the intercepted endpoint, exposing the access token to the proxy. If you operate behind such a proxy, audit your CA bundle and lock `bitwarden_server_url` to a server you control end-to-end.

---

## `bws run` is not a SecretEnv backend

`bws run -- <command>` injects all project secrets as env vars and execs the command. This is conceptually a sibling of `secretenv run` — they do similar things — but they are **not interchangeable**:

| Concern | `bws run` | `secretenv run` |
|---|---|---|
| Source | One Bitwarden project | Any SecretEnv backend or registry |
| Selection | All secrets in project | Aliases declared in `secretenv.toml` |
| Cross-backend | No | Yes |

Use `secretenv run` to consume Bitwarden secrets through the alias layer; use `bws run` only if your application reads ALL secrets from one Bitwarden project unaltered.

---

## RBAC and project scoping

Bitwarden Secrets Manager scopes access at the **project** level. A machine account is granted `read` or `read-write` on each project individually. Minimum permissions for SecretEnv operators:

- `get` / `list` / `check`: `read` on the project containing the target secret(s).
- `set` / `delete`: `read-write` on the project. (And `bitwarden_unsafe_set = true` per-instance.)

The wrapper does not manage projects, machine accounts, or token rotation — operators provision via the web UI.

---

## License

`bws` (the Bitwarden SDK that ships the CLI) is **GPL-3.0-only**. SecretEnv shells out to it; it is not a linked dependency, so the GPL boundary is per-process not per-link. The wrapper crate `secretenv-backend-bitwarden-sm` ships **AGPL-3.0-only** like every SecretEnv crate.

---

## Limitations

- **No secret history.** Bitwarden Secrets Manager surfaces revisions in the web UI (every `secret edit` bumps `revisionDate`) but the CLI exposes no `secret history` subcommand. `secretenv registry history <alias>` returns the trait-default "not implemented" until vendor exposes versioning.
- **No bulk write.** `bws secret delete` accepts multiple UUIDs in one call; SecretEnv's `Backend::delete` is single-URI by trait contract. The wrapper invokes single-UUID delete only. Bulk operations remain CLI-only.
- **No key-name lookup.** Address by UUID; alias via the registry.
- **Free-tier project / machine-account limits apply.** The Bitwarden free tier caps at 2 projects and 2 machine accounts per organization. Production usage requires a paid tier; smoke testing on free is fine.

---

## Troubleshooting

### `Missing access token`

The configured env var (default `BWS_ACCESS_TOKEN`) is unset.

```bash
export BWS_ACCESS_TOKEN='0...'    # or whatever name your bitwarden_access_token_env points at
```

If you've renamed the env var per-instance, check the `bitwarden_access_token_env` field in your `[backends.<instance>]` block and export the matching name.

### `set is disabled by default`

You hit the defense-in-depth gate. Either provision the secret via the web UI (preferred) or set `bitwarden_unsafe_set = true` per-instance. Re-read "Why `set` is disabled by default" above before flipping the flag.

### `URI '...' path must be a Bitwarden UUID`

The path is neither a 36-char hyphenated UUID nor a 32-char simple UUID. Get the canonical UUID from `bws secret list --output json | jq -r '.[].id'` (returns hyphenated form).

### `Cipher MAC doesn't match` from `bws`

`bws` doesn't strip surrounding double-quotes from `BWS_ACCESS_TOKEN`. If you exported `BWS_ACCESS_TOKEN="..."` (literal quotes), the quote characters become part of the token bytes and decryption fails. Re-export bare: `export BWS_ACCESS_TOKEN=0.uuid.base64:mac` (no quotes). Verify with `echo "len=${#BWS_ACCESS_TOKEN}"` — a clean token is 94 chars; quoted reads 96.

### Doctor returns `projects=0`

Your token is authenticated but scoped to zero projects. Either grant the machine account access to a project in the web UI, or check that you exported the right token (a token from a different organization will authenticate against the API but find no projects in yours).
