# OpenBao

**Type:** `openbao`
**CLI required:** [`bao`](https://openbao.org/docs/install/) v2+
**URI scheme:** `<instance-name>://mount/path/to/secret[#json-key=<field>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `bao v2.5.3` (build 2026-04-20) on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `openbao` backend. New here? See the [overview](/).

OpenBao is the Linux Foundation MPL-2.0 fork of HashiCorp Vault — same wire protocol, KV semantics, and auth methods. Pick OpenBao if you're already running a Vault-compatible instance and want the open-source governance model. Migration from Vault is a one-line config swap.

## When to pick this

- **Vault-compatible instances:** OpenBao understands the Vault API; use it with Vault servers
- **Open source governance:** MPL-2.0 licensed, Linux Foundation governed
- **Self-hosted or cloud:** run your own instance or use a managed provider
- **Enterprise features via OSS:** namespaces are free in OpenBao 2.x (Enterprise-gated in Vault)

## Configuration

```toml
[backends.openbao-dev]
type            = "openbao"
openbao_address = "http://127.0.0.1:8300"   # required
# openbao_namespace = "team-engineering"    # optional
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"openbao"` |
| `openbao_address` | Yes | Full URL of the OpenBao instance (include scheme). Dev mode listens on **HTTP** (`http://127.0.0.1:8300`), not HTTPS. Set explicitly to keep registry portable. |
| `openbao_namespace` | No | OpenBao namespace (free OSS feature in 2.x). Omit if not in use. |
| `bao_unsafe_set` | No | Defense-in-depth opt-in. Defaults to `false`; the safe `value=-` stdin form is used regardless. Reserved for forward-compatibility. |
| `timeout_secs` | No | Per-instance fetch timeout. Default: 30s. |

### Multiple instances or namespaces

```toml
[backends.bao-eng]
type              = "openbao"
openbao_address   = "https://bao.company.com"
openbao_namespace = "engineering"

[backends.bao-payments]
type              = "openbao"
openbao_address   = "https://bao.company.com"
openbao_namespace = "engineering/payments"
```

## URI Format

```
openbao-dev://secret/prod/db_password
└─────────┘  └─────┘ └──────────────┘
instance    mount   path within mount
```

The unified `bao kv` CLI handles KV v1 and v2 transparently. The mount is the KV backend's name (typically `secret`); the path is the secret's location within it.

### `#json-key=<field>` fragment

When a single secret holds a JSON object in the `value` field, `#json-key=<field>` selects one top-level scalar:

```toml
db_password = "openbao-dev://secret/prod/db_creds#json-key=password"
db_username = "openbao-dev://secret/prod/db_creds#json-key=username"
```

Provision the secret:

```bash
echo -n '{"username":"app","password":"sk_live_abc"}' \
  | bao kv put secret/prod/db_creds value=-
```

The fragment is recognized only on `get`. `set`, `delete`, `list`, and `history` reject any fragment.

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `bao` CLI. Any auth method the CLI supports works:

- `BAO_TOKEN` environment variable (CLI also reads `VAULT_TOKEN` for transition compat)
- `bao login` → token persisted at `~/.vault-token`
- AppRole, OIDC/JWT, Kubernetes, AWS IAM

The minimum read policy is:

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
```

`set` additionally needs `update` / `create`. `delete` needs `delete`.

## doctor Output

Healthy:

```
openbao-dev                                                     (openbao)
  ✓ bao CLI OpenBao v2.5.3
  ✓ authenticated  addr=http://127.0.0.1:8300  namespace=(none)
```

Not authenticated (token missing or expired):

```
openbao-dev                                                     (openbao)
  ✓ bao CLI OpenBao v2.5.3
  ✗ not authenticated
      → run: bao login  (or set BAO_TOKEN, or place a token in ~/.vault-token)
```

## Fragment directives

| Directive | Effect | Example |
|---|---|---|
| `json-key=<field>` | Extract top-level JSON field | `openbao-dev://secret/prod/creds#json-key=password` |

Other fragments are rejected with a specific error.

## History API support

Not implemented (planned for future). The `bao` CLI (v2.5.3) has no per-secret history subcommand. Version history is available via the REST API and the web UI; this backend will flip to a native implementation once the CLI supports it.

## Limitations

- **Storage model.** Every secret is stored in the `value` field of a KV v2 entry (`bao kv put <path> value=-`). Multi-field secrets are not produced by this backend.
- **Scheme mismatch gotcha.** Dev mode (`bao server -dev`) listens on **HTTP**, but the CLI defaults to **HTTPS**. Always set `openbao_address` explicitly with the correct scheme.
- **KV v1 vs v2.** `bao kv` CLI is transparent, but if you're migrating from Vault, verify your mount type in OpenBao (run `bao secrets list` to see mount types).

## Examples

### Local dev instance

```toml
[backends.openbao-dev]
type            = "openbao"
openbao_address = "http://127.0.0.1:8300"

[registries.default]
sources = ["openbao-dev://secret/registry"]
```

```bash
secretenv run -- npm start
```

### Multi-namespace production

```toml
[backends.bao-eng]
type              = "openbao"
openbao_address   = "https://bao.company.com"
openbao_namespace = "engineering"

[backends.bao-payments]
type              = "openbao"
openbao_address   = "https://bao.company.com"
openbao_namespace = "engineering/payments"

[registries.eng]
sources = ["bao-eng://secret/registry"]

[registries.payments]
sources = ["bao-payments://secret/registry"]
```

Deploy eng: `secretenv run --registry eng -- ./deploy.sh`

### With JSON multi-field secrets

Secret at `secret/prod/db_creds`:

```json
{"username":"app","password":"sk_live_abc"}
```

Aliases:

```toml
db_user = "openbao-dev://secret/prod/db_creds#json-key=username"
db_pass = "openbao-dev://secret/prod/db_creds#json-key=password"
```

## Troubleshooting

**"Error reading secret: http: server gave HTTP response to HTTPS client"**
Scheme mismatch. Dev mode is HTTP, not HTTPS. Set `openbao_address = "http://127.0.0.1:8300"` (or the correct scheme for your instance).

**"permission denied"**
Your policy doesn't grant the required capability. Run `bao policy read <policy>` to verify read/update/delete scopes. For read-only, ensure `"read"` is listed.

**"secret not found"**
The path doesn't exist. Verify with `bao kv list secret/` to enumerate existing secrets. Check the mount name is correct (typically `secret`).

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#json-key`, `#version`, etc. on other backends
- [Vault backend](vault.md) — compatible and equivalent (choose based on governance preference)
- [OpenBao CLI reference](https://openbao.org/docs/commands/) — authoritative OpenBao docs
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
