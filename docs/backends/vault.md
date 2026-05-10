# HashiCorp Vault

**Type:** `vault`
**CLI required:** [`vault`](https://developer.hashicorp.com/vault/docs/install)
**URI scheme:** `<instance>://mount/path/to/secret[#version=<n>]`
**Platform:** all (macOS, Linux, Windows)
**Tested:** `vault v2.0.0` (build 2026-04-13) on macOS Darwin 25.4 (SecretEnv v0.13.0, 2026-05-07)

> SecretEnv injects secrets from any backend as environment variables. This page covers the `vault` backend. New here? See the [overview](/).

HashiCorp Vault is a centralized, multi-tenant secrets store designed for enterprise teams. It offers fine-grained access control, comprehensive audit logging, and advanced authentication methods (AppRole, OIDC, Kubernetes, AWS IAM). Pick Vault when you need dynamic secrets, secrets rotation, or centralized credential management across infrastructure. The `vault` CLI delegates all authentication, eliminating the need for SecretEnv to manage tokens or auth flows.

## When to pick this

- **Enterprise multi-tenancy:** Vault namespaces isolate teams; fine-grained policies per secret path
- **Dynamic credentials:** Vault generates short-lived database passwords and API tokens
- **Audit compliance:** Full audit log of who accessed what and when
- **Advanced auth:** AppRole, OIDC, Kubernetes, AWS IAM, and more

## Configuration

```toml
[backends.vault-eng]
type            = "vault"
vault_address   = "https://vault.company.com"   # required
vault_namespace = "engineering"                  # optional — Vault Enterprise only
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"vault"` |
| `vault_address` | Yes | Full URL to your Vault instance (e.g., `https://vault.company.com:8200`) |
| `vault_namespace` | No | Vault Enterprise namespace path. Omit for open-source Vault (which rejects the flag) |
| `timeout_secs` | No | Per-instance fetch timeout override. Default: 30s. |

### Multiple Namespaces

```toml
[backends.vault-eng]
type            = "vault"
vault_address   = "https://vault.company.com"
vault_namespace = "engineering"

[backends.vault-payments]
type            = "vault"
vault_address   = "https://vault.company.com"
vault_namespace = "engineering/payments"
```

## URI Format

```
vault-eng://secret/myapp/db_password
└────────┘  └─────┘ └──────────────┘
instance    mount   path within mount
```

For KV v2 mounts, the `vault` CLI automatically injects the `data/` segment — you do **not** include it in the URI. Example: `vault-eng://secret/myapp/db` correctly maps to the KV v2 path `secret/data/myapp/db`.

For version pinning:

```
vault-eng://secret/myapp/db#version=5         # Pin to version 5
vault-eng://secret/myapp/db                   # Default: latest version
```

**Verify your setup with:** `secretenv doctor` — green output means you're ready to run `secretenv run -- <your command>`.

## Authentication

SecretEnv delegates to the `vault` CLI. Any auth method the CLI supports works:

- `VAULT_TOKEN` environment variable (for token auth)
- AppRole: `vault login -method=approle`
- OIDC / JWT: `vault login -method=oidc`
- Kubernetes: `vault login -method=kubernetes`
- AWS IAM: `vault login -method=aws`

Set up your preferred auth method once, then SecretEnv uses it transparently.

## doctor Output

Healthy state:

```
vault-eng                                                       (vault)
  ✓ vault CLI v2.0.0
  ✓ authenticated  addr=https://vault.company.com  namespace=engineering
```

Not authenticated:

```
vault-eng                                                       (vault)
  ✓ vault CLI v2.0.0
  ✗ not authenticated
      → run: vault login  (or set VAULT_TOKEN)
```

## Fragment directives

`#version=<n>` pins a specific KV v2 secret version:

| Directive | Effect | Example |
|---|---|---|
| `#version=5` | Fetch version 5 explicitly | `vault-eng://secret/myapp/db#version=5` |
| (no fragment) | Fetch the latest version | `vault-eng://secret/myapp/db` |

Shorthand fragments and unsupported directives are rejected with a migration hint.

## History API support

Full support via `vault kv metadata get -format=json`. `secretenv registry history <alias>` surfaces all versions with creation timestamp and soft-delete state. Entries appear most-recent-first. Actor (audit log identity) is not available via the metadata API (audit log access requires additional permissions).

## Limitations

- **KV v2 only for history.** `vault kv metadata get` only works on KV v2 mounts. KV v1 mounts have no version history available.
- **Soft-delete vs destroy.** `vault kv delete` soft-deletes (metadata + prior versions survive). Full destruction requires `vault kv destroy` explicitly. This is an operational safeguard.
- **Self-hosted domain trust.** `vault_address` is the trust boundary — see [security.md#self-hosted-domains](../security.md#self-hosted-domains) for the full disclosure discipline.
- **Namespace paths must exist.** Vault Enterprise namespace paths are hierarchical. Parent namespaces must exist before child namespaces can be referenced.

## Examples

### Single Vault instance, OSS

```toml
[backends.vault-default]
type            = "vault"
vault_address   = "https://vault.company.com"

[registries.default]
sources = ["vault-default://secret/myapp/registry"]
```

```bash
secretenv run -- npm start
```

### Enterprise with namespace isolation

```toml
[backends.vault-eng]
type            = "vault"
vault_address   = "https://vault.company.com"
vault_namespace = "engineering"

[backends.vault-finance]
type            = "vault"
vault_address   = "https://vault.company.com"
vault_namespace = "finance"

[registries.eng]
sources = ["vault-eng://secret/registry"]

[registries.finance]
sources = ["vault-finance://secret/registry"]
```

### Version pinning for rotation testing

```bash
secretenv run --registry vault-eng://secret/registry -- ./smoke-tests.sh
```

To pin a specific alias to an older version, set the alias to a versioned URI:

```bash
secretenv registry set db-pass "vault-eng://secret/db#version=3"
```

## Troubleshooting

**"permission denied"**
Check your Vault policy grants `read` on the secret path. Use `vault policy read <policy>` to list your assigned policies.

**"No value found at secret/data/myapp/missing"**
Verify the secret exists and the path is correct. Use `vault kv list secret/myapp` to list secrets at that path.

**"Metadata not supported on KV Version 1"**
History API only works on KV v2 mounts. Check your mount type with `vault secrets list` and specify the correct mount.

## See Also

- [`secretenv doctor`](/reference/cli-reference-full#secretenv-doctor) — health checks for all backends
- [Alias registry concepts](../reference/registry.md) — how registry sources resolve aliases
- [Fragment vocabulary](../reference/fragment-vocabulary.md) — `#version` directive reference
- [Self-hosted domain trust](../security.md#self-hosted-domains) — `vault_address` disclosure discipline
- [OpenBao](openbao.md) — LF MPL fork; near-identical wire protocol and KV semantics
- [All backends](README.md) — pick a different backend
- [Overview](/) — overview + workflows
