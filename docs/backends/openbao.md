# OpenBao

**Type:** `openbao`
**CLI required:** `bao`
**URI scheme:** `<instance-name>://mount/path/to/secret[#json-key=<field>]`

OpenBao is the [Linux Foundation MPL-2.0 fork of HashiCorp Vault](https://openbao.org/). The wire protocol, KV semantics, and auth methods are identical to Vault — the SecretEnv `openbao` backend is a near-clone of [`vault`](./vault.md) with three concrete differences: binary name, env-var prefix, and install path.

If you are already using the SecretEnv Vault backend, the migration is a one-line config swap and a rerun of `bao login`.

---

## Install

OpenBao is in homebrew-core — no tap dance, no BSL gymnastics:

```bash
brew install openbao
```

For Linux / Windows / manual binaries, see <https://openbao.org/docs/install/>.

> **Vault contrast:** HashiCorp Vault moved out of homebrew-core after the August 2023 BSL relicense, so its install path is the longer `brew tap hashicorp/tap && brew install hashicorp/tap/vault`. OpenBao avoids this entirely.

---

## Configuration

```toml
[backends.openbao-dev]
type        = "openbao"
bao_address = "http://127.0.0.1:8300"     # required
bao_namespace = "team-engineering"         # optional
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"openbao"` |
| `bao_address` | Yes | Full URL of the OpenBao instance. Set per-instance even though the `bao` CLI itself reads `BAO_ADDR` — the registry document must deterministically point at the same cluster regardless of operator shell state. |
| `bao_namespace` | No | OpenBao namespace (a free OSS feature in OpenBao 2.x, unlike Vault's Enterprise gating). Omit if not in use; the backend will not pass `-namespace` to the CLI. |
| `bao_bin` | No | Override the `bao` binary path. Defaults to `"bao"` (resolved via `$PATH`). Primarily a test hook. |
| `bao_unsafe_set` | No | Defense-in-depth opt-in for an argv-based `set` path. v0.10 always uses the `value=-` stdin form, so this flag is reserved for forward-compatibility — leave at the default `false`. |
| `timeout_secs` | No | Per-instance fetch timeout in seconds. Defaults to 30. |

### `BAO_ADDR` HTTP/HTTPS gotcha

The single most common first-use stumble: the `bao` CLI defaults to `https://127.0.0.1:8200`, but `bao server -dev` listens on **HTTP**. Mismatched schemes yield `Error reading secret: http: server gave HTTP response to HTTPS client` from the CLI.

Always set `bao_address` explicitly (including the scheme):

```toml
bao_address = "http://127.0.0.1:8300"   # dev mode
bao_address = "https://bao.company.com" # production
```

The factory rejects a missing `bao_address` to keep the registry document portable across operator shells.

### Multiple OpenBao instances or namespaces

```toml
[backends.bao-eng]
type          = "openbao"
bao_address   = "https://bao.company.com"
bao_namespace = "engineering"

[backends.bao-payments]
type          = "openbao"
bao_address   = "https://bao.company.com"
bao_namespace = "engineering/payments"
```

---

## URI Format

```
openbao-dev://secret/myapp/db_password
└─────────┘  └─────┘ └──────────────┘
 instance    mount   path within mount
```

The unified `bao kv` CLI handles KV v1 and v2 transparently — SecretEnv does not inject `data/` itself.

### `#json-key=<field>` fragment

When a single secret holds multiple values encoded as a JSON object in the canonical `value` field, the `#json-key=<field>` fragment selects one top-level scalar:

```toml
[registries.default.aliases]
db_password = "openbao-dev://secret/prod/db_creds#json-key=password"
db_username = "openbao-dev://secret/prod/db_creds#json-key=username"
```

Provision side:

```bash
echo -n '{"username":"app","password":"sk_live_abc"}' \
  | bao kv put secret/prod/db_creds value=-
```

The fragment is recognized only on `get`. `set`, `delete`, `list`, and `history` reject any fragment.

---

## Storage model

This backend writes every secret to the single `value` field of a KV v2 entry (`bao kv put <path> value=-` from stdin). Multi-field secrets are not produced — if you have an existing multi-field secret written out-of-band, only the `value` field is read.

Registry documents are stored as a JSON alias→URI map serialized to a string in the `value` field, matching the [`aws-secrets`](./aws-secrets.md) and [`aws-ssm`](./aws-ssm.md) shape. `secretenv registry set` produces this layout automatically.

---

## Authentication

SecretEnv delegates to the `bao` CLI. Any auth method the CLI supports works:

- `BAO_TOKEN` environment variable (the CLI also accepts `VAULT_TOKEN` for transition compatibility)
- `bao login` → token persisted at `~/.vault-token` (the filename is intentionally retained for transition compat from Vault)
- AppRole (`bao login -method=approle`)
- OIDC / JWT (`bao login -method=oidc`)
- Kubernetes (`bao login -method=kubernetes`)
- AWS IAM (`bao login -method=aws`)

The minimum policy a SecretEnv user needs is identical to Vault's — OpenBao consumes Vault HCL policies unchanged:

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
```

`set` additionally needs `update`/`create`. `delete` needs `delete`.

---

## doctor Output

```
openbao-dev                                                  (openbao)
  ✓ bao CLI OpenBao v2.5.3
  ✓ authenticated  addr=http://127.0.0.1:8300  namespace=(none)
```

```
openbao-dev                                                  (openbao)
  ✓ bao CLI OpenBao v2.5.3
  ✗ not authenticated — token expired
      → run: bao login  (or set BAO_TOKEN, or place a token in ~/.vault-token)
```

```
openbao-dev                                                  (openbao)
  ✗ bao CLI not found
      → install: brew install openbao  OR  https://openbao.org/docs/install/
```

---

## License note

OpenBao is MPL-2.0 (Linux Foundation, post-fork). HashiCorp Vault is BSL post-2023. Both ship the same wire protocol, but OpenBao is the open-source-first option for users who want the CNCF / Linux Foundation governance trajectory. SecretEnv treats the two backends peer-equal at the trait layer — switch by changing one config line.
