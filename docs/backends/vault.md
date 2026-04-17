# HashiCorp Vault

**Type:** `vault`  
**CLI required:** `vault`  
**URI scheme:** `<instance-name>://mount/path/to/secret`

---

## Configuration

```toml
[backends.vault-eng]
type              = "vault"
vault_address     = "https://vault.company.com"   # required
vault_namespace   = "engineering"                  # optional — Vault Enterprise only
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"vault"` |
| `vault_address` | Yes | Full URL to your Vault instance |
| `vault_namespace` | No | Vault Enterprise namespace. Omit for open source Vault. |

### Multiple Vault Instances or Namespaces

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

---

## URI Format

```
vault-eng://secret/myapp/db_password
└────────┘  └─────┘ └──────────────┘
instance    mount   path within mount
```

For KV v2, secretenv reads from the `data/` path automatically. You do not need to include `data/` in the URI.

---

## Authentication

secretenv delegates to the `vault` CLI. Any auth method the CLI supports works:

- `VAULT_TOKEN` environment variable
- AppRole (`vault login -method=approle`)
- OIDC / JWT (`vault login -method=oidc`)
- Kubernetes (`vault login -method=kubernetes`)
- AWS IAM (`vault login -method=aws`)

---

## doctor Output

```
vault-eng                                                       (vault)
  ✓ vault CLI v1.15.2
  ✓ authenticated  addr=https://vault.company.com  namespace=engineering
```

```
vault-eng                                                       (vault)
  ✓ vault CLI v1.15.2
  ✗ not authenticated — VAULT_TOKEN not set or expired
      → run: vault login
```
