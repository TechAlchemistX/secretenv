# 1Password

**Type:** `1password`  
**CLI required:** `op` (1Password CLI v2)  
**URI scheme:** `<instance-name>://vault/item/field`

---

## Configuration

```toml
[backends."1password-work"]
type       = "1password"            # required
op_account = "company.1password.com"  # optional — omit for single-account setups
```

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `"1password"` |
| `op_account` | No | Account domain. Required when multiple 1Password accounts are signed in |

### Multiple Accounts

```toml
[backends."1password-work"]
type       = "1password"
op_account = "company.1password.com"

[backends."1password-personal"]
type       = "1password"
op_account = "personal.1password.com"
```

---

## URI Format

```
1password-work://payments/stripe/api_key
└─────────────┘  └──────┘ └─────┘ └───────┘
instance name    vault    item    field
```

Fields map to the field labels in a 1Password item. For Login items, common fields are `username`, `password`. For API Credential items, use the field label you've configured.

---

## Authentication

**Local development:** Interactive biometric authentication via the 1Password desktop app. The `op` CLI communicates with the app over a local socket. No token management required.

**CI/CD:** Use a service account token. This is 1Password's official mechanism for non-interactive environments:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

Service accounts are created in the 1Password admin console. Scope them to specific vaults — don't grant access to all vaults for CI credentials.

---

## doctor Output

```
1password-work                                               (1password)
  ✓ op CLI v2.24.0
  ✓ authenticated  account=company.1password.com
```

```
1password-work                                               (1password)
  ✓ op CLI v2.24.0
  ✗ not authenticated
      → open 1Password app and sign in, or set OP_SERVICE_ACCOUNT_TOKEN for CI
```
