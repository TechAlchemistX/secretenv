# SecretEnv vs Vault Enterprise / CyberArk Conjur (identity platforms)

**TL;DR.** Vault Enterprise and CyberArk Conjur are **identity platforms** with policy engines, dynamic secrets, lease management, CAs, RBAC, audit logs, HSM integration. SecretEnv runs **on top of** them as one of 15 backends. Not competitors; a category SecretEnv routes to.

---

## What Vault Enterprise / Conjur do

**Secrets-and-identity platforms** with capabilities a CLI orchestration tool doesn't:

- **Policy engines**: Sentinel (Vault) or Conjur policy language
- **Dynamic secrets**: short-lived DB creds, STS tokens, SSH certs on demand
- **Lease management**: automatic renewal and revocation
- **Audit logs**: tamper-evident, hash-chained
- **Multi-tenancy**: namespaces (Vault), accounts (Conjur)
- **HSM integration**: hardware-sealed root keys
- **PKI / Certificate authority**: issue and rotate certs
- **Transit encryption**: encryption-as-a-service
- **Vendor support**: enterprise SLAs, professional services

SecretEnv does not replace these capabilities.

---

## How SecretEnv coexists

SecretEnv has `vault` and `conjur` backends (`vault kv get`, `conjur variable get` under the hood). SecretEnv treats Vault/Conjur as one of 15 backends.

Example multi-backend org:

```toml
# ~/.config/secretenv/config.toml

[backends.vault-prod]
type = "vault"
vault_address = "https://vault.acme.com"

[backends.aws-ssm-platform]
type = "aws-ssm"
aws_region = "us-east-2"

[backends.1password-work]
type = "1password"
op_account = "acme.1password.com"

[registries.default]
sources = ["vault-prod://secret/secretenv/registry"]
```

The registry can live in Vault (or anywhere). Aliases route to Vault, AWS SSM, 1Password selectively. SecretEnv orchestrates; Vault handles policy and lease management.

---

## Comparison

| Property | SecretEnv | Vault Enterprise / Conjur |
|---|---|---|
| Multi-backend orchestration across heterogeneous sources | ✓ | ✗ (Vault IS the source) |
| Policy engine | ✗ (delegate to backend ACLs) | ✓ (Sentinel / Conjur policy) |
| Dynamic secrets / lease management | ✗ | ✓ |
| Audit log | ✗ (delegate to backend logs) | ✓ (hash-chained) |
| HSM integration | ✗ | ✓ |
| PKI / Certificate authority | ✗ | ✓ |
| Centrally-shared mutable alias registry | ✓ | ✗ |
| Backend migration (cross-tool) | ✓ | ✗ (Vault is the only backend) |
| Local-dev ergonomics | Lightweight (CLI only) | Heavy (Vault server + auth + policy) |
| Cost | Free (AGPL) | Enterprise license |

---

## When to pick which

**Pick Vault Enterprise / Conjur if:**
- You need policy-as-code with rich evaluation (Sentinel, Conjur policy)
- You need dynamic secrets (short-lived DB creds, STS tokens)
- You need an enterprise-grade audit log
- You need HSM-rooted key management
- You're consolidating onto a single identity platform

**Pick SecretEnv if:**
- You have multiple backends already and need orchestration across them
- You want a lightweight CLI for dev + CI workflows
- You don't need (or already have separately) policy engines and audit infrastructure

**Run both if:**
- Vault is your primary identity platform AND you also use AWS SSM, 1Password, or others. SecretEnv routes across all of them; Vault remains the policy / lease authority for what lives in Vault.
