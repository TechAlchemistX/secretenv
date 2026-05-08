# SecretEnv vs Vault Enterprise / CyberArk Conjur (identity platforms)

**TL;DR.** HashiCorp Vault Enterprise and CyberArk Conjur are full **identity platforms** — they provide policy engines, dynamic secrets, lease management, certificate authorities, RBAC, multi-tenancy, audit logs, HSM integration, and more. SecretEnv runs **on top of** either of them as one of many backends. They're not competitors; they're a category SecretEnv routes to.

---

## What Vault Enterprise / Conjur do

These are **secrets-and-identity platforms** with capabilities far beyond what a CLI orchestration tool covers:

- **Policy engines** — fine-grained ACLs, Sentinel (Vault) or Conjur policy language
- **Dynamic secrets** — short-lived database credentials, AWS STS tokens, SSH certs generated on demand
- **Lease management** — automatic renewal and revocation cycles
- **Audit logs** — tamper-evident, hash-chained records of every access
- **Multi-tenancy** — namespaces (Vault), accounts (Conjur)
- **HSM integration** — root key sealed in hardware
- **PKI / Certificate authority** — issue and rotate certs
- **Transit encryption** — encryption-as-a-service for app-managed data
- **Vendor support** — enterprise SLAs, professional services

If you need any of the above, you need Vault Enterprise or Conjur. SecretEnv does not replace them.

---

## How SecretEnv coexists

SecretEnv has `vault` and `conjur` backends. They're CLI wrappers — `vault kv get` and `conjur variable get` under the hood. SecretEnv treats Vault/Conjur as one of 15 backends it can fetch from.

A typical multi-backend org:

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

The registry itself can live in Vault (or anywhere). Aliases route to Vault for some secrets, AWS SSM for others, 1Password for others. SecretEnv handles the orchestration; Vault handles its own piece.

---

## Comparison

| Property | Vault Enterprise / Conjur | SecretEnv |
|---|---|---|
| Multi-backend orchestration across heterogeneous sources | ✗ (Vault IS the source) | ✓ |
| Policy engine | ✓ (Sentinel / Conjur policy) | ✗ (delegate to backend ACLs) |
| Dynamic secrets / lease management | ✓ | ✗ |
| Audit log | ✓ (hash-chained) | ✗ (delegate to backend logs) |
| HSM integration | ✓ | ✗ |
| PKI / Certificate authority | ✓ | ✗ |
| Centrally-shared mutable alias registry | ✗ | ✓ |
| Backend migration (cross-tool) | ✗ (Vault is the only backend) | ✓ |
| Local-dev ergonomics | Heavy (Vault server + auth + policy) | Lightweight (CLI only) |
| Cost | Enterprise license | Free (AGPL) |

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
- Vault is your primary identity platform AND you also use AWS SSM, 1Password, or others — SecretEnv routes across all of them; Vault remains the policy / lease authority for what lives in Vault.
