# Registry Management

The alias registry is the document that maps human-readable alias names to fully-qualified backend URIs. It is the single source of truth for where every secret lives.

---

## What the Registry Is

A flat key-value TOML document stored in any backend you control:

```toml
# stored at aws-ssm-platform:///secretenv/registry

stripe-key      = "1password-work://payments/stripe/api_key"
db-url          = "aws-ssm-dev:///myapp/dev/db_url"
datadog-api-key = "1password-work://engineering/datadog/api_key"
redis-url       = "aws-ssm-dev:///myapp/dev/redis_url"
vault-token     = "vault-eng://secret/myapp/vault_token"
```

Keys are alias names. Values are backend URIs using named instances as the scheme.

---

## Cascading Registries

A registry configuration can cascade across multiple source documents. Sources are checked in order — first match wins. Entries in later sources that share a key with an earlier source are silently shadowed.

```toml
# config.toml

[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",       # team-specific, checked first
  "aws-ssm-platform:///secretenv/org-registry",  # org-wide fallback
]
```

Use cases for cascading:
- Team-specific aliases that override org-wide defaults
- Per-environment aliases alongside shared infrastructure aliases
- Gradual migration from one registry to another

---

## CLI Commands

All registry commands accept `--registry <name-or-uri>` to target a specific registry. Without it, the active registry (from `--registry` flag, `SECRETENV_REGISTRY`, or `[registries.default]`) is used.

### `registry list`

Shows all aliases across all sources in the active registry, with provenance and shadowing clearly marked.

```bash
secretenv registry list
secretenv registry list --registry dev
```

```
Registry: dev  (2 sources)
─────────────────────────────────────────────────────────────────────

aws-ssm-dev:///secretenv/dev-registry                    [source 1]
┌─────────────────────────────────────────────────────────────────┐
│  stripe-key       →  aws-ssm-dev:///myapp/dev/stripe_key       │
│  db-url           →  aws-ssm-dev:///myapp/dev/db_url           │
│  redis-url        →  aws-ssm-dev:///myapp/dev/redis_url        │
└─────────────────────────────────────────────────────────────────┘

aws-ssm-platform:///secretenv/org-registry               [source 2]
┌─────────────────────────────────────────────────────────────────┐
│  stripe-key       →  1password-work://payments/stripe   ↑ shadowed by source 1
│  datadog-api-key  →  1password-work://engineering/datadog       │
│  vault-token      →  vault-eng://secret/myapp/vault_token       │
└─────────────────────────────────────────────────────────────────┘

Resolved aliases: 5  (1 shadowed)
```

### `registry get`

Shows what a single alias resolves to, including which source it came from and what it shadows.

```bash
secretenv registry get stripe-key
secretenv registry get stripe-key --registry dev
```

```
stripe-key
  resolved by:  aws-ssm-dev:///secretenv/dev-registry  [source 1]
  points to:    aws-ssm-dev:///myapp/dev/stripe_key
  shadowing:    1password-work://payments/stripe  (source 2)
```

### `registry set`

Writes an alias to the registry. Always writes to source[0] of the active registry.

```bash
secretenv registry set stripe-key "1password-work://payments/stripe/api_key"
secretenv registry set db-url "aws-ssm-prod:///myapp/prod/db_url" --registry prod
```

```
✓ Written to source 1: aws-ssm-dev:///secretenv/dev-registry
  stripe-key  →  1password-work://payments/stripe/api_key
```

To write to a specific source, pass a direct URI:

```bash
secretenv registry set stripe-key "..." \
  --registry aws-ssm-platform:///secretenv/org-registry
```

**Validation:** the value must be a valid backend URI (contains `://` with a recognized scheme). Hard error otherwise.

### `registry unset`

Removes an alias from source[0] of the active registry.

```bash
secretenv registry unset old-deprecated-key
secretenv registry unset old-key --registry dev
```

```
✓ Removed from aws-ssm-dev:///secretenv/dev-registry
  old-key  (was → aws-ssm-dev:///myapp/dev/old_key)
```

If the alias only exists in a downstream source, secretenv warns rather than silently doing nothing:

```
⚠ 'datadog-api-key' not found in source 1 (aws-ssm-dev:///secretenv/dev-registry)
  found in source 2 (aws-ssm-platform:///secretenv/org-registry)
  to remove from source 2, pass it explicitly:
  secretenv registry unset datadog-api-key \
    --registry aws-ssm-platform:///secretenv/org-registry
```

### `registry history`

Shows version history of the registry document where the backend supports it.

```bash
secretenv registry history
secretenv registry history --registry prod
```

```
aws-ssm-platform:///secretenv/org-registry

  v4  2026-04-10  stripe-key updated  →  vault-eng://secret/payments/stripe
  v3  2026-03-20  db-url added
  v2  2026-03-15  datadog-api-key added
  v1  2026-03-01  registry created
```

Backend support:

| Backend | History support |
|---|---|
| AWS SSM SecureString | ✓ Parameter versions via SSM API |
| HashiCorp Vault KV v2 | ✓ Native versioning |
| 1Password | ✓ Item revision history |
| AWS Secrets Manager | ✓ Secret versions |
| Local file | ✗ No history |

### `registry invite`

Generates the onboarding command for a new team member based on the active registry configuration.

```bash
secretenv registry invite
```

```
Share this with new team members:

secretenv setup aws-ssm-platform:///secretenv/org-registry

Or with a distribution profile (pre-configures all backends and registries):
curl -sfS https://secretenv.dev/install.sh | sh -s -- --profile acme-corp
```

---

## Writing the Registry Document Manually

For teams managing infrastructure as code, the registry document can be managed via Terraform or any tool that can write to a backend. secretenv does not require using the CLI to manage registry content — it only needs to be able to read the document at runtime.

The registry document format is a flat TOML key-value structure:

```toml
alias-name = "backend-instance://path/to/secret"
```

Via Terraform (AWS SSM):

```hcl
resource "aws_ssm_parameter" "secretenv_registry" {
  name  = "/secretenv/org-registry"
  type  = "SecureString"   # always SecureString, never String
  value = jsonencode({
    "stripe-key"      = "1password-work://payments/stripe/api_key"
    "db-url"          = "aws-ssm-prod:///myapp/prod/db_url"
    "datadog-api-key" = "1password-work://engineering/datadog/api_key"
  })
}
```

Note: when managing the registry via Terraform, the alias-to-path mappings are in version-controlled Terraform state. This is an operational choice — the alias values (backend paths) are organizational configuration, not secret values, so this tradeoff is similar to managing Kubernetes ExternalSecrets manifests in code.

---

## Registry Access Controls

The registry document maps alias names to backend paths. It does not contain secret values. However its access controls matter.

**Treat the registry's access controls equivalently to your most sensitive secret.**

If an attacker can read the registry, they learn your secrets topology — which backends you use, what paths your secrets live at, your naming conventions. They do not get secret values. But if they already have authenticated access to the registry backend, they likely have broader backend access anyway.

Recommended storage:

| Backend | Recommended configuration |
|---|---|
| AWS SSM | `SecureString` type with KMS encryption. IAM policy: `ssm:GetParameter` scoped to the registry path only, for the identities that need it. |
| HashiCorp Vault | KV v2 with a policy that grants read access to the registry path. Separate policy from application secret access. |
| 1Password | Dedicated vault for secretenv registry. Share only with team leads and platform engineers, not all developers. |
| Local file | `chmod 600`. For solo developers only. |

---

## Alias Naming Conventions

No convention is enforced by secretenv. Recommendations:

- Use kebab-case: `stripe-key`, `prod-db-url`, `datadog-api-key`
- Keep alias names environment-agnostic where possible — route environments via registry selection, not alias naming
- Use consistent naming across services — if multiple services need a shared Datadog key, one alias shared via the org registry is better than `service-a-datadog-key` and `service-b-datadog-key`
- Prefix team-specific aliases if co-existing with an org registry: `payments-stripe-key` vs org-level `stripe-key`
