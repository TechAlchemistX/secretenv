# Configuration Reference

secretenv uses two configuration files with completely separate responsibilities.

| File | Location | Committed to git | Purpose |
|---|---|---|---|
| `secretenv.toml` | Repo root | Yes | What secrets this project needs |
| `config.toml` | `~/.config/secretenv/` | Never | Where secrets live, how to reach them |

---

## `secretenv.toml` — Project Manifest

### Rules

1. Only two value types: `from` and `default`. No exceptions.
2. No backend URIs. Only `secretenv://` aliases or static defaults.
3. No environment blocks. One `[secrets]` block only.
4. Safe to commit. Contains zero infrastructure information.

### Format

```toml
# secretenv.toml
# Committed to git. Contains no secrets, no paths, no environment logic.

[secrets]
# Alias lookup — resolved via registry at runtime
STRIPE_KEY      = { from = "secretenv://stripe-key" }
DATABASE_URL    = { from = "secretenv://db-url" }
DATADOG_API_KEY = { from = "secretenv://datadog-api-key" }
REDIS_URL       = { from = "secretenv://redis-url" }
VAULT_TOKEN     = { from = "secretenv://vault-token" }

# Static default — injected directly, no backend involved
LOG_LEVEL       = { default = "info" }
APP_ENV         = { default = "development" }
```

### Value Types

| Type | Syntax | Behavior |
|---|---|---|
| Alias lookup | `{ from = "secretenv://alias-name" }` | Resolves alias via active registry, fetches from named backend |
| Static default | `{ default = "value" }` | Injected as-is, no registry or backend involved |
| Direct backend URI | `{ from = "aws-ssm://..." }` | **Hard error. Prohibited without exception.** |

### What This File Does Not Do

- Does not know which environment is active
- Does not know which AWS account or region holds a secret
- Does not know which registry to read from
- Does not know what any alias resolves to

An attacker reading this file learns what secrets the project needs. Nothing about where they live.

---

## `config.toml` — Machine Configuration

### Location

```
~/.config/secretenv/config.toml
```

Follows XDG convention. One file per machine. Written by `secretenv setup`, pre-populated by a distribution profile, or created manually.

### Structure

Two top-level sections:

- `[registries]` — named registry configurations with cascading sources
- `[backends]` — named backend instances with credential configuration

---

## `[registries]`

### Behavior

- `[registries.default]` is optional. If absent and no `--registry` flag or `SECRETENV_REGISTRY` is set, secretenv errors hard.
- Each registry has a `sources` array. Sources cascade — first match wins.
- Cascading is intentional. Earlier sources shadow later ones.
- Missing registry name → hard error. No silent fallback to default.

### Format

```toml
# Optional default registry
[registries.default]
sources = [
  "aws-ssm-platform:///secretenv/org-registry",
]

# Named registries — activated via --registry <name>
[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",       # team aliases, checked first
  "aws-ssm-platform:///secretenv/org-registry",  # org-wide fallback
]

[registries.int]
sources = [
  "aws-ssm-int:///secretenv/int-registry",
  "aws-ssm-platform:///secretenv/org-registry",
]

[registries.local]
sources = [
  "local:///Users/yourname/.config/secretenv/local-registry.toml",
]
```

### Source URI Format

Every value in `sources` is a backend URI using the named instance as the scheme:

```
aws-ssm-platform:///secretenv/org-registry
└─────────────┘   └─────────────────────┘
named instance     path to registry document
(defined in        within that backend
[backends.*])
```

---

## `[backends]`

### Named Instances

A backend instance is a named configuration of a backend type. The instance name becomes the URI scheme used in registry documents and `sources` arrays.

Multiple instances of the same type are normal:

```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_profile = "dev"
aws_region  = "us-east-1"

[backends.aws-ssm-prod]
type        = "aws-ssm"
aws_profile = "prod"
aws_region  = "us-east-1"
```

One plugin. Two instances. Two credential sets. No new code.

### Backend Types and Fields

**`aws-ssm` — AWS SSM Parameter Store**
```toml
[backends.aws-ssm-dev]
type        = "aws-ssm"          # required
aws_profile = "dev"              # optional — omit to use ambient credentials
aws_region  = "us-east-1"       # required
```

**`aws-secrets` — AWS Secrets Manager**
```toml
[backends.aws-secrets-prod]
type        = "aws-secrets"
aws_profile = "prod"
aws_region  = "us-east-1"
```

**`1password` — 1Password**
```toml
[backends."1password-work"]
type       = "1password"
op_account = "company.1password.com"   # optional — omit for single-account setups
```

**`vault` — HashiCorp Vault**
```toml
[backends.vault-eng]
type              = "vault"
vault_address     = "https://vault.company.com"   # required
vault_namespace   = "engineering"                  # optional — Vault Enterprise only
```

**`gcp` — GCP Secret Manager**
```toml
[backends.gcp-prod]
type        = "gcp"
gcp_project = "my-project-prod"   # required
```

**`azure` — Azure Key Vault**
```toml
[backends.azure-prod]
type           = "azure"
azure_vault    = "my-keyvault"    # required
```

**`keeper` — Keeper**
```toml
[backends.keeper-work]
type = "keeper"
```

**`keychain` — macOS Keychain / Linux Secret Service**
```toml
[backends.keychain]
type = "keychain"
```

**`local` — Local file (zero infrastructure)**
```toml
[backends.local]
type = "local"
# no credentials required
```

---

## Full Example

```toml
# ~/.config/secretenv/config.toml

# ── Registries ──────────────────────────────────────────────────────────────

[registries.default]
sources = [
  "aws-ssm-platform:///secretenv/org-registry",
]

[registries.dev]
sources = [
  "aws-ssm-dev:///secretenv/dev-registry",
  "aws-ssm-platform:///secretenv/org-registry",
]

[registries.int]
sources = [
  "aws-ssm-int:///secretenv/int-registry",
  "aws-ssm-platform:///secretenv/org-registry",
]

# ── Backends ─────────────────────────────────────────────────────────────────

[backends.aws-ssm-platform]
type        = "aws-ssm"
aws_profile = "platform"
aws_region  = "us-east-2"

[backends.aws-ssm-dev]
type        = "aws-ssm"
aws_profile = "dev"
aws_region  = "us-east-1"

[backends.aws-ssm-int]
type        = "aws-ssm"
aws_profile = "int"
aws_region  = "us-east-1"

[backends."1password-work"]
type       = "1password"
op_account = "company.1password.com"

[backends.vault-eng]
type            = "vault"
vault_address   = "https://vault.company.com"
vault_namespace = "engineering"
```

---

## Registry Selection Precedence

```
1. --registry <name-or-uri>          ← explicit per-invocation
2. SECRETENV_REGISTRY=<name-or-uri>  ← CI / shell-session override
3. [registries.default] in config    ← machine default
4. hard error                        ← no assumption made
```

### Name vs URI Disambiguation

The `--registry` flag and `SECRETENV_REGISTRY` variable accept either a registry name or a direct URI. The rule is structural:

- Contains `://` → treat as direct URI (single source, no cascade)
- No `://` → treat as registry name, look up `[registries.<n>]`

TOML keys cannot contain `://`, so a registry name can never be mistaken for a URI.

---

## Error Reference

| Condition | Error |
|---|---|
| `--registry foo` but no `[registries.foo]` | `error: no registry named 'foo' in config` |
| No registry configured anywhere | `error: no registry configured — use --registry <name-or-uri> or set SECRETENV_REGISTRY` |
| Alias not found in cascade | `error: alias 'stripe-key' not found in registry 'dev' (checked 2 sources)` |
| Unknown backend instance in URI | `error: unknown backend 'aws-ssm-dev' — is it defined in config.toml?` |
| Backend fetch fails | `error: failed to fetch 'aws-ssm-dev:///myapp/dev/stripe' (alias: stripe-key): <backend error>` |
| Direct backend URI in secretenv.toml | `error: direct backend URIs are not allowed in secretenv.toml — use a secretenv:// alias` |
