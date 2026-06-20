# SecretEnv vs single-backend wrappers (`op run`, `doppler run`, `infisical run`)

**TL;DR.** `op run`, `doppler run`, `infisical run`, and similar single-backend wrappers are excellent if that backend is your only source. SecretEnv is for teams with 2+ backends, at which point single-backend wrappers create friction (one wrapper per repo, hardcoded URIs, no migration path).

---

## What single-backend wrappers do well

- Native UX (`op://` URIs, `doppler.yaml` config) integrated with the parent product
- Tight identity integration (biometric unlock, fine-grained tokens, machine identities)
- Web UIs for secret management
- Vendor support, audit logs, rotation orchestration

If you're 100% on one backend with no migration expected, the matching wrapper is the right answer.

---

## Where they fall short for multi-backend teams

The fundamental constraint: **single-backend wrappers assume they are the only wrapper.** When you have AWS SSM for infra, 1Password for team secrets, and Vault for service tokens, you need either:

- Three wrappers, manually composed per repo
- A homegrown orchestration layer
- A multi-backend tool (SecretEnv, fnox, Pulumi ESC)

| Property | SecretEnv | `op run` (and similar) |
|---|---|---|
| Multi-backend in one invocation | Yes (15 backends, parallel fetch) | No (single backend) |
| URIs in repo | `secretenv://alias-name` (no backend info) | `op://vault/item/field` (or `dp.` env vars) |
| Migrating from this backend to another | One `registry set` | Touch every repo that uses the wrapper |
| Multi-account in one workflow | Native: name backend instances per account | Limited (depends on wrapper) |
| CI/CD pattern | One pattern (`SECRETENV_REGISTRY` env var) for all backends | Wrapper-specific |

---

## What SecretEnv loses by being multi-backend

- **No backend-specific UX polish.** SecretEnv wraps CLIs; it doesn't add anything 1Password's browser extension or Doppler's web UI provide.
- **No vendor support.** Breaks go to community channels, not 1Password Support.
- **Generic error messages.** SecretEnv surfaces what the wrapped CLI says.

If your only backend is 1Password and you love `op run`, keep using it. SecretEnv is not a replacement.

---

## When to pick which

**Pick `op run` / `doppler run` / `infisical run` if:**
- You're committed to a single backend long-term
- You value the parent product's UI, support, and ergonomics over multi-backend flexibility
- Your team and CI all standardize on the same backend

**Pick SecretEnv if:**
- You have 2+ backends already (or expect to)
- You want one CI/CD pattern across all of them
- You want backend migration to be cheap (one registry set vs touching every repo)
- You want repos to contain alias names, not provider URIs
