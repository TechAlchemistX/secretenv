# SecretEnv vs single-backend wrappers (`op run`, `doppler run`, `infisical run`)

**TL;DR.** `op run` (1Password), `doppler run` (Doppler), `infisical run` (Infisical), and similar single-backend wrappers are **excellent if their backend is your only secrets backend.** They're tightly integrated with the backend's UI, ergonomics, and identity model. SecretEnv is for the case where your team uses two or more — at which point the single-backend wrappers stop helping and start hurting (one wrapper per repo, hardcoded backend URIs, no migration story).

---

## What single-backend wrappers do well

- Native UX — `op://` URIs, `doppler.yaml` config, `infisical secrets get` all feel like part of their parent product
- Tight identity integration — 1Password's biometric unlock, Doppler's fine-grained access tokens, Infisical's machine identities
- First-class web UIs for managing secrets and access
- Vendor support, audit logs, rotation orchestration as a service (where applicable)

If you're 100% on one backend and don't expect that to change, the matching wrapper is probably the right answer.

---

## Where they fall short for multi-backend teams

The fundamental constraint: **single-backend wrappers assume they are the only wrapper.** When you have AWS SSM for infra credentials AND 1Password for team secrets AND Vault for service tokens, you need either:

- Three different wrappers, manually composed in shell scripts per repo
- A homegrown orchestration layer
- A multi-backend tool (SecretEnv, fnox, Pulumi ESC)

| Property | `op run` (and similar) | SecretEnv |
|---|---|---|
| Multi-backend in one invocation | No (single backend) | Yes (15 backends, parallel fetch) |
| URIs in repo | `op://vault/item/field` (or `dp.` env vars) | `secretenv://alias-name` (no backend info) |
| Migrating from this backend to another | Touch every repo that uses the wrapper | One `registry set` |
| Multi-account in one workflow | Limited (depends on wrapper) | Native — name backend instances per account |
| CI/CD pattern | Wrapper-specific | One pattern (`SECRETENV_REGISTRY` env var) for all backends |

---

## What SecretEnv loses by being multi-backend

Honest:

- **No backend-specific UX polish.** SecretEnv talks to `op` / `doppler` / `infisical` via their CLIs; it doesn't add anything 1Password's browser extension or Doppler's web UI provide.
- **No vendor support.** If something breaks at the wrapper level, you're on community channels, not 1Password Support.
- **Generic error messages.** `op` knows what an "invalid item reference" is; SecretEnv mostly surfaces what the wrapped CLI says.

If your only backend is 1Password and you love `op` — keep using `op run`. SecretEnv doesn't make you switch.

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
