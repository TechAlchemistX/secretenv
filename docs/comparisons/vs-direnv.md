# SecretEnv vs `direnv`

**TL;DR.** [direnv](https://direnv.net/) is a shell hook for per-directory env vars on `cd`. **Not a secrets tool.** Backend integration is manual per `.envrc`, no standard schema. SecretEnv solves secrets orchestration direnv wasn't designed for.

---

## Where direnv shines

- Non-secret env vars per project (`PYTHONPATH`, `NODE_ENV`, `RUST_LOG=debug`)
- Auto-activating shell environments (venvs, version pins, direnv-flake)
- Layered composition (`.envrc.local`, `.envrc.private`)
- Shell-native UX, no invocation prefix

Use direnv if you don't have secrets.

---

## Where direnv falls short for secrets

| Property | SecretEnv | direnv |
|---|---|---|
| Backend integration | Native: 15 backends, declarative `secretenv.toml` | Manual scripting per `.envrc` (custom shell functions calling `aws`, `op`, `vault`, ...) |
| What's in the repo | `secretenv.toml` with alias names only | `.envrc` with backend paths + custom shell glue |
| Standard for "what this project needs" | `secretenv.toml` schema | None; every `.envrc` is a snowflake |
| Multi-environment routing | `--registry dev` / `--registry prod` | Edit `.envrc` per checkout / per branch / via if-statements |
| Backend migration | One `registry set` | Edit every `.envrc` |
| Onboarding | `secretenv profile install <org>` | "Read the README, install these CLIs, source this script, hope" |
| Offboarding | Revoke registry-backend access | Manual per-backend per-developer |

---

## They're complementary

```bash
# .envrc, non-secret env only
use flake
export PYTHONPATH="$PWD/src"
```

```bash
# Run with both:
direnv allow
secretenv run -- pytest
```

direnv auto-loads non-secrets on `cd`. SecretEnv injects secrets at execution. Two responsibilities, one flow.

---

## When to pick which

**Pick direnv (alone) if:**
- Your project has no secrets
- You want shell-native auto-activation without a runtime prefix

**Pick SecretEnv (alone) if:**
- You want one tool for the whole job, no per-directory shell hooks
- You want CI parity (same `secretenv run --` on laptop and in CI)

**Pick both if:**
- You want direnv's shell ergonomics + SecretEnv's secrets orchestration (most common)
