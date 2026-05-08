# SecretEnv vs `direnv`

**TL;DR.** [direnv](https://direnv.net/) is an excellent shell hook that loads per-directory environment variables when you `cd` into a project. It's the right tool for shell ergonomics and per-project env layering. It is **not a secrets tool** — backend integration is manual scripting per `.envrc`, paths live in the file, and there's no standard for what a project needs or where things live. SecretEnv solves the secrets-orchestration problem direnv was never designed for.

---

## Where direnv shines

- Loading non-secret env vars per project (`PYTHONPATH`, `NODE_ENV`, `RUST_LOG=debug`)
- Auto-activating shell environments (Python venvs, Node version pins, direnv-flake)
- Layered env composition (`.envrc.local`, `.envrc.private`)
- Shell-native UX — no extra invocation prefix needed

If you don't have secrets in your `.envrc`, direnv is great. Use it.

---

## Where direnv falls short for secrets

| Property | direnv | SecretEnv |
|---|---|---|
| Backend integration | Manual scripting per `.envrc` (custom shell functions calling `aws`, `op`, `vault`, ...) | Native — 15 backends, declarative `secretenv.toml` |
| What's in the repo | `.envrc` with backend paths + custom shell glue | `secretenv.toml` with alias names only |
| Standard for "what this project needs" | None — every `.envrc` is a snowflake | `secretenv.toml` schema |
| Multi-environment routing | Edit `.envrc` per checkout / per branch / via if-statements | `--registry dev` / `--registry prod` |
| Backend migration | Edit every `.envrc` | One `registry set` |
| Onboarding | "Read the README, install these CLIs, source this script, hope" | `secretenv profile install <org>` |
| Offboarding | Manual per-backend per-developer | Revoke registry-backend access |

---

## They're complementary

You can run direnv AND SecretEnv together:
- direnv handles non-secret env vars + shell activation per project
- SecretEnv handles the secrets

A common pattern:

```bash
# .envrc
use flake
export PYTHONPATH="$PWD/src"
# secrets are NOT here — they're in secretenv.toml
```

```bash
# Run with both:
direnv allow
secretenv run -- pytest
```

direnv loads the non-secret env on `cd`; SecretEnv injects secrets at the moment of execution. Two tools, two responsibilities.

---

## When to pick which

**Pick direnv (alone) if:**
- Your project has no secrets
- Your "secrets" are non-sensitive dev defaults that genuinely belong in a committed file
- You want shell-native auto-activation and don't want a runtime invocation prefix

**Pick SecretEnv (alone) if:**
- You want one tool for the whole job and don't need per-directory shell hooks
- You want CI parity (`secretenv run --` works the same in CI as on your laptop)
- You don't want to re-invent per-project shell glue for every backend you use

**Pick both if:**
- You want direnv's shell ergonomics + SecretEnv's secrets orchestration
- This is the most common pattern in practice
