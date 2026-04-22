# Cascade: local-first, Vault-fallback

Two-source registry where a local TOML file is checked FIRST and
HashiCorp Vault provides the team-wide fallback. This is the canonical
dev-override pattern: individual developers can override production
aliases with local values (e.g. point `db-url` at their laptop's local
Postgres) without editing the team registry.

## When to use this

- Every developer needs the same base set of aliases, but individuals
  want to override 2-3 per laptop (dev DB, localhost Redis, a personal
  Stripe test key).
- Onboarding flow: a new engineer gets Vault access on day one and
  everything works; they can add local overrides later.
- Team runs a Vault cluster already — no new infrastructure.

## Precedence

```
1. local registry (source 0)   ← dev overrides, first match wins
2. Vault registry (source 1)   ← team baseline
```

If `db-url` exists in source 0, source 1 is not consulted for that
alias. If `stripe-key` only exists in source 1, source 1 resolves it.

## What's in this directory

- `config.toml` — one cascading `dev` registry with local + Vault
  sources, and the two backends.
- `secretenv.toml` — project manifest.
- `local-registry/registry.toml` — personal overrides; gitignored in
  real use.

## Running it

```sh
# Prereqs:
#   vault CLI installed + VAULT_ADDR + VAULT_TOKEN set.
vault status       # should report sealed=false
secretenv --config examples/cascade-local-then-vault/config.toml doctor

# Run with cascade — local first, Vault fallback:
cd examples/cascade-local-then-vault
secretenv run --registry dev -- npm start
```

## Why not just two registries?

You can do that too (`--registry local`, `--registry team`). Cascade
shines when you want ONE invocation line (`secretenv run --registry
dev`) that works identically on every laptop, with per-laptop
overrides invisible to the user.
