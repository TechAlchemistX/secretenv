# Cascade: Local → Vault

Two-source registry. Local TOML checked first, Vault fallback. Lets devs override production aliases locally (e.g. `db-url` → localhost) without editing the team registry.

## When to use

- All devs share a baseline, but individuals need 2-3 local overrides
- New engineers get Vault access day one; local overrides come later
- Team already runs Vault

## Precedence

```
1. local registry (source 0)   ← dev overrides, first match wins
2. Vault registry (source 1)   ← team baseline
```

If `db-url` exists in source 0, source 1 is not consulted for that
alias. If `stripe-key` only exists in source 1, source 1 resolves it.

## Files

- `config.toml`: cascading `dev` registry with local + Vault sources
- `secretenv.toml`: project manifest
- `local-registry/registry.toml`: personal overrides (gitignored in real use)

## Running

```sh
# Prereqs: vault CLI + VAULT_ADDR + VAULT_TOKEN
vault status       # sealed=false
secretenv --config examples/cascade-local-then-vault/config.toml doctor

# Run with cascade:
cd examples/cascade-local-then-vault
secretenv run --registry dev -- npm start
```

## Why cascade over two registries?

You can use `--registry local` and `--registry team` separately. Cascade shines for a single invocation (`secretenv run --registry dev`) that works identically on every laptop with per-laptop overrides invisible to users.
