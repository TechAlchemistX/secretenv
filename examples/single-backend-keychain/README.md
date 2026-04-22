# Single-backend: macOS Keychain

New in v0.5. Secrets live in the macOS login keychain; the registry
lives in a local TOML file (Keychain can't host a registry — see
[list() limitation](#why-the-registry-is-local-not-keychain)).

## When to use this

- Solo macOS developer who already has keychain muscle memory from
  storing SSH passphrases, API tokens, etc.
- Offline-friendly: no network, no CLI auth setup, no cloud account.
- Items created by Keychain Access.app or `security add-generic-password`
  are ready to use immediately.

## Not for you if

- Team setup: Keychain is per-user, per-machine. Use a cloud backend
  for team secrets.
- Non-macOS: this backend errors cleanly on Linux/Windows. See
  [`single-backend-keychain`](../single-backend-keychain/) pairs with
  distro-specific backends in future releases (e.g. Secret Service for
  Linux in v0.6).

## What's in this directory

- `config.toml` — one `keychain` backend + one `local` backend for the
  registry.
- `secretenv.toml` — project manifest with two aliases.
- `local-registry/registry.toml` — alias-to-URI map pointing at
  Keychain items.

## Creating the items

```sh
# Create the secrets in your login keychain first:
security add-generic-password -s myapp -a stripe-key -w "sk_test_EXAMPLE"
security add-generic-password -s myapp -a database-url -w "postgres://localhost/appdb"

# Confirm with the native CLI:
security find-generic-password -s myapp -a stripe-key -w

# Then with secretenv:
secretenv --config examples/single-backend-keychain/config.toml \
  run -- env | grep -E 'STRIPE_KEY|DATABASE_URL'
```

## Why the registry is local, not Keychain

`security` has no safe list-all-items operation (the closest, `security
dump-keychain`, prompts per item and leaks every credential). SecretEnv
therefore implements Keychain as a `get`-only target — great for
storing values, not for listing aliases. Hence a local TOML registry
pointing at keychain URIs. See
[`docs/backends/keychain.md`](../../docs/backends/keychain.md) for the
full rationale.
