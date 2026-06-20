# Single-backend: macOS Keychain

Secrets in the login keychain; registry in a local TOML file (Keychain can't host a registry).

## When to use

- Solo macOS dev with keychain muscle memory
- Offline-friendly (no network, no auth setup)
- Keychain Access.app or `security` items ready immediately

## Not for you if

- Team setup, Keychain is per-user, per-machine
- Non-macOS, future releases will add distro-specific backends

## Files

- `config.toml`: `keychain` backend + `local` backend for registry
- `secretenv.toml`: project manifest with two aliases
- `local-registry/registry.toml`: alias-to-URI map for Keychain items

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

## Why registry is local

`security` has no safe list-all operation. `security dump-keychain` prompts per item and leaks all credentials. SecretEnv implements Keychain as get-only, great for values, not listing aliases. Hence a local TOML registry pointing at keychain URIs. See [`docs/backends/keychain.md`](../../docs/backends/keychain.md) for details.
