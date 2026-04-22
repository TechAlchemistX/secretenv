# Single-backend: Local file

The simplest possible SecretEnv setup. Registry and secrets both live
in local files on disk. No cloud, no CLIs, no network.

## When to use this

- Trying SecretEnv for the first time with zero account setup.
- Solo project where a single developer controls every secret.
- Offline/air-gapped dev where network backends aren't available.
- Teaching SecretEnv's alias → URI model without distracting backend
  auth concerns.

## What's in this directory

- `config.toml` — machine config declaring one `local` backend instance
  and a default registry that points at `local-registry/registry.toml`.
- `secretenv.toml` — project manifest using two aliases.
- `local-registry/registry.toml` — the alias-to-URI mapping.
- `local-secrets/` — the secret values themselves (one file per value).

## Running it

```sh
# Option A: pass the config explicitly
secretenv --config examples/single-backend-local/config.toml run -- env | grep -E 'API_KEY|DB_URL'

# Option B: symlink or copy config.toml into ~/.config/secretenv/
cp examples/single-backend-local/config.toml ~/.config/secretenv/config.toml
cd examples/single-backend-local && secretenv run -- env | grep API_KEY
```

## What to replace for real use

Production teams don't keep secret values on disk. Move the `api_key`
and `db_url` values into AWS SSM / 1Password / Vault, update the
registry entries to point there, and the `secretenv.toml` stays
identical.
