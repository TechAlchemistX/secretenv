# Single-backend: Local file

Simplest setup. Registry and secrets in local files. No cloud, no CLIs, no network.

## When to use

- First-time SecretEnv with zero account setup
- Solo projects where one dev controls all secrets
- Offline/air-gapped dev
- Learning the alias → URI model

## Files

- `config.toml`: machine config with `local` backend and registry path
- `secretenv.toml`: project manifest with two aliases
- `local-registry/registry.toml`: alias-to-URI mapping
- `local-secrets/`: secret values (one file per value)

## Running it

```sh
# Option A: pass the config explicitly
secretenv --config examples/single-backend-local/config.toml run -- env | grep -E 'API_KEY|DB_URL'

# Option B: symlink or copy config.toml into ~/.config/secretenv/
cp examples/single-backend-local/config.toml ~/.config/secretenv/config.toml
cd examples/single-backend-local && secretenv run -- env | grep API_KEY
```

## For production

Move `api_key` and `db_url` into AWS SSM / 1Password / Vault, update registry entries to point there. The `secretenv.toml` stays identical.
