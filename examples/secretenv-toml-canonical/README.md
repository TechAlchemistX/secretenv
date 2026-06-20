# Canonical `secretenv.toml` Reference

Exhaustively-commented reference. Not a starter file, too noisy for real repos. Use to look up syntax, then copy the minimal form into your `secretenv.toml`.

## Contents

- `secretenv.toml`: annotated manifest

## Covers

- Value shapes: `{ from = "secretenv://..." }` and `{ default = "..." }`
- Why direct URIs like `aws-ssm-prod:///...` are errors
- Alias naming (kebab-case in registries, SCREAMING_SNAKE for env vars)
- Registry alias resolution
- `--registry` and `SECRETENV_REGISTRY` precedence

## Related

- [`docs/reference/configuration.md`](../../docs/reference/configuration.md): `config.toml` reference
- [`docs/reference/registry.md`](../../docs/reference/registry.md): registry document shape
- [`docs/reference/fragment-vocabulary.md`](../../docs/reference/fragment-vocabulary.md): backend URI fragments
