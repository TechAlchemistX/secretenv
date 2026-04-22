# Canonical annotated `secretenv.toml`

Reference file — every directive SecretEnv accepts in a project
manifest, exhaustively commented. NOT a starter file; it's too noisy
to drop into a real repo. Use this to look up the syntax for a
particular directive, then copy the minimal form into your own
`secretenv.toml`.

## What's in this directory

- `secretenv.toml` — the annotated manifest.

## What this file covers

- The two value shapes: `{ from = "secretenv://..." }` and
  `{ default = "..." }`.
- Why direct backend URIs (`aws-ssm-prod:///...`) are a hard error.
- Alias naming conventions (kebab-case in registries, SCREAMING_SNAKE
  as env-var names).
- How the registry resolves an alias to its final URI.
- The resolution precedence for `--registry` and `SECRETENV_REGISTRY`.

## Related references

- [`docs/configuration.md`](../../docs/configuration.md) — the
  `config.toml` (machine config) counterpart.
- [`docs/registry.md`](../../docs/registry.md) — the alias registry
  document shape.
- [`docs/fragment-vocabulary.md`](../../docs/fragment-vocabulary.md) —
  per-backend URI fragment directives.
