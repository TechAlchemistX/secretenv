# SecretEnv Examples

Canonical configuration patterns for SecretEnv. Each subdirectory is a
realistic, minimally-complete setup you can copy, adapt, and drop onto a
machine.

## ⚠️ These are NOT Cargo `examples/`

This directory is at the workspace root, but it is **not** a Cargo
`examples/` target. It contains `config.toml` + `secretenv.toml`
fixtures, not runnable Rust binaries. `cargo build --examples` finds
nothing here (no `.rs` files), which is intentional — these are
configuration patterns that ship with the repo so users can see real,
working shapes rather than reverse-engineering them from docs.

If you want code examples (`.rs` binaries that call into
`secretenv-core`), open an issue; they'd live under
`crates/secretenv-cli/examples/` and pull in the core as a dependency.

## The seven patterns

| Directory | What it shows |
|---|---|
| [`single-backend-local/`](single-backend-local/) | Simplest setup: local-file registry + local-file secrets. No cloud at all — good for a solo dev or a first taste of SecretEnv. |
| [`single-backend-aws-ssm/`](single-backend-aws-ssm/) | Typical AWS-only team: registry + secrets both in AWS SSM Parameter Store. |
| [`single-backend-keychain/`](single-backend-keychain/) | macOS Keychain as the secret store. Registry must live elsewhere (local file here) because Keychain doesn't support `list`. |
| [`cascade-local-then-vault/`](cascade-local-then-vault/) | Dev-first cascade: local registry checked first, Vault fallback. Real pattern for mixed local-override + team-default workflows. |
| [`multi-cloud-aws-and-1password/`](multi-cloud-aws-and-1password/) | Real teams mid-migration: AWS SSM for infra, 1Password for human-managed secrets, plus named instances for multiple accounts. |
| [`ci-github-actions/`](ci-github-actions/) | GitHub Actions workflow snippet showing `SECRETENV_REGISTRY` injection and OIDC-assumed AWS role. |
| [`secretenv-toml-canonical/`](secretenv-toml-canonical/) | Exhaustively-annotated `secretenv.toml` covering every directive, fragment, and default form. Reference, not starter. |

## How to use these

1. Pick the pattern closest to your setup.
2. Copy its `config.toml` to `~/.config/secretenv/config.toml` (or set
   `--config <path>`).
3. Copy its `secretenv.toml` into a project repo and run
   `secretenv run -- <your-command>`.

The `config.toml` files use placeholder names (`my-team`, `acme-corp`,
etc.) — rename to match your real infrastructure.

## What's NOT covered here

- Backend-specific auth flows (AWS SSO, Vault login, `op signin`) —
  those live in each backend's doc under [`docs/backends/`](../docs/backends/).
- Distribution profiles — see [`docs/profiles.md`](../docs/profiles.md).
- Registry management commands — see [`docs/registry.md`](../docs/registry.md).
- The full threat model — see [`docs/security.md`](../docs/security.md).

## Related

- [Top-level README](../README.md) — product overview and quick start
- [`docs/configuration.md`](../docs/configuration.md) — reference for every
  config directive
- [`docs/adding-a-backend.md`](../docs/adding-a-backend.md) — if you want
  to write a new backend
