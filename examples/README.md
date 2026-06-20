# SecretEnv Examples

Configuration patterns you can copy and adapt. Each subdirectory is a realistic, complete setup.

## Not Cargo `examples/`

This directory contains `config.toml` + `secretenv.toml` fixtures, not Rust binaries. `cargo build --examples` finds nothing here (no `.rs` files), intentional. These are configuration patterns for reference, not code examples.

For code examples (`.rs` binaries using `secretenv-core`), open an issue.

## The seven patterns

| Directory | What it shows |
|---|---|
| [`single-backend-local/`](single-backend-local/) | Simplest setup: local-file registry + local-file secrets. No cloud at all, good for a solo dev or a first taste of SecretEnv. |
| [`single-backend-aws-ssm/`](single-backend-aws-ssm/) | Typical AWS-only team: registry + secrets both in AWS SSM Parameter Store. |
| [`single-backend-keychain/`](single-backend-keychain/) | macOS Keychain as the secret store. Registry must live elsewhere (local file here) because Keychain doesn't support `list`. |
| [`cascade-local-then-vault/`](cascade-local-then-vault/) | Dev-first cascade: local registry checked first, Vault fallback. Real pattern for mixed local-override + team-default workflows. |
| [`multi-cloud-aws-and-1password/`](multi-cloud-aws-and-1password/) | Real teams mid-migration: AWS SSM for infra, 1Password for human-managed secrets, plus named instances for multiple accounts. |
| [`ci-github-actions/`](ci-github-actions/) | GitHub Actions workflow snippet showing `SECRETENV_REGISTRY` injection and OIDC-assumed AWS role. |
| [`secretenv-toml-canonical/`](secretenv-toml-canonical/) | Exhaustively-annotated `secretenv.toml` covering every directive, fragment, and default form. Reference, not starter. |

## How to use

1. Pick the pattern closest to your setup.
2. Copy `config.toml` to `~/.config/secretenv/config.toml` (or use `--config <path>`).
3. Copy `secretenv.toml` into your project and run `secretenv run -- <your-command>`.

Rename placeholder names (`my-team`, `acme-corp`, etc.) to match your infrastructure.

## Not covered here

- Backend auth flows: see [`docs/backends/`](../docs/backends/).
- Distribution profiles: see [`docs/reference/profiles.md`](../docs/reference/profiles.md).
- Registry management: see [`docs/reference/registry.md`](../docs/reference/registry.md).
- Threat model: see [`docs/security.md`](../docs/security.md).

## Related

- [Top-level README](../README.md): product overview and quick start
- [`docs/reference/configuration.md`](../docs/reference/configuration.md): reference for every
  config directive
- [`docs/reference/adding-a-backend.md`](../docs/reference/adding-a-backend.md): if you want
  to write a new backend
