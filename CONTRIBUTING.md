# Contributing to SecretEnv

Thanks for considering a contribution. This document covers the mechanics. For the why — the architecture, the plugin model, the security posture — read [`README.md`](README.md) and [`docs/`](docs/) first.

## Development setup

You need a recent Rust stable toolchain. The repo pins one via `rust-toolchain.toml`, so `rustup` will pick it up automatically on first build.

Supporting tools used by the pre-commit suite:

```sh
cargo install cargo-deny --locked
cargo install cargo-audit --locked
```

## Pre-commit suite

Every commit on `main` must pass the following locally before opening a PR. CI re-runs the same checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- --deny warnings
cargo test --workspace
cargo deny check
cargo audit
```

If any of these fails, fix it at the source. Do **not** weaken the workspace-level lint configuration to paper over a failure; prefer a narrowly scoped `#[allow(...)]` with a comment explaining why.

## Branching & commit workflow

- Branch off `main` with a prefix: `feat/<short-slug>`, `fix/<short-slug>`, or `chore/<short-slug>`.
- One PR per logical change. Squash-merge.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat(core): ...`, `fix(backend-aws-ssm): ...`, `chore: ...`, `docs: ...`, `test: ...`
- Commits must be signed. See [`docs/signing.md`](docs/signing.md) if it exists, or configure `git config --global commit.gpgsign true` with an SSH signing key registered on your GitHub account.

## Adding a new backend

Follow the step-by-step walkthrough at [`docs/adding-a-backend.md`](docs/adding-a-backend.md). The architectural constraints — shell-out to native CLIs only, `Backend` + `BackendFactory` traits, no cloud-SDK imports — are load-bearing, not stylistic.

## Security

Security-relevant changes get extra care. See [`SECURITY.md`](SECURITY.md) for the disclosure policy and [`docs/security.md`](docs/security.md) for the threat model. Report vulnerabilities privately — do not open a public issue.
