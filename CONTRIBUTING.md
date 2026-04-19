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

## License and CLA

SecretEnv is licensed under **[GNU AGPL v3.0 (AGPL-3.0-only)](LICENSE)** starting with v0.3.0. v0.1 and v0.2.0 shipped under MIT; the published MIT releases remain available under their original terms.

All Contributions are accepted under the project's [Contributor License Agreement (CLA)](CLA.md). The CLA is a **license grant** (not a copyright assignment — You retain ownership of Your work) that lets the project relicense contributions under alternate terms, enabling dual-licensing (e.g., commercial licenses alongside the AGPL community license).

### Signing the CLA

Two things are required on every Contribution:

1. **Every commit must carry a `Signed-off-by` trailer** attesting to the CLA. Use `git commit -s` (or `--signoff`) — git appends the trailer from your configured `user.name` + `user.email` automatically:
   ```
   Signed-off-by: Jane Doe <jane@example.com>
   ```
   Missing trailer = no merge. This is enforced at review.

2. **First-time contributors:** add your name to [`AUTHORS.md`](AUTHORS.md) in the same PR as your first Contribution, using the format documented in that file. Subsequent Contributions only need the sign-off trailer.

Corporate contributors whose employer claims IP rights over their Contributions must additionally execute a Corporate CLA — contact the project maintainer to arrange this before submitting.

### Commit signing vs. CLA sign-off

These are two different things:

- **`git commit --signoff` (`-s`)** adds the `Signed-off-by` line (CLA attestation). **Required.**
- **`git commit --gpg-sign` (`-S`) / SSH signing (`commit.gpgsign = true`)** cryptographically signs the commit. **Also required** per the Branching & Commit Workflow section above.

Configure both; they compose. A typical commit on this repo carries both a cryptographic signature (verifies identity) and a `Signed-off-by` trailer (CLA assent).
