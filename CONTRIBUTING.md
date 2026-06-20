# Contributing to SecretEnv

Thanks for considering a contribution. This document covers the mechanics. For the why (the architecture, the plugin model, the security posture), read [`README.md`](README.md) and [`docs/`](docs/) first.

## Development setup

Install Rust via rustup. The repo pins a toolchain in `rust-toolchain.toml`. Rustup picks it up automatically. The pin keeps local and CI on the same compiler.

Install supporting tools:

```sh
cargo install cargo-deny --locked
cargo install cargo-audit --locked
```

## Pre-commit

Every commit must pass locally before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- --deny warnings
cargo test --workspace
cargo deny check
cargo audit
```

Fix failures at the source, not by weakening lints. Use narrowly-scoped `#[allow(...)]` with a comment if needed.

## Branching & commits

- Branch: `feat/<slug>`, `fix/<slug>`, or `chore/<slug>` off `main`
- One PR per logical change; squash-merge
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `feat(core):`, `fix(backend-aws-ssm):`, `chore:`, etc.
- Sign commits with SSH key: `git config --global commit.gpgsign true`

## New backends

Follow [`docs/reference/adding-a-backend.md`](docs/reference/adding-a-backend.md). Architectural constraints (shell-out to native CLIs, `Backend` + `BackendFactory` traits, no cloud SDKs) are load-bearing.

## Telemetry setters

`SecretEnvSpan` has no `set_attribute(key, value)` escape hatch. All OTel attributes go through typed `record_*` setters. Closed-set values use enums, not `&str`.

**Closed enums live in `secretenv-telemetry::span`, not the domain crate.** Dependency direction: `secretenv-core → secretenv-telemetry`. Adding a typed setter requires three changes in `secretenv-telemetry`:

1. Closed enum (e.g. `BackendType`, `SecretEnvCommand`, `MigrateOutcome`) with `into_attribute_value`/`as_attribute_value` in `span.rs`
2. `record_<attr>(&mut self, value: TheEnum)` setter on `SecretEnvSpan`
3. Consuming caller in `secretenv-core`/`-migrate`/`-mcp` converting runtime strings

Do not add `&str` setters for closed-set values.

## Panics in production

Production code must not panic on operator or agent input. Two exceptions (both require comments):

- **Hand-audited `expect`**: e.g. compiling regex literals. Add `#[allow(clippy::expect_used)]` with a one-line justification that the failure is impossible by construction.
- **By-construction panic**: internal invariants making branches unreachable. Prefer making it unrepresentable in the type system (marker-type pattern in `secretenv-mcp`). If unproportionate, add a `// by construction:` comment at the panic site (see `aggregate_errors` in `secretenv-core::runner`).

Prefer the type-system lift. A `tracing::warn!` + soft-fail is a smell, not a safety net.

## Marker types

Use context-specific marker types that omit unreachable variants instead of runtime guards or `unreachable!()`. The compiler enforces the invariant. Convert at context boundaries via a trait.

Examples: `ResolvedConfirmVia` (omits `Auto` post-resolution), `MutationSpanName` (closed enum drives span-name + sampler whitelist), `OperatorDecision` family (`MutationOperatorDecision` omits `DryRun`; `MigrateOperatorDecision` retains it).

The on-disk/serde union stays shared; only in-memory marker types split. Prefer this over the `// by construction:` documented panic.

## Security

Security-relevant changes get extra care. See [`SECURITY.md`](SECURITY.md) for the disclosure policy and [`docs/security.md`](docs/security.md) for the threat model. Report vulnerabilities privately. Do not open a public issue.

## License and CLA

SecretEnv is licensed under **[GNU AGPL v3.0](LICENSE)** from v0.3.0 forward. v0.1 to 0.2.0 shipped under MIT.

All contributions are accepted under the [Contributor License Agreement](CLA.md), a license grant (not copyright assignment) enabling dual-licensing.

### CLA requirements

1. **Sign-off on every commit:** Use `git commit -s`. Adds `Signed-off-by` trailer from your configured `user.name` + `user.email`. Missing trailer = no merge.
2. **First-time contributors:** Add your name to [`AUTHORS.md`](AUTHORS.md) in the same PR. Subsequent contributions only need the trailer.
3. **Corporate contributors:** Your employer must execute a Corporate CLA. Contact the maintainer first.

### Commit signing vs. sign-off

Two distinct things:
- **`git commit -s` (sign-off)**: adds `Signed-off-by` (CLA attestation). Required.
- **`git commit -S` (cryptographic signature)**: signs the commit with SSH key. Required.

Configure both. A typical commit carries cryptographic signature + `Signed-off-by` trailer.
