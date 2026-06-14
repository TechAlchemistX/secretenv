# Contributing to SecretEnv

Thanks for considering a contribution. This document covers the mechanics. For the why — the architecture, the plugin model, the security posture — read [`README.md`](README.md) and [`docs/`](docs/) first.

## Development setup

You need a recent Rust stable toolchain. The repo pins one via `rust-toolchain.toml`, so `rustup` will pick it up automatically on first build. The pin is deliberate: it keeps local and CI on the same compiler so new clippy lints + trybuild fixture text drift do not surface as red CI on push. Bumping the pin is its own chore — see `kb/wiki/runbooks/rust-toolchain-bump.md`.

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

## Adding a telemetry attribute (typed setter)

`SecretEnvSpan` has **no `set_attribute(key, value)` escape hatch** — every emitted OTel attribute goes through a typed `record_*` setter, and there is no string-keyed path. When the value is a closed set (a backend type, a command name, an outcome), the setter takes a **closed enum, not a `&str`**, so a typo or a leaky raw string cannot reach the wire.

The rule that trips contributors: **those closed enums live in `secretenv-telemetry::span`, not in the crate that owns the domain concept.** The dependency direction is `secretenv-core → secretenv-telemetry` (and `secretenv-migrate`/`secretenv-mcp` likewise depend *on* telemetry), so telemetry cannot depend back on core to reuse, say, a backend-type enum defined there. Adding a typed setter is therefore a three-part change, all in `secretenv-telemetry`:

1. the closed enum (e.g. `BackendType`, `SecretEnvCommand`, `MigrateOutcome`) — with an `into_attribute_value`/`as_attribute_value` method — in `span.rs`;
2. the `record_<attr>(&mut self, value: TheEnum)` setter on `SecretEnvSpan`;
3. the consuming caller in `secretenv-core`/`-migrate`/`-mcp`, which converts a runtime string at the boundary via the enum's `from_runtime_str` (or constructs the variant directly).

A setter that takes `&str` for a value that is really a closed set is a half-closure — see the v0.18→v0.19 history of `record_migrate_*_backend_type` (Arch-M4 / Arch-W-4). Do not add new `&str` setters for closed-set values.

## Panics in production code

Production code (everything outside `#[cfg(test)]`) must not `panic!`/`unreachable!`/`unwrap`/`expect` on any input an operator or agent can influence. Two narrow exceptions, each requiring a comment:

- **Statically-valid `expect`** — e.g. compiling a hand-audited `regex` literal. Carry `#[allow(clippy::expect_used)]` and a one-line justification that the failure is impossible by construction and would surface at first use, not in a user path.
- **By-construction `panic!`** — when an internal invariant makes a branch unreachable, prefer making it unrepresentable in the type system (the `ResolvedConfirmVia` / `MutationOperatorDecision` marker-type pattern — see `secretenv-mcp`) over a runtime guard. If a type-level lift is disproportionate for a single internal caller, document the precondition with a `// by construction:` block at the panic site (see `aggregate_errors` in `secretenv-core::runner`).

Prefer the type-system lift. A `tracing::warn!` + soft-fail on a "can't happen" branch is a smell, not a safety net.

## Marker types and the `Decision` trait

When an enum variant is unreachable in a specific context, prefer a context-specific marker type that structurally omits the variant over a runtime guard or `unreachable!()` arm. The impossible state then cannot be witnessed in that context; the compiler enforces the invariant rather than a human reader. Convert to and from the shared on-disk or serde type at the context boundary via a small trait. This pattern has three instances in the codebase: `ResolvedConfirmVia` (produced by `resolve_confirm_via` in the policy gate; omits `Auto` once resolution has run, eliminating the v0.17 `unreachable!()`), `MutationSpanName` (the closed enum drives both the span-name constructor and the sampler whitelist so adding a variant covers both), and the v0.19 `OperatorDecision` family (`MutationOperatorDecision` omits `DryRun` — mutation tools structurally cannot receive a dry-run decision; `MigrateOperatorDecision` retains it; the `Decision` trait's `to_audit() -> OperatorDecision` is the single projection point so echo and audit-write cannot diverge). The on-disk/serde union (`OperatorDecision`) remains one type shared across all contexts; only the in-memory marker types are split. See also `## Panics in production code` above — the marker-type lift is the preferred alternative to the `// by construction:` documented panic.

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
