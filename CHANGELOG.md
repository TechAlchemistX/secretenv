# Changelog

All notable changes to SecretEnv are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `YYYY-MM-DD` (UTC).

## [Unreleased]

### Added

- **Registry cascades.** `[registries.<name>]` now accepts multiple
  `sources = [...]` entries. Lookup is first-match-wins from `sources[0]`
  downward; `sources[0]` remains the single write target for
  `registry set/unset`. All sources are fetched concurrently via
  `futures::future::join_all`; any source failure fails the whole
  resolve (silent fall-through would hide environment problems).
- `secretenv_core::CascadeLayer` public type exposing per-source
  `{source, map}` for future doctor/verbose reporting.
- `AliasMap::get` now returns `(target_uri, source_uri)` so callers can
  tell which cascade layer an alias was resolved from.
- `AliasMap::primary_source`, `layers`, `sources` accessors.
- `BackendUri.fragment: Option<String>` — parses the `#<fragment>` suffix
  of `scheme://path#fragment` URIs. Not yet consumed by any backend; v0.2
  Phase 6 (aws-secrets) will use it for `#json-key` extraction (RE-2).
- `secretenv_core::with_timeout` helper and `DEFAULT_GET_TIMEOUT` (30s) /
  `DEFAULT_CHECK_TIMEOUT` (10s) constants. Backend ops now have deadlines;
  `doctor` and `run` cannot hang indefinitely on a wedged CLI (CV-5).
- `BackendConfig.raw_fields` now preserves typed TOML values
  (`HashMap<String, toml::Value>` instead of `HashMap<String, String>`).
  Factories can read `as_str`, `as_integer`, `as_bool`, `as_array` — v0.2+
  backends get typed config fields without a later ABI break (RE-1).

### Changed

- **Parallel secret fetch.** `runner::build_env` dispatches every
  alias-backed secret concurrently via `futures::future::join_all`
  instead of awaiting them one at a time. `Default`-sourced entries
  stay inline (zero I/O). Declaration order in the emitted env map is
  preserved regardless of backend completion order.
- **Multi-error aggregation.** When more than one alias fetch fails,
  the returned error now lists every failure in one message
  (`<N> secrets failed to resolve:` followed by one line per alias
  with env-var, URI, and upstream cause). Single-failure error shape
  is unchanged so operators with one broken alias see the same
  message as before (RE-7).
- `ResolvedSource::Uri` is now a struct variant `{ target, source }`
  instead of `Uri(BackendUri)`. The added `source` field carries the
  cascade layer URI the alias resolved from, for future `--verbose`
  and `doctor --extensive` surfacing.
- `registry set`/`unset` writes use `BTreeMap<String, String>` internally
  so alias output is alphabetically sorted and deterministic across
  runs — no more spurious diffs on every write (CV-4).
- `BackendFactory::create` signature: `config: &HashMap<String, toml::Value>`
  (was `config: HashMap<String, String>` by value). Borrowed config removes
  a per-load clone and matches core's borrowed-config convention (RE-5).
- `Manifest::find_upward` stops at project-root sentinels (`.git`, `.hg`,
  `.svn`, `.secretenv-root`). A hostile `secretenv.toml` dropped upstream
  of the user's project can no longer hijack alias resolution (CV-6).
  Falls back to v0.1 behavior when no sentinel exists anywhere.
- `--verbose` stderr output omits full URI paths — only env-var + backend
  instance name. Registry topology no longer leaks into CI build logs on
  `--verbose` runs (CV-7). Full URIs remain available under `--dry-run`.

### Fixed

- **AWS SSM `set`** pipes secret values via child-process stdin using
  `--value file:///dev/stdin`. The secret never appears on argv, closing
  the `/proc/<pid>/cmdline` local-user exposure window (CV-1 — critical).
- **1Password `set`** documents its remaining argv exposure with an
  inline comment + stderr warning on every call. Full stdin fix pending
  a v0.3 follow-up with `op` CLI version gating (CV-1 — partial).
- `BackendUri::parse` rejects invalid scheme characters (anything outside
  `[a-zA-Z0-9][a-zA-Z0-9_-]*`), NUL bytes in path/fragment, and ASCII
  control characters except tab. Warns on Unicode bidi-override codepoints
  without rejecting them (CV-3).
- `SECRETENV_REGISTRY` and `SECRETENV_CONFIG` scrubbed from the child
  process environment before `exec()`/`spawn`. CLI-layer config provenance
  no longer leaks to the child (SEC-1).

### Security

- Phase 0.5 security preflight complete. See
  `kb/wiki/reviews/pre-v0.2-review.md` for the three-reviewer audit that
  identified the above items, and `kb/wiki/build-plan-v0.2.md §Phase 0.5`
  for the subtask breakdown. Remaining audit items are addressed in the
  Phase 1+ feature work.

### Internal

- v0.2 development baseline: branch `feat/v0.2-prep` opened, workspace bumped
  to 0.2.0, roadmap updated to reflect the Vault + AWS Secrets Manager
  dual-backend release.
- `tokio` promoted from dev-dep to runtime dep on `secretenv-core` (needed
  for `tokio::time::timeout` in the timeout wrapper). Workspace tokio
  features gain `"time"`.
- `tracing` added as a direct runtime dep on `secretenv-core` (bidi-override
  warning) and `secretenv-backend-1password` (argv-exposure warning).
- `toml` added as a direct runtime dep on `secretenv-backend-aws-ssm` (now
  references `toml::Value` in the factory signature).

## [0.1.1] - 2026-04-17

First public release of SecretEnv.

### Added

- Core CLI surface: `run`, `registry list/get/set/unset`, `setup`, `doctor`,
  `get`.
- Three backends: `local` (TOML file), `aws-ssm` (AWS Systems Manager
  Parameter Store via `aws` CLI), `1password` (1Password via `op` CLI).
- `secretenv.toml` manifest format with alias (`from = "secretenv://..."`)
  and default (`default = "..."`) secret declarations.
- `~/.config/secretenv/config.toml` machine-level configuration with
  `[registries.<name>] sources = [...]` and `[backends.<name>]` blocks.
- `secretenv://<alias>` URI scheme for aliases resolved against the
  registry; direct-scheme URIs (e.g. `aws-ssm-prod:///path`) for concrete
  backend references inside registry documents.
- `BackendRegistry` + `Backend` + `BackendFactory` plugin system; all
  backends compiled into a single binary (no compile-time feature flags).
- Level 1 (CLI present) + Level 2 (authenticated) doctor checks, with
  `--json` output for CI integration.
- `secretenv setup <registry-uri>` bootstrap with `--force`, `--skip-doctor`,
  and backend-specific flags (`--region`, `--profile`, `--account`).
- `install.sh` POSIX installer with `--profile <name>` distribution-profile
  support (downloads config from `https://secretenv.dev/profiles/<name>.toml`
  by default; override via `SECRETENV_PROFILE_URL`).
- Homebrew tap at `TechAlchemistX/homebrew-secretenv`.
- Release workflow builds and publishes for `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

### Security

- Workspace-wide `unsafe_code = "forbid"`.
- Clippy `unwrap_used` / `expect_used` set to warn; CI denies warnings.
- Secret values wrapped in `zeroize::Zeroizing<String>` in the runner;
  `exec()` replaces the parent process, zeroing automatically on drop.
- No shell interpolation — every backend uses
  `tokio::process::Command::args([...])` with separate argv strings.
- `cargo deny check` + `cargo audit` gate every PR.
- Errors include alias + URI + instance name + trimmed backend stderr,
  never the secret value.

[Unreleased]: https://github.com/TechAlchemistX/secretenv/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.1.1
