# Changelog

All notable changes to SecretEnv are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `YYYY-MM-DD` (UTC).

## [Unreleased]

### Added

- **`secretenv-backend-gcp` (new crate):** first v0.3 backend — Google Cloud Secret Manager via the `gcloud` CLI. URI shape `gcp-<instance>:///<secret-name>[#version=<n>]`. Canonical `#version=<n>` directive supports positive integers + `latest` (latest = flag omitted; `gcloud` resolves to newest enabled version). Required config: `gcp_project`. Optional: `gcp_impersonate_service_account` (plausibility-validated as an SA email at factory time), `gcloud_bin` (test hook). `set` pipes the secret value through child stdin via `--data-file=/dev/stdin` (CV-1 discipline); fragment on `set` URI explicitly rejected before any network call. `check()` runs Level 1 (`gcloud --version`) + Level 2 (`gcloud auth print-access-token`) + identity enrichment (`gcloud config get-value account`) concurrently via `tokio::join!`. The OAuth2 bearer token returned by `print-access-token` is read only for exit status — `output.stdout` is dropped immediately and never interpolated into logs, errors, or identity strings. A dedicated canary test (`check_level2_auth_ok_never_logs_token_body`) locks this defense-in-depth contract with a sentinel token substring. Strict-mode mocks from day one — 32 tests across factory validation, the `check` probe triad, `get` + `set` + `delete` + `list`, fragment grammar rejection (shorthand, unsupported directive, invalid version value, invalid secret name), impersonation argv shape, and two drift-catch locks (missing `--project`, CV-1 stdin discipline). Secret-name charset `[a-zA-Z0-9_-]{1,255}` validated locally BEFORE any `gcloud` call.
- **`secretenv setup` gains `--gcp-project` + `--gcp-impersonate-service-account` flags** for gcp-scheme registry URIs. Scheme router accepts `gcp` + `gcp-*` suffix forms; registry serializer emits gcp registries as JSON (same wire shape as aws-ssm / vault / aws-secrets).

## [0.3.0-alpha.0]

**Headline:** v0.3 Phase 0 groundwork. Workspace version bumped to `0.3.0-alpha.0` — the aggregate release window is now open. This patch is pure internal refactoring — zero behavior change. GCP + Azure backend implementation follows in subsequent patches.

Aggregate release posture (locked 2026-04-19): the entire v0.2.1 → v0.2.7 + v0.3 backend series will ship as ONE cohesive `v0.3.0` release on crates.io, Homebrew, and GH Releases.

### Changed

- **`Backend::check_extensive`:** now has a default implementation on the trait itself (`Ok(self.list(test_uri).await?.len())`). The five backends' duplicated verbatim impls removed. A backend with a faster "count without materializing" CLI path may still override. Rust-engineer review flagged this as a 5× duplication.
- **`secretenv-core::factory_helpers`:** new public module exposing `required_string(config, field, backend_type, instance_name)` and `optional_string(config, field, backend_type, instance_name)`. The `backend_type` label is the new argument (vs. v0.2's hard-coded-per-backend strings); error shape is unchanged. aws-ssm, vault, aws-secrets factory blocks now call the shared helpers. v0.3 gcp + azure will use the same entry points, avoiding two more copies. 6 new unit tests in the helper module.
- **`Backend::check` for aws-ssm, aws-secrets, vault, 1password:** Level 1 (`<cli> --version`) and Level 2 (auth probe) now run concurrently via `tokio::join!`. The two probes are independent; serializing them doubled `secretenv doctor` latency per backend. For a config with 5 backends (current) that's ~5× the latency saving vs. v0.2; for v0.3 with 7 backends (adding gcp + azure) it becomes ~7×. No behavior change — error handling and short-circuiting semantics preserved.

### Internal

- Workspace version 0.2.7 → 0.3.0-alpha.0.
- Workspace test count 359 → 365 (+6 new factory_helpers unit tests).
- CHANGELOG entries undated — per the dev-only posture, no tag pushed yet. Date fills in at `v0.3.0` tag.

## [0.2.7]

**Headline:** security hardening follow-up to the v0.2.x retrofit series — three reviewer agents (code / security / rust) audited the full v0.2.x scope; this patch lands the defense-in-depth fixes surfaced by the security review. No user-facing behavior change for valid URIs.

### Security

- **`secretenv-testing::StrictMock`:** env-var keys passed to `Response::with_env_var` / `with_env_absent` are now validated at call time against `^[A-Za-z_][A-Za-z0-9_]*$`. A malformed key (e.g. `"KEY}; rm -rf /; :{"`) panics immediately rather than injecting arbitrary shell into the generated mock script. Closes a test-author-side defense-in-depth gap flagged by the security review.
- **`secretenv-testing::StrictMock`:** stdin-fragment mismatch diagnostic now emits only a REDACTED fingerprint of the missing fragment (`<len>-byte:<first-4-chars>…` for long values, `<len>-byte:<redacted>` for short). Previously, CV-1 stdin-discipline tests used canary secret values as the `stdin_must_contain` fragment; a regression that routed the secret to argv would have echoed the full secret to stderr and into CI logs. Now only the fingerprint appears.
- **`secretenv-testing::strict::escape_for_double_quoted`:** now panics on embedded `\n` / `\r` instead of silently swapping them for space. Caller contract was already "no newlines"; enforcement was lax. Fail-fast catches bugs where a diagnostic string was assumed safe but wasn't.
- **`secretenv-core::uri`:** new `BackendUri::reject_any_fragment(backend_label)` method + `FragmentError::UnsupportedForBackend` variant. Called from the top of `get` / `set` / `delete` / `list` in **aws-ssm**, **vault**, and **1password** — backends which do not accept fragment directives. Previously, a URI like `vault-prod:///secret/x#json-key=password` was silently accepted and the fragment dropped; now surfaces a clear "this backend accepts no fragment directives" error. Applied transitively to `list` paths that delegate to `get` (aws-ssm, 1password).
- **`secretenv-backend-1password::get`:** added a `debug_assert!` post-condition on `parse_path` output (no `/` in any of `(vault, item, field)`) to guard against future parse_path regressions that could leak the path structure into the `op://<v>/<i>/<f>` argv token.
- **Integration smoke harness:** the shared `secretenv-validation/api-key` fixture restore is now wired via `trap restore_fixture_on_exit EXIT` at the top of `/tmp/secretenv-test/scripts/run-tests.sh`. A mid-run failure, SIGINT, or interpreter error cannot leave the fixture polluted — the NEXT run's tests 30 / 39 will see the canonical `sk_test_secrets_22222` value regardless of how the prior run terminated. The v0.2.6 test 118 ("fixture restored") is retained for observability parity but is now a consequence of the trap handler, not the primary mechanism.

### Internal

- 6 new unit tests in `secretenv-testing::strict::tests` covering the above: `stdin_fragment_redaction_fingerprint_hides_value_never_leaks_full`, four panic-tests for env-var key validation, `escape_for_double_quoted_panics_on_newline`. The existing `stdin_check_rejects_when_fragment_missing` test updated to assert the redacted-fingerprint contract AND that the full secret does NOT appear in stderr.
- Workspace test count **353 → 359**.

### Origin

Findings surfaced by three parallel reviewer agents (code-reviewer, security-engineer, rust-engineer) auditing the full v0.2.x scope (fragment grammar, StrictMock harness, 5 backends, v0.2.6 fragment-before-network fix). The reviewers' v0.3-spec findings (GCP `print-access-token --project` flag, Azure argv size miscounts, Azure vault-URL regex path traversal) are applied to `kb/wiki/backends/{gcp,azure}.md` alongside this patch. The `AwsCli` / `tokio::join!` / `Response`-`Rule` unification / `IndexMap` refactors flagged by the rust-engineer land as v0.3 Phase 0.

## [0.2.6]

**Headline:** internal test-infrastructure release — aws-secrets backend's mock-CLI tests migrated to `StrictMock`, closing out the v0.2.x strict-mode retrofit series. **The first prod-code bug surfaced by the strict retrofit lands alongside the migration**: `AwsSecretsBackend::get()` was calling `aws secretsmanager get-secret-value` BEFORE validating the fragment directive, meaning a URI like `aws-secrets-prod:///myapp/cfg#password` (legacy shorthand, rejected since v0.2.1) would make a wasted AWS API call before surfacing the local grammar error. The v0.2 permissive-mock tests silently masked the extra call. Fixed: fragment validation now happens up-front, no AWS call occurs for invalid-grammar URIs.

### Fixed

- **`secretenv-backend-aws-secrets`:** `get()` now validates the fragment directive (`#json-key=<field>`, shorthand rejection, unsupported-directive rejection) BEFORE invoking `aws secretsmanager get-secret-value`. Pre-fix, an invalid fragment (`#password`, `#version=5`, or `#json-key=X,version=5`) caused a round-trip to AWS — wasting an IAM permission check, API latency, and potentially leaking an access pattern — before surfacing the local error. Caught by v0.2.6 strict-mode mocks with empty-rule installations (`StrictMock::new("aws").install(...)`) that reject any AWS call with exit 97; the v0.2 permissive-mock form returned success on the call, silently masking the extra round-trip. No end-user-visible behavior change for valid URIs.

### Changed

- **Internal:** all 25 mock-using tests in `secretenv-backend-aws-secrets` converted from the v0.2 raw `install_mock_aws(body)` API to declarative `StrictMock::new("aws").on(argv, Response).install(...)`. Every `secretsmanager get-secret-value`, `secretsmanager put-secret-value`, `secretsmanager delete-secret`, `sts get-caller-identity`, and `aws --version` argv is now asserted exactly. PR #33 BUG-2 (leading-slash on `--secret-id`) is **implicitly locked** across every migrated test — the declared argv carries the POST-STRIP secret ID; any regression would fail with a `strict-mock-no-match` diagnostic.
- **Internal:** argv-builder helpers `get_argv(secret_id)` / `put_argv(secret_id)` / `delete_argv(secret_id)` + `STS_ARGV_NO_PROFILE` const keep test bodies concise and make "what argv changed?" diffs narrow when a real shape change ships.
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin` — CV-1 discipline is now a typed harness assertion rather than a log-file grep (parallel to aws-ssm v0.2.3 + vault v0.2.5).
- **Internal:** two new drift-catch regression-lock tests:
  - `get_drift_catch_rejects_leading_slash_on_secret_id` — POSITIVE BUG-2 lock: declares argv with the pre-fix slash-prefixed form; post-fix code diverges, strict harness emits exit 97 surfaced to the caller.
  - `set_drift_catch_rejects_secret_leaking_to_argv` — CV-1 parallel.
- **Internal:** three `command_always_passes_region` / `command_omits_profile` / `command_includes_profile` v0.2 log-file argv-shape tests collapsed: `--region us-east-1` is now implicitly asserted in every migrated test through the `get_argv` / `put_argv` / `delete_argv` helpers; profile-absent and profile-present cases retained as dedicated tests.
- **Internal:** v0.2.1 shorthand-reject and unsupported-directive-reject tests (`get_rejects_legacy_shorthand_fragment_with_migration_hint`, `get_rejects_unsupported_directive_with_enumerated_list`) now use empty-rule mocks — any AWS call exits 97 — making "this error originates in the fragment parser before any AWS call" a typed assertion. Both test bodies include an explicit `!msg.contains("strict-mock-no-match")` check to verify the error comes from the backend's grammar code, not the harness.

## [0.2.5]

**Headline:** internal test-infrastructure release — vault backend's mock-CLI tests migrated to `StrictMock`, and PR #33 BUG-1 (the flag-order fix: address/namespace routed via `VAULT_ADDR` / `VAULT_NAMESPACE` env vars rather than argv flags) is now a typed regression lock on every vault argv. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 17 mock-using tests in `secretenv-backend-vault` converted from the v0.2 raw `install_mock` API to declarative `StrictMock::new("vault")...install()`. Every `vault kv get`, `vault kv put`, `vault kv delete`, `vault token lookup`, and `vault --version` argv is now asserted exactly. The PR #33 BUG-1 regression lock (no `-address` / `-namespace` argv flags) is implicit in the strict argv match — any regression that reintroduces those flags would fail with a `strict-mock-no-match` diagnostic.
- **Internal:** the two env-log side-channel tests (`command_omits_namespace_env_when_not_configured`, `command_includes_namespace_env_when_configured`) rewritten as declarative `with_env_var` / `with_env_absent` assertions — shorter, tighter, and checkable uniformly with argv at every invocation (not just this one test).
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin` — CV-1 discipline is now a typed harness assertion rather than a log-file grep (same pattern aws-ssm adopted in v0.2.3).
- **Internal:** two new drift-catch regression-lock tests (`set_drift_catch_rejects_secret_leaking_to_argv` for CV-1, `get_drift_catch_env_check_rejects_wrong_vault_addr` for env-pathway) that prove the strict harness surfaces env drift loudly when it occurs.

### Added

- **`secretenv-testing`:** `Response::with_env_var(key, value)` and `Response::with_env_absent(key)` chainable methods for declaring per-rule env-var contracts. The generated POSIX shell uses `${KEY+set}` parameter expansion rather than `grep` so values with spaces, quotes, or regex metacharacters round-trip safely. Additive; `#[non_exhaustive]` policy honored. 6 new unit tests in `secretenv-testing::strict::tests` cover match / mismatch / key-absent / absence-violated / absence-satisfied / special-char-value.

### Fixed

- **None.** The retrofit surfaced no prod bugs in the vault backend — the PR #33 fix is correct and now has typed regression locks preventing its accidental reversal.

## [0.2.4]

**Headline:** internal test-infrastructure release — 1password backend's mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 13 mock-using tests in `secretenv-backend-1password` converted from the v0.2 raw `install_mock_op(body)` API to declarative `StrictMock::new("op").on(argv, Response).install(...)`. Every `op read`, `op item edit`, `op --version`, and `op whoami --format=json` argv is now asserted exactly (including the `--account <X>` tail when `op_account` is configured); a regression that drops `--account`, reorders `--vault`, or changes the `F=value` assignment shape will fail at test time rather than silently passing.
- **Internal:** `delete_runs_edit_with_empty_value` simplified — the args-log side-channel that verified the empty `F=` assignment is now obsolete because the declared argv token `F=` IS the assertion under strict match.
- **Internal:** two new drift-catch regression-lock tests (`get_drift_catch_rejects_missing_account_flag`, `set_drift_catch_rejects_missing_vault_flag`) that prove the strict harness surfaces drift loudly when it occurs.
- **Internal (one exception):** `get_non_utf8_response_errors_with_context` stays on the v0.2 raw `install_mock` harness because its assertion relies on a non-UTF-8 response, which the strict harness's `Response.stdout: String` cannot express. Documented inline; same carve-out as aws-ssm in v0.2.3.

### Fixed

- **None.** The retrofit surfaced no prod bugs in the 1password backend. Version-gating for the `set` stdin path (tracked in the backend's CV-1 comment) remains a v0.3 follow-up — not yet implemented, so no strict-mode coverage added for it.

## [0.2.3]

**Headline:** internal test-infrastructure release — aws-ssm backend's mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Changed

- **Internal:** all 14 mock-using tests in `secretenv-backend-aws-ssm` converted from the v0.2 raw `install_mock_aws(body)` API to declarative `StrictMock::new("aws").on(argv, Response).install(...)`. Every flag, positional, and value in every `aws` argv is now asserted exactly; a future refactor that drops `--with-decryption`, reorders `--region`/`--profile`, or reintroduces the CV-1 argv-leak regression will fail at test time rather than silently passing.
- **Internal:** `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin`. CV-1 discipline is now a typed harness assertion rather than a log-file grep.
- **Internal:** two new drift-catch regression-lock tests (`get_drift_catch_rejects_missing_with_decryption_flag`, `set_drift_catch_rejects_secret_leaking_to_argv`) that prove the strict harness surfaces drift loudly when it occurs.
- **Internal (one exception):** `get_non_utf8_response_errors_with_context` stays on the v0.2 raw `install_mock` harness because its assertion relies on a non-UTF-8 response, which the strict harness's `Response.stdout: String` cannot express. Documented inline.

### Added

- **`secretenv-testing`:** `Response::with_stderr(stderr)` chainable method for expressing "response emits on stderr, not stdout." Additive; `#[non_exhaustive]` policy honored.

## [0.2.2]

**Headline:** internal test-infrastructure release — strict-mode mock harness for backend crates. No user-facing CLI changes.

### Added

- **`secretenv-testing::StrictMock`** — declarative mock-CLI builder.
  `StrictMock::new(bin).on(argv, Response).install(dir)` generates a
  POSIX shell script that matches the full joined argv against a rule
  list and exits 97 on no-match with a diagnostic naming the observed
  argv and every declared shape. Closes the gap that let the v0.2.0
  vault flag-order bug and aws-secrets leading-slash bug ship through
  `cargo test --workspace` green. `Response::success`,
  `Response::failure`, and `Response::success_with_stdin` (for testing
  the CV-1 stdin-delivery discipline) cover the response shapes
  backend tests need. Types are `#[non_exhaustive]` so future
  matchers (`PositionalThenFlags`, `Regex`, env-var assertions) can
  land additively as concrete backend retrofits need them.
- `crates/secretenv-cli/tests/e2e.rs` — two end-to-end scenarios
  proving `StrictMock` works in anger through the full secretenv call
  chain: one happy-path exercising exact argv match, one drift-catch
  asserting exit 97 surfaces a clear diagnostic naming the missing
  flag. These will serve as the reference pattern for the per-backend
  retrofits in v0.2.3 → v0.2.6.
- `secretenv-backend-local` crate-level doc note explaining why the
  v0.2.2 strict-mode retrofit covers it by documentation only — the
  backend does not shell out, so there is no argv surface to validate.

### Changed

- **Internal only:** strict-mode harness test infrastructure. No CLI
  behavior, URI grammar, or backend semantics changed. Users upgrading
  will see no difference.

## [0.2.1]

**Headline:** canonical `#key=value` fragment grammar. One deliberate pre-launch breaking change that locks the URI vocabulary before public eyes see the v0.2.0 shorthand form.

### Changed — BREAKING (pre-launch correction window)

- **Fragment grammar canonicalized.** URI fragments now must match
  `#key=value[,key=value]*` under a single grammar enforced by
  `BackendUri::fragment_directives()` in `secretenv-core`. Each backend
  declares the directive keys it recognizes; unknown keys error with
  the full URI and a list of recognized directives. See
  [`docs/fragment-vocabulary.md`](docs/fragment-vocabulary.md) for the
  grammar and the per-backend directive registry.
- **aws-secrets**: `#<field>` shorthand (v0.2.0) → `#json-key=<field>`
  canonical (v0.2.1). The shorthand is rejected at URI-parse time with
  a `ShorthandRejected` error that names the canonical replacement
  literally (e.g. `aws-secrets:///db#password` fails with a hint
  suggesting `aws-secrets:///db#json-key=password`). The backend
  recognizes only `json-key`; any other directive — alone or alongside
  `json-key` — surfaces as a single error listing every offender.

  This is the only deliberate breaking change permitted inside a 0.2.x
  patch. It was taken before public launch while the install base was
  zero (v0.2.0 tag was ~1 day old; Show HN not yet posted). Post-launch,
  0.x.y patches remain non-breaking per standard semver.

### Added

- `BackendUri::fragment_directives()` — typed accessor that parses
  the fragment body into a directive map per the canonical grammar.
  `FragmentError` (re-exported from `secretenv_core`) reports
  `ShorthandRejected`, `Malformed`, and `DuplicateKey` with enough
  context for a caller to produce a helpful user-facing message.
- Canonical grammar doc at `docs/fragment-vocabulary.md` (user-facing)
  and `kb/wiki/fragment-vocabulary.md` (project wiki). Both include
  the directive registry and the migration table for v0.2.0 shorthand
  URIs.

### Migration

| v0.2.0 (removed) | v0.2.1+ (canonical) |
|---|---|
| `aws-secrets-prod:///db-creds#password` | `aws-secrets-prod:///db-creds#json-key=password` |
| `aws-secrets-prod:///db-creds#host` | `aws-secrets-prod:///db-creds#json-key=host` |

If an error message in your logs mentions "legacy plain-string shorthand", rewrite the cited URI per the table above. No config or registry changes needed beyond the URI bodies.

## [0.2.0] - 2026-04-18

**Headline:** 2 new backends (Vault, AWS Secrets Manager), cascading registries, parallel secret fetch, shell completions, enriched `resolve` report, per-cascade-source doctor, shared `secretenv-testing` crate, and a 7-item security preflight. 13 PRs (#22–#34) from scaffolding to tag.

### Added

- **Shell completions.** New `secretenv completions <bash|zsh|fish>`
  subcommand emits a completion script generated from clap's command
  tree. Writes to `--output <path>` (chmod 0o644) or stdout. When
  stdout is a TTY, a shell-specific install hint is printed to
  stderr; when redirected (the usual `... > _secretenv` pipeline)
  stderr stays silent. PowerShell/Elvish deliberately omitted from
  v0.2 — no reason to carry the surface preemptively.
- **AWS Secrets Manager backend** (`type = "aws-secrets"`). Wraps the
  same `aws` CLI as `aws-ssm` — auth story is identical (every
  profile / SSO / IAM-role flow works unchanged). URI shape:
  `aws-secrets-<instance>:///<secret-id>[#<json-key>]`. First consumer
  of the `BackendUri.fragment` field added in Phase 0.5 RE-2:
  `#<json-key>` extracts a top-level field from a JSON-valued secret,
  coercing scalars (string/number/boolean/null) to strings and
  erroring on nested objects/arrays with the available field names
  listed so operators can correct the URI. `set` pipes through child
  stdin via `--secret-string file:///dev/stdin` (CV-1 discipline);
  `delete` is unconditionally `--force-delete-without-recovery` to
  keep semantics symmetric with aws-ssm/vault. Update-only — creating
  new secrets requires `aws secretsmanager create-secret` (deferred
  to v0.3 alongside `SecretBinary` + nested-field extraction). 26
  mock-CLI tests cover every row of the spec's harness table.
- `secretenv setup` routes `aws-secrets(-*)` schemes to the new
  backend type; `--region` + `--profile` flags apply to both AWS
  backends identically.
- **HashiCorp Vault backend** (`type = "vault"`). Wraps the `vault` CLI
  — every auth flow the CLI supports (`VAULT_TOKEN`, `AppRole`, OIDC,
  Kubernetes, AWS IAM) works transparently with no secretenv auth
  surface. URI shape: `vault-<instance>://<mount>/<path>`. Uses the
  unified `vault kv` CLI so KV v1 and KV v2 mounts work identically
  (the CLI handles `data/` segment injection for v2 internally). `get`
  uses `-field=value` for trim-one-newline single-value semantics;
  `set` pipes the secret through child stdin via `value=-` (CV-1
  discipline — the secret never appears on argv). Level 2 doctor
  check uses `vault token lookup` (vs `vault status` which succeeds
  with no token). Supports Vault Enterprise namespaces via optional
  `vault_namespace` config field — the `-namespace` flag is omitted
  when unset because open-source Vault rejects it. 25 mock-CLI tests
  cover every row of the spec's harness table.
- `secretenv setup` gains `--vault-address` and `--vault-namespace`
  flags. Scheme prefixes `vault` and `vault-*` map to the vault
  backend type.
- **Session-scoped registry cache.** New `secretenv_core::RegistryCache`
  memoizes `backend.list(source)` results by source URI for the life of
  a process. `resolve_registry` takes `&mut RegistryCache` and only
  issues a backend call on cache miss; subsequent references to the
  same source return a zero-I/O `Arc<CascadeLayer>`. Within a single
  `resolve_registry` call, the cache is warmed concurrently via
  `futures::future::join_all` so Phase 1's cascade parallelism is
  preserved. The cache holds alias-to-URI pointers only — secret
  values are never cached.
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

- **`secretenv doctor`** gains a `Registries` section that reports
  per-source reachability for every cascade source in `config.toml`.
  Each source line shows ✓/✗ + the source URI + a one-word suffix
  (`reachable` / `backend not authenticated` / `backend CLI 'x' missing`
  / `backend error`); non-OK sources render an indented `→ <hint>`
  with the actionable remediation. A single backend-instance status
  feeds every source that uses it (no duplicate `check()` calls).
  `--json` gains a top-level `registries: [{name, sources: [{uri,
  status, hint}]}]` key. `skip_serializing_if = "Vec::is_empty"`
  means consumers of the v0.1 doctor JSON shape see no new key when
  no registries are configured — backward-compatible.
- **`doctor` exit code still driven by backend-level summary only.**
  A backend failure already propagates to every source that uses it,
  so doubling the signal at the source level would double-count.
  Registry section is informational.
- **`secretenv resolve <alias>`** now emits a tabular metadata report
  instead of printing only the resolved URI. Rows: `alias`, `env var`
  (reverse-lookup from the manifest, `(none)` if unused),
  `resolved` (target backend URI), `source` (cascade layer URI + the
  layer index), and `backend` (one-line Level 2 status of the target
  backend instance — doubles as a lightweight pre-flight check). New
  `--json` flag emits the same data as structured JSON for editor /
  IDE consumers. Manifest loading is best-effort: a missing
  `secretenv.toml` no longer blocks resolve, it just sets `env_var`
  to `(none)`. Backend check failure does not fail resolve — the
  mapping is still printed so operators can debug auth separately.
- **`resolve_registry` signature.** Added a `cache: &mut RegistryCache`
  parameter. Callers must now construct a `RegistryCache::new()`
  (typically per command) and pass it through. Breaking change for
  anyone consuming `secretenv-core` as a library.
- **`AliasMap` internals.** Layers are now held as
  `Vec<Arc<CascadeLayer>>` instead of `Vec<CascadeLayer>`.
  `AliasMap::layers()` returns `&[Arc<CascadeLayer>]`. Enables
  shared-layer semantics between the cache and returned maps with
  zero deep clones.
- **Backend crate directories** renamed to match their published
  crate names: `crates/backends/backend-local` →
  `crates/backends/secretenv-backend-local` (and same for
  `aws-ssm`, `1password`). The v0.1 crates.io-prep rename deliberately
  left the directories unchanged; aligning them removes the
  path-vs-package-name inconsistency that was tripping readers. The
  CLI directory (`crates/secretenv-cli/`) stays as-is — it publishes
  as plain `secretenv` so `cargo install secretenv` lines up with the
  binary name.
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

- **Extracted `secretenv-testing` crate** (unpublished). The `install_mock`
  shell-script writer with its Linux ETXTBSY probe loop previously lived
  in three separate locations (`backend-aws-ssm/src/lib.rs`,
  `backend-1password/src/lib.rs`, `secretenv-cli/tests/e2e.rs`). All
  three now call into the shared crate. Public surface is
  `install_mock(dir, bin_name, body) -> PathBuf` plus thin
  `install_mock_aws` / `install_mock_op` wrappers. `publish = false`
  for v0.2 — revisit once Phase 5 (Vault) + Phase 6 (AWS Secrets
  Manager) have proven the API shape.
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

[Unreleased]: https://github.com/TechAlchemistX/secretenv/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.3
[0.2.2]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.2
[0.2.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.1
[0.2.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.0
[0.1.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.1.1
