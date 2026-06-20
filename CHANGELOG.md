# Changelog

All notable changes to SecretEnv are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Dates are `YYYY-MM-DD` (UTC).

Alongside the standard sections (Added, Changed, Deprecated, Removed, Fixed, Security), releases from v0.14.0 onward use a `Known limitations` subsection for behavior that ships honestly but is incomplete by design.

## [0.19.0] - 2026-06-14

Second non-backend hardening minor (hardening #2), consuming the v0.18 carry-forward queue and the deferred post-release documentation phase; no new backends (total 15), no new crates (workspace count 24); live-backend smoke 779 PASS / 0 FAIL / 2 expected SKIP across all 15 backends.

### Added
- `--otel-include-error-detail` now live: a failed `secretenv.backend.fetch` emits the scrubbed `secretenv.backend.error.message` span attribute when set (default OFF, attribute absent otherwise); raw error chain passes through the `BackendErrorStderr` scrubber (its only constructor); new `#[tokio::test]` `sec_f5_error_detail_emitted_only_when_opted_in` in `secretenv-core::runner` uses `LocalTraceCapture` to assert present-when-ON/absent-when-OFF; section 36 Block G adds 3 live smoke assertions (1289-1291).

### Changed
- `OperatorDecision` marker-type family split (BREAKING): `OperatorDecision` retained as neutral on-disk serde union (audit log + JSON-Lines unchanged, including the `"dryrun"` lowercase rename); two new marker types `MutationOperatorDecision` (`Approved`/`Denied`/`Timeout`/`AutoApproved`, no `DryRun`) and `MigrateOperatorDecision` (those four plus `DryRun`); new `Decision` trait (`to_audit() -> OperatorDecision`) is the single projection point; the 4 dead `Ok(OperatorDecision::DryRun)` match arms in `mutation_runner.rs` + `tools/mod.rs` deleted.
- `SecretEnvSpan::record_migrate_source_backend_type` and `record_migrate_dest_backend_type` now take `BackendType` (were `&str`); migrate call sites wrap runtime strings via `BackendType::from_runtime_str`; typed-setter total on `SecretEnvSpan` is 57 (BREAKING).
- `LocalTraceCapture::install` uses an `InstalledFlagGuard` RAII guard: clears the `INSTALLED` `AtomicBool` on unwind if OTel-SDK setup panics mid-install; `disarm()` hands ownership to the capture's `Drop` on success; no public-API change.
- Internal `build_env`/`fetch_one` gained an `otel_include_error_detail: bool` parameter for the wire-up (private functions, not a public-API break).
- `secretenv.backend.probe.{level,outcome}` vocabularies unified (partial, BREAKING): span-side enums `BackendProbeLevel` (`connectivity`/`full`) and `BackendProbeOutcome` (`success`/`timeout`/`permission_denied`/`error`) removed; the metric enums `ProbeLevel` (`l1-cli`/`l2-auth`/`l3-read`) and `ProbeOutcome` (`ok`/`cli-missing`/`not-authenticated`/`registry-unreachable`/`timeout`/`unknown`) are now the single vocabulary for both span and metric; the run-path `secretenv.backend.probe` span now emits `l3-read` and `ok`/`unknown`; metric path stays unwired pending v0.20.

### BREAKING
- `SecretEnvSpan::record_migrate_source_backend_type(BackendType)` (was `&str`): pass a `BackendType` variant or `BackendType::from_runtime_str(s)`.
- `SecretEnvSpan::record_migrate_dest_backend_type(BackendType)` (was `&str`): same migration path.
- `SecretEnvSpan::record_backend_probe_level(ProbeLevel)` (was `BackendProbeLevel`, now removed): pass a `ProbeLevel` variant (`L1Cli`/`L2Auth`/`L3Read`).
- `SecretEnvSpan::record_backend_probe_outcome(ProbeOutcome)` (was `BackendProbeOutcome`, now removed): pass a `ProbeOutcome` variant (`Ok`/`CliMissing`/`NotAuthenticated`/`RegistryUnreachable`/`Timeout`/`Unknown`).
- `secretenv-mcp` `OperatorDecision` family split: `enforce_mutation_policy` now returns `MutationOperatorDecision` (no `DryRun` variant); `audit_migrate` now takes `MigrateOperatorDecision`; `echo_decision` is now generic over `impl Decision` (call `.to_audit()` for the on-disk `OperatorDecision` union).

### Fixed
- `aggregate_errors` now panics explicitly on empty input: the `len() == 1` guard previously skipped `swap_remove` so empty input fell through to a malformed `"0 secrets failed"` object; added `assert!(!errors.is_empty(), ...)`, corrected the CONTRIBUTING exemplar, added a `#[should_panic]` test.

### Security
- The backend error-message scrubber gains a scheme-less userinfo arm: prior arms left a scheme-less `user:secret@vault.internal:8200/path` fragment intact when the password was under 32 chars; new optional `(?:[^\s'"/@]+@)?` userinfo-prefix arm added to the two bare-host arms, gated by the same port-or-path requirement; +2 regression tests; distinct from the v0.18 fix.

### Documentation
- `docs/reference/opentelemetry.md` §2/§3 note on `secretenv.backend.error.message` updated to reflect it is now live when `--otel-include-error-detail` is set.
- README OTel section corrected from "traces, metrics, and logs" to "traces and metrics" (logs signal deferred to v0.20).
- Rustdoc fixes: `record_migrate_source_backend_type`/`record_migrate_dest_backend_type` doc softened to "a typo'd literal at the call site cannot reach the attribute"; `echo_decision` doc no longer states "two enums"; `fresh_run_id` doc softened.
- CONTRIBUTING: new subsection documenting the make-illegal-states-unrepresentable + `Decision`-trait marker-type idiom.

### Known limitations
- OTel `LoggerProvider` not installed: `tracing::*!` events surface as span events via the `tracing-opentelemetry` bridge, not native OTel `LogRecord`. Deferred to v0.20.
- Flat span topology: `secretenv.run` and children emit as siblings, not a parent-child tree. Deferred to v0.20 pending a `BoxedSpan` exposure decision.
- `secretenv.exec.flush` schema-reserved span not emitted: Drop cannot fire across `execve`; needs `pre_exec` hook + manual flush. Deferred to v0.20.
- Pre-existing: migrate early-error paths log `AutoApproved` before the policy gate ran; the rename preserved this v0.18 behavior; needs a design decision. Deferred to v0.19.x / v0.20.
- OTEL-SMOKE-CI-HARDENING: section 36 not in the `--local-only`/CI gate; 3 pre-existing flush-timing flakes (assertions 1210/1283/1237) block reliable CI execution; still runs on a full smoke and via `--sections 36`. Own-cycle fix deferred.

## [0.18.0] - 2026-06-03

Named non-backend hardening minor consuming the ~25-item carry-forward queue from the v0.17 OpenTelemetry cycle (modeled on v0.4); no new backends (total 15), workspace crate count stays 22; ships ~5 deliberate pre-launch BREAKING public-API changes; live-backend smoke 796 PASS / 0 FAIL / 3 expected SKIP across all 15 backends.

### Added
- `--otel-include-error-detail` flag on `secretenv run` (and `RunOptions::otel_include_error_detail`): opt-in toggle to emit scrubbed backend stderr on `secretenv.backend.error.message` span attribute (default OFF, attribute absent); reserved in v0.18.0 (flag, scrubber, typed setter all ship but no production caller emits yet, wire-up tracked for a later release).
- `BackendErrorStderr` newtype + shape scrubber (`secretenv_telemetry::BackendErrorStderr`, re-exported from `secretenv_core`): three-pass conservative regex set strips URI shapes, AWS 12-digit account IDs, and high-entropy tokens (32+ chars); the newtype's only constructor is the scrubber.
- `SecretEnvSpan::record_backend_error_message_scrubbed(&BackendErrorStderr, opt_in: bool)` typed setter: opt-in emits the scrubbed payload, opt-out leaves the attribute absent; setter count grows 38 to 39.
- `LocalTraceCaptureError` typed-error enum with `AlreadyInstalled` variant, returned by `LocalTraceCapture::install`.
- `MutationSpanName` closed enum (`secretenv_telemetry::span::MutationSpanName`): 8 variants (4 MCP mutation tools + 4 migrate phases); `as_str()` returns canonical OTel name, `all()` returns every variant.
- `SecretEnvSpan::start_mutation(MutationSpanName) -> (Self, SpanGuard)` typed constructor: sole entry point for starting mutation spans.
- `SecretEnvCommand` closed enum (`secretenv_telemetry::span::SecretEnvCommand`): 7 variants (Run/Get/Migrate/Doctor/Redact/Mcp/Registry), `#[non_exhaustive]`.
- `BackendType` closed enum (`secretenv_telemetry::span::BackendType`): 15 canonical backend variants + `Unknown(String)` fallback; `BackendType::from_runtime_str(&str)` parses a `Backend::backend_type()` return.
- `[mcp].allow_cli_overrides` config knob (default `true`): when `false`, user-scope vetoes per-IDE profile argv overrides (e.g. Gemini's `--allow-mutations=always`), rendered IDE configs strip suppressed args + emit a `tracing::warn!`; new public `secretenv_mcp::setup::render_config_with_overrides(profile, binary, allow_cli_overrides)`.
- `secretenv mcp setup --check-overrides`: read-only operator-discovery subcommand scanning every supported IDE config path, reporting present SecretEnv MCP argv overrides + which would be vetoed; mutually exclusive with all other `mcp setup` flags.
- `OperatorDecision::DryRun` + `OperatorDecisionEcho::DryRun` variants: migrate audit log now records a dedicated entry for `dry_run = true` migrations.
- `SecretEnvSpan::record_migrate_collapsed(bool)` setter + policy entry: forward-compat slot for dual-control collapse detection, emitted as `false` in v0.18 (no backend exposes atomic `cas_set` yet).
- 5 schema-reserved OTel spans now emit (5 of 6): `secretenv.manifest.load` (`Manifest::load_from`), `secretenv.registry.load` (`resolve_registry`), `secretenv.backend.probe` (`fetch_one`), `secretenv.exec.prepare` (`exec_with_env`), `secretenv.doctor.registry` (`run_doctor` per-registry cascade-reachability pass).
- 5 new closed enums for schema-reserved attributes, all `#[non_exhaustive]`: `ManifestOutcome` (Ok/NotFound/ParseError/ValidationError), `RegistrySelectionKind` (ByName/Uri), `BackendProbeLevel` (Connectivity/Full), `BackendProbeOutcome` (Success/Timeout/PermissionDenied/Error), `DoctorCheckLevel` (Quick/Standard/Extensive).
- 13 new typed setters on `SecretEnvSpan` for schema-reserved span attributes: `record_manifest_path_relative`, `record_manifest_alias_count`, `record_manifest_default_count`, `record_manifest_outcome`, `record_registry_selection`, `record_registry_source_count`, `record_registry_source_index`, `record_backend_probe_level`, `record_backend_probe_outcome`, `record_backend_fetch_attempt`, `record_doctor_check_level`, `record_doctor_backend_count`, `record_doctor_failure_count`; setter count grows 39 to 52.

### Changed
- `LocalTraceCapture::install()` returns `Result<Self, LocalTraceCaptureError>` (was `-> Self`): module-level `INSTALLED: AtomicBool` guard prevents a second live install from swapping the global `TracerProvider`; Drop clears the flag; the `secretenv doctor --trace` call site bubbles via `anyhow`.
- `TelemetryGuard::Drop` is now bounded at 1s via a worker-thread + `recv_timeout` pattern (extracted as private `run_bounded_or_detach(timeout, work)`, shared with `flush_before_exec`); CTRL-C against `secretenv run` with a slow OTLP collector no longer hangs; on timeout the worker detaches and a `tracing::warn!` fires.
- `MutationNonDroppableSampler::is_mutation_span()` walks `MutationSpanName::all()` instead of a hand-maintained `&[&str]` allowlist (removed); the closed enum is the single source of truth; migrated all 8 mutation call sites in `secretenv-migrate` + `secretenv-mcp::tools` to `start_mutation`.
- `resolve_confirm_via` returns `Result<ResolvedConfirmVia>` (was `Result<ConfirmVia>`): new internal closed enum `ResolvedConfirmVia` mirrors every `ConfirmVia` variant except `Auto`, eliminating the v0.17 `unreachable!`; `OperatorDecision` and `OperatorDecisionEcho` both gain `#[non_exhaustive]`.
- `secretenv_telemetry::init` signature is now `init(service_version: &str) -> Result<TelemetryGuard, InitError>` (was `init()`): `service.version` resource attribute now flows from the calling binary's `env!("CARGO_PKG_VERSION")` (BREAKING).
- `InitError::Exporter` carries a structured cause: `InitError::Exporter(#[from] opentelemetry_otlp::ExporterBuildError)` instead of `Exporter(String)`; `InitError` also gains `#[non_exhaustive]`.
- `init_with_env` is `#[doc(hidden)]`: still `pub` but absent from public rustdoc (test-injection seam).
- `LocalTraceSpan` is `#[non_exhaustive]`: adding fields like `trace_id` in v0.19+ is no longer breaking.
- `SecretEnvSpan::record_command` takes `SecretEnvCommand` (was `&str`); 3 call sites migrated.
- `SecretEnvSpan::record_backend_type` takes `BackendType` (was `&str`); 3 call sites migrated.
- `fresh_run_id()` fallback is no longer all-zeros: when `getrandom` fails it emits a `tracing::warn!` once per process and returns a process+time-derived hex string from `process::id()` XOR low/high 64 bits of `SystemTime::now()` nanos; the v0.17 all-zero sentinel is gone.

### BREAKING
- `secretenv_telemetry::init()` to `init(service_version: &str)`: migrate to `init(env!("CARGO_PKG_VERSION"))`.
- `LocalTraceCapture::install()` now returns `Result<Self, LocalTraceCaptureError>` (was `-> Self`): handle/propagate the `AlreadyInstalled` error via `?`.
- `InitError::Exporter(#[from] opentelemetry_otlp::ExporterBuildError)` (was `Exporter(String)`), `InitError` now `#[non_exhaustive]`: match on the structured cause and add a wildcard arm.
- `SecretEnvSpan::record_command(SecretEnvCommand)` (was `&str`): pass a `SecretEnvCommand` variant.
- `SecretEnvSpan::record_backend_type(BackendType)` (was `&str`): pass a `BackendType` variant or `BackendType::from_runtime_str(s)`.

### Fixed
- `secretenv.manifest.path` no longer leaks an absolute path when the manifest path has no filename component (`/`, `..`, empty): `Manifest::load_from` emits a `<no-basename>` sentinel.
- The backend error-message scrubber now strips bare `host:port` clusters without a trailing path (e.g. `vault.prod.internal:8200`): prior URI regex required a `/path` suffix; new arm gated on a literal port to avoid over-stripping dotted prose.
- `OperatorDecision::DryRun` contract-violation arms are now observable: non-migrate MCP tool arms treating a `DryRun` decision as a violation now populate `error_message` and append an audit-log entry instead of refusing silently.
- `resolve_confirm_via` no longer silently absorbs unknown `ConfirmVia` variants: the `ConfirmVia::Auto | _` wildcard split into explicit `Auto` arm plus a `_` arm erroring with a build-version-mismatch message; sibling `AllowMutations` consumer gains the same guard.

### Security
- Stderr-in-otel regression test: `crates/secretenv-telemetry/tests/ts12_stderr_in_otel.rs` passes a backend stderr containing `vault.prod.internal:8200/v1/secret/payments/stripe` through the setter with `opt_in = true` and asserts URL fragment + path segments + literal URL + port + scheme are absent from the emitted attribute; opt-out arm asserts the attribute is absent entirely.
- `MutationSpanName` structural binding regression test: `crates/secretenv-telemetry/tests/mutation_span_name_structural_binding.rs` walks every `MutationSpanName::all()` variant through `start_mutation` against an `AlwaysOff` inner sampler and asserts the non-droppable wrapper force-records each; plus a predicate-only test and a negative-coverage test on 8 non-mutation names.

### Hardening
- 6 `as u64` truncating casts changed to `u64::try_from(...).unwrap_or(u64::MAX)` in `secretenv-core::runner`.
- Duplicate `fetch_ms` recomputation in `fetch_one` collapsed: the probe/fetch block returns `(fetch_result, ms)`; the outer scope reuses `fetch_ms` for metric emission.
- `MigrationPlan.transaction_id` doc comment documenting the move-into-`MigrateReport` invariant.
- `RegistrySelection::registry_label()` kept as `Option<&str>`; new companion `registry_label_for_telemetry() -> &str` returns the `REGISTRY_NAME_DIRECT_URI` sentinel for direct-URI selections.
- `LocalTraceCapture::drain` saturation behavior documented (`try_from` saturates at `u64::MAX` for post-year-584-million `SystemTime`; `map_or(0, ...)` covers pre-epoch clock skew).
- `_guard` lifetime comment on the `secretenv.redact.filter_event` span site to prevent future remove-as-unused.
- `secretenv_telemetry::REGISTRY_NAME_DIRECT_URI` + `PROCESS_COMMAND_NAME_EMPTY` constants lift the v0.17 `"<direct-uri>"` and `"<empty>"` magic strings.
- `SpanGuard._private: ()` keep decision documented: the sealing is load-bearing against external crates.
- `doctor.rs::probe_otel_reachability` honors `OTEL_EXPORTER_OTLP_PROTOCOL`: `http/protobuf` and `http/json` select port 4318, anything else keeps the 4317 default.
- `host.name` FQDN documentation note added to `docs/reference/opentelemetry.md` §2 attribute matrix.
- Dead typed-setter keep decision: `record_alias_count`, `record_cascade_layer_index`, `record_backend_cli_name`, etc. retained as spec'd ALLOW surface for future callers.

### Documentation
- `docs/reference/opentelemetry.md` attribute-matrix accuracy fixes: `secretenv.backend.probe.level` documented as `connectivity`/`full` (was `l1_cli`/`l2_auth`/`l3_read`); `secretenv.registry.selection` as `by_name`/`uri` (was `named`/`direct-uri`); `secretenv.manifest.path` clarified as basename-only with `<no-basename>` sentinel; §6 mutation-span set completed with `secretenv.migrate.delete` + a note that `secretenv.migrate.probe` is read-only and excluded.
- `host.name` FQDN leakage note added to §2 of the attribute matrix (also under Hardening).
- `--otel-include-error-detail --help` clarified to state the flag is reserved in v0.18.0 (parses + scrubber ships, no production caller emits yet).

### Known limitations
- OTel `LoggerProvider` not installed: `tracing::*!` events surface as span events via the `tracing-opentelemetry` bridge, not native OTel `LogRecord`. Deferred to v0.19+.
- Flat span topology: `secretenv.run` and children emit as siblings, not a parent-child tree. Deferred to v0.20 pending a `BoxedSpan` exposure decision.
- `secretenv.exec.flush` schema-reserved span not emitted: Drop cannot fire across `execve`; needs `pre_exec` hook + manual flush. Deferred to v0.20 (the other five schema-reserved spans ship in v0.18).
- Typed-setter coverage: ~13 of the spec's ALLOW attributes still have no `SecretEnvSpan` setter; each lands in the cycle that wires its first caller.

## [0.17.0] - 2026-05-28

First-class OpenTelemetry instrumentation: traces and metrics across resolution, redact, migrate, and MCP surfaces with zero startup cost when no `OTEL_*` env vars are set; backend total stays at 15; adds the `secretenv-telemetry` crate (first OTel-enabled publish) with 38 typed `SecretEnvSpan` setters and 10 metric instruments.

### Added
- OpenTelemetry traces: `secretenv.run` root span wrapping resolution + exec, with `secretenv.resolution` (per-alias) and `secretenv.backend.fetch` (per-fetch) children; ends before `execve`; attrs `run.dry_run`/`run.verbose`/`run.outcome`/`run.failed_alias_count`, `resolution.outcome`/`resolution.latency_ms`, `backend.fetch.outcome`/`backend.fetch.duration_ms`.
- OpenTelemetry metrics: 10 typed instruments: `resolution.duration`, `resolution.count`, `backend.fetch.duration`, `backend.probe.count`, `redact.events`, `mcp.tool.calls`, `mcp.tool.duration`, `doctor.failure.count`, `migrate.operation.count`, `registry.alias_count` gauge; `alias.name` structurally absent from every histogram/gauge.
- Redact span emission (`secretenv.redact.filter_event`): one span per non-empty stdout/stderr stream in runtime-pipe mode, one on the post-hoc `secretenv redact <file>` path; carries `mode`, `stream`, `match_count`, `byte_count`; `redact.alias_name` never emitted.
- Migrate phase tree: `secretenv.registry.migrate` root plus 5 children (`probe`/`read`/`write`/`pointer_flip`/`delete`); mutation non-droppable sampler keeps every child + root under aggressive sampling.
- MCP tool spans: all 14 tools emit `secretenv.mcp.tool.<name>` with `tool_name`, `client_name`, and `argument_alias_name` for the 4 alias-mutation tools (`set_alias`/`delete_alias`/`migrate_alias`/`gen_password`); `argument_reason` never emitted.
- Mutation non-droppable sampler: `MutationNonDroppableSampler<S>` forces `RecordAndSample` for the 8 mutation span names (4 MCP + 4 migrate); override-safe against `OTEL_TRACES_SAMPLER=traceidratio OTEL_TRACES_SAMPLER_ARG=0.0001`.
- Doctor OTel surfaces: `secretenv doctor --extensive` reports `OTEL_EXPORTER_OTLP_ENDPOINT` + TCP-connect reachability; `secretenv doctor --trace` renders a local-capture span table via in-process `InMemorySpanExporter`.
- `secretenv run --verbose`: per-alias resolution timing table on stderr.
- W3C TRACEPARENT propagation: inbound only; `secretenv.run` becomes child of the parent trace when `TRACEPARENT`/`TRACESTATE` set; outbound deferred to v1.0+.
- Section 36 smoke harness (`scripts/smoke-test/run-tests.sh`, ~430 LOC, Blocks A-E); Docker Jaeger collector lifecycle (`scripts/smoke-test/lib/otel-collector.sh`); fixture `scripts/smoke-test/fixtures/v0.17-otel/`; 60 assertions; soft-SKIPs when `docker`/`jq` missing.
- Compile-fail no-leak guards: trybuild gates at `crates/secretenv-telemetry/tests/ui_sec_inv_04/`, `ui_sec_inv_12/`, `ui_sec_inv_19/`; CI grep gate `scripts/check_tracing_leaks.sh` extended with 7 leak patterns.

### Changed
- Span topology: `secretenv.registry.migrate` (was `secretenv.migrate`); mutation sampler whitelist updated to match.
- `SecretEnvSpan` typed builder: 13 new `record_*` methods totalling 38 typed setters; one method per ALLOW attribute, none for DENY; no generic `set_attribute(k, v)`.
- `RunOptions` is now `#[non_exhaustive]`.

### BREAKING
- Migrate span renamed `secretenv.migrate` to `secretenv.registry.migrate`; update OTel queries/dashboards referencing the old name.
- `RunOptions` gains `#[non_exhaustive]`; downstream direct-struct constructors must switch to `..Default::default()` or the builder; within-workspace callers unaffected.

### Security
- The typed-builder no-leak guarantee holds across v0.17: 5 new DENY attributes (`run.command_argv`, `run.env_var_value`, `registry.source_uri`, `backend.namespace`, `gen.password.{value,entropy_bits}`) have no setter; enforced via typed builder + 4 compile-fail guards + CI grep gate.
- Three no-leak invariants verified: `mcp.argument_reason`, `redact.alias_name`, and the 8 mutation span names, checked by live smoke + integration tests.
- `secretenv.run.command_name` is basename of argv[0] only; path prefixes stripped before emission.

### Known limitations
- `--otel-include-error-detail` flag not yet shipped; `backend.error.message` ships as unconditionally DENY (no `record_error_message` setter); lands in v0.18.
- Logs signal not installed: v0.17 installs `TracerProvider` + `MeterProvider`; `LoggerProvider` reserved for v0.17.x/v0.18; `tracing::*!` events surface as span events via the bridge.
- 11 spec-listed spans schema-reserved, not emitted: `secretenv.manifest.load`, `secretenv.registry.load`, `secretenv.backend.probe`, `secretenv.exec.prepare`, `secretenv.exec.flush`, `secretenv.doctor` root, `secretenv.doctor.registry`, `secretenv.mcp.policy.evaluate`, `secretenv.mcp.confirm`, `secretenv.registry.transaction`, `secretenv.audit.append`; `execve` handoff covered by explicit `flush_before_exec`; lands in a later v0.17.x release; no security-invariant impact.
- Span parent-child relationships are flat: each span started independently via `SecretEnvSpan::start(...)` without context attach; tree-shape lift deferred to v0.17.x; mutation non-droppability is unaffected.

### v0.16.2 - Refactor sprint (merged-not-tagged) - in progress

Carries the three substantive refactors v0.16.1 deferred (each adds new public crate/subcommand surface needing an audit) plus the Copilot empty-schema fixture.

- `run_mutation` combinator (module in `secretenv-mcp`) collapses ~120 LOC of policy-gate + audit-log boilerplate across `set_alias`/`delete_alias`/`init_project`; `redact_file`/`gen_password`/`migrate_alias` kept as-is; retired `should_audit` helper.
- New `secretenv-registry-mutate` crate extracting the `list + edit + serialize + set` transaction body duplicated by `secretenv-cli` (`registry_set`/`registry_unset`) and `secretenv-mcp` (`registry_writer`); CLI + MCP keep their own selection helper but share the writer; workspace + release.yml publish-list update.
- `audit_log.rs` `flock(LOCK_EX)` around every append, size rotation at `[mcp].audit_log_max_bytes` (default 10 MiB; 0 disables) with `[mcp].audit_log_max_rotations` cap (default 5; 0 truncates), new `secretenv mcp audit tail [--lines N] [--path PATH]` subcommand.
- New `secretenv-mcp-config` crate lifting the typed `[mcp]` schema (`AllowMutations`, `ConfirmVia`, `McpConfig`, `PolicyOverrides`) out of `secretenv-mcp`; backward-compat re-exports preserve `secretenv_mcp::config::*`; workspace + release.yml publish-list update.
- Copilot empty-schema A/B test prep: operator-led fixture at `scripts/smoke-test/fixtures/vscode-mcp-copilot/`; no source-level change to `MutationApproval` in v0.16.2.

Pending in v0.16.2: audit trio, live-backend smoke, PR + squash-merge.

## [0.16.0] - 2026-05-24

`secretenv mcp serve` lands: a stdio-only Model Context Protocol server giving AI agents structured registry access without exposing resolved secret values; 14 MCP tools across read/mutation/generation/migration; day-one support for 8 IDEs via `secretenv mcp setup --ide <name>`; backend total stays at 15; workspace unit tests 1018 to 1043; three new crates published to crates.io: `secretenv-mcp`, `secretenv-backends-init`, `secretenv-migrate`.

### BREAKING
- `[mcp].confirm_via` default flipped `Tty` to `Auto`; `Auto` resolves per request (elicitation if declared, else TTY for standalone shell, else refuse); `Tty` remains valid as explicit opt-in.
- `ConfirmVia` + `MigrateReportOutcome` enums marked `#[non_exhaustive]`; downstream `match` must add a `_` arm; the `MigrateOutcomeEcho` mirror enum in `secretenv_mcp::boundary` is NOT `#[non_exhaustive]`.

### Added
- `secretenv mcp serve`: stdio-only MCP server on `rmcp` 1.7; 14 tools (`getting_started`, `version_info`, `list_tools`, `redact_status`, `list_backends`, `detect_password_managers`, `doctor`, `resolve_status`, `list_aliases`, `set_alias`, `delete_alias`, `init_project`, `redact_file`, `gen_password`, `migrate_alias`); per-tool JSON Schema; per-tool description budget <=~200 tokens; `[mcp]` config knobs `allow_mutations`, `confirm_via`, `disabled_tools`, `mutation_log`; `disabled_tools` filters both `tools/list` and dispatch via `ToolRouter::remove_route`.
- Structural no-leak surface: `secretenv-mcp` cannot construct/serialize/deserialize `secretenv_core::Secret<T>`; enforced by `clippy.toml` `disallowed-types` ban, `tests/boundary_test.rs` compile-time assertions (trybuild `Secret: !Serialize` + response-struct field-name bans on `value`/`secret`/`password`/`token`/`raw`), and live-smoke value-grep; two escape-hatch modules `internal/gen_engine.rs` + `internal/redact_file.rs` named under `#[allow(clippy::disallowed_types)]`.
- MCP elicitation primitive: `ConfirmVia::Elicitation` + `ConfirmVia::Auto` using MCP's native server-to-client elicit RPC; empty-schema `MutationApproval{}` with hand-written `JsonSchema` impl emitting `{"type":"object","properties":{},"additionalProperties":false}`; single-click decision per mutation.
- `secretenv mcp serve --allow-mutations <mode>` + `--confirm-via <surface>` flags: per-launch policy overrides; public `PolicyOverrides` struct + `serve_with_overrides()` entry point; override application logged via `tracing::info!`.
- `secretenv mcp setup --ide <name>`: per-IDE config-snippet helper for 8 IDEs (Claude Code, Cursor, Codex, VS Code Copilot, Continue, Cline, Gemini Code Assist + Gemini CLI, OpenCode) plus a `generic` profile; print-by-default, `--write` mode (refuses if target exists unless `--force`); IDEs lacking elicitation ship `--allow-mutations=always` baked into args[]; Claude Code profile emits `claude mcp add` rather than overwriting `~/.claude.json`.
- `secretenv mcp disable` / `secretenv mcp enable`: toggle persistent disable sentinel at `$XDG_CONFIG_HOME/secretenv/mcp-disabled`; `disable --duration <dur>` for time-limited disables.
- Mutation audit log: JSON-Lines append-only at `$XDG_STATE_HOME/secretenv/mcp-mutations.log` capturing `(ts, tool_name, alias_name, backend_instance, agent_reason, operator_decision, mcp_client_id)` for every mutation regardless of decision; `agent_reason` recorded verbatim, never in JSON-RPC response or OTel.
- XDG config path support on macOS: honors `$XDG_CONFIG_HOME` and `~/.config/secretenv/config.toml`; precedence `$XDG_CONFIG_HOME` to `~/.config/secretenv/` to platform-native; added a stderr warning when `XDG_CONFIG_HOME` redirects config away from platform default.
- `secretenv-mcp`, `secretenv-backends-init`, `secretenv-migrate` published to crates.io for the first time; internal-but-`pub` modules marked `#[doc(hidden)]`.

### Changed
- Migrate engine extracted to `secretenv-migrate` library crate; consumed by CLI `secretenv registry migrate` and MCP `migrate_alias`.
- `secretenv-backends-init` crate extracted: shared `BackendRegistry::load_from_config()` factory wiring consumed by CLI + MCP.
- CLI `--config` help text rewritten for XDG-aware precedence.

### Fixed
- Backend URIs no longer in `Err::Display` paths feeding MCP `error_message`; source-side cleanup of `with_context` callsites in `secretenv-mcp::tools::registry_writer` + `internal::redact_file`; new `secretenv_mcp::error::safe_error_message(&anyhow::Error) -> String` scrubber rewriting `scheme://body` to `scheme://[redacted]`; all 25 `format!("{e:#}")` callsites swapped; `no_raw_anyhow_format_in_tool_module` compile-time guard; 12 regression tests in `tests/uri_not_in_error_message.rs`.
- `secretenv_mcp::policy::sanitize_for_tty()` strips C0/C1/DEL control characters from agent-controlled fragments before the operator-facing confirmation surface; bidi-control sanitization deferred to v0.16.1.
- `default_config_path()` Linux CI dedup bug where `XDG_CONFIG_HOME` and `$HOME/.config/secretenv/...` resolved to the same path; `8d493ca` added symmetric dedup via a `push_unique` closure.
- Single-click elicitation UX: initial empty-schema attempt (`a7add8f`) rejected by the validator; hand-written `JsonSchema` impl for `MutationApproval{}` yields Accept/Decline/Cancel with no form field.

### Security
- No `Secret<T>` in `secretenv-mcp`: structurally enforced via the three-gate stack.
- `agent_reason` is audit-only: wording refined to allow operator-facing surfaces (TTY prompt, elicitation modal) to render it; never in tool-result payload or OTel.
- No value bytes in `gen_password` response: `GenPasswordResponse` has no value-bearing field; rejection-sampling verified for non-power-of-two charsets; `Zeroizing<Vec<u8>>` for raw entropy; explicit `drop(value)` after `Backend::set`.
- Backend URIs not in `Err::Display`: two-layer defense plus compile-time regression guard.
- `policy::resolve_confirm_via()` resolution order (elicitation, tty, refuse) is load-bearing and immutable without a new audit; rustdoc lists the justification.
- macOS code-signing in release.yml: pipeline now ad-hoc-signs the macOS binary (`codesign --sign -`) between strip and tarball-package, fixing SIGKILL on first invocation; full Developer ID notarization is post-v0.16.
- `#[non_exhaustive]` on `ConfirmVia` + `MigrateReportOutcome` (BREAKING, above).
- Public-API hygiene: `secretenv-mcp` rustdoc lists the stable surface (`serve`, `serve_with_overrides`, `disable`/`enable`/`disable_sentinel_path`, `PolicyOverrides`, `AllowMutations`, `ConfirmVia`); internal `pub` modules `#[doc(hidden)]`.

### Known limitations
- Only Claude Code has working MCP elicitation in v0.16; Gemini CLI, Cline, Codex, OpenCode fail to advertise the capability, VS Code Copilot advertises but does not render empty-schema requests; per-IDE `--allow-mutations=always` argv override is the mitigation (audit log still records `autoapproved`); upstream PRs + Copilot empty-schema investigation queued for v0.16.1.
- Per-IDE `--allow-mutations=always` override has no user-scope opt-out; a hostile `.mcp.json` can weaken `[mcp].allow_mutations = "confirm"`; mitigated by IDE workspace-trust prompts, audit log, and override scope limited to `allow_mutations`/`confirm_via`; v0.17 adds `[mcp].allow_cli_overrides = false`.
- `tools/mod.rs` is ~1700 LOC with ~400 LOC of duplicated policy-gate boilerplate across 6 mutation handlers; `run_mutation` combinator refactor deferred to v0.16.1.
- `mcp_client_id` hardcoded `"unknown"` in audit entries; `clientInfo` not yet threaded to `MutationLogEntry`; mitigated by logging launch argv; v0.17 fix.
- TTY TOCTOU between prompt-write and response-read (v0.16.1); migrate dual-control collapsed to single confirmation (v0.17); migrate `dry_run=true` skips policy gate (v0.17 adds per-call audit entry for dry-run).
- `secretenv mcp setup --ide <key> --write` has no merge logic; operator must `jq` merge manually; `--merge` flag queued for v0.16.1.
- Schemars 1.0 `"format": "uint"` validation noise on strict MCP clients; cosmetic only; v0.16.1 cleanup.
- Claude Code elicitation modal defaults focus on "Accept"; easy mis-approval; v0.16.1 investigates a `confirm_via = "elicitation-default-deny"` variant.

## [0.15.0] - 2026-05-20

The headline `secretenv registry migrate` command plus 5 additive `Backend` trait methods land; the v0.14.x hygiene cycle (merged-not-tagged) was absorbed into v0.15.0 on tag.

### BREAKING
- `Backend::serialize_registry_doc` + `Backend::deserialize_registry_doc` move off the trait to free functions over a new `RegistryFormat::{Json, Toml}` enum; backends declare wire format via `Backend::registry_format(&self) -> RegistryFormat` (default `Json`; `local` and `1password` override to `Toml`); external plugins must remove their overrides and override `registry_format()` if not JSON.
- `mcp-safe` Cargo feature polarity flipped to additive `value-access`; default features now `[]` (the safe surface), `value-access` gates `expose_secret`, the `Backend` re-export, `runner::*` re-exports, and `EnvEntry::value()`; workspace deps enable `value-access` so workspace consumers are unchanged; external consumers set `default-features = false` for the safe surface or `features = ["value-access"]` for value APIs.
- `pub mod runner` is now cfg-gated under `value-access`; reaching `runner::*` from a no-`value-access` consumer is a compile error.

### Added
- `secretenv registry migrate <alias> <dest-uri>`: reads from source, writes to destination, atomically flips the registry pointer; no consuming repo touches a backend URI; flags `--dry-run`, `--yes`, `--from <uri>`, `--delete-source` (separately confirmed even under `--yes`), `--json` (`MigrateReport`), `--registry <name|uri>`; source kept by default; partial failures never auto-roll-back by deletion (manual recovery commands given).
- Five new additive `Backend` trait methods (default impls preserve v0.14 behavior):
  - `write_secret(&self, &BackendUri, &Secret<String>)` (borrow-not-clone); default `BackendError::WriteNotSupported`; 12 Native backends override with passthrough, 3 Gated (`1password`, `keeper`, `bitwarden-sm`) refuse unless their `*_unsafe_set` flag is set.
  - `delete_secret(&self, &BackendUri)` for `--delete-source`; default `BackendError::DeleteNotSupported`; same Native/Gated split.
  - `probe_write(&self, &BackendUri)` + `has_probe_write(&self) -> bool` for the `--dry-run` write-permission probe; default no-op with `has_probe_write() == false`; HashiCorp Vault overrides with a real `vault token capabilities` probe.
  - `delete_hint(&self, &BackendUri) -> String`: backend-native cleanup command in the success message; terminal-only, never crosses JSON/MCP/OTel.
- `secretenv_core::BackendError`: new `#[non_exhaustive]` error enum with `WriteNotSupported` and `DeleteNotSupported` for structural dispatch.
- Migrate telemetry surface in `secretenv-telemetry::SecretEnvSpan`: six new `record_migrate_*` methods (`record_migrate_phase`, `record_migrate_outcome`, `record_migrate_source_backend_type`, `record_migrate_dest_backend_type`, `record_migrate_delete_source`, `record_migrate_transaction_id`) plus closed enums `MigratePhase`, `MigrateOutcome`; `RedactionPolicy` matrix gains 11 migrate rows (7 ALLOW, 4 DENY); migrated value, alias name, source/dest URIs, and source/dest instance names are DENY.

### Changed
- CI: trybuild harness renamed `mcp_safe_trybuild` to `value_access_trybuild`; ui fixtures `mcp_safe_ui/` to `value_access_ui/`; job now runs `cargo test -p secretenv-core --no-default-features --test value_access_trybuild`.
- Code hygiene polish:
  - `refuse_special_paths` now scans the first `Normal` path component, catching relative `proc/foo` / `./proc/foo` (was bounded to `components[1]`).
  - `Scrubber::pattern_len` documents the Aho-Corasick `pat_id in [0, num_patterns)` invariant + `pub(crate)` scope.
  - `aggregate_errors` documents the non-empty input precondition.
  - `SpanGuard._private: ()` documented as the sealed-construction marker.
  - `RedactionPolicy` derives `Copy` (was `Clone` only).
  - Stale `v0.3 TODO` in `secretenv-backend-aws-secrets/src/lib.rs` rewritten as current open follow-ups.
  - Off-by-one regression test `streaming_accepts_pattern_at_exact_tail_window` covers `pattern_len == MODE_A_TAIL_WINDOW`.
  - `tracing` dep in `secretenv-telemetry/Cargo.toml` documented as the v0.17 `tracing::Subscriber` anchor.
  - `runner.rs::inject_env_entries` extracts the three identical env-injection loops (tokio pipe-redact, unix `exec()`, non-unix `spawn()`).
  - `CHANGELOG.md` header documents the `Known limitations` subsection convention.

### Security
- `TaintedValue.bytes` now `Zeroizing<Vec<u8>>` (`crates/secretenv-core/src/redact/mod.rs`); end-of-run drop scrubs plaintext heap bytes.
- Alias-name skip notice moved from `tracing::warn!` to `eprintln!` (`redact/mod.rs`); keeps it operator-local stderr.
- `scripts/check_tracing_leaks.sh` extended for `event!(Level::..)`, `Span::current().record("value", ...)`, and bare `warn!`/`info!`/`error!` after `use tracing::*;`; tightens the `value = ...` check to require `?`/`%` sigils.
- `secretenv run --help` documents Mode A limits: `/dev/tty` escape, `syslog`/`journald`, `mmap`, core dumps, SDK re-fetch.
- `forward_signals_to` adds `SIGQUIT` + `SIGUSR1` + `SIGUSR2` (`runner.rs`).
- `RedactionEvent::for_otel()` projection (`crates/secretenv-telemetry/src/event.rs`) strips `alias_name` before non-terminal emission; OTel sinks at v0.17 must use it.
- `SECRETENV_*` prefix wildcard env scrub (`runner.rs::scrub_secretenv_env`); explicit `RESERVED_ENV_VARS` denylist retained as belt-and-braces.
- Backup-path setuid mask documented (`redact/mod.rs::write_backup_secure`); existing `& 0o777` mask drops setuid/setgid/sticky bits.
- `EnvEntry.alias_name` doc tightened (`runner.rs`); field stays `Option<String>`; future leak vectors must project away via `RedactionEvent::for_otel`.

### CI
- `rust-toolchain.toml` pinned to `1.95.0` (was floating `stable`); symmetric with CI's `dtolnay/rust-toolchain@stable`; eliminates red CI on rust point-releases; bump is its own chore (Issue #03).

### Known limitations
- Registry-document read-modify-write is not atomic in v0.15; both `secretenv registry set` and the `migrate` pointer-flip do `Backend::list(...)` to in-memory `BTreeMap` mutate to `Backend::set(...)`; no backend carries CAS/If-Match/version-stamp, so concurrent mutations on the same instance can clobber each other; mitigation: operators serialize their own mutations; v0.17 introduces `Backend::cas_set(uri, expected_etag, new)` (ETag/version backends implement it, others degrade under explicit acknowledgment).

## [0.14.0] - 2026-05-15

`secretenv redact` lands in two modes plus the foundation machinery v0.15 migrate, v0.16 MCP, and v0.17 OTel depend on; backend total stays 15; workspace unit tests 893 to 918 (+25).

### BREAKING
- `Backend::get(&self, uri: &BackendUri) -> Result<Secret<String>>` (was `Result<String>`). Cascades across all 15 backends, `secretenv-testing` mocks, the CLI `get` handler, the resolver, and the runner's `EnvEntry`. External plugins update `get()` return type and wrap with `Secret::new(...)`; internal consumers use `as_str_internal()`, CLI callers use `value.expose_secret()`.
- `Backend::serialize_registry_doc` + `Backend::deserialize_registry_doc` moved from a `secretenv-cli` match-arm helper to trait methods on `Backend`. Default impl JSON; `local` and `1password` override to TOML. Removes the v0.13-era silent "not supported" runtime failure.
- `pub use backend::Backend` is cfg-gated to `not(feature = "mcp-safe")` on `secretenv-core`. Crates linking with `mcp-safe` reach the trait via `secretenv_core::backend::Backend`; the CLI never enables `mcp-safe`.

### Added
- `secretenv redact <path>`: Mode B post-hoc file scrubber. Aho-Corasick byte scanner over resolved values; substitutes `[redacted:<alias>]` or `--redact-token <fixed>`. `--in-place` rewrites atomically via sibling tempfile + `rename(2)` with mode preservation; `--backup <suffix>` keeps a copy; `--dry-run` counts without writing.
- Runtime redaction in `secretenv run` (Mode A), on by default. Streaming Aho-Corasick scrubber on stdout/stderr with a `max(pattern_len) - 1`-byte carry-over window for cross-chunk matches. `--redact` forces pipe mode on a TTY; `--no-redact --i-know` opts out. Default `Auto` falls back to `exec()` when stdin is a TTY with a stderr advisory.
- Signal forwarding in mode A: `SIGINT`, `SIGTERM`, `SIGHUP` forwarded to the child via `rustix::process::kill_process`.
- `secretenv-core::Secret<T>`: generic newtype wrapping `Zeroizing<T>`. Custom `Debug` redacts; no `Display`, `Clone`, `Serialize`, `Deserialize`, `From<String>`, or `Into<String>`. `expose_secret()` cfg-gated behind `not(feature = "mcp-safe")`.
- `secretenv-core::McpSafe`: sealed marker trait. v0.14 seals `HistoryEntry`; v0.16 adds `AliasList`, `ResolveStatus`, `DoctorReport`. `Secret<T>` is not sealed, so a missing impl is a compile-time refusal to expose values.
- `mcp-safe` Cargo feature on `secretenv-core`: subtractive, removes `expose_secret` and the crate-root `Backend` re-export. CI gate `cargo test -p secretenv-core --features mcp-safe --test mcp_safe_trybuild` runs as a dedicated job.
- `secretenv-telemetry` crate: ships `SecretEnvSpan` typed attribute builder (one method per ALLOW attribute, no `set_attribute(&str, &str)` escape hatch), `SecretEnvErrorKind` closed enum, `RedactionEvent` / `RedactionStream` / `RedactionSource`, `RedactionPolicy`, and `RedactionSink` trait + `NoopRedactionSink`. No `opentelemetry` dependency at v0.14.
- `Backend::supports_native_gen()`: default `false`, reserved for v0.16's MCP `gen_password` tool routing.
- Typed per-handler reports (`crates/secretenv-cli/src/reports.rs`): `RunReport`, `RedactReport`, `RegistryReport`, `ResolveReport`, `GetReport`, `SetupReport`, `ProfileReport`, `CompletionsReport`, plus `CommandOutcome` and `RedactMode` enums. v0.14 discards them via `let _ = handler.await?;`.

### Changed
- `secretenv run` defaults to redacted output: non-TTY parents get pipe-based redaction, TTY parents get the auto-fallback advisory.
- Internal `serialize_registry(backend_type, &map)` helper removed from `secretenv-cli`; dispatch is now `backend.serialize_registry_doc(&map)`. The four CLI-layer helper unit tests removed; round-trip tests live in each backend crate.
- Workspace deps: `aho-corasick = "1"`, `rustix = { version = "1", features = ["fs", "process"] }` added; `tokio` gains `"signal"`; `tempfile` promoted from dev-dep to runtime dep on `secretenv-core`.
- `EnvEntry.value` switched from `Zeroizing<String>` to `Secret<String>`.
- CI: workspace `cargo test` no longer passes `--all-features` (mcp-safe is subtractive and would cascade under feature unification). Dedicated `mcp-safe-trybuild` job covers it; a `secret-no-leak-grep` job fails on a `Display` impl for `Secret` or a forbidden derive.

### Security
- New `docs/security.md#redaction-v014` covers the redact threat model and Limits matrix: `/dev/tty`, `syslog(3)` / `journald`, `mmap`'d output, core dumps, and PTY-bound interactive children are not covered.
- `O_NOFOLLOW` on every redact file open; symlink-swap-between-stat-and-open rejected.
- Foreign-owner refusal: redact refuses files owned by a UID other than the caller's EUID unless `--allow-foreign-owner`.
- `/proc`, `/sys`, `/dev` refused outright.
- Minimum tainted-value length 8 bytes; shorter values dropped with a `tracing::warn!` carrying the alias name but never the value or length.
- 64 KiB max tainted-value length for mode A; larger patterns refuse mode-A startup.
- Foundation work for v0.16's MCP boundary (`Secret<T>`, `McpSafe`, `mcp-safe`) and v0.17's OTel discipline (`SecretEnvSpan`, `SecretEnvErrorKind`, `RedactionPolicy`).

### Known limitations
- Typed-report `Drop` does not fire on `secretenv run`'s exec/exit happy paths; it reaches `Drop` on early-return error paths but not when `cmd_run` ends and the process exits with the child's status. v0.17 adds a pre-exec hook (~30 LOC) to force emission; until then `secretenv run` OTel uses the `RunOptions`-resident hook path.
- Three v0.15 architectural follow-ups identified (non-blocking): polarity-flip `mcp-safe` to additive `value-access` before v0.16; relocate `serialize_registry_doc`/`deserialize_registry_doc` to a free function + `RegistryFormat` enum; lift `reports.rs` into `secretenv-core` once v0.16 MCP is the second consumer.

## [0.13.0] - 2026-05-06

Hygiene and docs release absorbing both v0.12.x carry-forward queues; no new backend, platform, or schema change; backend total stays 15; workspace unit tests 876 to 893 (+17); live full-matrix smoke 508/508 PASS (was 454/508; +54 from GCP env-debt fixes); the release-prep audit trio ran clean.

### Fixed
- GCP env-debt: drop redundant `GCP_PROJECT="${SECRETENV_TEST_GCP_PROJECT:-eva-dev-490220}"` shadow in `scripts/smoke-test/run-tests.sh`; `lib/common.sh` already exports the env-driven value and `require_cloud_env()` enforces it. Single source of truth is `SECRETENV_TEST_GCP_PROJECT`, no fallback.
- GCP env-debt: Test-150 assertion `project=eva-dev-490220` now interpolates `${GCP_PROJECT}` (`run-tests.sh:917`); was a hardcoded literal that failed even with correct env.
- GCP env-debt: Section 15 wrapped in standard SKIP-on-precondition mirroring sections 21+; probes `gcloud secrets list --project ... --limit 1` and records a single `119 v0.3 gcp section skipped` SKIP instead of cascading 12+ FAILs.
- GCP env-debt: global `export CLOUDSDK_CORE_DISABLE_PROMPTS=1` at the top of `run-tests.sh` so `secretenv doctor --fix` against a NotAuth GCP backend cannot spawn `gcloud auth login` and hang the matrix.
- GCP env-debt: pre-smoke runbook step added (operator-facing): `gcloud auth list` + ADC verification + project-match check.
- bitwarden-sm: `bitwarden_bin` control-character validation parity via `has_forbidden_control_char` (matching `bitwarden_server_url` / `bitwarden_access_token_env`) + new `factory_rejects_control_char_in_bitwarden_bin` test.
- bitwarden-sm: `bitwarden_access_token_env` validation order: control-char + POSIX-name checks now run inside the `if let Some(env)` branch; the default branch returns the const directly.
- bitwarden-sm: `parse_version_token` permissive scanner finds the first `<X.Y.Z>` whitespace token instead of anchoring on literal `bws ` prefix; tolerates rebrands and trailing build metadata; six new regression tests.
- bitwarden-sm: `SecretGetResponse.value` doc-comment hardened, naming the `#[serde(default)]` rationale and the section-28 smoke assertion.
- bitwarden-sm: `ProjectListElement.id` no longer `#[serde(default)]`; field is now REQUIRED, so an omitting envelope surfaces as a parse error at Level 2.
- bitwarden-sm: `extract_json_field` array/object rejection split into two explicit arms (one per JSON kind).
- bitwarden-sm: `set_uses_secret_edit_not_create` mock body `ok("{}")` to `ok("")` (the `secret edit` stdout is unread).
- bitwarden-sm: `set_rejects_fragment` test adds positive `assert!(msg.contains("fragment"))`.
- bitwarden-sm: 6 new `extract_json_field` variant tests (string / number / boolean / null / array-rejection / object-rejection) pinning exact bail wording.
- infisical: doctor false-NotAuthenticated under infisical 0.43.79; `Backend::check()` configured the `infisical user get token --plain` probe with `Stdio::piped()` stderr but waited via `.status()`, which does not drain piped streams; once CLI stderr exceeded the pipe buffer the child blocked. Fix: `probe.stderr(Stdio::piped())` to `probe.stderr(Stdio::null())` (`secretenv-backend-infisical/src/lib.rs:454`).
- bitwarden-sm docs: security note added (`docs/backends/bitwarden-sm.md`) on `bitwarden_server_url` token-forwarding risk, naming the typo-squat / poisoned-template threat and three mitigations plus a TLS-trust-delegation paragraph for intercepting proxies.

### Changed
- Release-prep audit trio (security + code + deployment) made default cadence for the third consecutive cycle. Security APPROVE (0 BLOCK + 0 HIGH + 0 MED + 2 LOW); code-reviewer APPROVE with HIGH (`parse_version_token` doc-comment LIMITATION, landed inline); deployment REJECT-then-APPROVE (workspace version bump, landed inline). No carry-forward to v0.13.x.
- No three-agent feature-cycle audit run; no new backend or feature surface.

### Known limitations
- Cross-backend cascade FAILs (sections 7 / 8 / 9 / 17 / 22 azure-reg) when one backend in the alias map is NotAuth not addressed; needs an architectural change to the resolver's partial-readiness behavior. Out of scope.
- Drop dead `backend_type: &'static str` field on `BitwardenSmBackend` declined: clippy `unnecessary_literal_bound` flags the resulting shape, and all 14 other family backends keep the field.
- `bws_command` / `bws_secret_command` DRY merge deferred (taste-driven).
- Four LOW style nits deferred: `unsafe_set_refused` hint phrasing, `secret_uuid` `Cow<'_, str>` allocation, `drop(lock)` style consistency, `apply_env` rename to `apply_env_with_token_required`.

## [0.12.0] - 2026-05-05

Seventh single-backend-per-release cycle adding Bitwarden Secrets Manager (the developer/CI product, via `bws` CLI v2.x), bringing the total to 15; workspace unit tests 830 to 876 (+46); live smoke Section 28 29/29 PASS; the feature-cycle trio surfaced 3 HIGH (landed inline), 7 MEDIUM + 10 LOW deferred to v0.12.x; absorbs the v0.11.x merged-not-tagged hygiene cycle.

### Added
- `secretenv-backend-bitwarden-sm` crate: `BitwardenSmFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `bitwarden-sm-<instance>://<uuid>[#json-key=<field>]` where `<uuid>` is the 36-char canonical hyphenated form or 32-char simple form. Addresses every secret by server-generated UUID. 46 unit tests.
- `bitwarden_unsafe_set` defense-in-depth gate: `bws` v2.0.0 has no stdin path for `secret create` / `secret edit` (value is on argv via `--value`). Default: `set` and `delete` REFUSE; `bitwarden_unsafe_set = true` opens the argv path. Both gated by the same flag.
- `set` updates only, never creates: the URI is a UUID, so `set` always invokes `bws secret edit --value <value> <uuid>`, never `bws secret create`.
- Token routing via env: `BWS_ACCESS_TOKEN` is canonical; multi-instance renames via `bitwarden_access_token_env`. Token set on child env only, never on argv, registry, or logs. `doctor` shows only env-var NAME and project COUNT.
- Server URL omitted when default: `bitwarden_server_url` optional; when unset the wrapper actively REMOVES `BWS_SERVER_URL` from the child env. EU / self-hosted set it explicitly.
- `#json-key=<field>` fragment on `get` extracts a top-level scalar from JSON-encoded `value`; `set` / `delete` / `list` / `history` reject any fragment.
- URI parser strict UUID validation: 32-char `[0-9a-f]+` at parse time; 36-char hyphenated rejected with a clear error; mixed-case hex normalized to lowercase.
- `history` returns trait-default "not implemented"; the CLI exposes no `secret history` subcommand.
- `bitwarden-sm` added to `serialize_registry` JSON arm in `secretenv-cli/src/cli.rs`.
- Smoke harness Section 28: 29 records covering doctor Level 1+2, scalar round-trip, `#json-key=password` extraction, end-to-end `run`, set-blocked-by-default + opt-in cycle, fragment-reject, history-not-implemented, registry-source cross-backend chain, URI-parser non-UUID rejection. Skipped when `bws` missing, `BWS_ACCESS_TOKEN` unset, `bws project list` fails, or fixture UUIDs missing.
- Backend total 14 to 15; README backend table flipped Bitwarden Secrets Manager to "Available" with `type` string `bitwarden-sm`.
- Roadmap swap (2026-05-05): v0.12 was Delinea Secret Server; Delinea needs an invite-only trial so the order swaps to v0.12 = Bitwarden Secrets Manager, v0.13 = Delinea (deferred).

### Fixed (v0.11.x hygiene, merged-not-tagged)
- `aws-secrets` `extract_json_field` `map.remove` allocation fix (`secretenv-backend-aws-secrets/src/lib.rs:442-475`); the `String` arm now moves rather than clones.
- `.github/workflows/release.yml:177-194` backend-publish strict-mode: the 14-line `cargo publish` block now starts with `set -euo pipefail`.
- `conjur` backend `tracing::warn` on `conjur_unsafe_set = true` runtime branch (`secretenv-backend-conjur/src/lib.rs:280-294`) naming instance + URI + operation.
- `conjur` `parse_version_token` dead-fallback cleanup (`lib.rs:549-559`): replaced `split('-').next().unwrap_or(token)` with `split_once('-').map_or(token, |(prefix, _)| prefix)`.
- `conjur` `parse_json_key_fragment` two-pass cleanup (`lib.rs:212-242`): refactored to single-pass `shift_remove` + leftover-emptiness check.

### Changed
- First hygiene cycle to land entirely from the v0.11.x post-cycle carry-forward queue; no three-agent retrospective audit (every item closed a prior-audit finding).

### Known limitations
- Full-matrix smoke surfaced 51 cascading FAILs from pre-existing GCP env-debt (`eva-dev-490220` hardcoded + gcloud reauth); not v0.12-introduced, deferred to v0.12.x.
- `variable_id` inline control-char rejection declined; already locked at `secretenv-core::BackendUri::parse` (`uri.rs:96`).
- `teardown.sh` shell-quoting parity declined; would need a workspace-wide harness rewrite.
- Smoke `|| true` failure-signal loss declined (cosmetic).
- Audit-artifact cross-link declined (no artifact exists).
- CHANGELOG history-wording cleanup declined (historical v0.10.0 says "history-unsupported" vs later "history-not-implemented"); don't edit history.
- `history()` for openbao via `bao kv metadata get` deferred (KV v1/v2 mount detection, soft-delete + destroy markers).

## [0.11.0] - 2026-04-30

Sixth single-backend-per-release cycle adding CyberArk Conjur (Apache-2.0 OSS / Enterprise wire-compatible, via the Go-based `conjur` v8 CLI), bringing the total to 14; first non-Vault-family enterprise backend and first cycle to run the release-prep audit by default; workspace unit tests 778 to 830 (+52); live smoke 452 to 479 (+27 for Section 27); full matrix 479/479 clean after release rebuild; trio audit landed 1 BLOCKING + 1 HIGH + 7 MEDIUM/LOW inline.

### Added
- `secretenv-backend-conjur` crate: `ConjurFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `conjur-<instance>://<variable-id>[#json-key=<field>]` (no KV-mount segment). `CONJUR_APPLIANCE_URL` + `CONJUR_ACCOUNT` routed via per-child env, uniform across `version`, `whoami`, and every `variable` invocation. 52 unit tests.
- `-f /dev/stdin` safe-stdin path (equivalent to OpenBao's `value=-`); Conjur v8 has no `--value-from-stdin`. `conjur_unsafe_set = true` is the explicit opt-in for the `-v <value>` argv path. Default-off invariant machine-checked.
- `#json-key=<field>` fragment on `get` parses the value as JSON and extracts the named top-level scalar; `set` / `delete` / `list` / `history` reject any fragment.
- `delete` as clear-via-empty-set: Conjur has no native delete; `delete()` writes the empty string via the safe `-f /dev/stdin` path, retaining the policy definition.
- Identity line surfaces configured authn: `whoami` JSON returns `{account, username, client_ip, user_agent, token_issued_at}` with no authenticator name, so the doctor line is `account=<from-whoami> identity=<username> authn=<from-conjur_authn-config>` (default `"authn"`).
- v7 (Ruby) CLI rejection: `check()` Level 1 parses the token from `Conjur CLI version <X.Y.Z>[-<build-sha>]` and fails fast on v7 with a "v8+ required" message + Docker install hint; an unparseable version line surfaces as `BackendStatus::Error`.
- `list()` returns alphabetically-sorted entries (sorts before returning, since `HashMap::into_iter` is randomized per-process).
- `conjur` added to `serialize_registry` JSON arm (`secretenv-cli`).
- Smoke harness Section 27 (27 assertions, ids 390-416) covering doctor / get / fragment / run / cycle / fragment-reject / history-not-implemented / registry-source / cross-backend resolve. Skipped if `conjur` missing, server unreachable, or session expired. Seeds `secretenv-smoke/{scalar,json-multi,conjur-registry,cycle}`.
- `docs/backends/conjur.md`: leads with the install gotcha (Docker-image canonical, PyPI EOL v7), resource-graph model + `delete` semantic gap + identity-line authn convention.
- `.github/workflows/release.yml`: adds `cargo publish -p secretenv-backend-conjur --locked`.
- `secretenv-backend-conjur` AGPL-3.0-only exception in `deny.toml`.
- README backend table 13 to 14 + backend-count badge bumped (stale "Coming Soon" Conjur stub deleted).

### Changed
- Pre-cycle live-probe ran against `Conjur CLI version 8.1.3-879b90b` and corrected spec inaccuracies: CLI is Go-based v8, not Python (canonical install `cyberark/conjur-cli:8` Docker image); `--value-from-stdin` does not exist in v8 (substitute `-f /dev/stdin`); `CONJUR_APPLIANCE_URL` + `CONJUR_ACCOUNT` env routing works without `~/.conjurrc`; `whoami` JSON shape has no authenticator name; `variable get` still appends one trailing `\n`.
- First tagged release after the v0.10.x merged-not-tagged hygiene cycle; the Homebrew formula re-renders with the corrected `license "AGPL-3.0-only"` (v0.3 onward had pushed the wrong MIT label).
- New feedback memory: the three-agent feature audit must be followed by a second targeted audit over the release-prep delta (smoke patches, version bump, CHANGELOG closeout, release.yml) before tag push; adopted as standard cadence from v0.11 on.

### Fixed
- Homebrew formula license (`.github/workflows/release.yml:251`): `license "MIT"` to `license "AGPL-3.0-only"`; the workspace has been AGPL-3.0-only since the v0.3 relicense.
- CHANGELOG line 57: folded v0.9.1 hygiene block referenced "v0.10 Bitwarden release"; v0.10 shipped as OpenBao. Updated to "v0.10 OpenBao release".
- CHANGELOG headline test counts in `[0.10.0]`: cited `705 to 748` corrected to actual `735 to 778`; the `+43 from openbao` delta was correct.
- Duplicate `## [0.8.0] - 2026-04-24` header at lines 106/108 removed.

### Known limitations
- Homebrew formula `desc` length + workspace-description-as-source-of-truth deferred (intentional Homebrew brevity).
- `set -euo pipefail` in release.yml bash blocks deferred (existing safety loop on line 241 sufficient).
- `sleep 45` rationale comment deferred (empirically sufficient through v0.1 to v0.10).
- CHANGELOG date 2026-04-27 vs commit date 2026-04-26: no change (tag pushed 2026-04-27 UTC, file header declares UTC dates).

## [0.10.0] - 2026-04-27

Fifth single-backend-per-release cycle adding OpenBao (Linux Foundation MPL-2.0 Vault fork, via the `bao` CLI 2.x), bringing the total to 13; workspace unit tests 735 to 778 (+43); live smoke 419 to 452 (+29 for Section 26); full matrix 452/452 after a smoke-test patch; trio audit landed 1 HIGH + 3 MEDIUM inline; folds the v0.9.2 hygiene cycle.

### Added
- `secretenv-backend-openbao` crate: `OpenBaoFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `openbao-<instance>://<mount>/<path>[#json-key=<field>]`. `BAO_ADDR` / `BAO_NAMESPACE` routed via per-child env. Three divergences from Vault: binary name (`bao` vs `vault`), env-var prefix (`BAO_*` with `VAULT_*` CLI fallback), install path (`brew install openbao`, no tap).
- `bao_unsafe_set` defense-in-depth flag: reserved opt-in for any future argv-routing regression. v0.10 always uses the safe `value=-` stdin form; defaults `false`, observed at factory time. Default-off invariant machine-checked.
- `#json-key=<field>` fragment on `get` parses the `value` field as JSON and extracts the named top-level scalar; `set` / `delete` / `list` / `history` reject any fragment.
- `openbao` added to `serialize_registry` JSON arm (`secretenv-cli`); registry docs round-trip as `value=-` JSON-strings.
- Smoke harness Section 26 (29 assertions) covering doctor / get / fragment / run / cycle / fragment-reject / history-unsupported / registry-source / cross-backend resolve / HTTP/HTTPS mismatch. Skipped if `bao` missing or server sealed/unreachable.
- `docs/backends/openbao.md`: leads with the `BAO_ADDR` HTTP/HTTPS gotcha, contrasts the install path with Vault's tap form, explains the MPL-2.0 vs BSL governance distinction.
- `secretenv-backend-openbao` AGPL-3.0-only exception in `deny.toml`.
- README backend table 12 to 13 + backend-count badge bumped.
- Smoke harness README inventory + `SECTIONS` array: sections 22-26 backfilled (23-25 had drifted).
- v0.9.2 hygiene: `cf_kv_list_prefix` config field (cf-kv) optional key-prefix filter passed to `wrangler kv key list` as `--prefix <value>`; empty string normalized to `None` at factory time.
- v0.9.2 hygiene: 17 new factory-validation unit tests across `secretenv-backend-1password` (+5), `secretenv-backend-cf-kv` (+4 plus +2 prefix), `secretenv-backend-vault` (+4), `secretenv-backend-aws-secrets` (+4).
- v0.9.1 hygiene: `keeper_list_max_records` (Keeper) opt-in cap on `list()` per-record fan-out; default unset; hitting the cap emits a `tracing::warn!`.
- 343a registry-namespace must NOT contain scalar fixtures (negative assertion locks the two-namespace discipline).
- 352-354 wrangler-delete-actually-deletes canary: provisions a probe key, deletes via wrangler in non-TTY mode, asserts post-delete read returns `404` and `wrangler kv key list` no longer shows the probe.

### Changed
- Intentional spec divergence: `list()` storage model reads a JSON-string from the canonical `value` field (`aws-secrets`-style) driven by single-field-per-secret writer discipline (`bao kv put <path> value=-`), not the spec's original Vault-style `data.data` multi-field map; documented in lib.rs, `docs/backends/openbao.md`, and the spec amended.
- v0.9.1 hygiene: `keeper_config_path` validated at factory time (file existence + POSIX mode `0o077` mask); permissive modes bail with a `chmod 600` hint.
- v0.9.1 hygiene: cf-kv `WranglerWhoami::parse` refactored to `find_map`.
- v0.9.1 hygiene: cf-kv `resolve_target` allocation-free (`split_once('/')` chain replaces `Vec<&str>` collect).
- v0.9.1 hygiene: cf-kv smoke namespace IDs centralized to `scripts/smoke-test/lib/cfkv-namespace.env`.
- v0.9.1 hygiene: cf-kv docs expanded with Troubleshooting, `set()` opt-in posture comparison table, multi-namespace worked example.
- v0.9.1 hygiene: backend-spec template checklist gains explicit "new crate to `deny.toml` per-crate AGPL exception" + `cargo deny check licenses` preflight gate.

### Removed
- v0.9.1 hygiene: `keeper_folder` config field, declared since v0.8 but never wired up.

### Fixed
- v0.9.1 hygiene: Section 17 (v0.4 history) `seed_runtime_from_fixtures` git-init validity gate; replaced `[ ! -d .git ]` with a `git rev-parse --git-dir` validity probe that wipes and reinits broken state; recovers 8 baseline failures (assertions 185-192).
- v0.9.1 hygiene: Section 25k cf-kv post-delete read assertion switched pattern from lowercase `'not found'` to literal `'404'` to match wrangler 4.85.0's `404: Not Found`.

### Known limitations
- v0.9.2 hygiene: workspace-wide placeholder-field audit found zero placeholder fields outside the already-removed `keeper_folder`; the two grep hits (backend-doppler, backend-infisical) are forward-compat doc phrases, not dead config.
- cf-kv `bulk get` deferred (Cloudflare API in open-beta; trigger: GA).
- cf-kv `#metadata` fragment declined (speculative).
- Rust 1.87+ `env::set_var` unsafe-wrap deferred (workspace MSRV is 1.75; trigger: next MSRV bump).
- 256 KiB `spawn_blocking` measured benchmark deferred (no `cargo bench` / criterion infra yet).
- Smoke matrix delta: v0.9.0 pre-tag 408/419 PASS (11 baseline failures: 8 history + 3 Infisical); v0.9.1 post-fix 420/423 PASS (3 remaining Infisical session expired locally, environmental).

## [0.9.0] - 2026-04-25

Fourth single-backend solo-fresh-session release; adds Cloudflare Workers KV (`cf-kv` via wrangler 4.x) for 12 backends total; unit tests 676 to 705, live smoke 395 to 419.

### Added
- Cloudflare Workers KV backend (`cf-kv`) wrapping wrangler CLI 4.x; supports OAuth (`wrangler login`) and `CLOUDFLARE_API_TOKEN` auth. Two-segment URI `cf-kv-<instance>:///<namespace-id>/<key>`, optional single-segment `cf-kv-<instance>:///<key>` via `cf_kv_default_namespace_id`. `set()` writes through mode-0600 tempfile + `--path` (no `_unsafe_set`). `list()` is Pattern A bulk-mode with sequential per-key value hydration; `history()` unsupported. 12th backend.
- Smoke Section 25 (assertions 330-352, 13 total) covering cf-kv as secrets backend and registry source; two-namespace pattern (`secretenv-smoke-v09` + `secretenv-smoke-v09-registry`).

### Fixed
- Tightened `cf-kv` key-not-found detector from loose `"10009"` substring to word-boundary forms (`error 10009` / `code 10009` / `code: 10009`).
- Made `set()` tempfile flush fatal (`with_context` instead of `.ok()`).
- Added `NotFound` mapping to the `whoami` arm of `check()`.

## [0.8.0] - 2026-04-24

Third single-backend solo-fresh-session release; adds Keeper (Keeper Commander v17+) for 11 backends total; unit tests 645 to 676, live smoke 383 to 395; bundles v0.7.1 + v0.7.2 merged-not-tagged hygiene work.

### Added
- Keeper backend (`keeper`) wrapping the `keeper` CLI (Keeper Commander v17+, `pip install keepercommander`); 11th backend. Requires persistent-login setup as a prerequisite (device token via `keeper shell` then `this-device register` then `this-device persistent-login on`). Enforces `--batch-mode` on every invocation. URI `keeper-<instance>:///<record-uid-or-title>`, optional `#field=<name>` fragment (default password). Config: `keeper_config_path`, `keeper_unsafe_set` (default false, gates argv-based `set()`, emits `tracing::warn!`), `timeout_secs`, `keeper_bin`. `list()` Pattern A bulk model, per-record failures emit `tracing::warn!`. `history()` unsupported.
- Smoke Section 24, 12 live assertions; provisions `SMOKE_TEST_VALUE` (`kp_vault_88888`) and `SMOKE_REGISTRY_ALIAS` records; tagged `cloud=yes`.

### Changed
- Workspace version 0.7.1 to 0.8.0 (skips a 0.7.2 tag; crates.io sees v0.7.0 to v0.8.0 linearly).
- Backend count 10 to 11; README badge + supported-backends table updated.

### Fixed
- Infisical `set()` value-aware stderr scrub; fd-based chmod; non-UTF-8 `$TMPDIR` explicit bail.
- Doppler `ResolvedTarget` struct replaces positional tuple; tightened `not found` heuristic so auth errors no longer mask as missing-secret; `tracing::debug!` on set/delete happy paths.
- Both Doppler + Infisical `list()` JSON parse hops to `spawn_blocking` at 256 KiB and above.
- Infisical env-inherit test deterministic via mutex-serialized `EnvVarGuard`.
- Doppler + Infisical now exercised as registry sources in live smoke (sections 22g, 23g).
- Documentation polish: Infisical self-hosted domain trust, Doppler IAM/RBAC + chmod advisory, `docs/security.md#self-hosted-domains` cross-linked.

## [0.7.1] - 2026-04-23

DEFER-closeout hygiene patch closing 20 items from the v0.6 Doppler and v0.7 Infisical audits; no user-facing behavior change beyond tightened error messages; unit tests 637 to 642, live smoke unchanged at 373.

### Changed
- Doppler `resolve_target` returns a struct (`ResolvedTarget { project, config, secret }`) replacing the positional tuple across `get` / `set` / `delete` / `list`.
- Doppler `not found` heuristic tightened to require the canonical `"Could not find requested secret"` prefix; auth errors surface verbatim via `operation_failure_message`. Regression tests on `get()` and `delete()`.
- Doppler segment-count error surfaces parsed segments (`got 2 segment(s): [acme, prd]`).
- Doppler `set()` and `delete()` emit `tracing::debug!` on happy paths (no values logged).
- Infisical `resolve_target` lifetimes split to `<'s, 'u>(&'s self, uri: &'u BackendUri) -> Result<ResolvedTarget<'u>> where 's: 'u`.
- Both backends' `list()` JSON parse uses `tokio::task::spawn_blocking` above 256 KiB; threshold provisional.
- Infisical drift-catch test renamed `delete_without_type_shared_flag_would_fail_strict_mock` to `delete_requires_type_shared_flag`; dual-purpose doc comment added to `set_value_never_appears_on_argv`.

### Fixed
- Infisical `set()` stderr scrubs the secret value before folding into the error chain via `set_failure_message` (replaces value with `<REDACTED>` when 4+ chars). Unit tests cover scrub + passthrough.
- Infisical env-inherit test `check_not_authenticated_when_probe_fails_and_no_token` now wrapped in RAII `EnvVarGuard` (mutex-serialized against `ENV_LOCK`), deterministic regardless of parent-process state.

### Security
- Infisical `set()` uses fd-based `chmod` (`tempfile.as_file().set_permissions(perm)`) instead of path-based, closing the TOCTOU window.
- Infisical `set()` explicit bail on non-UTF-8 `$TMPDIR` paths (`to_str().ok_or_else(...)?` instead of `to_string_lossy()`).

### Docs
- Infisical self-hosted domain-trust section expanded with pin-the-cert callout, verify checklist, `openssl s_client` snippet; cross-linked to `docs/security.md#self-hosted-domains`.
- Infisical `NamedTempFile` panic-safety wording added.
- Doppler IAM/RBAC expansion: service-token scope-mismatch vs auth-error distinction, service accounts, multi-workplace pattern.
- Doppler `doppler_token` file-permissions advisory (`chmod 600 config.toml` + 700 parent dir).
- Smoke harness Infisical blocks flagged "fixtures only, never use for a real secret" on `provision.sh` and `teardown.sh`.
- `docs/security.md` new Self-hosted Domains section cross-linked from Infisical and Vault; covers five-point discipline.

## [0.7.0] - 2026-04-22

Third single-backend release, second solo-fresh-session; adds Infisical (SaaS + self-hostable) for 10 backends total; unit tests 604 to 637, live smoke 362 to 377.

### Added
- Infisical backend (`infisical`) wrapping the `infisical` CLI (v0.43+); 10th backend. Works against hosted SaaS and self-hosted via `infisical_domain`. URI full form `infisical-<instance>:///<project-id>/<env>/<secret>` or short form `infisical-<instance>:///<secret>` with `infisical_project_id` + `infisical_environment` defaults; nested folders fold into middle segments. Config: `infisical_project_id`, `infisical_environment`, `infisical_secret_path` (default `/`), `infisical_token`, `infisical_domain`, `timeout_secs`, `infisical_bin`. Tokens travel via `INFISICAL_TOKEN` env, never `--token` argv (canary `token_travels_via_env_not_argv`); domain via `INFISICAL_API_URL`, never `--domain` (canary `domain_travels_via_env_not_argv`). `set()` writes `NAME=VALUE` to mode-0600 `NamedTempFile` and spawns `infisical secrets set --file <tempfile> --type shared` (canary `set_value_never_appears_on_argv`). `--type shared` mandatory on set and delete (CLI default is `personal`); drift-catch locks it. `list()` uses `--output json` (Doppler-style bulk model). `history()` unsupported. 
- Smoke Section 23; provisions `SMOKE_TEST_VALUE=sk_test_infisical_55555` in `secretenv-validation` at `dev@/`; live matrix 362 to 373. `backend.set()` not live-smoked (registry set is Pattern B only); unit-test canaries cover set discipline.

## [0.6.0] - 2026-04-22

Second single-backend release, first solo-fresh-session cycle; adds Doppler for 9 backends total; unit tests 575 to 604, live smoke 347 to 362.

### Added
- Doppler backend (`doppler`) wrapping the `doppler` CLI (v3+); 9th backend. URI full form `doppler-<instance>:///<project>/<config>/<secret>` or short form `doppler-<instance>:///<secret>` with `doppler_project` + `doppler_config` defaults. Config: `doppler_project`, `doppler_config`, `doppler_token`, `timeout_secs`, `doppler_bin`. Tokens travel via `DOPPLER_TOKEN` env, never `--token` argv (canary `token_travels_via_env_not_argv`). `set` pipes values through child stdin with `--no-interactive`. `list()` uses the whole config as alias map with a `DOPPLER_*`-prefix filter excluding synthetic `DOPPLER_PROJECT` / `DOPPLER_CONFIG` / `DOPPLER_ENVIRONMENT`. `history()` unsupported.
- Smoke Section 22, 15 live assertions; provisions `secretenv-validation` project + `dev` config with `SMOKE_TEST_VALUE`; tagged `cloud=yes`; filter locked by unit tests `list_returns_filtered_map` + `list_filters_every_doppler_prefixed_key`; live matrix 347 to 362.

### Fixed
- Provision harness Azure soft-delete recoverable state handling. Added `az_ensure_available()` in `scripts/smoke-test/provision.sh` that pre-checks `show-deleted` per fixture, runs `az keyvault secret recover` + `sleep 8` when soft-deleted, making provision idempotent across teardown/provision cycles.

## [0.5.0] - 2026-04-22

First single-backend-per-release cycle; adds macOS Keychain, canonical `examples/` directory, and 5 blocking audit fixes for 8 backends total; unit tests 536 to 575, live smoke 336 to 347.

### Added
- macOS Keychain backend (`keychain`) wrapping the system `security` CLI for `generic-password` / `internet-password` items; 8th backend. URI `keychain-<instance>:///<service>/<account>`. Config: `keychain_path`, `kind` (`generic-password` default or `internet-password`), `timeout_secs`. Platform-gated (factory bails on non-macOS; crate compiles everywhere). Every invocation uses `stdin: Stdio::null()`. `set` passes value via child argv (same-UID exposure accepted, no opt-in gate), `tracing::warn!` on every set. `list()` intentionally unsupported; `history()` and extensive-check unsupported.
- `examples/` directory at repo root with seven subdirectories (`single-backend-local/`, `single-backend-aws-ssm/`, `single-backend-keychain/`, `cascade-local-then-vault/`, `multi-cloud-aws-and-1password/`, `ci-github-actions/`, `secretenv-toml-canonical/`), each with `config.toml` + `secretenv.toml` + README. Top-level `examples/README.md` flags the "NOT Cargo examples" caveat.
- Smoke Section 21; provisions a test keychain at `$RUNTIME_DIR/test.keychain-db`; exercises doctor/get/run/list/history; tagged `cloud=yes`; live matrix 336 to 347.

### Tests
- Workspace unit tests 536 to 575 (+39), all in `secretenv-backend-keychain`: URI parsing (incl `%2F` escape), factory validation, get/set/delete strict-mock argv, list/check_extensive/history unsupported messages, check() paths, drift-catch locks for argv invariants.
- Live smoke 336 to 347 (+11): Section 21 Keychain.

### Internal
- Three-agent closing audit landed 5 BLOCKING findings before tag:
- `keychain_path` values starting with `-` rejected at factory time.
- `check()` distinguishes `"No such keychain"` (missing file, Error) from locked keychain (`NotAuthenticated`, unlock hint).
- `check()` validates `show-keychain-info` output contains a `Keychain` sentinel before returning Ok.
- Three drift-catch tests added declaring `-k <path>` argv on get/delete/check, asserting no-match.
- `history()` overridden to call `reject_any_fragment("keychain")` before bailing.

## [0.4.0] - 2026-04-22

Team ergonomics + distribution profile system + tooling hygiene; no new backends (still 7); unit tests 442 to 536, live smoke 250 to 336; 6 blocking audit findings closed.

### Added
- `secretenv profile install|list|update|uninstall` distribution profile system. A profile is a TOML doc (`[backends.*]` + `[registries.*]` only) fetched over HTTPS and auto-merged at load time; fills gaps, never overrides (user config wins; among profiles alphabetical filename order decides). Lands in `<config_dir>/profiles/<name>.toml` with sidecar `<name>.meta.json` (source URL + ETag + timestamp) for `If-None-Match` re-fetch. Default base URL `https://secretenv.io/profiles`; overridable via `SECRETENV_PROFILE_URL` or `--url` (supports `file://`). Fetches via `curl` subprocess; bodies validated as `Config` before write. Names go through ASCII allowlist (`[A-Za-z0-9][A-Za-z0-9_-]*`, 64-char cap, Windows reserved-name check); `curl --max-filesize 1MiB` + `--proto =https,file`. `profile list --json` emits array; `profile update` with no name updates all.
- `Config::load` + `Config::load_from` auto-merge profiles from the `profiles/` directory. New public helpers `secretenv_core::default_config_path_xdg()` and `secretenv_core::profiles_dir_for(config_path)`; 1 MiB per-file size cap.
- `secretenv registry history <alias>` shows version history, most-recent-first. New `Backend::history()` trait method returns `Vec<HistoryEntry>` (`version`, `timestamp`, `actor`, `description`); default reports unsupported. Native impls: `local` (`git log --follow`), `aws-ssm` (`aws ssm get-parameter-history`, value field deliberately not deserialized), `vault` (`vault kv metadata get`, KV v2 only, soft-deleted/destroyed surfaced). `aws-secrets`, `1password`, `gcp`, `azure` report unsupported via default.
- `HistoryEntry` struct exported from `secretenv_core`; fields string-typed.
- `secretenv registry invite [--registry <name>] [--invitee <id>] [--json]` produces copy-pasteable onboarding payload: config.toml snippet, per-backend IAM/RBAC grant command, two universal verify steps. Local renders filesystem/git guidance; unknown types render generic pointer.
- `secretenv doctor --fix` shells out to canonical remediation CLI per backend type (`aws sso login`, `op signin`, `gcloud auth login`, `az login`, `vault login`) with inherited stdio when `NotAuthenticated`; re-runs check() once; records `Remediation actions` / `fix_actions`.
- `secretenv doctor --extensive` Level 3 depth probe; reads every matching `[registries.*]` source and runs `Backend::check_extensive(uri)`; renders `depth probe` block + `backends[*].depth` array; source URIs deduped.
- `--fix` and `--extensive` compose in a single invocation.
- `DoctorOpts` struct passes flags to `run_doctor`; implements `Default`.
- Per-instance `timeout_secs` config override applies to get/set/delete/list/history; positive integer, default `DEFAULT_GET_TIMEOUT` (30s); `check` uses `DEFAULT_CHECK_TIMEOUT` (10s) and ignores it. New `Backend::timeout()` trait method; call sites in `runner::fetch_one` and `resolver::fetch_layer` wrap with `with_timeout`. New `optional_duration_secs` + `optional_bool` helpers in `secretenv_core::factory_helpers`.
- `scripts/smoke-test/` promoted into the repo: `provision.sh`, `run-tests.sh`, `teardown.sh`, `lib/common.sh`, `fixtures/`, `README.md`. `run-tests.sh` adds `--sections N,M,P-Q`, `--local-only` (sections 1, 12, 18), `--list-sections`.
- `smoke-local` CI gate in `.github/workflows/ci.yml` runs `--local-only` on every push/PR.
- SPDX + copyright headers on every `crates/**/*.rs` (29 files): `// Copyright (C) 2026 Mandeep Patel` + `// SPDX-License-Identifier: AGPL-3.0-only`.

### Changed
- 1Password `set` now safe-by-default; refuses with a clear error explaining argv exposure, instructing manual edit or `op_unsafe_set = true` opt-in (retains argv behavior + tracing warning). Behavior change for `secretenv registry set` against 1Password; documented as a pre-launch breaking change.
- Canonical domain renamed `secretenv.dev` to `secretenv.io` across install.sh, README, CHANGELOG, SECURITY, docs, Cargo metadata. Shell-level `install.sh --profile <name>` flag removed (wrote unvalidated TOML); now errors pointing to `secretenv profile install`.
- `UpdateOutcome` and `UpdateReport` marked `#[non_exhaustive]`.
- `profile install` / `update` / `uninstall` status messages flipped `println!` to `eprintln!`.
- `deny.toml` AGPL allowance tightened: removed `AGPL-3.0-only` from global `licenses.allow`; first-party crates admitted via per-crate `licenses.exceptions` entries.
- Profiles posture v0.4: unsigned + HTTPS only; signing + central index deferred to v0.5+.

### Tests
- Workspace unit tests 442 to 536 (+94): doctor (+11), registry history (+10), registry invite (+16 in `crates/secretenv-cli/src/invite.rs`), profile (+19), config merge (+5), CLI integration (+6).
- Live smoke 250 to 336 (+86): registry history (24), registry invite (35), doctor `--fix`/`--extensive` (15), `timeout_secs` + `op_unsafe_set` (12).

### Internal
- Workspace version 0.3.0 to 0.4.0.
- GitHub Actions bumped for Node 24: `actions/checkout` v4 to v6, `actions/upload-artifact` v4 to v7, `actions/download-artifact` v4 to v8, `softprops/action-gh-release` v2 to v3.
- `secretenv-testing` stays `publish = false`.
- Closing reviewer-trio audit 2026-04-21 surfaced 6 blocking findings, all closed before tag.

## [0.3.0] - 2026-04-19

Two new cloud backends (GCP Secret Manager + Azure Key Vault), canonical `#key=value` fragment grammar, strict-mode mock harness across every backend, shared factory helpers, parallel check() via `tokio::join!`, and relicensing MIT to AGPL-3.0-only + CLA; ships the v0.2.1 to v0.2.7 arc as one release for 7 backends total.

### Added
- `Response::with_stdin_fragment(impl Into<String>)` chainable method on `secretenv-testing::Response`; appends to `stdin_must_contain`. `success_with_stdin` constructor remains.
- `check_extensive_counts_registry_entries` unit test added to `secretenv-backend-gcp` and `secretenv-backend-azure`; locks trait-default `Ok(self.list(test_uri).await?.len())`.
- `set_drift_catch_rejects_data_flag_on_argv` unit test added to `secretenv-backend-gcp`; declares buggy `--data=<secret>` form.
- Fragment-error messages link to `docs/fragment-vocabulary.md` in gcp and azure `resolve_version`; tests assert `msg.contains("fragment-vocabulary")`.
- Contributor License Agreement: new `CLA.md` (license grant, not copyright assignment), `AUTHORS.md` (signed-contributor ledger), expanded `CONTRIBUTING.md` License-and-CLA section. Signing via `git commit --signoff` + adding name to `AUTHORS.md`. No CLA = no merge.
- `secretenv-backend-azure` new crate: Azure Key Vault via the `az` CLI. URI `azure-<instance>:///<secret-name>[#version=<32-char-hex>]`; `#version=` accepts 32-char lowercase-hex ID or `latest` (latest/absent omits `--version`). Required `azure_vault_url` regex-validated across four sovereign-cloud domains (`.vault.azure.net`, `.vault.azure.cn`, `.vault.usgovcloudapi.net`, `.vault.microsoftazure.de`) with path-traversal + hyphen-edge rejection. Optional `azure_tenant`, `azure_subscription`, `az_bin`. `set` pipes via `--file /dev/stdin --encoding utf-8` (load-bearing; default base64 corrupts text). Fragment on set rejected before network. `check()` runs `az --version` + `az account show` via `tokio::join!`. Soft-delete documented (purge is manual). Cert-bound secrets surface a distinct error. 36 strict-mode tests.
- `secretenv setup` gains `--azure-vault-url` + `--azure-tenant` + `--azure-subscription` flags; scheme router accepts `azure` + `azure-*`; serializer adds `azure` JSON arm.
- `secretenv-backend-gcp` new crate: Google Cloud Secret Manager via the `gcloud` CLI. URI `gcp-<instance>:///<secret-name>[#version=<n>]`; `#version=` supports positive integers + `latest` (latest omits flag). Required `gcp_project`. Optional `gcp_impersonate_service_account` (SA-email plausibility-validated), `gcloud_bin`. `set` pipes via `--data-file=/dev/stdin`; fragment on set rejected before network. `check()` runs `gcloud --version` + `gcloud auth print-access-token` + `gcloud config get-value account` via `tokio::join!`; token read for exit status only, stdout dropped (canary `check_level2_auth_ok_never_logs_token_body`). 32 strict-mode tests. Secret-name charset `[a-zA-Z0-9_-]{1,255}` validated locally before any gcloud call.
- `secretenv setup` gains `--gcp-project` + `--gcp-impersonate-service-account` flags; scheme router accepts `gcp` + `gcp-*`; serializer emits gcp registries as JSON.

### Changed
- `BackendUri::fragment_directives` return type `HashMap<String, String>` to `IndexMap<String, String>`; insertion order deterministic, removes `sort_unstable`; backends call `.shift_remove(...)`. Pre-launch breaking change. Touched `secretenv-core/src/uri.rs`, `secretenv-backend-{aws-secrets,gcp,azure}/src/lib.rs`.
- `strict::Rule` refactor: flattened fields collapsed to `Rule { argv, response: Response }`; `StrictMock::on` copies one struct move. `Rule` is private, no API break.
- Drift-catch assertion bodies tightened from `msg.contains("strict-mock-no-match") || msg.contains("azure")` (tautology) to `msg.contains("strict-mock-no-match")` only; applied to gcp + azure.
- LICENSE MIT to AGPL-3.0-only (pre-launch breaking change). Published MIT releases (v0.1.x, v0.2.0) remain under original terms; AGPLv3 applies going forward. AGPLv3 closes the SaaS-wrapping loophole.
- Workspace `Cargo.toml` `license` field flipped `"MIT"` to `"AGPL-3.0-only"`; inherited via `license.workspace = true`.
- README badge + License section updated to reflect AGPLv3 + MIT-era disclosure.

### Fixed
- Azure vault URL regex accepted 1-char names but rejected 2-char. Flipped to `^https://[a-zA-Z0-9][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]\.vault\...` (required middle+last, min 3, max 24). Three new tests: `factory_rejects_one_char_vault_name`, `factory_rejects_two_char_vault_name`, `factory_accepts_three_char_vault_name`.

## [0.3.0-alpha.0]

v0.3 groundwork; pure internal refactoring, zero behavior change; aggregate release window opened (v0.2.1 to v0.2.7 + v0.3 ships as one v0.3.0 release).

### Changed
- `Backend::check_extensive` now has a trait default implementation (`Ok(self.list(test_uri).await?.len())`); five backends' duplicated impls removed; faster backends may override.
- `secretenv-core::factory_helpers` new public module exposing `required_string(config, field, backend_type, instance_name)` and `optional_string(...)`; `backend_type` label is the new argument; aws-ssm, vault, aws-secrets call shared helpers; 6 new unit tests.
- `Backend::check` for aws-ssm, aws-secrets, vault, 1password runs Level 1 (`<cli> --version`) and Level 2 (auth probe) concurrently via `tokio::join!`; no behavior change.

### Internal
- Workspace version 0.2.7 to 0.3.0-alpha.0.
- Workspace test count 359 to 365 (+6 factory_helpers tests).
- CHANGELOG entries undated per dev-only posture; date fills in at v0.3.0 tag.

## [0.2.7]

Security hardening follow-up to the v0.2.x retrofit series; defense-in-depth fixes from a three-reviewer audit, no user-facing behavior change for valid URIs.

### Security
- `secretenv-testing::StrictMock`: env-var keys passed to `Response::with_env_var` / `with_env_absent` are validated at call time against `^[A-Za-z_][A-Za-z0-9_]*$`; a malformed key panics immediately instead of injecting shell into the generated mock script.
- `secretenv-testing::StrictMock`: stdin-fragment mismatch diagnostic now emits only a REDACTED fingerprint (`<len>-byte:<first-4-chars>...` for long values, `<len>-byte:<redacted>` for short), never the full secret.
- `secretenv-testing::strict::escape_for_double_quoted`: panics on embedded `\n` / `\r` instead of silently swapping for space.
- `secretenv-core::uri`: new `BackendUri::reject_any_fragment(backend_label)` method + `FragmentError::UnsupportedForBackend` variant; called from `get` / `set` / `delete` / `list` in aws-ssm, vault, and 1password (which accept no fragment directives), applied transitively to `list` paths that delegate to `get`.
- `secretenv-backend-1password::get`: added `debug_assert!` post-condition on `parse_path` output (no `/` in `(vault, item, field)`) to guard against path structure leaking into the `op://<v>/<i>/<f>` argv token.
- Integration smoke harness: shared `secretenv-validation/api-key` fixture restore wired via `trap restore_fixture_on_exit EXIT` at the top of `run-tests.sh`; v0.2.6 test 118 retained for observability.

### Internal
- 6 new unit tests in `secretenv-testing::strict::tests`: `stdin_fragment_redaction_fingerprint_hides_value_never_leaks_full`, four env-var key validation panic-tests, `escape_for_double_quoted_panics_on_newline`; existing `stdin_check_rejects_when_fragment_missing` updated to assert the redacted-fingerprint contract.
- Workspace test count 353 to 359.

## [0.2.6]

Internal test-infrastructure release: aws-secrets backend mock-CLI tests migrated to `StrictMock`, plus the first prod-code bug surfaced by the strict retrofit.

### Fixed
- `secretenv-backend-aws-secrets`: `get()` now validates the fragment directive (`#json-key=<field>`, shorthand rejection, unsupported-directive rejection) BEFORE invoking `aws secretsmanager get-secret-value`; pre-fix an invalid fragment caused a wasted AWS round-trip. No end-user-visible behavior change for valid URIs.

### Changed
- Internal: all 25 mock-using tests in `secretenv-backend-aws-secrets` converted to declarative `StrictMock::new("aws").on(argv, Response).install(...)`; every `secretsmanager get-secret-value` / `put-secret-value` / `delete-secret`, `sts get-caller-identity`, and `aws --version` argv asserted exactly. The PR #33 leading-slash-on-`--secret-id` fix is implicitly locked across every migrated test.
- Internal: argv-builder helpers `get_argv(secret_id)` / `put_argv(secret_id)` / `delete_argv(secret_id)` + `STS_ARGV_NO_PROFILE` const.
- Internal: `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin`.
- Internal: two new drift-catch regression-lock tests: `get_drift_catch_rejects_leading_slash_on_secret_id` and `set_drift_catch_rejects_secret_leaking_to_argv`.
- Internal: three `command_always_passes_region` / `command_omits_profile` / `command_includes_profile` log-file argv-shape tests collapsed; `--region us-east-1` now implicitly asserted via the argv helpers, profile-absent and profile-present cases retained.
- Internal: v0.2.1 shorthand-reject and unsupported-directive-reject tests (`get_rejects_legacy_shorthand_fragment_with_migration_hint`, `get_rejects_unsupported_directive_with_enumerated_list`) now use empty-rule mocks; both include a `!msg.contains("strict-mock-no-match")` check.

## [0.2.5]

Internal test-infrastructure release: vault backend mock-CLI tests migrated to `StrictMock`; the PR #33 address/namespace fix (via `VAULT_ADDR` / `VAULT_NAMESPACE` env vars, not argv flags) now a typed regression lock. No user-facing CLI changes; no prod bugs surfaced.

### Added
- `secretenv-testing`: `Response::with_env_var(key, value)` and `Response::with_env_absent(key)` chainable per-rule env-var contracts; generated POSIX shell uses `${KEY+set}` parameter expansion so values with spaces/quotes/regex metacharacters round-trip. Additive, `#[non_exhaustive]` honored. 6 new unit tests in `secretenv-testing::strict::tests`.

### Changed
- Internal: all 17 mock-using tests in `secretenv-backend-vault` converted to declarative `StrictMock::new("vault")...install()`; every `vault kv get` / `put` / `delete`, `vault token lookup`, and `vault --version` argv asserted exactly. The address/namespace regression lock (no `-address` / `-namespace` argv flags) is implicit in the match.
- Internal: env-log side-channel tests (`command_omits_namespace_env_when_not_configured`, `command_includes_namespace_env_when_configured`) rewritten as declarative `with_env_var` / `with_env_absent` assertions.
- Internal: `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin`.
- Internal: two new drift-catch regression-lock tests: `set_drift_catch_rejects_secret_leaking_to_argv` and `get_drift_catch_env_check_rejects_wrong_vault_addr` (env-pathway).

### Fixed
- None. The retrofit surfaced no prod bugs in the vault backend.

## [0.2.4]

Internal test-infrastructure release: 1password backend mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Changed
- Internal: all 13 mock-using tests in `secretenv-backend-1password` converted to declarative `StrictMock::new("op").on(argv, Response).install(...)`; every `op read`, `op item edit`, `op --version`, and `op whoami --format=json` argv asserted exactly (including the `--account <X>` tail when configured).
- Internal: `delete_runs_edit_with_empty_value` simplified; the declared argv token `F=` is now the assertion under strict match.
- Internal: two new drift-catch regression-lock tests: `get_drift_catch_rejects_missing_account_flag`, `set_drift_catch_rejects_missing_vault_flag`.
- Internal (one exception): `get_non_utf8_response_errors_with_context` stays on the raw `install_mock` harness because its assertion relies on a non-UTF-8 response, which `Response.stdout: String` cannot express.

### Fixed
- None. The retrofit surfaced no prod bugs in the 1password backend; `set` stdin-path version-gating remains a v0.3 follow-up.

## [0.2.3]

Internal test-infrastructure release: aws-ssm backend mock-CLI tests migrated to `StrictMock`. No user-facing CLI changes; no prod bugs surfaced.

### Added
- `secretenv-testing`: `Response::with_stderr(stderr)` chainable method for "response emits on stderr, not stdout." Additive, `#[non_exhaustive]` honored.

### Changed
- Internal: all 14 mock-using tests in `secretenv-backend-aws-ssm` converted to declarative `StrictMock::new("aws").on(argv, Response).install(...)`; every flag, positional, and value in every `aws` argv asserted exactly.
- Internal: `set_passes_secret_value_via_stdin_not_argv` rewritten using `Response::success_with_stdin`.
- Internal: two new drift-catch regression-lock tests: `get_drift_catch_rejects_missing_with_decryption_flag`, `set_drift_catch_rejects_secret_leaking_to_argv`.
- Internal (one exception): `get_non_utf8_response_errors_with_context` stays on the raw `install_mock` harness due to its non-UTF-8 response assertion.

## [0.2.2]

Internal test-infrastructure release: strict-mode mock harness for backend crates. No user-facing CLI changes.

### Added
- `secretenv-testing::StrictMock`: declarative mock-CLI builder. `StrictMock::new(bin).on(argv, Response).install(dir)` generates a POSIX shell script matching full joined argv against a rule list, exiting 97 on no-match with a diagnostic naming the observed argv and every declared shape. `Response::success`, `Response::failure`, and `Response::success_with_stdin` cover the needed shapes. Types are `#[non_exhaustive]` so future matchers (`PositionalThenFlags`, `Regex`, env-var assertions) can land additively.
- `crates/secretenv-cli/tests/e2e.rs`: two end-to-end scenarios proving `StrictMock` through the full call chain (one happy-path exact argv match, one drift-catch asserting exit 97); reference pattern for the v0.2.3 to v0.2.6 per-backend retrofits.
- `secretenv-backend-local` crate-level doc note explaining the retrofit covers it by documentation only since the backend does not shell out.

### Changed
- Internal only: strict-mode harness test infrastructure. No CLI behavior, URI grammar, or backend semantics changed.

## [0.2.1]

Canonical `#key=value` fragment grammar; one deliberate pre-launch breaking change locking the URI vocabulary.

### Changed, BREAKING (pre-launch correction window)
- Fragment grammar canonicalized. URI fragments must match `#key=value[,key=value]*` under a single grammar enforced by `BackendUri::fragment_directives()` in `secretenv-core`; each backend declares its recognized directive keys, unknown keys error with the full URI and a recognized-directive list.
- aws-secrets: `#<field>` shorthand (v0.2.0) becomes `#json-key=<field>` canonical (v0.2.1); the shorthand is rejected at URI-parse time with a `ShorthandRejected` error naming the canonical replacement (e.g. `aws-secrets:///db#password` suggests `aws-secrets:///db#json-key=password`). The backend recognizes only `json-key`; any other directive surfaces as a single error listing every offender. Only deliberate breaking change permitted inside a 0.2.x patch, taken pre-launch with zero install base.

### Added
- `BackendUri::fragment_directives()`: typed accessor parsing the fragment body into a directive map per the canonical grammar. `FragmentError` (re-exported from `secretenv_core`) reports `ShorthandRejected`, `Malformed`, and `DuplicateKey`.
- Canonical grammar doc at `docs/fragment-vocabulary.md` including the directive registry and the v0.2.0 shorthand migration table.

### Migration

| v0.2.0 (removed) | v0.2.1+ (canonical) |
|---|---|
| `aws-secrets-prod:///db-creds#password` | `aws-secrets-prod:///db-creds#json-key=password` |
| `aws-secrets-prod:///db-creds#host` | `aws-secrets-prod:///db-creds#json-key=host` |

If an error mentions "legacy plain-string shorthand", rewrite the cited URI per the table; no config or registry changes needed beyond the URI bodies.

## [0.2.0] - 2026-04-18

2 new backends (Vault, AWS Secrets Manager), cascading registries, parallel secret fetch, shell completions, enriched `resolve` report, per-cascade-source doctor, shared `secretenv-testing` crate, and a 7-item security preflight; 13 PRs (#22 to #34).

### Added
- Shell completions: new `secretenv completions <bash|zsh|fish>` subcommand emits a clap-generated completion script; writes to `--output <path>` (chmod 0o644) or stdout, with a shell-specific install hint to stderr when stdout is a TTY. PowerShell/Elvish deliberately omitted.
- AWS Secrets Manager backend (`type = "aws-secrets"`): wraps the same `aws` CLI as `aws-ssm` (identical auth). URI shape `aws-secrets-<instance>:///<secret-id>[#<json-key>]`; first consumer of `BackendUri.fragment`. `#<json-key>` extracts a top-level field from a JSON-valued secret, coercing scalars to strings and erroring on nested objects/arrays with available field names listed. `set` pipes via `--secret-string file:///dev/stdin`; `delete` is unconditionally `--force-delete-without-recovery`. Update-only (create deferred to v0.3). 26 mock-CLI tests.
- `secretenv setup` routes `aws-secrets(-*)` schemes to the new backend type; `--region` + `--profile` apply to both AWS backends.
- HashiCorp Vault backend (`type = "vault"`): wraps the `vault` CLI (every CLI auth flow works transparently). URI shape `vault-<instance>://<mount>/<path>`; unified `vault kv` CLI so KV v1 and v2 work identically. `get` uses `-field=value`; `set` pipes via `value=-`; Level 2 doctor uses `vault token lookup`. Supports Enterprise namespaces via optional `vault_namespace` config field (`-namespace` omitted when unset). 25 mock-CLI tests.
- `secretenv setup` gains `--vault-address` and `--vault-namespace` flags; `vault` and `vault-*` scheme prefixes map to the vault backend type.
- Session-scoped registry cache: new `secretenv_core::RegistryCache` memoizes `backend.list(source)` by source URI for the process lifetime. `resolve_registry` takes `&mut RegistryCache`, issues a backend call only on cache miss, returns a zero-I/O `Arc<CascadeLayer>` on hit; cache warmed concurrently via `futures::future::join_all`. Holds alias-to-URI pointers only, never secret values.
- Registry cascades: `[registries.<name>]` accepts multiple `sources = [...]` entries; lookup is first-match-wins from `sources[0]` down, `sources[0]` remains the single write target for `registry set/unset`; all sources fetched concurrently via `futures::future::join_all`, any source failure fails the whole resolve.
- `secretenv_core::CascadeLayer` public type exposing per-source `{source, map}`.
- `AliasMap::get` now returns `(target_uri, source_uri)` so callers can tell which cascade layer resolved an alias.
- `AliasMap::primary_source`, `layers`, `sources` accessors.
- `BackendUri.fragment: Option<String>`: parses the `#<fragment>` suffix; not yet consumed by any backend.
- `secretenv_core::with_timeout` helper and `DEFAULT_GET_TIMEOUT` (30s) / `DEFAULT_CHECK_TIMEOUT` (10s) constants; backend ops now have deadlines so `doctor` and `run` cannot hang on a wedged CLI.
- `BackendConfig.raw_fields` now preserves typed TOML values (`HashMap<String, toml::Value>` instead of `HashMap<String, String>`); factories can read `as_str`, `as_integer`, `as_bool`, `as_array`.

### Changed
- `secretenv doctor` gains a `Registries` section reporting per-source reachability for every cascade source; each line shows status + source URI + a one-word suffix (`reachable` / `backend not authenticated` / `backend CLI 'x' missing` / `backend error`), non-OK sources render an indented hint. A single backend-instance status feeds every source using it. `--json` gains a top-level `registries: [{name, sources: [{uri, status, hint}]}]` key with `skip_serializing_if = "Vec::is_empty"` for v0.1 backward-compatibility.
- `doctor` exit code still driven by backend-level summary only; the Registry section is informational.
- `secretenv resolve <alias>` now emits a tabular metadata report instead of just the resolved URI: rows `alias`, `env var`, `resolved`, `source` (cascade layer URI + index), `backend` (one-line Level 2 status). New `--json` flag. Manifest loading is best-effort (missing `secretenv.toml` sets `env_var` to `(none)`); backend check failure does not fail resolve.
- `resolve_registry` signature: added a `cache: &mut RegistryCache` parameter; callers construct `RegistryCache::new()` and pass it through. Breaking for library consumers of `secretenv-core`.
- `AliasMap` internals: layers held as `Vec<Arc<CascadeLayer>>` instead of `Vec<CascadeLayer>`; `AliasMap::layers()` returns `&[Arc<CascadeLayer>]`.
- Backend crate directories renamed to match published crate names: `crates/backends/backend-local` becomes `crates/backends/secretenv-backend-local` (same for `aws-ssm`, `1password`); the CLI directory `crates/secretenv-cli/` stays (publishes as plain `secretenv`).
- Parallel secret fetch: `runner::build_env` dispatches every alias-backed secret concurrently via `futures::future::join_all`; `Default`-sourced entries stay inline; declaration order in the emitted env map is preserved.
- Multi-error aggregation: more than one failed alias fetch returns one message listing every failure (`<N> secrets failed to resolve:` plus one line per alias with env-var, URI, cause); single-failure shape unchanged.
- `ResolvedSource::Uri` is now a struct variant `{ target, source }` instead of `Uri(BackendUri)`; the added `source` field carries the cascade layer URI.
- `registry set`/`unset` writes use `BTreeMap<String, String>` internally so alias output is alphabetically sorted and deterministic.
- `BackendFactory::create` signature: `config: &HashMap<String, toml::Value>` (was `HashMap<String, String>` by value), removing a per-load clone.
- `Manifest::find_upward` stops at project-root sentinels (`.git`, `.hg`, `.svn`, `.secretenv-root`) so a hostile upstream `secretenv.toml` cannot hijack alias resolution; falls back to v0.1 behavior with no sentinel.
- `--verbose` stderr output omits full URI paths (only env-var + backend instance name); full URIs remain under `--dry-run`.

### Fixed
- AWS SSM `set` pipes secret values via child-process stdin using `--value file:///dev/stdin`; secret never appears on argv, closing the `/proc/<pid>/cmdline` exposure window (critical).
- 1Password `set` documents its remaining argv exposure with an inline comment + stderr warning on every call; full stdin fix pending v0.3 with `op` CLI version gating (partial).
- `BackendUri::parse` rejects invalid scheme characters (outside `[a-zA-Z0-9][a-zA-Z0-9_-]*`), NUL bytes in path/fragment, and ASCII control characters except tab; warns on Unicode bidi-override codepoints without rejecting.
- `SECRETENV_REGISTRY` and `SECRETENV_CONFIG` scrubbed from the child process environment before `exec()`/`spawn`.

### Security
- Security preflight complete (three-reviewer audit); remaining audit items addressed in later feature work.

### Internal
- Extracted `secretenv-testing` crate (unpublished): the `install_mock` shell-script writer with its Linux ETXTBSY probe loop, previously duplicated in `backend-aws-ssm`, `backend-1password`, and `secretenv-cli/tests/e2e.rs`, now shared. Public surface `install_mock(dir, bin_name, body) -> PathBuf` plus `install_mock_aws` / `install_mock_op` wrappers; `publish = false` for v0.2.
- v0.2 dev baseline: branch `feat/v0.2-prep`, workspace bumped to 0.2.0, roadmap updated.
- `tokio` promoted from dev-dep to runtime dep on `secretenv-core` (for `tokio::time::timeout`); workspace tokio features gain `"time"`.
- `tracing` added as a direct runtime dep on `secretenv-core` (bidi-override warning) and `secretenv-backend-1password` (argv-exposure warning).
- `toml` added as a direct runtime dep on `secretenv-backend-aws-ssm` (factory signature now references `toml::Value`).

## [0.1.1] - 2026-04-17

First public release of SecretEnv.

### Added
- Core CLI surface: `run`, `registry list/get/set/unset`, `setup`, `doctor`, `get`.
- Three backends: `local` (TOML file), `aws-ssm` (AWS Systems Manager Parameter Store via `aws` CLI), `1password` (via `op` CLI).
- `secretenv.toml` manifest format with alias (`from = "secretenv://..."`) and default (`default = "..."`) secret declarations.
- `~/.config/secretenv/config.toml` machine-level config with `[registries.<name>] sources = [...]` and `[backends.<name>]` blocks.
- `secretenv://<alias>` URI scheme for registry-resolved aliases; direct-scheme URIs (e.g. `aws-ssm-prod:///path`) for concrete backend references.
- `BackendRegistry` + `Backend` + `BackendFactory` plugin system; all backends compiled into a single binary (no compile-time feature flags).
- Level 1 (CLI present) + Level 2 (authenticated) doctor checks, with `--json` output.
- `secretenv setup <registry-uri>` bootstrap with `--force`, `--skip-doctor`, and backend-specific flags (`--region`, `--profile`, `--account`).
- `install.sh` POSIX installer with `--profile <name>` distribution-profile support (downloads config from `https://secretenv.io/profiles/<name>.toml` by default; override via `SECRETENV_PROFILE_URL`).
- Homebrew tap at `TechAlchemistX/homebrew-secretenv`.
- Release workflow builds and publishes for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

### Security
- Workspace-wide `unsafe_code = "forbid"`.
- Clippy `unwrap_used` / `expect_used` set to warn; CI denies warnings.
- Secret values wrapped in `zeroize::Zeroizing<String>` in the runner; `exec()` replaces the parent process, zeroing automatically on drop.
- No shell interpolation; every backend uses `tokio::process::Command::args([...])` with separate argv strings.
- `cargo deny check` + `cargo audit` gate every PR.
- Errors include alias + URI + instance name + trimmed backend stderr, never the secret value.

<!-- Release tags. Only git-tagged versions are linked; untagged patch/alpha sections (0.7.1, 0.3.0-alpha.0, 0.2.1-0.2.7) have no release tag. -->
[0.19.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.19.0
[0.18.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.18.0
[0.17.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.17.0
[0.16.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.16.0
[0.15.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.15.0
[0.14.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.14.0
[0.13.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.13.0
[0.12.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.12.0
[0.11.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.11.0
[0.10.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.10.0
[0.9.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.9.0
[0.8.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.8.0
[0.7.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.7.0
[0.6.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.6.0
[0.5.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.5.0
[0.4.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.4.0
[0.3.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.3.0
[0.2.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.0
[0.1.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.1.1
