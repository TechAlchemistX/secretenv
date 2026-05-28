# Changelog

All notable changes to SecretEnv are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `YYYY-MM-DD` (UTC).

In addition to the Keep-a-Changelog sections (`Added` / `Changed` / `Deprecated`
/ `Removed` / `Fixed` / `Security`), SecretEnv cycles use a project-specific
**`Known limitations`** subsection — introduced in v0.14.0 — to document
behaviour that ships honestly but is incomplete by design (planned phase-out,
deferred follow-up, or contract that would surprise an operator). Future
cycles should reach for this subsection rather than burying limitations in
prose. Cross-reference the kb wiki for the long-form ticket.

## [Unreleased]

(Empty — pending v0.17.x carry-forwards.)

## [0.17.0] - 2026-05-28

**Headline:** First-class OpenTelemetry instrumentation lands. Traces (spans) and metrics ship across the full resolution flow + v0.14 redact + v0.15 migrate + v0.16 MCP surfaces. Zero startup cost when no `OTEL_*` env vars are set (the OTel SDK is linked but no providers are installed). Authoritative attribute matrix locked in `docs/reference/opentelemetry.md` §2 (51 ALLOW · 25 DENY · structurally enforced via the typed `SecretEnvSpan` builder — no generic `set_attribute(k, v)` escape hatch).

v0.16.0 → v0.17.0: backend total stays at **15**; workspace gains the `secretenv-telemetry` first OTel-enabled publish + 9 (Phase 8b) + 4 (Phase 8c) + 3 (Phase 9b) new typed-attribute setters totalling 38 in `SecretEnvSpan`; 4 new metric call-sites against the 10 Phase 4 instruments.

### Added

- **OpenTelemetry traces.** The `secretenv.run` root span wraps the entire resolution + exec lifecycle, with per-alias `secretenv.resolution` and per-fetch `secretenv.backend.fetch` children. Ends explicitly before `execve` (Drop can't fire across exec). 4 spec-mandated attrs on each: `run.dry_run` / `run.verbose` / `run.outcome` / `run.failed_alias_count` plus `resolution.outcome` + `resolution.latency_ms` plus `backend.fetch.outcome` + `backend.fetch.duration_ms`.
- **OpenTelemetry metrics.** 10 typed instruments: `resolution.duration` + `resolution.count` histograms/counters, `backend.fetch.duration` + `backend.probe.count`, `redact.events`, `mcp.tool.calls` + `mcp.tool.duration`, `doctor.failure.count`, `migrate.operation.count`, `registry.alias_count` gauge. Cardinality-safe by construction — `alias.name` is structurally absent from every histogram/gauge signature.
- **Redact span emission** (`secretenv.redact.filter_event`). One span per non-empty stdout/stderr stream in runtime-pipe mode, one span on the post-hoc `secretenv redact <file>` CLI path. Carries `mode` (runtime / post-hoc / disabled), `stream` (stdout / stderr), `match_count`, `byte_count`. SEC-INV-19: `redact.alias_name` is **never** emitted — alias names live only in the operator-local terminal substitution token.
- **Migrate phase tree** (`secretenv.registry.migrate` root + 5 child spans: `probe` / `read` / `write` / `pointer_flip` / `delete`). Mutation non-droppable sampler keeps every child + root in the trace stream even under aggressive ratio sampling (SEC-INV-22).
- **MCP tool spans.** All 14 MCP tools emit `secretenv.mcp.tool.<name>` spans with `tool_name`, `client_name` (from rmcp peer.client_info), and — for the 4 alias-mutation tools (`set_alias` / `delete_alias` / `migrate_alias` / `gen_password`) — `argument_alias_name`. SEC-INV-12: `argument_reason` is **never** emitted (prompt-injection vehicle; lives in the audit log only).
- **Mutation non-droppable sampler.** `MutationNonDroppableSampler<S>` wraps any operator-configured sampler and forces `RecordAndSample` for the 8 mutation span names (4 MCP + 4 migrate phases). Override-safe: `OTEL_TRACES_SAMPLER=traceidratio OTEL_TRACES_SAMPLER_ARG=0.0001` still emits every mutation. Smoke-tested live.
- **Doctor OTel surfaces.** `secretenv doctor --extensive` adds an OTel section reporting `OTEL_EXPORTER_OTLP_ENDPOINT` + TCP-connect reachability (no test span emitted). `secretenv doctor --trace` renders a local-capture span table (uses an in-process `InMemorySpanExporter`; no collector required).
- **`secretenv run --verbose`** — per-alias resolution timing table on stderr; no collector required.
- **W3C TRACEPARENT propagation.** Inbound only — `secretenv.run` becomes a child of the parent trace when run from a CI system that sets `TRACEPARENT` / `TRACESTATE`. Outbound propagation to the exec'd child binary is deferred to v1.0+.
- **Section 36 smoke harness** (`scripts/smoke-test/run-tests.sh` ~430 LOC across Blocks A–E). Docker Jaeger collector lifecycle (`scripts/smoke-test/lib/otel-collector.sh`). Isolated local-backend fixture (`scripts/smoke-test/fixtures/v0.17-otel/`). 60 assertions covering trace emission, redact spans, migrate phase tree, MCP tool attrs, console metric exporter shape, SEC-INV negative checks. Soft-SKIPs when `docker` or `jq` missing. Operator runbook at `kb/wiki/runbooks/v0.17-otel-smoke.md`.
- **Compile-fail SEC-INV guards.** trybuild gates at `crates/secretenv-telemetry/tests/ui_sec_inv_04/` (no `set_attribute` escape hatch + no `record_alias_uri_*` setter) + `ui_sec_inv_12/` (no `record_mcp_argument_reason`) + `ui_sec_inv_19/` (no `record_redact_alias_name`). CI grep gate `scripts/check_tracing_leaks.sh` extended with 7 leak patterns covering bare-macro / `Span::record(...)` / `event!()` forms.

### Changed

- **Spec §4 span topology** — `secretenv.registry.migrate` (was `secretenv.migrate`) brings the migrate root span in line with the spec'd name. Mutation sampler whitelist updated to match.
- **`SecretEnvSpan` typed builder** — 13 new `record_*` methods totalling 38 typed setters. Every emitted ALLOW attribute has exactly one method; every DENY attribute has no method. No generic `set_attribute(k, v)` exists anywhere on the type.
- **`RunOptions` is now `#[non_exhaustive]`** so future v0.17.x additions don't silently break downstream record-update constructions.

### BREAKING

- **Migrate OTel span name renamed** — `secretenv.migrate` → `secretenv.registry.migrate`. Operators with OTel-backend queries / dashboards referencing the old name need to update. The rename brings the code into line with `docs/reference/opentelemetry.md` §4.2; the old name was a leftover from the metric name being reused as the span name.
- **`RunOptions` gains `#[non_exhaustive]`** — downstream library integrators constructing `RunOptions { dry_run, verbose, redact, redact_token }` directly will need to switch to `RunOptions { dry_run, ..Default::default() }` or use the builder pattern. Within-workspace callers unaffected.

### Security

- **SEC-INV-04 holds** across the v0.17 surface expansion — every new ALLOW attribute went through a typed `record_*` setter; every new DENY attribute (5 added: `run.command_argv`, `run.env_var_value`, `registry.source_uri`, `backend.namespace`, `gen.password.{value,entropy_bits}`) has no setter. Structural enforcement via the typed builder + 4 compile-fail guards + CI grep gate.
- **SEC-INV-12 / -19 / -22 all green.** `mcp.argument_reason`, `redact.alias_name`, and the 8 mutation span names are all verified by live smoke assertions in section 36 plus integration tests in `crates/secretenv-telemetry/tests/`.
- **Phase 9b Sec F-1 fix** — `secretenv.run.command_name` is the basename of argv[0] only; absolute and relative path prefixes are stripped before emission to prevent host filesystem layout leaks to OTel collectors.

### Known limitations

- **`--otel-include-error-detail` flag is not yet shipped.** Spec §3 promises this per-run opt-in for `backend.error.message` emission (gated through the SEC-INV-20 scrubber). v0.17 ships the schema-reserved attribute as unconditionally DENY (structurally enforced by absence of `SecretEnvSpan::record_error_message` setter). Tracked at `kb/wiki/v0.17-deferred-items.md`; lands in v0.18.
- **Logs signal not installed.** `docs/reference/opentelemetry.md` §1 mentions "traces + metrics + logs". v0.17 installs `TracerProvider` + `MeterProvider`; `LoggerProvider` is reserved for a v0.17.x or v0.18 cycle. `tracing::*!` events still surface via the tracing-opentelemetry bridge as span events, just not as OTel `LogRecord` instances.
- **6 spec-listed spans are schema-reserved, not emitted.** `secretenv.manifest.load`, `secretenv.registry.load`, `secretenv.backend.probe` (under resolution), `secretenv.exec.prepare`, `secretenv.exec.flush`, `secretenv.doctor.registry`. The `execve` handoff is covered by an explicit `flush_before_exec` call rather than an `exec.flush` span. These will land as a v0.17.x hygiene chip; their absence does not affect any SEC-INV invariant. See spec §4 callout box.
- **Span parent-child relationships are flat** in v0.17 — each span is started independently via `SecretEnvSpan::start(...)` without `Context::current_with_span(...).attach()`. Operators inspecting trace UIs will see all spans at the root level rather than nested. The mutation non-droppable sampler operates per span name, not via trace ancestry, so SEC-INV-22 is unaffected. Tree-shape lift deferred to v0.17.x hygiene.

### v0.16.2 — Refactor sprint (merged-not-tagged) — in progress

Carries the three substantive refactors that v0.16.1's hygiene cycle deferred mid-cycle because each introduces new public crate/subcommand surface that needs a real Phase 7 audit. Plus F-11 (Copilot empty-schema A/B test) operator-led fixture.

- **D.2a — `run_mutation` combinator** (module in `secretenv-mcp`). Per Phase 7 code-review High-1: collapses ~120 LOC of policy-gate + audit-log boilerplate across the `set_alias` / `delete_alias` / `init_project` handlers into one combinator call. `redact_file` / `gen_password` / `migrate_alias` kept as-is (multi-stage validation / orphan-state precision that the clean combinator shape would lose). Retired the misleading `should_audit` helper.
- **D.2b — new `secretenv-registry-mutate` crate.** Per Phase 7 architecture C-2 + code-review Medium: extracts the `list + edit + serialize + set` transaction body that `secretenv-cli` (`registry_set` / `registry_unset`) and `secretenv-mcp` (`registry_writer`) previously duplicated line-for-line. CLI + MCP each keep their own selection helper (env-aware vs named-only) but share the writer. Workspace + release.yml publish-list update.
- **D.3 — `audit_log.rs` fcntl-lock + size rotation + `secretenv mcp audit tail` subcommand.** `flock(LOCK_EX)` around every append (cross-process serialization for multi-IDE deployments). Size-based rotation at `[mcp].audit_log_max_bytes` (default 10 MiB; 0 disables) with `[mcp].audit_log_max_rotations` cap (default 5; 0 truncates). New operator subcommand `secretenv mcp audit tail [--lines N] [--path PATH]` for read-only chronological inspection of recent entries.
- **D.5 — new `secretenv-mcp-config` crate.** Per Phase 7 architecture C-1: lifts the typed `[mcp]` config schema (`AllowMutations`, `ConfirmVia`, `McpConfig`, `PolicyOverrides`) out of `secretenv-mcp` into a slim sibling crate so future consumers (e.g. a slimmer `secretenv doctor` that validates `[mcp]` without spinning up rmcp) can depend on the config types alone. Backward-compat re-exports preserve every `secretenv_mcp::config::*` path. Workspace + release.yml publish-list update.
- **F-11 Copilot empty-schema A/B test prep.** Operator-led fixture at `scripts/smoke-test/fixtures/vscode-mcp-copilot/` + runbook at `kb/wiki/runbooks/copilot-elicitation-validation.md`. No source-level change to `MutationApproval` in v0.16.2 — the runbook walks the operator through the A/B and the decision tree gates whether option (a) (`confirm: bool` no-op field) ships as default or F-11 closes as upstream-fix-only.

Pending in v0.16.2 (this cycle): Phase 7 audit trio, Phase 8 live-backend smoke, Phase 10 PR + squash-merge.

> Carried over to a future cycle: v0.17 OpenTelemetry (design-locked); Item 12 operator-led upstream issues with Gemini / Cline / Codex / OpenCode for `elicitation: {}` capability declaration; F-3 `[mcp].allow_cli_overrides`; F-7 `mcp_client_id` threading; M-9 / M-12 migrate dual-control reconciliation + `dry_run` audit entry; R-3 `secretenv mcp setup --check-overrides` detector.

## [0.16.0] - 2026-05-24

**Headline:** `secretenv mcp serve` lands — the stdio-only Model Context Protocol server giving AI agents (Claude Code, Cursor, Cline, Gemini CLI / Code Assist, Codex, OpenCode, VS Code Copilot, Continue) structured access to the SecretEnv registry **without ever exposing a resolved secret value**. 14 MCP tools cover read, mutation, generation, and migration paths. Cross-IDE day-one support for 8 IDEs via `secretenv mcp setup --ide <name>`. Backend total stays at **15**.

v0.15.0 → v0.16.0: workspace unit tests **1018 → 1043** (+25 from MCP + elicitation + XDG-path + per-IDE-override + SEC-INV-20 regression coverage). Three new crates published to crates.io for the first time: `secretenv-mcp`, `secretenv-backends-init`, `secretenv-migrate`.

### BREAKING

- **(Phase 7c) `[mcp].confirm_via` default flipped from `Tty` → `Auto`.** v0.16-pre-Phase-7c default (`Tty`) deadlocked inside TUI host IDEs that own the controlling terminal in raw mode (Claude Code FINDING-4; predicted by Phase 7 security audit M-15). The new `Auto` default resolves at runtime per request: if the client declared MCP elicitation capability at the initialize handshake, use `Elicitation`; else if `stdin` is a TTY (standalone shell), use `Tty`; else refuse with a clear error pointing at remediation. The `Tty` variant remains valid as an explicit opt-in for standalone shell use. Per `kb/wiki/feedback_prelaunch_breaking_changes.md` (one bundled BREAKING in a `0.x.y` cycle is acceptable pre-public-announcement; install base for the v0.16 MCP surface is zero).
- **(Phase 7h R-4) `ConfirmVia` + `MigrateReportOutcome` enums marked `#[non_exhaustive]`.** Locks freedom to add variants in v0.16.x patches without breaking downstream `match` arms. Downstream consumers using `match` on these enums must add a `_` arm. The MCP boundary's `MigrateOutcomeEcho` mirror enum in `secretenv_mcp::boundary` is NOT `#[non_exhaustive]` (it's an output type, semver-stable for response consumers).

### Added

- **`secretenv mcp serve`** — the headline v0.16 feature. Stdio-only MCP server built on the official `rmcp` 1.7 Rust SDK. 14 tools: `getting_started`, `version_info`, `list_tools`, `redact_status`, `list_backends`, `detect_password_managers`, `doctor`, `resolve_status`, `list_aliases`, `set_alias`, `delete_alias`, `init_project`, `redact_file`, `gen_password`, `migrate_alias`. Per-tool JSON Schema; structured response shapes; per-tool description budget ≤ ~200 tokens. Operator-side knobs via `[mcp]` config: `allow_mutations`, `confirm_via`, `disabled_tools`, `mutation_log`. `disabled_tools` filters BOTH `tools/list` AND dispatch at runtime via `ToolRouter::remove_route`. Full design + per-tool spec: `docs/reference/mcp.md` + `kb/wiki/build-plan-v0.16-mcp.md`.
- **Structural no-leak surface (SEC-INV-02)** — the `secretenv-mcp` crate **structurally cannot** construct, deserialize, or serialize a `secretenv_core::Secret<T>`. Enforcement stack: (a) `clippy.toml` bans `disallowed-types` of `Secret`/`ResolvedValue` across the crate; (b) `tests/boundary_test.rs` compile-time assertions (`Secret: !Serialize` via trybuild + per-tool response-struct exhaustiveness checks banning the field names `value`, `secret`, `password`, `token`, `raw`); (c) Phase 8 live-smoke value-grep against the section-35 fixture sentinel. The Cargo feature `value-access` (additive — landed v0.15) is documentation, not the structural guarantee: workspace feature unification means `secretenv-cli`'s opt-in flips the bit for the in-workspace build; the three CI gates above are what hold the line. Two documented escape-hatch modules — `internal/gen_engine.rs` (gen_password CSPRNG path) + `internal/redact_file.rs` (redact_file tainted-set build) — name `Secret` under `#[allow(clippy::disallowed_types)]` with operator-facing justification.
- **MCP elicitation primitive (Phase 7c)** — `ConfirmVia::Elicitation` + `ConfirmVia::Auto` variants. The elicitation surface uses MCP's native server→client elicit RPC; the IDE renders a confirmation modal in its own UI. Replaces the prior `/dev/tty` mechanism which deadlocked TUI host IDEs (FINDING-4). Empty-schema `MutationApproval{}` with hand-written `JsonSchema` impl emitting explicit `{"type":"object","properties":{},"additionalProperties":false}` (schemars 1.0's derive omits `properties` for fieldless structs; the MCP elicitation validator requires it present even when empty). Single-click decision per mutation — no checkbox to tick.
- **`secretenv mcp serve --allow-mutations <mode>` + `--confirm-via <surface>` CLI flags (Phase 7f)** — per-launch policy overrides on top of `[mcp]` config. Operators scope the override to a specific IDE's `mcpServers` args block rather than weakening their global config. Public `PolicyOverrides` struct + `serve_with_overrides()` entry point exposed from `secretenv_mcp` for embedders. Override application is logged via `tracing::info!` for observability.
- **`secretenv mcp setup --ide <name>`** — per-IDE config-snippet helper covering 8 IDEs (Claude Code, Cursor, Codex, VS Code Copilot, Continue, Cline, Gemini Code Assist + Gemini CLI, OpenCode) plus a `generic` profile for any IDE adopting the de-facto Claude `mcpServers` shape. Print-by-default (paste-ready); `--write` mode (refuses if target exists unless `--force`). Profiles for IDEs that don't fully advertise MCP elicitation (Gemini, OpenCode, Cursor speculative, Continue speculative) ship with `--allow-mutations=always` baked into the args[] per Phase 7f override pattern — operators can remove the flag if their IDE adds elicitation support. Claude Code profile emits `claude mcp add` shell command rather than overwriting `~/.claude.json` directly (the file contains unrelated Claude Code state).
- **`secretenv mcp disable` / `secretenv mcp enable`** — toggle the persistent disable sentinel at `$XDG_CONFIG_HOME/secretenv/mcp-disabled` (or the platform-native equivalent). `disable --duration <dur>` for time-limited disables; sentinel honored by every `mcp serve` invocation.
- **Mutation audit log** — JSON-Lines append-only log at `$XDG_STATE_HOME/secretenv/mcp-mutations.log` (or platform equivalent) capturing `(ts, tool_name, alias_name, backend_instance, agent_reason, operator_decision, mcp_client_id)` for every mutation tool call regardless of decision. `agent_reason` is recorded verbatim per SEC-INV-12 (never echoed back in JSON-RPC response, never set as OTel span attribute; operator-facing surfaces — TTY prompt, elicitation modal body — MAY render it).
- **XDG config path support on macOS (Phase 7d)** — `secretenv` now honors `$XDG_CONFIG_HOME` AND `~/.config/secretenv/config.toml` on macOS, not just `~/Library/Application Support/secretenv/`. Precedence: `$XDG_CONFIG_HOME` → `~/.config/secretenv/` → platform-native. Unblocks dotfiles workflows (stow / chezmoi / yadm). Phase 9 audit FINDING-F-1 added a stderr warning when `XDG_CONFIG_HOME` redirects config away from platform default, defending against hostile `.envrc` silent-redirect threats.
- **`secretenv-mcp`, `secretenv-backends-init`, `secretenv-migrate` published to crates.io for the first time.** External embedders can now `cargo add secretenv-mcp` to spawn an MCP server in their own binary; `secretenv-migrate` exposes the migrate engine library lifted out of the CLI binary (v0.15 carry-forward closed). Stable public surface documented at crate-level rustdoc; internal-but-`pub` modules marked `#[doc(hidden)]` for clarity.

### Changed

- **Migrate engine extracted to `secretenv-migrate` library crate (Phase 1a)** — was previously a private module in the `secretenv-cli` binary. Both the CLI's `secretenv registry migrate` subcommand and the new MCP `migrate_alias` tool consume the library crate. v0.15 audit B1 carry-forward closed.
- **`secretenv-backends-init` crate extracted (Phase 3f)** — shared factory wiring for `BackendRegistry::load_from_config()`. Consumed by both `secretenv-cli` and `secretenv-mcp` so the binary and the MCP server build registries via the same code path.
- **CLI `--config` help text rewritten** to reflect the new XDG-aware precedence on every platform (FINDING-2 fix).

### Fixed

- **(SEC-INV-20, Phase 7b) Backend URIs no longer appear in `Err::Display` paths** that flow into MCP `error_message` response fields. Source-side cleanup of every `with_context(|| format!(... `{uri}`))` callsite in `secretenv-mcp::tools::registry_writer` + `secretenv-mcp::internal::redact_file` (registry-name + alias-name only — URI bodies dropped). New `secretenv_mcp::error::safe_error_message(&anyhow::Error) -> String` scrubber as defense-in-depth: walks the chain, rewrites `scheme://body` → `scheme://[redacted]`. All 18 (later 25 after Phase 7c additions; Phase 7h closed the remaining 7 sites) `format!("{e:#}")` callsites feeding `error_message` swapped to `safe_error_message(&e)`. Static `no_raw_anyhow_format_in_tool_module` regression guard catches future re-introduction at compile time. 12 end-to-end JSON-serialization regression tests in `tests/uri_not_in_error_message.rs` lock in the SEC-INV-20 fix.
- **(Phase 7b) `secretenv_mcp::policy::sanitize_for_tty()` strips C0/C1/DEL control characters** from agent-controlled fragments before they reach the operator-facing confirmation surface (TTY prompt OR elicitation modal body). Closes the terminal-injection / fake-approval spoofing attack (hostile alias = `"OK\n\r[secretenv mcp] Approve? [Y/n] "`). Bidi-control sanitization (RTL override, ZWJ, etc.) deferred to v0.16.1 per Phase 9 F-2.
- **(Phase 7d) `default_config_path()` Linux CI dedup bug** — on Ubuntu CI `XDG_CONFIG_HOME=/home/runner/.config` and `$HOME/.config/secretenv/...` resolve to the same path; the original dedup only checked `native` against the candidate list, not the XDG/HOME pair. `8d493ca` introduced symmetric dedup via a `push_unique` closure.
- **(Phase 7e + 7e-fix) Single-click elicitation UX** — initial empty-schema attempt (`a7add8f`) shipped broken because schemars 1.0 derive emits `{"type":"object"}` with no `properties` key, which the MCP elicitation validator rejects. Hand-written `JsonSchema` impl for `MutationApproval{}` emits explicit `{"type":"object","properties":{},"additionalProperties":false}`. Operator gets Accept/Decline/Cancel buttons with no extra form field to tick.

### Security

- **SEC-INV-02 (no `Secret<T>` in `secretenv-mcp`):** structurally enforced. See "Added → Structural no-leak surface" above for the three-gate stack.
- **SEC-INV-12 (agent_reason audit-only):** wording refined in Phase 7h to acknowledge operator-facing surfaces (TTY prompt body, elicitation modal body) MAY render `agent_reason`. The protocol-level boundary (server → agent's tool-result payload, OTel span attributes) is unchanged: `agent_reason` is NEVER in either.
- **SEC-INV-15 (no value bytes in `gen_password` response):** `GenPasswordResponse` field set has no value-bearing field; rejection-sampling correctness verified for non-power-of-two charsets; `Zeroizing<Vec<u8>>` for raw entropy; explicit `drop(value)` after `Backend::set`.
- **SEC-INV-20 (URIs not in `Err::Display`):** see "Fixed → Phase 7b" above. Two-layer defense (source-side + scrubber) + compile-time regression guard.
- **`policy::resolve_confirm_via()` resolution order is LOAD-BEARING.** The priority chain (elicitation → tty → refuse) is documented as immutable without a new security audit; reordering would re-introduce Phase 7 FINDING-4 deadlocks. Rustdoc on the function lists the security justification per step.
- **macOS code-signing in release.yml (FINDING-5):** the release pipeline now ad-hoc-signs the macOS binary (`codesign --sign -`) between `strip` and tarball-package. Before this fix every Homebrew + manual-tarball installer on macOS would hit SIGKILL on the first `secretenv --version` invocation. Full Apple Developer ID notarization remains a post-v0.16 release-engineering upgrade.
- **`#[non_exhaustive]` on `ConfirmVia` + `MigrateReportOutcome`** (BREAKING, see above). Semver-freedom for future variants AND a defensive forcing-function for downstream consumers to think about unknown variants in `match` arms.
- **Public-API hygiene:** `secretenv-mcp` crate-level rustdoc lists the stable public surface (`serve`, `serve_with_overrides`, `disable`/`enable`/`disable_sentinel_path`, `PolicyOverrides`, `AllowMutations`, `ConfirmVia`); internal-but-`pub` modules (`tools`, `boundary`, `policy`, `internal`, `setup`, `audit_log`, `config`, `error`) are `#[doc(hidden)]` — their shapes are NOT covered by semver guarantees for external embedders.

### Known limitations

- **(Phase 8b F-9/F-12/F-13/F-16) Only Claude Code has working MCP elicitation in v0.16.** Verified empirically against 6 mainstream IDEs: Gemini CLI, Cline, Codex, OpenCode all fail to advertise the MCP elicitation capability at the initialize handshake. VS Code Copilot advertises it but doesn't render our empty-schema requests (F-11 hypothesis: Copilot may only render schemas with form fields). Per-IDE `--allow-mutations=always` argv override (Phase 7f) is the v0.16 mitigation — surfaced in `secretenv mcp setup --ide <key>` helper output for affected IDEs by default. The override skips the per-mutation confirmation gate but the audit log still captures every mutation with `autoapproved` decision. Upstream PRs to Gemini / Cline / Codex / OpenCode requesting they declare `elicitation: {}` in their `registerCapabilities` calls are queued for the v0.16.1 hygiene cycle. F-11 (VS Code Copilot empty-schema) investigation also queued — a `ConfirmVia::ElicitationWithDummy` variant adding a no-op form field could potentially unlock Copilot specifically.
- **(Phase 9 F-3) Per-IDE `--allow-mutations=always` argv override has no user-scope opt-out.** A workspace-trusted `.mcp.json` (e.g. checked into a hostile repo) can silently weaken the operator's global `[mcp].allow_mutations = "confirm"` setting. Three mitigating factors: IDE-side workspace-trust prompts (VS Code Copilot, Claude Code's `.mcp.json`) catch most cases at registration time; the audit log captures every mutation regardless; the override surface is ONLY for `[mcp].allow_mutations` + `[mcp].confirm_via` (not backend instances or registries). v0.17 carry-forward will add `[mcp].allow_cli_overrides = false` config knob (opt-in to honor argv overrides).
- **(Phase 7 audit + Phase 9 R-1) `tools/mod.rs` is ~1700 LOC with ~400 LOC of duplicated 4-arm policy-gate match boilerplate across 6 mutation handlers.** Phase 7 audit's `run_mutation` combinator refactor (consolidating the gate + audit-log boilerplate into a single helper) carries forward to v0.16.1 hygiene cycle. The duplication is mechanical to factor out; deferred per `kb/wiki/feedback_pr_scoping_hygiene_carrier.md` to keep the feature-cycle PR scoped.
- **(Phase 7 audit + Phase 9 F-7) `mcp_client_id` hardcoded `"unknown"` in audit log entries.** The rmcp `initialize` handshake's `clientInfo` is available but not yet threaded through to `MutationLogEntry`. Audit log loses ability to attribute mutations to Claude Code vs Cursor vs Codex etc. Mitigated by: every mutation logs the launching command-line argv (in `tracing::info!`) so post-incident reconstruction is possible. v0.17 fix.
- **(Phase 7 audit M-7, M-9, M-12) Additional security carry-forwards:** TTY TOCTOU between prompt-write and response-read (M-7, queued for v0.16.1); migrate dual-control collapsed to single confirmation (M-9, design change for v0.17); migrate `dry_run=true` skips policy gate entirely (M-12, can be used as topology reconnaissance — v0.17 add per-call audit-log entry even for dry-run).
- **(Phase 8b F-8) `secretenv mcp setup --ide <key> --write` has no merge logic.** For IDEs with existing settings.json content (Gemini, Cline, Continue), operator must use `jq '. * {...}'` to merge manually. `--merge` flag queued for v0.16.1 hygiene.
- **(Phase 8b F-15) Schemars 1.0 `"format": "uint"` validation noise.** OpenCode + likely other strict MCP clients emit non-blocking validation warnings for our response schemas. Cosmetic noise only — no functional impact. v0.16.1 cleanup.
- **(Phase 7c F-4 — operator focus default)** Claude Code elicitation modal defaults focus on the "Accept" button. Spacebar/Enter accepts. Easy mis-approval — operator must visually confirm before pressing. v0.16.1 carry-forward: investigate `confirm_via = "elicitation-default-deny"` variant that requests the client surface the deny option as default.

## [0.15.0] - 2026-05-20

> v0.14.x hygiene cycle (merged-not-tagged) absorbed into v0.15.0 on tag.

### BREAKING

v0.15.0 Phase 0 lands a bundled BREAKING block — three architectural follow-ups from the v0.14 Phase 9b architect-reviewer audit ([[v0.14-issues/04-v0.15-architectural-followups]] arch-H1/H2/H3). Per [[feedback_prelaunch_breaking_changes]], one bundled BREAKING in a `0.x.y` cycle is acceptable pre-public-announcement; v0.15 honors this by bundling all three into one CHANGELOG block (mirroring v0.14's Q-O1 a/b/c bundle).

- **(arch-H1) `Backend::serialize_registry_doc` + `Backend::deserialize_registry_doc` move off the trait** to free functions over a new `RegistryFormat::{Json, Toml}` enum. Backends now declare their wire format via the new `Backend::registry_format(&self) -> RegistryFormat` trait method (default `Json`); `local` and `1password` override to `Toml`. Wire-format encode/decode is the responsibility of the format enum, not the backend — v0.14's "default-with-override" trait method was an over-fit since the format selection is purely about the wire representation. External backend plugins must (a) remove their `serialize_registry_doc`/`deserialize_registry_doc` overrides and (b) override `registry_format()` if they don't use the JSON default.
- **(arch-H2) `mcp-safe` Cargo feature polarity flipped to additive `value-access`.** v0.14's subtractive `mcp-safe` was a Cargo anti-pattern (feature unification across the dep graph). v0.15 inverts: default features are now `[]` (the safe surface — what `mcp-safe` enabled at v0.14), and the new `value-access` feature gates `expose_secret`, the `Backend` re-export, the `runner::*` re-exports, and `EnvEntry::value()`. The workspace-level `[workspace.dependencies]` for `secretenv-core` enables `features = ["value-access"]` so every workspace consumer keeps today's behaviour without per-crate Cargo.toml changes. External consumers must:
  - `default-features = false` on their `secretenv-core` dep to get the safe (no-value-access) surface — formerly: `features = ["mcp-safe"]`.
  - `features = ["value-access"]` to keep value-producing APIs — formerly: omitting `mcp-safe`.
- **(arch-H3) `pub mod runner` is now cfg-gated under the `value-access` feature.** v0.14 left the module unconditionally `pub`, so downstream crates could `use secretenv_core::runner::{...}` to bypass the re-export gate. v0.15 closes the bypass at the module declaration site; reaching `runner::*` from a no-`value-access` consumer is now a compile error, not a doc-only convention.

### Added

- **`secretenv registry migrate <alias> <dest-uri>`** — the headline v0.15 feature. Migrates an alias's secret value from one backend to another in a single operation: read from the source, write to the destination, then atomically flip the registry pointer. No consuming repo touches a backend URI, so a migration never requires a code change. Flags: `--dry-run` (probe + plan, zero mutation), `--yes` (skip the top-level prompt), `--from <uri>` (override the inferred source for recovery flows), `--delete-source` (opt-in source cleanup, separately confirmed even under `--yes`), `--json` (machine-readable `MigrateReport` for CI), `--registry <name|uri>` (registry selection). The source value is **kept by default**; partial failures **never auto-roll-back by deletion** — the operator is given the manual recovery commands. Full reference: `docs/reference/migrate.md`.
- **Five new `Backend` trait methods**, all additive with default impls so existing backends and external plugins compile unchanged:
  - `write_secret(&self, &BackendUri, &Secret<String>)` — the migrate destination-write path; takes the value by `&Secret<String>` reference (borrow-not-clone). Default returns the typed `BackendError::WriteNotSupported`. 12 `Native` backends override with a passthrough; 3 `Gated` backends (`1password`, `keeper`, `bitwarden-sm`) refuse unless their `*_unsafe_set` config flag is set.
  - `delete_secret(&self, &BackendUri)` — the opt-in `--delete-source` cleanup leg. Default returns `BackendError::DeleteNotSupported`. Same Native/Gated split as `write_secret`.
  - `probe_write(&self, &BackendUri)` + `has_probe_write(&self) -> bool` — the `--dry-run` write-permission probe. Default is a no-op (`Ok(())`) with `has_probe_write() == false`; HashiCorp Vault overrides with a real `vault token capabilities` probe.
  - `delete_hint(&self, &BackendUri) -> String` — a backend-native copy-paste cleanup command surfaced in the migrate success message. Terminal-only; never crosses the JSON / MCP / OTel boundaries.
- **`secretenv_core::BackendError`** — a new typed error enum (`#[non_exhaustive]`) with variants `WriteNotSupported` and `DeleteNotSupported`, letting the migrate handler dispatch structurally instead of string-matching `anyhow::Error` context.
- **Migrate telemetry surface** in `secretenv-telemetry::SecretEnvSpan` — six new `record_migrate_*` typed-attribute methods (`record_migrate_phase`, `record_migrate_outcome`, `record_migrate_source_backend_type`, `record_migrate_dest_backend_type`, `record_migrate_delete_source`, `record_migrate_transaction_id`) plus two new closed enums (`MigratePhase`, `MigrateOutcome`). The `RedactionPolicy` canonical matrix gains 11 new rows for migrate attributes — 7 ALLOW, 4 DENY. The migrated value, alias name, source/dest URIs, and source/dest backend instance names are all explicit DENY rows; only the backend TYPE strings, the phase/outcome enums, the `--delete-source` flag value, and the transaction id are ALLOW.

> **Backward-compatibility note:** every trait method above ships with a default implementation that preserves v0.14 behaviour. A backend that does not override `write_secret`/`delete_secret`/`probe_write`/`delete_hint` simply cannot be a migrate destination/source — it is not a compile break. `BackendError` is `#[non_exhaustive]`, so future variants land additively. The v0.15 BREAKING surface is confined entirely to the Phase 0 block above (arch-H1/H2/H3); the migrate feature itself is purely additive.

### Changed

- CI: the trybuild compile-fail harness renamed from `mcp_safe_trybuild` to `value_access_trybuild`; ui fixtures dir from `mcp_safe_ui/` to `value_access_ui/`. The job now invokes `cargo test -p secretenv-core --no-default-features --test value_access_trybuild` (was `--features mcp-safe --test mcp_safe_trybuild`). Same load-bearing assertion: value-producing APIs do not compile on the SAFE surface.
- **Code-hygiene polish** absorbing Phase 7/9/9b code-reviewer LOW chips:
  - `refuse_special_paths` now scans the first `Normal` path component, catching relative `proc/foo` / `./proc/foo` inputs (was bounded to `components[1]` which only matched absolute paths). (Code-hygiene chip.)
  - `Scrubber::pattern_len` documents the Aho-Corasick `pat_id ∈ [0, num_patterns)` invariant + the `pub(crate)` scope that upholds it.
  - `aggregate_errors` documents the non-empty input precondition.
  - `SpanGuard._private: ()` documented as the sealed-construction marker (kept, not removed).
  - `RedactionPolicy` derives `Copy` (was `Clone` only); the type wraps a `&'static` slice and is trivially `Copy`.
  - Stale `v0.3 TODO` block in `secretenv-backend-aws-secrets/src/lib.rs` rewritten as the current "open follow-ups" view.
  - Off-by-one regression test added: `streaming_accepts_pattern_at_exact_tail_window` covers `pattern_len == MODE_A_TAIL_WINDOW` (the previous suite only covered `>`).
  - `tracing` dep in `secretenv-telemetry/Cargo.toml` documented as the anchor for v0.17's planned `tracing::Subscriber` impl (avoiding a remove-then-readd churn).
  - `runner.rs::inject_env_entries` helper extracts the three identical env-injection loops (tokio pipe-redact, unix `exec()`, non-unix `spawn()`).
  - `CHANGELOG.md` header documents the project-specific `Known limitations` subsection convention introduced in v0.14.0.

### Security

- **Defense-in-depth: `TaintedValue.bytes` now `Zeroizing<Vec<u8>>`** (`crates/secretenv-core/src/redact/mod.rs`). End-of-run drop scrubs plaintext bytes from the heap rather than leaving them dangling until the allocator reuses the slot. Aho-Corasick's own automaton still retains the patterns for its lifetime — Zeroizing here is strictly the operator-controlled half. (v0.14.x DiD chip M1.)
- **Alias-name skip notice moved from `tracing::warn!` to `eprintln!`** (`crates/secretenv-core/src/redact/mod.rs`). SEC-INV-19 carve-out: alias names are DENY for OTel because they fingerprint resolved values; this notice MUST stay operator-local stderr so a future `tracing::Subscriber → OTel` adapter cannot route it to a shared trace surface. (DiD chip M2.)
- **`scripts/check_tracing_leaks.sh` extended.** Adds coverage for `event!(Level::..)`, `Span::current().record("value", ...)`, and bare `warn!`/`info!`/`error!` macros after `use tracing::*;`; tightens the `value = ...` structured-field check by requiring `?`/`%` sigils, eliminating false positives on unrelated fields named `value`. (DiD chip M3.)
- **`secretenv run --help` now documents Mode A limits** including the `/dev/tty` escape, `syslog`/`journald`, `mmap`, core dumps, and SDK re-fetch — parity with `docs/security.md`. (DiD chip M4.)
- **`forward_signals_to` adds `SIGQUIT` + `SIGUSR1` + `SIGUSR2`** (`crates/secretenv-core/src/runner.rs`). The child's own quit handler runs on Ctrl-\, and children that use SIGUSR1/2 for runtime control (logrotate, nginx reload) receive them when the parent does. (DiD chip L2.)
- **`RedactionEvent::for_otel()` projection** (`crates/secretenv-telemetry/src/event.rs`). Strips `alias_name` (DENY per SEC-INV-19) before emission to any non-operator-terminal destination; OTel sinks at v0.17 MUST use this projection. (DiD chip L4.)
- **`SECRETENV_*` prefix wildcard env scrub** (`crates/secretenv-core/src/runner.rs::scrub_secretenv_env`). The explicit `RESERVED_ENV_VARS` denylist is retained as belt-and-braces; the prefix scrub closes the regression window where a future `SECRETENV_TOKEN`-style const is added to the codebase without being added to the explicit list. (DiD chip L5.)
- **Backup-path setuid mask documented** (`crates/secretenv-core/src/redact/mod.rs::write_backup_secure`). The existing `& 0o777` mask is correct — it drops setuid / setgid / sticky bits from the source — but the invariant was undocumented; a future maintainer might widen the mask without knowing the security commitment. Added an inline comment naming the chip. (DiD chip L6.)
- **`EnvEntry.alias_name` doc tightened with SEC-INV-19 reference** (`crates/secretenv-core/src/runner.rs`). Field stays `Option<String>` (not `Secret<String>`) per L1 chip's own recommendation; future leak vectors must project away the alias via `RedactionEvent::for_otel`.

### CI

- **`rust-toolchain.toml` pinned to `1.95.0`** (was floating `stable`). Symmetric with CI's `dtolnay/rust-toolchain@stable` (which honors the project pin), eliminating red CI on every rust point-release for new clippy lints + trybuild fixture text drift. Bump is its own chore per the new runbook at `kb/wiki/runbooks/rust-toolchain-bump.md`; `CONTRIBUTING.md` references the runbook. (Issue #03.)

### Known limitations

- **(SEC-INV-23) Registry-document read-modify-write is not atomic in v0.15.** Both `secretenv registry set` and the new `secretenv registry migrate` pointer-flip phase implement document mutation as `Backend::list(...)` → mutate the in-memory `BTreeMap` → `Backend::set(...)`. None of the 15 backends carry CAS / If-Match / version-stamp plumbing today, so concurrent registry mutations on the same instance can clobber each other (classic lost-update race). The window is short (one round-trip) and the surface area is operator-driven (registry mutations are rare events), so this is shipping as a documented limitation. Mitigation: operators must serialize their own registry mutations against a single instance. v0.17 will introduce `Backend::cas_set(uri, expected_etag, new)` — backends with native ETag/version semantics (AWS S3, GCS, etcd-backed Vault) will implement it; backends without (local file, 1Password, keychain) will continue to degrade to current behavior under explicit acknowledgment. Phase 7 audit (architect-reviewer H2, code-reviewer B2) flagged this; both agreed v0.15 ships honestly with the limitation documented rather than blocking on the larger v0.17 surface.

## [0.14.0] - 2026-05-15

**Headline:** `secretenv redact` lands in two modes, plus the foundation machinery three downstream cycles (v0.15 migrate, v0.16 MCP, v0.17 OTel) depend on. Backend total stays at **15**.

v0.13.0 → v0.14.0: workspace unit tests **893 → 918** (+25 from redact unit/integration + telemetry + Secret + McpSafe trybuild coverage).

### BREAKING

Three deliberate breaking changes, bundled per the v0.14+ Q-O1 resolution (one CHANGELOG block instead of three separate patch tags). Pre-launch install-base is zero; the window for one bundled break before public announcement is honored per the [[feedback_prelaunch_breaking_changes]] policy.

- **`Backend::get(&self, uri: &BackendUri) -> Result<Secret<String>>`** (was `Result<String>`). Cascades across all 15 backends, `secretenv-testing` mocks, the CLI's `get` handler, the resolver, and the runner's `EnvEntry`. External backend plugins must update their `get()` return type and wrap their fetched value with `Secret::new(...)`. Internal consumers (`build_env` → child `exec`) extract via the crate-internal `as_str_internal()`; CLI callers use `value.expose_secret()`. **Q-O1.a.**
- **`Backend::serialize_registry_doc` + `Backend::deserialize_registry_doc`** moved from `secretenv-cli`'s match-arm helper to trait methods on `Backend`. Default impl is JSON; `local` and `1password` override to TOML. Removes the v0.13-era silent "not supported" failure mode where a new backend without a CLI dispatch update produced a runtime error. **Q-O1.b.**
- **`pub use backend::Backend`** is cfg-gated to `not(feature = "mcp-safe")` on `secretenv-core`. Crates linking with the new `mcp-safe` feature (the v0.16 MCP server) must reach the trait via the module path `secretenv_core::backend::Backend`. The CLI never enables `mcp-safe`. **Q-O1.c.**

### Added

- **`secretenv redact <path>`** — Mode B post-hoc file scrubber. Aho-Corasick byte scanner over the resolved-value set; substitutes with `[redacted:<alias>]` (or `--redact-token <fixed>`). `--in-place` rewrites atomically through a sibling tempfile + `rename(2)` with mode preservation; `--backup <suffix>` keeps a copy; `--dry-run` counts without writing.
- **Runtime redaction** in `secretenv run` (Mode A) — on by default. Pipes stdout/stderr through a streaming Aho-Corasick scrubber with a `max(pattern_len) - 1`-byte carry-over window so matches across read-chunk boundaries fire correctly. `--redact` forces pipe-based mode on a TTY; `--no-redact --i-know` opts out entirely. Default (`Auto`) falls back to `exec()` when stdin is a TTY and emits a one-line stderr advisory.
- **Signal forwarding** in mode A — `SIGINT`, `SIGTERM`, `SIGHUP` to the parent are forwarded to the child via `rustix::process::kill_process`.
- **`secretenv-core::Secret<T>`** — generic newtype wrapping `Zeroizing<T>`. Custom `Debug` redacts; no `Display`, `Clone`, `Serialize`, `Deserialize`, `From<String>`, or `Into<String>`. `expose_secret()` is cfg-gated behind `not(feature = "mcp-safe")`.
- **`secretenv-core::McpSafe`** — sealed marker trait. v0.14 seals `HistoryEntry`; v0.16 adds `AliasList`, `ResolveStatus`, `DoctorReport` when those types crystallize. Critically, `Secret<T>` is **not** sealed — the MCP server's tool signatures will be typed against `T: McpSafe`, so a missing impl is a compile-time refusal to expose values.
- **`mcp-safe` Cargo feature** on `secretenv-core` — subtractive: removes `expose_secret` and the crate-root `Backend` re-export. CI gate: `cargo test -p secretenv-core --features mcp-safe --test mcp_safe_trybuild` runs as a dedicated job and verifies the compile-fail surface.
- **`secretenv-telemetry` crate** — new workspace member. Ships `SecretEnvSpan` typed attribute builder (one method per ALLOW attribute in the v0.14+ §6 matrix; no `set_attribute(&str, &str)` escape hatch), `SecretEnvErrorKind` closed enum, `RedactionEvent` / `RedactionStream` / `RedactionSource`, `RedactionPolicy` (declarative ALLOW/DENY classification of every span attribute), and `RedactionSink` trait + `NoopRedactionSink`. **No `opentelemetry` dependency at v0.14** — the load-bearing v0.14 deliverable is the typed surface; v0.17 wires the OTLP exporter through the same trait without restructuring any call site.
- **`Backend::supports_native_gen()`** — default `false`. Reserved for v0.16's MCP `gen_password` tool routing.
- **Typed per-handler reports** (`crates/secretenv-cli/src/reports.rs`) — `RunReport`, `RedactReport`, `RegistryReport`, `ResolveReport`, `GetReport`, `SetupReport`, `ProfileReport`, `CompletionsReport`, plus `CommandOutcome` and `RedactMode` enums. v0.14 discards them via `let _ = handler.await?;` in the dispatcher; v0.17 wires the report's `Drop` to OTel span emission without touching the handlers again.

### Changed

- `secretenv run` defaults to redacted output. Non-TTY parents (CI, scripts) get pipe-based redaction; TTY parents get the auto-fallback advisory.
- Internal `serialize_registry(backend_type, &map)` helper removed from `secretenv-cli`; dispatch is now `backend.serialize_registry_doc(&map)`. The four CLI-layer unit tests covering the helper are removed; equivalent round-trip tests live in each backend's own crate.
- Workspace deps: `aho-corasick = "1"`, `rustix = { version = "1", features = ["fs", "process"] }` added. `tokio` gains the `"signal"` feature. `tempfile` promoted from dev-dep to runtime dep on `secretenv-core` (consumed by `redact::scrub_file_in_place`).
- `EnvEntry.value` switched from `Zeroizing<String>` to `Secret<String>` (preserves the zero-on-drop property via `Zeroizing`'s presence inside `Secret`).
- CI: workspace `cargo test` no longer passes `--all-features`. `mcp-safe` is subtractive and feature-unification under `--all-features` would cascade it across the 15 backends and break injection. The dedicated `mcp-safe-trybuild` CI job covers that surface. A `secret-no-leak-grep` CI job fails the build on a `Display` impl for `Secret` or a forbidden derive.

### Security

- New `docs/security.md#redaction-v014` section covers the redact threat model and the **Limits matrix**: writes to `/dev/tty`, `syslog(3)` / `journald`, `mmap`'d output, core dumps + post-mortem analysis, and PTY-bound interactive children are **not** covered by redaction. Operators are explicitly told this.
- `O_NOFOLLOW` on every redact file open; symlink-swap-between-stat-and-open is rejected.
- Foreign-owner refusal: redact refuses files owned by a UID other than the caller's EUID unless `--allow-foreign-owner` opts in.
- `/proc`, `/sys`, `/dev` are refused outright — "scrubbing" a kernel pseudofile is meaningless.
- Minimum tainted-value length of 8 bytes. Shorter values are dropped from the tainted set with a `tracing::warn!` that carries the alias name but never the value or its length.
- 64 KiB max tainted-value length for mode A. Larger patterns refuse mode-A startup with a clear error (matches cannot reliably fire across the stream's chunk boundaries).
- Foundation work for v0.16's MCP-server boundary (`Secret<T>`, `McpSafe`, `mcp-safe` feature) and v0.17's OTel attribute discipline (`SecretEnvSpan`, `SecretEnvErrorKind`, `RedactionPolicy`) lands in this cycle so neither downstream cycle has to retrofit instrumentation across the codebase.

### Known limitations

- **Typed-report `Drop` does not fire on `secretenv run`'s exec/exit happy paths.** The per-handler typed reports (`RunReport` et al.) reach their `Drop` impl on early-return error paths but not when `run` reaches the end of `cmd_run` and the process exits with the child's status. Surfaced by the Phase 9b architecture review (arch-H5). v0.14 ships this honestly: the report types are the load-bearing surface for v0.16+v0.17 consumers, and the v0.14 dispatcher already discards them via `let _ = handler.await?`. v0.17 adds a pre-exec hook (~30 LOC in the runner) that forces the report's emission before the `exec`/exit. Until then, OTel emission for `secretenv run` will use the `RunOptions`-resident hook path; reports remain authoritative for all other handlers.
- **Three v0.15 architectural follow-ups identified during Phase 9b review** (none blocking v0.14 ship): polarity-flip the `mcp-safe` feature to additive `value-access` before v0.16's MCP crate locks in the subtractive surface; relocate `serialize_registry_doc`/`deserialize_registry_doc` from the `Backend` trait to a free function + `RegistryFormat` enum; lift `crates/secretenv-cli/src/reports.rs` down into `secretenv-core` once v0.16 MCP becomes the second consumer.

## [0.13.0] - 2026-05-06

**Headline:** **hygiene + docs release** absorbing both v0.12.x carry-forward queues. Originally queued as Delinea Secret Server (per [[roadmap]]); Delinea remains blocked on invite-only trial access (vendor-side), so v0.13 fills the slot with the merged-not-tagged hygiene work that would otherwise have rolled forward to the next backend cycle. **No new backend, no new platform, no schema change.** Backend total stays at **15**.

v0.12.0 → v0.13.0: workspace unit tests **876 → 893** (+17 from new bitwarden-sm regression coverage). Live full-matrix smoke against operator's real backends: **508/508 PASS** (was 454/508 at the v0.12.0 baseline; +54 cleared by the GCP env-debt fixes — Section 15 SKIP-on-precondition guard, env-driven `GCP_PROJECT`, and `CLOUDSDK_CORE_DISABLE_PROMPTS=1` global). Phase 9 release-prep audit trio (security-auditor + code-reviewer + deployment-engineer) ran clean: 0 BLOCKING + 0 HIGH from security; 0 BLOCKING + 1 HIGH (doc-comment LIMITATION note for `parse_version_token` — landed inline) from code-reviewer; 1 BLOCKING from deployment (workspace version bump — landed inline as part of release prep) — **Phase 9 paid for itself a third consecutive cycle** per [[feedback_audit_after_release_prep]].

### Fixed — GCP environment debt (smoke harness)

Closes [[v0.12-issues/01-gcp-env-debt]]. Surfaced by the v0.12 Phase 8 full-matrix smoke as 51 cascading FAILs unrelated to v0.12 feature work; rooted in two distinct issues in `scripts/smoke-test/run-tests.sh`.

- **Drop redundant `GCP_PROJECT="${SECRETENV_TEST_GCP_PROJECT:-eva-dev-490220}"` shadow** (`scripts/smoke-test/run-tests.sh`) — `lib/common.sh` already exports the env-driven value, and `require_cloud_env()` already enforces non-empty before any cloud section runs. The line was dead at best, silently retargeting a long-decommissioned project at worst. Single source of truth: `SECRETENV_TEST_GCP_PROJECT`. No fallback.
- **Test-150 assertion `project=eva-dev-490220` interpolates `${GCP_PROJECT}`** (`scripts/smoke-test/run-tests.sh:917`) — was a hardcoded literal that would FAIL even with the right env exported.
- **Section 15 wrapped in standard SKIP-on-precondition** mirroring sections 21+ (Doppler, Keeper, openbao, conjur, bitwarden-sm). Probes `gcloud secrets list --project ... --limit 1` before running the body; on failure records a single `119 v0.3 gcp section skipped — gcloud secrets list failed` SKIP with operator hint instead of cascading 12+ FAILs through doctor + cross-backend resolver. SKIP-record number `119` matches the section's first test ID per the established convention.
- **Global `export CLOUDSDK_CORE_DISABLE_PROMPTS=1`** at the top of `scripts/smoke-test/run-tests.sh` — `secretenv doctor --fix` against a NotAuth GCP backend can no longer spawn `gcloud auth login` and hang the whole matrix on a browser callback (live-observed during v0.12 Phase 8: section 19a stalled with the gcloud PID parked on stdin). With the prompt suppressed, gcloud fails fast with a clean error and the test proceeds.
- **Pre-smoke runbook step** added to `kb/wiki/parallel-backend-workflow.md` (operator-facing) — `gcloud auth list` + ADC verification + project-match check, mirroring the existing `op signin` priming pattern.

Cross-backend cascade FAILs (sections 7 / 8 / 9 / 17 / 22 azure-reg) when one backend in the alias map is NotAuth — NOT addressed; that requires an architectural change to the cross-backend resolver's behavior on partial-readiness manifests. Out of scope for this hygiene cycle. Captured for a future polish cycle.

### Fixed — bitwarden-sm Phase 7 deferred chips

Closes [[v0.12-issues/02-phase-7-deferred-chips]]. Phase 7 closing-audit MEDIUM/LOW findings deferred from v0.12.0 per [[feedback_pr_scoping_hygiene_carrier]]. The Phase 7 HIGH chips landed inline before v0.12.0; this cycle absorbs the deferred residue.

- **`bitwarden_bin` control-character validation parity** (`crates/backends/secretenv-backend-bitwarden-sm/src/lib.rs`) — `bitwarden_server_url` and `bitwarden_access_token_env` already ran through `has_forbidden_control_char`; `bitwarden_bin` did not. Inconsistent hardening; a NUL byte in the binary path produced a confusing OS-level error far from the config site instead of a typed config-site message. Now mirrors the sibling check + new `factory_rejects_control_char_in_bitwarden_bin` regression test.
- **`bitwarden_access_token_env` validation order** (`create_concrete`) — the `unwrap_or_else(|| DEFAULT_TOKEN_ENV.to_owned())` default path was running the control-char + POSIX-name checks against a `&'static str` constant (dead code on the common path). Validation now lives inside the `if let Some(env) = ...` branch; default branch returns the const directly. Existing tests confirm both paths still round-trip cleanly.
- **`parse_version_token` permissive scanner** — was anchored on the literal `bws ` prefix, so a future rebrand (`bws-cli`, `bitwarden-sm-cli`, etc.) would have failed Level 1 opaquely. New scanner finds the first `<X.Y.Z>` whitespace token; tolerates rebrands and trailing build metadata; defends against pathological double-prefix input (`bws bws 0.5.0`). Doc-comment names the trust boundary (`bws --version` stdout sits inside the `bitwarden_bin` trust envelope) and the LIMITATION (first numeric triple wins; an embedded IPv4 fragment BEFORE the version would misparse). Six new regression tests cover canonical, rebrand, trailing-metadata, no-numeric-triple, two-component-rejection, and the "first triple wins" tie-break.
- **`SecretGetResponse.value` doc-comment hardened** — names the `#[serde(default)]` rationale (forward-compat with future `bws` schema drift) and the section-28 smoke assertion that catches the silent-empty-value drift.
- **`ProjectListElement.id` no longer `#[serde(default)]`** — the doc-comment claimed `id` "anchors the shape" but `default` let `[{}]` parse fine, contradicting the claim. Field is now REQUIRED; an envelope shape that omits it surfaces as a parse error at Level 2.
- **`extract_json_field` array/object rejection** — split the combined `ref v @ (Array | Object)` arm into two explicit arms (one per JSON kind). Same error wording, less indirection.
- **`set_uses_secret_edit_not_create` mock body `ok("{}")` → `ok("")`** — the `secret edit` stdout is unread by the wrapper (only `status.success()` and `stderr` are inspected); empty body is honest about that vs. a misleading-looking JSON object.
- **`set_rejects_fragment` test** — added positive `assert!(msg.contains("fragment"))` alongside the existing absence-of-`disabled by default` check, verifying the fragment-reject branch fired (not just that the unsafe-set branch didn't).
- **6 new `extract_json_field` variant tests** covering string / number / boolean / null / array-rejection / object-rejection branches — pin the exact bail wording so a future refactor surfaces unintended message changes.

### Fixed — `infisical` backend doctor false-NotAuthenticated under `infisical` 0.43.79

Surfaced during the v0.13.0 hygiene-cycle live smoke (post-`infisical login`, with a valid cached JWT). `secretenv doctor` reported `infisical` as `not authenticated` even though `infisical user get token --plain` returned exit 0 with a valid token in the operator's shell.

Root cause: `Backend::check()` configured the `infisical user get token --plain` probe with `Stdio::piped()` for stderr but waited via `.status()`, which does not drain piped streams. Once the `infisical` CLI's stderr output (upgrade-available notice + auth-state lines) exceeded the OS pipe buffer, the child blocked on stderr write and exited abnormally — surfacing as a spurious `NotAuthenticated` from a logged-in CLI. The bug was always present but only manifested as the CLI's notice payload grew with releases (last reproduced against `infisical` 0.43.79 with the `0.43.79 -> 0.43.80` upgrade banner).

Fix: change `probe.stderr(Stdio::piped())` to `probe.stderr(Stdio::null())` (`crates/backends/secretenv-backend-infisical/src/lib.rs:454`). The probe's documented intent — per its own comment — is "we don't need its value, only exit status," so dropping the pipe matches stated behavior. Code-comment expanded to call out the pipe-buffer-vs-`.status()` interaction so a future maintainer doesn't reintroduce the pattern.

Caught only because the v0.13 hygiene cycle re-ran the full smoke matrix end-to-end against the operator's live backends; standalone unit tests with strict mocks could not have surfaced this (the mock CLI emits no stderr).

### Fixed — `bitwarden_server_url` documentation

- **Security note added** (`docs/backends/bitwarden-sm.md`) on `bitwarden_server_url` token-forwarding risk — naming the typo-squat / poisoned-template threat model and three concrete operator mitigations. Includes a TLS-trust-delegation paragraph for operators on corporate networks with intercepting proxies (private CA bundles).

### Process

- **Phase 9 audit trio (security + code + deployment) made default cadence** for the third consecutive cycle. Security: APPROVE outright (0 BLOCK + 0 HIGH + 0 MED + 2 LOW polish). Code-reviewer: APPROVE w/ HIGH (`parse_version_token` doc-comment LIMITATION note — landed inline). Deployment: REJECT-then-APPROVE (workspace version bump pre-tag — landed inline). Every BLOCKING + HIGH + MEDIUM + LOW finding closed in this cycle (no carry-forward to v0.13.x).
- **No three-agent feature-cycle audit (Phase 7) run** — this cycle introduces no new backend / no new feature surface; the bitwarden-sm changes are direct closures of audited findings, and the smoke-harness changes are bash-script hygiene. Phase 9 is the appropriate gate for hygiene + docs cycles.

### Deferred / declined

- **Drop dead `backend_type: &'static str` field on `BitwardenSmBackend`** — flagged by the v0.12 Phase 7 code-reviewer as a "minor maintainability nit." Declined here for two reasons: (1) clippy `unnecessary_literal_bound` flags the resulting `fn backend_type(&self) -> &str { "bitwarden-sm" }` shape against the trait's elided-lifetime return signature; (2) every other backend in the family (14 of them) keeps the same field. Family consistency wins over the local cleanup.
- **Cross-backend cascade resolver behavior on partial-readiness manifests** (sections 7 / 8 / 9 / 17 / 22 azure-reg in the smoke matrix) — when one backend in an alias map is NotAuth, `secretenv run` aborts the whole resolution. Architectural; not a hygiene-cycle change.
- **`bws_command` / `bws_secret_command` DRY merge** — the two helpers are near-duplicates but the deduplication is taste-driven, not correctness-driven. Defer until naturally touched by a future change.
- **Four LOW style nits** carried into a future polish cycle (no v0.13.x queue opened — the hygiene/docs scope is fully closed): `unsafe_set_refused` hint phrasing, `secret_uuid` `Cow<'_, str>` allocation, `drop(lock)` style consistency, `apply_env` rename to `apply_env_with_token_required`.

## [0.12.0] - 2026-05-05

**Headline:** seventh release of the single-backend-per-release cycle; seventh [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Bitwarden Secrets Manager** (the developer/CI product, distinct from Bitwarden Password Manager) via the `bws` CLI v2.x — brings the total to **15**. First cycle to pull a backend forward in the queue (was v0.13 per [[roadmap]]; Delinea Secret Server slipped to v0.13 pending invite-only trial access). Tag absorbs the v0.11.x merged-not-tagged hygiene cycle below.

v0.11.0 → v0.12.0: workspace unit tests **830 → 876** (+46 from the new bitwarden-sm crate). Live smoke matrix Section 28 (bitwarden-sm): **29/29 PASS** against operator's live cloud account. Phase 7 closing trio (security + code + rust) surfaced 3 HIGH findings (1 security, 2 code-reviewer) — all landed inline before tag; 7 MEDIUM + 10 LOW deferred to v0.12.x hygiene queue per [[feedback_pr_scoping_hygiene_carrier]] ([[v0.12-issues/02-phase-7-deferred-chips]]). Phase 8 live smoke caught two production bugs that Phase 7 audit-only would have missed (envelope-shape `deny_unknown_fields` + UUID dual-form parser) — vindicates the audit-then-smoke-then-audit-again sequence from [[feedback_audit_after_release_prep]].

The full-matrix smoke run additionally surfaced 51 cascading FAILs from pre-existing **GCP environment debt** ([[v0.12-issues/01-gcp-env-debt]]) — `eva-dev-490220` hardcoded in `run-tests.sh` + `gcloud` reauth needed. NOT v0.12-introduced; deferred to v0.12.x hygiene cycle. Section 28's bitwarden-sm work sits in a self-contained config and was unaffected.

### Added — Bitwarden Secrets Manager backend (v0.12)

- **`secretenv-backend-bitwarden-sm` crate** — `BitwardenSmFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `bitwarden-sm-<instance>://<uuid>[#json-key=<field>]` where `<uuid>` is either the 36-char canonical hyphenated form (`8-4-4-4-12`, what `bws` emits + what users copy from the web UI) OR the 32-char simple form (no hyphens). Bitwarden Secrets Manager addresses every secret by server-generated UUID — `bws secret get` accepts UUID only, and the server allows duplicate KEY names within a project, so key-name addressing would be both ambiguous and costlier. Human-readable aliases live in the SecretEnv registry layer. **46 unit tests** via the strict-mock harness.
- **`bitwarden_unsafe_set` defense-in-depth gate** — `bws` v2.0.0 has NO stdin path for `secret create` / `secret edit` (live-probed against `bws 2.0.0` 2026-05-05); the value is on argv via `--value <VALUE>`. Default posture: `set` and `delete` REFUSE with a clear error pointing operators at the Bitwarden web UI. Setting `bitwarden_unsafe_set = true` opens the argv path explicitly. Same precedent as `op_unsafe_set` / `bao_unsafe_set` / `conjur_unsafe_set`. Both `set` AND `delete` gated by the same flag (the threat model is "destructive write operations from a wrapped CLI", not argv-leak risk specifically).
- **`set` updates only — never creates** — the URI is a UUID, which can only refer to a secret that already exists; `set` always invokes `bws secret edit --value <value> <uuid>` and never `bws secret create`. Secret provisioning is an out-of-band web-UI workflow that returns a UUID; the operator then writes that UUID into the registry.
- **Token routing via env** — `BWS_ACCESS_TOKEN` is the canonical env var `bws` reads; multi-instance setups rename via `bitwarden_access_token_env` (e.g. `BWS_ACCESS_TOKEN_PROD`). The wrapper sources the token from the operator shell at command time and sets `BWS_ACCESS_TOKEN` on the child env only — never on argv, never in the registry doc, never logged. Token VALUE never echoed by `doctor`; only the env-var NAME and project COUNT appear.
- **Server URL — omit when default** — `bitwarden_server_url` is optional; when unset the wrapper actively REMOVES `BWS_SERVER_URL` from the child env (so the CLI's built-in US-cloud default applies, even if the operator's parent shell has it set globally). EU / self-hosted operators set the field explicitly.
- **`#json-key=<field>` fragment on `get`** — extracts a top-level scalar from a JSON-encoded `value`. Mirrors `aws-secrets` / `openbao` / `conjur`. `set` / `delete` / `list` / `history` reject any fragment.
- **URI parser strict UUID validation** — 32-char `[0-9a-f]+` enforced at parse time; hyphenated UUIDs (36-char canonical form) rejected with a clear error naming the constraint, rather than letting `bws` produce a cryptic "invalid length" message later. Mixed-case hex normalized to lowercase so registry documents written either way round-trip.
- **`history` returns trait-default "not implemented"** — Bitwarden Secrets Manager surfaces secret revisions in the web UI (every `secret edit` bumps `revisionDate`) but the CLI exposes no `secret history` subcommand. Out of scope until vendor exposes versioning.
- **`bitwarden-sm` added to `serialize_registry` JSON arm** in `secretenv-cli/src/cli.rs` so `registry set` / `unset` write through the JSON-string-in-`value` shape (matching `aws-secrets` / `openbao` / `conjur`).
- **Smoke harness Section 28** — 29 records (13 `run_test` + 16 `assert_*`) covering doctor Level 1+2 (with `server=` / `token=$BWS_ACCESS_TOKEN` / `projects=` checks), scalar round-trip, `#json-key=password` fragment extraction, end-to-end `run`, set-blocked-by-default + opt-in cycle, fragment-reject on registry list, history-not-implemented surface, registry-source cross-backend chain, and URI-parser non-UUID rejection. Phase 8 live-cloud run: 29/29 PASS against the operator's live Bitwarden Secrets Manager account. Skipped when `bws` missing OR `BWS_ACCESS_TOKEN` unset OR `bws project list` fails OR fixture UUIDs missing.
- **Backend total 14 → 15.** README backend table flipped Bitwarden Secrets Manager from "Coming Soon" to "Available" and corrected the row's `type` string to `bitwarden-sm` (leaves the `bitwarden` namespace open for a future Password Manager `bw` wrapper without rename pain).
- **Roadmap swap (2026-05-05)** — v0.12 was originally Delinea Secret Server. Delinea's local-stack provisioning requires an invite-only trial (vendor-side); Bitwarden Secrets Manager is publicly available, so the cycle order swaps: **v0.12 = Bitwarden Secrets Manager**, **v0.13 = Delinea Secret Server (deferred pending invite)**.

### v0.11.x hygiene — closing-audit deferred LOW chips (merged-not-tagged)

Sixth merged-not-tagged hygiene cycle (v0.7.1 / v0.7.2 / v0.9.1 / v0.9.2 / v0.10.x → **v0.11.x**) per the rolling-backlog pattern: merged to `main`, workspace `version` stays at `0.11.0`, no tag pushed. Triggered by routine post-cycle slack and a desire to clean the v0.11 carry-forward queue before v0.12 (Delinea Secret Server) opens. Every chip below was already audited during v0.10's or v0.11's closing trio — the hygiene cycle just lands the deferred LOW fixes that were explicitly punted to keep the v0.11 PR scoped per [[feedback_pr_scoping_hygiene_carrier]].

#### Fixed

- **`aws-secrets` `extract_json_field` `map.remove` allocation fix** (`crates/backends/secretenv-backend-aws-secrets/src/lib.rs:442-475`) — the same single-line allocation fix that landed in `openbao` during the v0.10 Phase 6 audit and in `conjur` during v0.11 Phase 7. The `String` arm now moves rather than clones (`map.remove` instead of `map.get` + `.clone()`). Carried forward from v0.10.x; deliberately deferred from v0.11 to keep the conjur PR scoped.
- **`.github/workflows/release.yml:177-194` backend-publish strict-mode** — the 14-line `cargo publish` block now starts with `set -euo pipefail` so a transient mid-list failure (crates.io 5xx, indexing race, network blip) fails the workflow step rather than being masked by bash's last-command-only exit semantics. v0.10.x deferred this; Phase 9 security audit re-flagged at v0.11; landing here. Mirrors the strict-mode discipline that landed on the Package-tarball block in v0.11.0.
- **`conjur` backend `tracing::warn` on `conjur_unsafe_set = true` runtime branch** (`crates/backends/secretenv-backend-conjur/src/lib.rs:280-294`) — when the operator opts into the `-v <value>` argv path, the backend now emits a per-invocation `tracing::warn!` naming the instance + URI + operation. Mirrors the 1Password / Keeper precedent. `secretenv --verbose` now surfaces the choice as a runtime breadcrumb instead of silently routing through argv. Phase 7 closing security-auditor LOW.
- **`conjur` `parse_version_token` dead-fallback cleanup** (`crates/backends/secretenv-backend-conjur/src/lib.rs:549-559`) — the prior `split('-').next().unwrap_or(token)` shape had an unreachable fallback arm (`split` always yields at least one element). Replaced with `split_once('-').map_or(token, |(prefix, _)| prefix)` for clearer intent. Phase 7 closing rust-engineer LOW.
- **`conjur` `parse_json_key_fragment` two-pass cleanup** (`crates/backends/secretenv-backend-conjur/src/lib.rs:212-242`) — the prior `contains_key` + `len()` shape made two passes over directives in the common single-key case. Refactored to single-pass `shift_remove` + leftover-emptiness check; whatever remains in the map after extracting `json-key` is by definition the unsupported set. Phase 7 closing rust-engineer LOW.

#### Process

- This is the **first hygiene cycle to land entirely from the v0.11.x post-cycle carry-forward queue** documented in [[roadmap]]. The `feedback_pr_scoping_hygiene_carrier.md` discipline is now an established pattern across two cycles (v0.10.x retrospective + v0.11.x carry-forward); subsequent cycles should default to it. No three-agent retrospective audit run on this commit because every chip closed a finding from v0.10 / v0.11 closing audits — re-auditing closed findings would be theatre.

#### Deferred / declined

- **`variable_id` inline control-char rejection** — Phase 7 security-auditor LOW. Already locked at the upstream `secretenv-core::BackendUri::parse` layer (`uri.rs:96`) with a regression-lock test (`uri_parser_rejects_control_chars_in_variable_id_path` in the conjur crate). Inline check would be defense-in-depth only; not landing.
- **`teardown.sh` shell-quoting parity** — Phase 7 security-auditor MEDIUM. Same `run "..."` wrapper pattern every prior backend uses; not a regression. Would need a workspace-wide rewrite of the smoke harness to address; out of scope for this hygiene cycle.
- **Smoke `|| true` failure-signal loss** — Phase 7 security-auditor LOW. Cosmetic; the assertion below catches the real failure regardless. Not landing.
- **Phase 9 audit-artifact wiki cross-link** — Phase 9 security-auditor LOW. No `kb/wiki/reviews/2026-04-30-v0.11-conjur-audit.md` artifact exists; nothing to link. Declined.
- **CHANGELOG history-wording cleanup** — Phase 9 code-reviewer LOW (advisory). The historical v0.10.0 block at `CHANGELOG.md` still says "history-unsupported" while v0.11.0+ uses "history-not-implemented". Don't retroactively edit history.
- **`history()` for openbao via `bao kv metadata get`** — v0.10.x carry-forward. Non-trivial (KV v1/v2 mount detection, soft-delete + destroy markers); requires real design work. Stays in v0.10.x deferred-with-trigger queue.

## [0.11.0] - 2026-04-30

**Headline:** sixth release of the single-backend-per-release cycle; sixth [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **CyberArk Conjur** (Apache-2.0 OSS / Enterprise wire-compatible, via the Go-based `conjur` v8 CLI) — brings the total to **14**. First non-Vault-family enterprise backend; first cycle to land Phase 0 prep as a discrete pre-cycle session and the **first cycle to run the Phase 9 release-prep audit by default** per `feedback_audit_after_release_prep` — the discipline the v0.10.x retrospective surfaced.

v0.10.0 → v0.11.0: workspace unit tests **778 → 830** (+52 from the new conjur crate, counted by `cargo test --workspace` `test result: ok.` lines summed). Live smoke matrix **452 → 479** (+27 for Section 27: doctor Level 1+2 with `account=` / `identity=` / `authn=` checks, scalar round-trip, `#json-key=password` fragment extraction, end-to-end `run`, set/list/unset cycle on `secretenv-smoke/cycle`, fragment-reject on registry list, history-not-implemented surface, registry-source cross-backend chain). Pre-tag full-matrix smoke: 27/27 on Section 27 first run after a stale `target/release/secretenv` binary blocked the conjur factory in an initial attempt; full matrix **479/479** clean after release rebuild. Closing three-agent trio audit (security + code + rust) landed 1 BLOCKING + 1 HIGH + 7 MEDIUM/LOW findings inline before tag; LOW + remaining MEDIUMs deferred to v0.11.x carry-forward.

This is the **first tagged release after the v0.10.x merged-not-tagged hygiene cycle** — the Homebrew formula re-renders with the corrected `license "AGPL-3.0-only"` (v0.3 onward had been pushing the wrong MIT label to the tap; fixed in v0.10.x but only takes effect on the next tagged release, which is this one).

### Added — CyberArk Conjur backend (v0.11)

- **`secretenv-backend-conjur` crate** — `ConjurFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `conjur-<instance>://<variable-id>[#json-key=<field>]` (no KV-mount segment — Conjur uses a resource-graph identity model where the variable ID IS the path). `CONJUR_APPLIANCE_URL` + `CONJUR_ACCOUNT` routed via per-child env (uniform across `version`, `whoami`, and every `variable` invocation; the `version_command()` helper landed in the closing audit applies env even though `--version` doesn't strictly need it, so the env-only invariant stays uniform). 52 unit tests via the strict-mock harness.
- **`-f /dev/stdin` safe-stdin path** — CV-1-equivalent to OpenBao's `value=-`. Conjur v8 has no `--value-from-stdin` flag; using the kernel `/dev/stdin` pseudo-file lets the CLI read the value bytes "as if from a file" without touching disk and without ever appearing on argv. `conjur_unsafe_set = true` is the explicit operator opt-in for the `-v <value>` argv path (only legitimate when `/dev/stdin` is unavailable, e.g. chrooted CI runner with stripped `/dev/`). Default-off invariant machine-checked via `ConjurFactory::create_concrete` test path; argv-path-unreachable test registers ONLY the argv-mock entry and asserts the safe branch was taken.
- **`#json-key=<field>` fragment on `get`** — parses the variable value as a JSON object and extracts the named top-level scalar. Mirrors `aws-secrets` / `openbao`. `set` / `delete` / `list` / `history` reject any fragment.
- **`delete` as clear-via-empty-set** — Conjur has no native delete (variables are policy-defined; full removal requires policy reload, which a typical SecretEnv operator can't do). `delete()` writes the empty string via the same safe `-f /dev/stdin` path used by `set`. The variable retains its policy definition; only the value is emptied. Documented as a deliberate semantic gap; mirrors 1Password's `delete` precedent.
- **Identity line surfaces configured authn** — Conjur's `whoami` JSON returns `{account, username, client_ip, user_agent, token_issued_at}` and does NOT include the authenticator name. The doctor identity line constructs `account=<from-whoami> identity=<username-from-whoami> authn=<from-conjur_authn-config>` (default authn `"authn"`).
- **v7 (Ruby) CLI rejection** — `check()` Level 1 parses the version token from `Conjur CLI version <X.Y.Z>[-<build-sha>]` and fails fast on v7 with a clear "v8+ required" message + Docker-image install hint. A version line that doesn't parse (no literal "version " token) also surfaces as `BackendStatus::Error` rather than silently bypassing the v7 branch — closes a defense-in-depth gap surfaced by the closing security audit.
- **`list()` returns alphabetically-sorted entries** — `HashMap::into_iter` is randomized per-process; `list()` now sorts before returning so callers and the smoke harness's `assert_contains` checks see deterministic output across runs. Lifted from the closing rust-engineer audit.
- **`conjur` addition to `serialize_registry` JSON arm** (`secretenv-cli`) — registry documents through the `conjur` backend round-trip as JSON-string values stored in the variable, matching `aws-ssm` / `aws-secrets` / `gcp` / `azure` / `vault` / `openbao`.
- **Smoke harness Section 27** (27 assertions, ids 390–416, covering doctor / get / fragment / run / cycle / fragment-reject / history-not-implemented / registry-source / cross-backend resolve). Skipped cleanly if `conjur` is missing OR the server is unreachable OR the session is expired. Provision side seeds `secretenv-smoke/{scalar,json-multi,conjur-registry,cycle}` under root policy.
- **`docs/backends/conjur.md`** — leads with the install gotcha (Docker-image canonical, PyPI is EOL v7), explains the resource-graph model + `delete` semantic gap + identity-line authn convention.
- **`.github/workflows/release.yml`** — adds `cargo publish -p secretenv-backend-conjur --locked` to the backend-publish list.
- **`secretenv-backend-conjur` AGPL-3.0-only exception** in `deny.toml`.
- **README backend table** 13 → 14 + backend-count badge bumped (and stale "Coming Soon" Conjur stub row deleted).

#### Phase 0 corrections (2026-04-30, pre-cycle)

The pre-cycle Phase 0 live-probe ran against `Conjur CLI version 8.1.3-879b90b` at the local Conjur OSS docker-compose harness and corrected several spec inaccuracies before the cycle opened. Captured here so the v0.11 tagged CHANGELOG block carries the rationale.

- **CLI is Go-based v8, not Python.** PyPI `conjur` is the EOL Ruby v7 line. No Homebrew tap; no native macOS binary. Canonical install is the `cyberark/conjur-cli:8` Docker image. Spec install hint corrected; doctor v7 rejection wired.
- **`--value-from-stdin` does not exist in v8.** The CV-1-safe substitute is `-f /dev/stdin` with stdin-piped value.
- **`CONJUR_APPLIANCE_URL` + `CONJUR_ACCOUNT` env routing works without a `~/.conjurrc`.** Standard env-only contract retained; no per-instance config-file fallback shipped.
- **`whoami` JSON shape:** `{account, username, client_ip, user_agent, token_issued_at}` — no authenticator name. Identity-line `authn=` derives from configured `conjur_authn`.
- **`variable get` still appends one trailing `\n`.** Strip-one rule stands.

### v0.10.x hygiene — Homebrew formula license fix + retrospective audit closeout (merged-not-tagged)

Rolling-backlog cycle following the v0.7.1 / v0.7.2 / v0.9.1 / v0.9.2 dev-work pattern: merged to `main`, workspace `version` stays at `0.10.0`, no tag pushed. Triggered by the user catching a real Homebrew-formula license bug post-tag and the realization that the Phase 6 three-agent audit at v0.10.0 ran BEFORE the Phase 8 release-prep commit landed, so the smoke patch + version bump + CHANGELOG closeout + `release.yml` change shipped unreviewed. Retrospective three-agent audit (security + code + deployment) ran against the as-shipped state @ `368c38a`; this CHANGELOG block + commit closes the BLOCKING/HIGH findings.

#### Fixed

- **Homebrew formula license** (`.github/workflows/release.yml:251`) — `license "MIT"` → `license "AGPL-3.0-only"`. Workspace has been AGPL-3.0-only since the v0.3 relicense; every release since had been pushing a wrongly-licensed brew formula to `TechAlchemistX/homebrew-secretenv`. Real legal-surface bug, not just cosmetic. The next tagged release will re-render the formula correctly. Caught by the retrospective deployment-engineer audit pass.
- **CHANGELOG line 57** — folded v0.9.1 hygiene block referenced "v0.10 Bitwarden release" but v0.10 shipped as **OpenBao** (queue was reordered 2026-04-25 putting OpenBao before Bitwarden). Updated to "v0.10 OpenBao release".
- **CHANGELOG headline test counts in `[0.10.0]`** — cited `705 → 748` was wrong on both ends. Actual counts (`cargo test --workspace` summed): `735 → 778`. The `+43 from openbao` delta was correct; baselines were prediction-error. Caught by the retrospective code-reviewer audit pass.
- **Duplicate `## [0.8.0] - 2026-04-24` header** — pre-existing CHANGELOG defect at lines 106/108, removed.

#### Process

- New feedback memory `feedback_audit_after_release_prep.md` — the Phase 6 three-agent audit must be followed by a second targeted audit pass over the Phase 8 release-prep delta (smoke patches, version bump, CHANGELOG closeout, release.yml changes) BEFORE tag push. v0.10.0 missed this and surfaced a release-yml bug post-tag; v0.11+ cycles add it as Phase 6.5.

#### Deferred / declined

- **Homebrew formula `desc` length + workspace-description-as-source-of-truth** — devops audit HIGH. Intentional Homebrew-side brevity vs longer CLI Cargo.toml description. Documenting intent in a comment is fine but not load-bearing; deferred.
- **`set -euo pipefail` in release.yml bash blocks** — devops audit MEDIUM. Existing safety loop on line 241 is sufficient; defense-in-depth strict-mode would be polish, not a real bug class.
- **`sleep 45` rationale comment** — devops audit MEDIUM. 45s has been empirically sufficient through v0.1–v0.10; document if a future release times out.
- **CHANGELOG date 2026-04-27 vs commit date 2026-04-26** — code-reviewer audit MEDIUM. CHANGELOG file's own header at line 8 declares UTC dates; tag pushed 2026-04-27T01:50:35Z UTC, so 2026-04-27 is correct per the file's convention. No change.

## [0.10.0] - 2026-04-27

**Headline:** fifth release of the single-backend-per-release cycle; fifth [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **OpenBao** (Linux Foundation MPL-2.0 fork of HashiCorp Vault, via the `bao` CLI 2.x) — brings the total to **13**. First Vault-fork peer; near-clone of `secretenv-backend-vault` with three concrete divergences: binary name (`bao` vs `vault`), env-var prefix (`BAO_*` with `VAULT_*` CLI fallback for transition), and install path (`brew install openbao` direct from homebrew-core, no tap dance — explicit contrast with Vault's post-BSL `brew tap hashicorp/tap` form). The `#json-key=<field>` fragment ships from day one — Vault's deferred-launch fragment work informs OpenBao's, so v0.10 lands the same JSON-extraction pattern `aws-secrets` pioneered.

v0.9.0 → v0.10.0: workspace unit tests **735 → 778** (+43 from the new openbao crate, counted by `cargo test --workspace` `test result: ok.` lines summed). Live smoke matrix **419 → 452** (+29 for Section 26: doctor Level 1+2, scalar round-trip, `#json-key` fragment, end-to-end `run`, set/list/unset cycle, fragment-reject, history-unsupported, registry-source cross-backend chain, HTTP/HTTPS mismatch surface). Pre-tag full-matrix smoke passed 444/452 on the first run; the eight failures were all in Section 26 and all smoke-test design bugs (a redundant fragment-on-scalar test, a missing pre-seed at the unique-per-run cycle path that `registry set` reads-then-writes, and a stale "not supported" assertion vs the trait-default "not implemented" wording). Re-run after the smoke-test patch: **452/452**. Closing three-agent trio audit (security + code + rust) landed 1 HIGH + 3 MEDIUM findings inline before tag; LOW + remaining MEDIUMs deferred to v0.10.x carry-forward.

This release also folds the **v0.9.2 hygiene cycle** (merged-not-tagged 2026-04-26 per the rolling-backlog pattern) into the tagged CHANGELOG.

### Added — OpenBao backend (v0.10)

- **`secretenv-backend-openbao` crate** — `OpenBaoFactory` registered unconditionally in `secretenv-cli/src/backends_init.rs`. URI shape `openbao-<instance>://<mount>/<path>[#json-key=<field>]`. `BAO_ADDR` / `BAO_NAMESPACE` routed via per-child env (same lesson as Vault PR #33; argv-form `-address` flags after positional path tokens are rejected by the CLI parser).
- **`bao_unsafe_set` defense-in-depth flag** — reserved opt-in for any future regression that routes the secret through argv. v0.10 always uses the safe `value=-` stdin form; the flag defaults to `false` and is observed at factory time only. Default-off invariant machine-checked via `OpenBaoFactory::create_concrete` test path.
- **`#json-key=<field>` fragment on `get`** — parses the `value` field as a JSON object and extracts the named top-level scalar. Mirrors `aws-secrets`. `set` / `delete` / `list` / `history` reject any fragment.
- **`openbao` addition to `serialize_registry` JSON arm** (`secretenv-cli`) — registry documents through the `openbao` backend round-trip as `value=-` JSON-strings, matching `aws-ssm` / `aws-secrets` / `gcp` / `azure` / `vault`.
- **Smoke harness Section 26** (29 assertions covering doctor / get / fragment / run / cycle / fragment-reject / history-unsupported / registry-source / cross-backend resolve / HTTP/HTTPS mismatch). Skipped cleanly if `bao` is missing OR the server is sealed/unreachable.
- **`docs/backends/openbao.md`** — leads with the `BAO_ADDR` HTTP/HTTPS gotcha, contrasts the install path with Vault's tap form, explains the MPL-2.0 vs BSL governance distinction.
- **`secretenv-backend-openbao` AGPL-3.0-only exception** in `deny.toml`.
- **README backend table** 12 → 13 + backend-count badge bumped.
- **Smoke harness README inventory** + `SECTIONS` array — sections 22–26 backfilled; sections 23–25 had drifted from prior cycles.

### Spec divergence (intentional)

- **`list()` storage model** — the spec at `kb/wiki/backends/openbao.md` originally described `list()` as parsing `data.data` as a multi-field alias map (Vault-style). The shipped implementation instead reads a JSON-string from the canonical `value` field (`aws-secrets`-style), driven by a single-field-per-secret writer discipline (`bao kv put <path> value=-`). The aws-secrets shape is internally consistent with this backend's `set()` path and with the `#json-key=<field>` fragment design that ships from day one. Documented in lib.rs crate-level docs, `docs/backends/openbao.md` "Storage model" section, and the spec was amended to match.

### Folded — v0.9.2 hygiene (merged-not-tagged 2026-04-26)

Fourth consecutive rolling-backlog cycle (v0.7.1 → v0.7.2 → v0.9.1 → **v0.9.2**) draining the v0.9.x carry-forward queue before the v0.10 OpenBao cycle opens. Merged to `main`, workspace `version` stays at `0.9.0`, no tag. v0.10 OpenBao release will fold these into its tagged CHANGELOG.

#### Added

- **`cf_kv_list_prefix` config field** (cf-kv backend) — optional key-prefix filter passed to `wrangler kv key list` as `--prefix <value>`. Enables single-namespace scalar+registry mixing via key conventions (e.g. `cf_kv_list_prefix = "registry/"` so registry-source aliases live under `registry/<alias-name>` while plain scalar secrets share the namespace at the top level). Empty string is normalized to `None` at factory time. Closes the v0.9.x carry-forward "cf-kv `--prefix` flag" item. Pre-v0.9.2 alternative — two separate namespaces — still works and remains the default posture for accounts where namespace count is not a constraint.
- **17 new factory-validation unit tests** across `secretenv-backend-1password` (+5: `op_unsafe_set` accept/reject + `timeout_secs` honor/default/reject), `secretenv-backend-cf-kv` (+4: `wrangler_bin` reject + `timeout_secs` honor/reject/zero) and prefix-related (+2 above), `secretenv-backend-vault` (+4: `vault_namespace`/`vault_bin` reject + `timeout_secs` honor/default), `secretenv-backend-aws-secrets` (+4: `aws_profile`/`aws_bin` reject + `timeout_secs` honor/default). Closes the cf-kv code-reviewer M1 carry-forward "factory-helper test parity audit" — the four backends with the thinnest factory-validation coverage now match the keeper / azure / aws-ssm pattern.

#### Audited (no findings)

- **Workspace-wide placeholder-field audit** — methodology: `grep -rn "Reserved\|reserved" crates/backends/*/src/*.rs` plus per-backend struct-field walk for any `Option<T>` config field never read after factory construction. Result: zero placeholder fields outside the `keeper_folder` already removed in v0.9.1. The two grep hits (`backend-doppler` "Fragments are reserved for v0.7+", `backend-infisical` "Fragments are reserved and currently rejected") are doc-comment phrases describing forward-compatibility posture, not dead config fields. Audit captured here so it doesn't get re-run unnecessarily next cycle.

#### Deferred / declined (carry-forward closeout notes)

- **cf-kv `bulk get`** — DEFER. Cloudflare API still in open-beta as of 2026-04-26. Trigger to revisit: GA announcement.
- **cf-kv `#metadata` fragment** — DECLINE. Speculative; zero user demand. Resurrect on demand.
- **Rust 1.87+ `env::set_var` unsafe-wrap (R-13 from v0.7.2)** — DEFER. Workspace MSRV is 1.75. Bumping to 1.87 in a hygiene patch is a user-facing breaking floor change, not hygiene. Trigger: next natural workspace MSRV bump.
- **256 KiB `spawn_blocking` measured benchmark (v0.7.2 carry-over)** — DEFER. Needs `cargo bench` / criterion infrastructure that doesn't exist in the workspace yet. Trigger: dedicated benchmark-infrastructure micro-cycle.

### v0.9.1 hygiene (merged-not-tagged 2026-04-25)

Rolling-backlog cycle following the v0.7.1 / v0.7.2 dev-work pattern: merged to `main`, workspace `version` stays at `0.9.0`, no tag. Closes 13 actionable items from the v0.9 trio audit deferred list ([reviews/2026-04-25-v0.9-cf-kv-audit](kb/wiki/reviews/2026-04-25-v0.9-cf-kv-audit.md)) plus the v0.8.x Keeper carry-forward backlog plus baseline smoke hygiene. v0.10 OpenBao release will fold these into its tagged CHANGELOG.

#### Added

- **`keeper_list_max_records`** (Keeper backend) — opt-in cap on `list()` per-record fan-out. Default unset (no cap). Bounds heap residence and outbound rate-limit pressure on large vaults; hitting the cap emits a `tracing::warn!`. Closes Keeper trio sec-H1 follow-up.

#### Changed

- **`keeper_config_path` validated at factory time** — file existence + POSIX mode `0o077` mask. Permissive modes (group/other-readable) now bail with a `chmod 600` hint instead of silently loading a Keeper device token from a shared file. Closes Keeper trio sec-H2.
- **cf-kv `WranglerWhoami::parse` refactored to `find_map`** — clearer style, same behavior. Closes cf-kv rust-L1.
- **cf-kv `resolve_target` allocation-free** — `split_once('/')` chain replaces the previous `Vec<&str>` collect. Closes cf-kv rust-L5.
- **cf-kv smoke namespace IDs centralized** to `scripts/smoke-test/lib/cfkv-namespace.env` — single source of truth (was 3-place duplication). Closes cf-kv code-reviewer L2.
- **cf-kv docs expanded** with Troubleshooting, `set()` opt-in posture comparison table vs other backends, and multi-namespace worked example. Closes cf-kv code-reviewer L1.
- **Backend-spec template Phase 1 checklist** explicit "new crate → `deny.toml` per-crate AGPL exception" + `cargo deny check licenses` preflight gate. Captures the v0.8 Keeper lesson so future cycles don't hit the CI-only failure.

#### Removed

- **`keeper_folder` config field** — declared since v0.8 but never wired up (documented as "reserved for future short-form URI scoping. Currently accepted but unused"). API-surface debt removed; if folder scoping ships in a future release it will be re-introduced under a deliberate spec.

#### Fixed

- **Section 17 (v0.4 history) — `seed_runtime_from_fixtures` git-init validity gate.** The previous `[ ! -d .git ]` check skipped re-init when `.git/` existed but was broken (e.g., empty from a prior failed run). Replaced with `git rev-parse --git-dir` validity probe that wipes and reinits broken state. Recovers the 8 baseline failures (assertions 185-192) that were stuck in this state. Pre-existing baseline drift surfaced by v0.9 pre-tag full-matrix smoke.
- **Section 25k cf-kv post-delete read assertion** — switched pattern from lowercase `'not found'` to literal `'404'` to match wrangler 4.85.0's actual `404: Not Found` (capital N) error string. Same evidence; immune to case-shifts.

#### Smoke Section 25 additions (v0.9.1 hygiene)

- **343a — registry-namespace must NOT contain scalar fixtures** (sec-L1). Negative assertion locks the two-namespace discipline so a future regression mixing scalar + URI keys in the registry namespace fails loudly.
- **352–354 — wrangler-delete-actually-deletes canary** (sec-M2). Provisions a probe key, deletes via wrangler in the same non-TTY mode the cf-kv backend uses, asserts (a) post-delete read returns `404`, (b) `wrangler kv key list` no longer shows the probe. Locks the wrangler contract our backend depends on; if wrangler ever regresses to default-no on its interactive confirmation prompt, this canary catches it.

#### Smoke matrix delta

- v0.9.0 pre-tag: 408/419 PASS (11 baseline failures: 8 history + 3 Infisical).
- v0.9.1 post-fix: **420/423 PASS** (3 remaining = Infisical session expired locally; environmental, not code). +12 net recovered + 4 new assertions.

## [0.9.0] - 2026-04-25

**Headline:** fourth release of the single-backend-per-release cycle; fourth [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Cloudflare Workers KV** (`cf-kv` via `wrangler` CLI 4.x) — brings the total to **12**. First backend whose Phase 0 CLI-shape probe materially flipped the spec: the v0.7-era spec recommended a curl-against-REST design citing 2-3 s wrangler startup, but live measurement at wrangler 4.85.0 showed 0.28 s startup (Bun runtime), so the entire curl branch was retired and the backend ships wrangler-wrapped. v0.8.0 → v0.9.0: workspace unit tests **676 → 705** (+29 from the new cf-kv crate); live smoke matrix **395 → 419** (+24 for Section 25's 13 cf-kv assertions plus a few extras). Pre-tag full-matrix smoke passed all 13 cf-kv assertions on the second run after fixing a registry-source design issue (single namespace can't mix scalar secrets with URI-valued aliases — the resolver bails on the first non-URI value; switched to a two-namespace pattern, mirroring how Doppler/Infisical use separate paths). Closing three-agent trio audit (security + code + rust) landed 8 BLOCKING/HIGH/MEDIUM findings inline before tag. The remaining 11 baseline-smoke failures (8 in v0.4 history + 3 in v0.7 Infisical) are environmental drift unrelated to v0.9 — to be addressed in a follow-up hygiene cycle.

### Added

- **Cloudflare Workers KV backend** (`cf-kv`) wrapping the official `wrangler` CLI 4.x. Supports OAuth (`wrangler login`) and `CLOUDFLARE_API_TOKEN` env-var auth transparently. Two-segment URI shape `cf-kv-<instance>:///<namespace-id>/<key>`, with optional single-segment form `cf-kv-<instance>:///<key>` enabled by `cf_kv_default_namespace_id` config. `set()` writes through a mode-0600 tempfile + `--path` flag (no `_unsafe_set` opt-in needed — strictly safer than argv; matches Infisical's `--file` discipline). `list()` is Pattern A bulk-mode with sequential per-key fan-out for value hydration; `history()` is unsupported (KV has no per-key versioning — overwrites simply replace). Brings the total backend count to **12**. Spec at [docs/backends/cf-kv.md](docs/backends/cf-kv.md).
- **Smoke Section 25** (assertions 330-352, 13 total) covering cf-kv as both a secrets backend (doctor / get / run-injection / history-unsupported / fragment-reject) AND a registry source (registry list / registry get / cross-backend resolve / end-to-end run via cf-kv-backed registry → local-main file content). Two-namespace pattern (`secretenv-smoke-v09` for secrets + `secretenv-smoke-v09-registry` for URI-valued aliases) is documented in `provision.sh` since cf-kv namespaces are flat (no folders to scope mixed key types).

### Fixed

- **Tightened `cf-kv` "key not found" detector** from a loose `"10009"` substring match to word-boundary forms (`error 10009` / `code 10009` / `code: 10009`) — prevents false-positives on stderr containing the digit run inside request IDs or timestamps. Surfaced by Phase 6 trio audit.
- **Made `set()` tempfile flush fatal** (`with_context` instead of `.ok()`) — silently dropping a flush error could leave wrangler reading a truncated value with no surface to caller. Surfaced by Phase 6 trio audit.
- **Added `NotFound` mapping to the `whoami` arm of `check()`** — the `tokio::join!` fires both probes simultaneously; the previous code only mapped `NotFound` on the version arm. Defense-in-depth for OS-shape variation. Surfaced by Phase 6 trio audit.

## [0.8.0] - 2026-04-24

**Headline:** third release of the single-backend-per-release cycle; third [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Keeper** (Keeper Security vault via Keeper Commander v17+) — brings the total to 11. First backend to require a **prerequisite setup step** (persistent-login device-token registration); the install UX has an extra paragraph in docs as a result. v0.7.1 → v0.8.0: workspace unit tests **645 → 676** (+31 from the new Keeper crate); live smoke matrix **383 → 395** (+12 for Section 24). Pre-tag full-matrix smoke passed 395/395 across all 11 backends on first clean run; closing three-agent trio audit (security + code + rust) landed 9 BLOCKING/HIGH/MEDIUM findings inline before tag, including a post-audit whoami text-parse fix surfaced during pre-tag smoke (CLI v17 `keeper whoami` has no `--format=json` flag — a spec/impl drift caught at the final integration gate). Note: v0.7.1 + v0.7.2 shipped as merged-not-tagged hygiene cycles; workspace version stayed at 0.7.1 until this tag bumps directly to 0.8.0.

### Added

- **Keeper backend** (`keeper`) — 11th backend. Wraps the `keeper` CLI (Keeper Commander v17+, installed via `pip install keepercommander`) to read, write (opt-in), delete, and list secrets in a user's Keeper vault. Unlike every other SecretEnv backend, **Keeper requires persistent-login setup as a prerequisite** — one-shot CLI invocations prompt for the master password unless a device token has been persisted via `keeper shell` → `this-device register` → `this-device persistent-login on`. The backend enforces `--batch-mode` on every invocation to prevent interactive prompts from hanging; a non-authenticated instance surfaces cleanly through `doctor` with a setup hint rather than blocking. URI shape: `keeper-<instance>:///<record-uid-or-title>` — a single path segment the CLI resolves to either a 22-char base64url UID or a record title. Optional `#field=<name>` fragment selects a typed or custom field (default: password). Config fields: `keeper_config_path` (custom `~/.keeper/config.json` path for multi-account setups), `keeper_unsafe_set` (default `false`; opt-in gate for argv-based `set()` — the Keeper CLI has no stdin form for field values, matching 1Password's `op_unsafe_set` precedent; emits `tracing::warn!` per unsafe invocation), `timeout_secs`, `keeper_bin` (test hook). `list()` uses the Pattern A bulk model (each vault record = one alias, password field = target URI) mirroring Doppler + Infisical; per-record failures during the hydration fan-out emit `tracing::warn!` with instance + title + reason rather than silent-continue (divergence from the silent pattern was flagged + fixed inline during trio audit). `history()` is unsupported — CLI `history` is interactive-shell command history, NOT per-record version history; bails with Vault-UI pointer. Full reference at [`docs/backends/keeper.md`](docs/backends/keeper.md).
- **Smoke harness Section 24** — 12 live-backend assertions for the new Keeper backend. Provisions `SMOKE_TEST_VALUE` (scalar `kp_vault_88888`) and `SMOKE_REGISTRY_ALIAS` (URI-valued) records in the user's root folder; exercises `doctor` / `get` (round-trip via both title and registry alias) / `run` (end-to-end env injection) / `history` (unsupported bail) / unknown-fragment-reject end-to-end. Tears down both records after. Tagged `cloud=yes`; skipped when the `keeper` CLI is missing OR persistent login isn't set up.

### Fixed (v0.7.1 + v0.7.2 hygiene work, merged as dev work 2026-04-23/24)

The v0.7.1 (#67) and v0.7.2 (#68) cycles closed 25 DEFER items from the v0.6 Doppler and v0.7 Infisical closing audits as *merged-but-unreleased* work on `main`. Shipping now under the v0.8.0 tag so downstream users benefit. Full detail in [v0.7.1 CHANGELOG](#071---2026-04-23) and the build log.

Key items:
- Infisical `set()` value-aware stderr scrub; fd-based chmod; non-UTF-8 `$TMPDIR` explicit bail.
- Doppler `ResolvedTarget` struct (replaces positional tuple); tightened `not found` heuristic so auth errors no longer mask as missing-secret; `tracing::debug!` on set/delete happy paths.
- Both Doppler + Infisical `list()` JSON parse hops to `spawn_blocking` ≥256 KiB (threshold PROVISIONAL pending 10K-secret benchmark).
- Infisical env-inherit test deterministic via mutex-serialized `EnvVarGuard`.
- Live smoke coverage: Doppler + Infisical finally exercised as registry sources (sections 22g, 23g) — closed the long-deferred TODO from v0.6.
- Documentation polish: Infisical self-hosted domain trust, Doppler IAM/RBAC + chmod advisory, `docs/security.md#self-hosted-domains` cross-linked from Infisical + Vault.

### Changed

- **Workspace version 0.7.1 → 0.8.0.** v0.7.1 + v0.7.2 held Cargo.toml at 0.7.1 while merging hygiene work as dev-only (no tag, no crates.io publish). This v0.8.0 tag bumps directly to 0.8.0, skipping a 0.7.2 tag. Users pulling from crates.io see v0.7.0 → v0.8.0 linearly; the intermediate hygiene fixes are bundled into v0.8.0.
- **Backend count 10 → 11.** README badge + supported-backends table reflect the Keeper addition.

### Deferred to v0.8.x+

- **Keeper `keeper_config_path` world-readable stat-check** at factory time (trio security H2). Feature-add, not tag-blocker.
- **Keeper Pattern A `registry set` extension.** Would let `registry set`/`unset` target Keeper (as well as Doppler + Infisical). Feature, not hygiene; target v0.9+.
- **`keeper_folder` short-form URI scoping.** Field declared + accepted; implementation deferred.
- **Rust 1.87+ `env::set_var` unsafe-wrap** (v0.7.2 carry-over R-13) — triggers when workspace rust-version floor moves.
- **256 KiB `spawn_blocking` threshold benchmark** (v0.7.2 carry-over) — distinct activity, not hygiene-shaped.

## [0.7.1] - 2026-04-23

**Headline:** dedicated DEFER-closeout hygiene patch between v0.7.0 and v0.8, keeping the next backend cycle cleanly thematic. Twenty items from the v0.6 (Doppler) and v0.7 (Infisical) closing audits closed in a single patch PR: three security-hardening items on Infisical's `set()` temp-file path, six consistency items unifying Doppler and Infisical error shapes and symmetry patterns, three testing-quality items (deterministic env-isolation, list()-parse spawn_blocking on multi-MB payloads, symmetric drift-catch naming), and eight documentation polish items spanning the self-hosted-domain trust boundary, IAM/RBAC walkthroughs, and smoke-harness fixture comments. No user-facing behavior changes beyond tightened error messages. v0.7.0 → v0.7.1: workspace unit tests **637 → 642** (+5); live smoke matrix unchanged at **373 assertions** (hygiene doesn't add assertions; pre-tag smoke re-runs the v0.7.0 baseline). Closing audit by the `code-reviewer` agent landed 2 HIGH fixes (ENV_LOCK invariant documentation + spawn_blocking threshold provisional flag) inline before tag; 0 BLOCKING findings.

### Changed

- **Doppler `resolve_target` returns a struct** (`ResolvedTarget { project, config, secret }`), replacing the positional `(&str, &str, &str)` tuple. Mirrors the Infisical backend's shape so the two SaaS-bulk-model backends read the same way across four call sites (`get` / `set` / `delete` / `list`).
- **Doppler `not found` heuristic tightened.** Now requires the CLI's canonical `"Could not find requested secret"` prefix rather than the looser `"not found"` substring. Before: a stderr line like `Doppler Error: Unauthorized: token not found` (auth-error phrasing) false-positived into the friendly "secret not found" arm and hid the real failure. After: only the canonical missing-secret phrasing routes to the friendly arm; auth errors surface verbatim via `operation_failure_message`. Regression tests on both `get()` and `delete()` lock the distinction.
- **Doppler segment-count error surfaces parsed segments.** A URI like `doppler-prod:///acme/prd` (two segments) now errors with `got 2 segment(s): [acme, prd]` instead of just `got 2 segment(s)`.
- **Doppler `set()` and `delete()` emit `tracing::debug!` on happy paths.** Matches the Keychain backend's audit-symmetry precedent. No values logged — only instance, op, project, config, secret name.
- **Infisical `resolve_target` lifetimes split.** Previously `<'a>(&'a self, uri: &'a BackendUri)` over-constrained `self` and `uri` to the same lifetime. Now `<'s, 'u>(&'s self, uri: &'u BackendUri) -> Result<ResolvedTarget<'u>> where 's: 'u` — callers with `self` outliving the URI (the common case) get precise borrow-checker reasoning without an artificial lifetime tie.
- **Both backends' `list()` JSON parse uses `tokio::task::spawn_blocking` above 256 KiB.** Below the threshold, the zero-overhead inline path runs (thread-pool dispatch > parse cost for a typical small registry). Above it, the parse runs on a blocking worker thread so a multi-MB payload stops stalling the tokio executor. Threshold is provisional — a measured benchmark is deferred to v0.7.2+.
- **Infisical drift-catch test renamed.** `delete_without_type_shared_flag_would_fail_strict_mock` → `delete_requires_type_shared_flag` for symmetry with the existing set() canary. Dual-purpose doc comment added to `set_value_never_appears_on_argv` flagging its paired `--type shared` drift-catch role.

### Fixed

- **Infisical `set()` stderr scrubs the secret value** before folding stderr into the error chain. A CLI parse-error that echoes the `--file` contents back can surface `NAME=VALUE` in stderr; the new `set_failure_message` helper replaces the value string with `<REDACTED>` when present (≥4 chars to avoid collision-prone short values), preserving non-value diagnostic information for debugging. Dedicated unit tests cover both the scrub path and the passthrough case.
- **Infisical env-inherit test deterministic.** `check_not_authenticated_when_probe_fails_and_no_token` previously carried a runtime skip if the parent process had `$INFISICAL_TOKEN` set. Now wrapped in an RAII `EnvVarGuard` (mutex-serialized against `ENV_LOCK`) that unsets for the test duration and restores on drop. Test runs and asserts deterministically regardless of parent-process state.

### Security

- **Infisical `set()` uses fd-based `chmod` instead of path-based.** Replaces `std::fs::set_permissions(tempfile.path(), perm)` with `tempfile.as_file().set_permissions(perm)` — closes the narrow TOCTOU window between `NamedTempFile::new()` and the redundant 0600 re-assertion. (The `NamedTempFile` crate already creates with `O_CREAT|O_EXCL` + mode 0600 on Unix; the explicit re-chmod is belt-and-braces.)
- **Infisical `set()` explicit bail on non-UTF-8 `$TMPDIR` paths.** Replaces `to_string_lossy().into_owned()` with `to_str().ok_or_else(...)?` — a non-UTF-8 temp path now surfaces a clear error instead of passing a U+FFFD-substituted garbled string to `infisical secrets set --file` (which would fail with an opaque "file not found").

### Docs

- **Infisical self-hosted domain-trust section expanded.** New subsection under [Minting a service token](docs/backends/infisical.md) with pin-the-cert callout, verify-the-domain checklist, `openssl s_client` inspection snippet, and the "malicious domain receives every token" threat statement. Cross-linked to new `docs/security.md#self-hosted-domains`.
- **Infisical `NamedTempFile` panic-safety wording.** `set()` discipline section now spells out that `Drop` runs during unwind so panics / cancellations / runtime drops cannot orphan a secret-bearing file under `$TMPDIR`.
- **Doppler IAM/RBAC expansion** under [Service-token scope mismatch](docs/backends/doppler.md): service-token scope-mismatch vs. auth-error distinction (ties back to the tightened `not found` heuristic above), service accounts and project-level access grants, multi-workplace setup pattern.
- **Doppler `doppler_token` file-permissions advisory.** Explicit `chmod 600 config.toml` guidance matching the 1Password backend's precedent, with a pointer to also `700`-scope the parent directory.
- **Smoke harness Infisical blocks flagged "fixtures only, never use for a real secret"** on both `provision.sh` and `teardown.sh`. The provisioner uses the CLI's positional argv form (value on argv) because the value is a known-fixed fixture string and this is a fixture hook, not the code path end-users invoke.
- **`docs/security.md` new Self-hosted Domains section** cross-linked from both Infisical (`infisical_domain`) and Vault (`vault_address`). Covers the five-point discipline: verify the domain, pin HTTPS, confirm the cert chain, don't inherit a domain from an untrusted registry, rotate tokens after suspected exposure.

### Deferred to v0.7.2+

- **10K-secret `list()` benchmark** for the 256 KiB `spawn_blocking` threshold. Constant is explicitly marked `PROVISIONAL` in-source; benchmark to be captured under the smoke-harness report that exercises `list()` against a large real registry.
- **Pattern A registry `set` extension** (would let `registry set`/`unset` target Doppler + Infisical). This is a feature, not hygiene. Logged in the v0.8+ roadmap row.
- **Already-correct-code-just-needs-a-comment** items from the v0.7 audit (redundant chmod rationale, `sync_all` doc, env-var check scope comment) — drive-by cleanups for any future PR touching those lines.

## [0.7.0] - 2026-04-22

**Headline:** third release of the single-backend-per-release cycle; second [[project_cycle_execution_model|solo-fresh-session]] release. One new backend — **Infisical** (SaaS + self-hostable) — brings the total to 10. Spec at [[backends/infisical]] shipped with three inline post-implementation corrections (no `secrets versions` subcommand at CLI v0.43.77; `--plain` deprecated on list (use `--output json`); `delete --type` defaults to `personal` and must be passed `--type shared` explicitly). v0.6.0 → v0.7.0: workspace unit tests **604 → 637** (+33); live smoke matrix **362 → 377** (+15). Pre-tag full-matrix smoke passed 377/377 across all 10 backends; closing reviewer-trio audit (security + code + rust) landed 3 BLOCKING fixes (serde `rename_all`, `list()` iterator readability, `with_context` quality) inline before tag; one post-audit `list()` semantic fix landed during pre-tag smoke (corrected to return `(name, value-as-URI)` pairs matching the Doppler-style bulk model). DEFER items consolidated into [[build-plan-v0.7.1]] for the next hygiene cycle.

### Added

- **Infisical backend** (`infisical`) — 10th backend. Wraps the `infisical` CLI (v0.43+) to read, write, delete, and list secrets in Infisical projects + environments + folders. Works against both the hosted SaaS at `app.infisical.com` and self-hosted Infisical instances — one config field (`infisical_domain`) flips between them. URI shape: full form `infisical-<instance>:///<project-id>/<env>/<secret>` or short form `infisical-<instance>:///<secret>` when `infisical_project_id` + `infisical_environment` defaults are set in `[backends.<instance>]`. Nested folders fold into middle segments (`<project-id>/<env>/<folder1>/<folder2>/<secret>` → path = `/folder1/folder2`). Config fields (all optional): `infisical_project_id`, `infisical_environment` (both-or-neither), `infisical_secret_path` (default `/`), `infisical_token` (per-instance override for `$INFISICAL_TOKEN`), `infisical_domain` (self-hosted instance URL), `timeout_secs`, `infisical_bin` (test hook). Tokens travel via the `INFISICAL_TOKEN` subprocess env var — **never** via the `--token` argv flag (canary test `token_travels_via_env_not_argv` locks this); self-hosted domain travels via `INFISICAL_API_URL` env, never `--domain` on argv (symmetric discipline, `domain_travels_via_env_not_argv` canary). `set()` writes `NAME=VALUE` to a mode-0600 `NamedTempFile` under `$TMPDIR` and spawns `infisical secrets set --file <tempfile> --type shared` — the CLI has no stdin form, and using argv-positional form would expose values via `ps`; canary test `set_value_never_appears_on_argv` asserts values never reach argv. **`--type shared` is mandatory on set AND delete** — the CLI default is `personal` (user-override scope), which would silently target the wrong secret on shared project secrets; drift-catch test locks the invariant. `list()` uses `--output json` (the forward-compatible form; `--plain` is deprecated at v0.43.77) and follows the **Doppler-style bulk model** — each Infisical secret in the scoped env+path becomes one alias, the secret's value serves as the alias's target URI. `history()` is unsupported in v0.7 — the `infisical` CLI (v0.43.77) exposes no `secrets versions` subcommand; history exists in the Infisical Dashboard and REST API only. Full reference at [`docs/backends/infisical.md`](docs/backends/infisical.md).
- **Smoke harness Section 23** — live-backend assertions for the new Infisical backend. Provisions `SMOKE_TEST_VALUE=sk_test_infisical_55555` in the user's `secretenv-validation` project at `dev@/`; exercises `doctor` / `get` (full-form and short-form) / `run` / fragment-reject / `history` (unsupported bail) end-to-end. Tears down the seeded secret after. Tagged `cloud=yes`; skipped when the `infisical` CLI is missing or not authenticated. Project ID is overridable via `$SECRETENV_INFISICAL_PROJECT_ID`. Live matrix grows 362 → 373 (+11). Live-smoke of `backend.set()` is deliberately omitted — `registry set` only supports Pattern B backends (single-doc registries: local / 1password / aws-ssm / vault / aws-secrets / gcp / azure); Infisical follows the Pattern A Doppler-style bulk model, and unit-test canaries (argv + `--type shared` drift-catch) cover `set()` discipline. Extending `registry set` to Pattern A backends is deferred to v0.8+.

## [0.6.0] - 2026-04-22

**Headline:** second release of the single-backend-per-release cycle. One new backend (Doppler, 9th total), first **solo-fresh-session** cycle per the post-v0.5 execution model — orchestrator-solo through Phase 6, paused for sister-pane authentication at Phase 7, then tagged. Spec at [[backends/doppler]] shipped two post-implementation corrections (no `doppler secrets versions` subcommand in CLI v3.76.0; `DOPPLER_` prefix is not hard-reserved by Doppler). 9 backends supported: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure, keychain, **doppler**. v0.5.0 → v0.6.0: unit tests **575 → 604** (+29); live smoke matrix **347 → 362** (+15). Pre-tag full-matrix smoke passed 362/362 across all 9 backends; closing reviewer-trio audit (security + code + rust) landed one BLOCKING fix (short-form URI + fragment-reject live assertions) plus three minor cleanups inline before tag; DEFER items captured in [[reviews/2026-04-22-v0.6-doppler-audit]].

### Added

- **Doppler backend** (`doppler`) — 9th backend. Wraps the `doppler` CLI (v3+) to read, write, delete, and list secrets in Doppler projects + configs. URI shape: full form `doppler-<instance>:///<project>/<config>/<secret>` or short form `doppler-<instance>:///<secret>` when `doppler_project` + `doppler_config` defaults are set in `[backends.<instance>]`. Config fields (all optional): `doppler_project`, `doppler_config` (both-or-neither), `doppler_token` (per-instance override for `$DOPPLER_TOKEN`), `timeout_secs`, `doppler_bin` (test hook). Tokens travel via the `DOPPLER_TOKEN` subprocess env var — **never** via the `--token` argv flag (canary test `token_travels_via_env_not_argv` locks this). `set` pipes values through child stdin with `--no-interactive` (CV-1 discipline, locked by stdin-fragment canary). `list()` uses the entire Doppler config as the alias map (each Doppler secret = one alias), with a **`DOPPLER_*`-prefix filter** that excludes the synthetic `DOPPLER_PROJECT` / `DOPPLER_CONFIG` / `DOPPLER_ENVIRONMENT` entries Doppler auto-injects into every `secrets download`. `history()` is unsupported in v0.6 — the `doppler` CLI (v3.76.0) exposes no `secrets versions` subcommand; history exists in the Doppler Dashboard and REST API only. A future CLI release adding `secrets versions` can flip this to a native implementation in a patch. Full reference at [`docs/backends/doppler.md`](docs/backends/doppler.md).
- **Smoke harness Section 22** — 15 live-backend assertions for the new Doppler backend. Provisions a `secretenv-validation` Doppler project + `dev` config with a `SMOKE_TEST_VALUE` fixture; exercises `doctor` / `get` (full-form and short-form) / `run` / fragment-reject / `history` (unsupported bail) end-to-end; tears down the test secret after. Tagged `cloud=yes`; skipped when the `doppler` CLI is missing or not authenticated. The synthetic-`DOPPLER_*`-key filter is locked by unit tests (`list_returns_filtered_map` + `list_filters_every_doppler_prefixed_key`) rather than in the live matrix, since `registry list --registry <doppler-URI>` requires every entry's value to parse as a URI — and the live fixture's scalar `SMOKE_TEST_VALUE` exercises the `get` round-trip instead. Live matrix grows 347 → 362 (+15).

### Fixed

- **Provision harness — Azure soft-delete recoverable state handling.** The v0.5 provision flow failed on a fresh run whenever `az keyvault secret delete` from a prior teardown had soft-deleted (rather than purged) the two `secretenv-validation-*` fixtures. The resulting `409 Conflict — ObjectIsDeletedButRecoverable` aborted the Azure block and cascaded into missing-secret failures in the v0.3 Azure smoke sections. Added `az_ensure_available()` helper in `scripts/smoke-test/provision.sh` that pre-checks `show-deleted` state per fixture, calls `az keyvault secret recover` + `sleep 8` propagation wait when soft-deleted, then proceeds to `set`. Makes provision fully idempotent across teardown/provision cycles.

## [0.5.0] - 2026-04-22

**Headline:** first release of the "single backend per release" cycle — one new backend (macOS Keychain), the canonical `examples/` directory at repo root, and the five blocking fixes from the parallel three-agent closing audit. Rung-1 release of the [parallel-backend-workflow](kb/wiki/parallel-backend-workflow.md) — last "orchestrator writes the code" cycle before external agent sessions take over in v0.6. 8 backends supported: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure, **keychain**. v0.4.0 → v0.5.0: unit tests **536 → 575** (+39); live smoke matrix **336 → 347** (+11). Pre-tag full-matrix smoke passed 347/347 against all 8 backends; closing reviewer-trio audit (security + code + rust) landed 5 BLOCKING fixes before tag; DEFER items captured below.

### Added

- **macOS Keychain backend** (`keychain`) — 8th backend. Wraps the system `security` CLI to read, write, and delete `generic-password` or `internet-password` items in any addressable keychain (the user's login keychain by default, or a custom keychain via `keychain_path`). URI shape: `keychain-<instance>:///<service>/<account>`. Config fields: `keychain_path` (optional; default = login keychain), `kind` (optional; `"generic-password"` default or `"internet-password"`), `timeout_secs` (optional). Platform-gated: the factory bails on non-macOS at config-load time with a clear "macOS-only" error; the crate itself compiles everywhere so the workspace tests cleanly on Linux/Windows CI. Every `security` invocation uses `stdin: Stdio::null()` to prevent password-prompt hangs on locked keychains. `set` passes the secret value through child argv; on macOS's same-UID process model this exposure is same-UID-only and we accept it (no opt-in gate, unlike 1Password's `op_unsafe_set` on Linux), with a `tracing::warn!` on every `set` for audit. **`list()` is intentionally unsupported** — `security` has no safe list-by-prefix operation; host your alias registry on a different backend type (local, aws-ssm, aws-secrets, 1password, vault, gcp, or azure). `history()` and extensive-check are likewise unsupported (Keychain has no native version-history API). Full reference at [`docs/backends/keychain.md`](docs/backends/keychain.md).
- **`examples/` directory at repo root** — canonical configuration patterns. Seven subdirectories: `single-backend-local/`, `single-backend-aws-ssm/`, `single-backend-keychain/`, `cascade-local-then-vault/`, `multi-cloud-aws-and-1password/`, `ci-github-actions/`, `secretenv-toml-canonical/`. Each has `config.toml` + `secretenv.toml` + a README explaining the *why* of the pattern. Top-level [`examples/README.md`](examples/README.md) flags the "NOT Cargo examples" caveat so `cargo build --examples` is expected to no-op.
- **Smoke harness Section 21** — live-backend integration coverage for the new keychain backend. Provisions a self-contained test keychain at `$RUNTIME_DIR/test.keychain-db`, exercises `doctor` / `get` / `run` / `list` / `history` end-to-end, and tears down after. Tagged `cloud=yes` so `--local-only` (Ubuntu CI) skips it; macOS full-matrix runs include it. Live matrix grows 336 → 347 (+11).

### Tests

- Workspace unit tests **536 → 575** (+39): all in the new `secretenv-backend-keychain` crate. Covers URI parsing (including `%2F` slash-escape); factory validation (kind enum, timeout_secs, `keychain_path` flag-injection rejection, cross-platform cfg-gated tests); get/set/delete strict-mock argv coverage; list / check_extensive / history backend-specific unsupported-error messages; check() paths (Ok, Locked/NotAuthenticated, CliMissing, missing keychain file → Error, wrong stdout shape → Error); and drift-catch regression locks for every argv invariant (missing `-U` upsert, `-k`-vs-positional on get/delete/check).
- Live smoke matrix **336 → 347** (+11): Section 21 Keychain.

### Internal — closing audit (2026-04-22)

Three-agent audit (`security-engineer` + `code-reviewer` + `rust-engineer`) ran in parallel against the merged v0.5 backend + smoke + docs. Five BLOCKING findings landed in an audit-polish PR; all DEFER items captured in `kb/wiki/build-log.md`:

- `keychain_path` values starting with `-` rejected at factory time (would be parsed as a flag by `security` once appended to argv).
- `check()` distinguishes `"No such keychain"` (missing file → `Error`, no fix available) from "locked keychain" (`NotAuthenticated`, `security unlock-keychain` hint).
- `check()` validates that `show-keychain-info` output contains a `Keychain` sentinel (in stdout or stderr — the real binary writes to stderr) before returning `Ok`, guarding against a shadowing PATH binary.
- Three drift-catch tests added — declaring `-k <path>` argv on get / delete / check and asserting no-match, locking the trailing-positional convention against future reintroduction.
- `history()` overridden to call `reject_any_fragment("keychain")` before bailing, so a `#version=2`-carrying URI surfaces the unsupported-directive mistake rather than silently dropping the fragment.

## [0.4.0] - 2026-04-22

**Headline:** team ergonomics + distribution profile system + tooling hygiene. Functionality-only release — **no new backends** (still 7 live: local, aws-ssm, aws-secrets, 1password, vault, gcp, azure). Aggregate of v0.4 phases 1-7: `doctor --fix/--extensive` + `registry history/invite` (operator surfaces), distribution profile system served from `https://secretenv.io/profiles/` (the headline feature), per-instance `timeout_secs` + 1Password `set` safe-by-default, smoke-harness promoted into the repo with selective-run flags, GitHub Actions Node 24 readiness, `deny.toml` AGPL tightening, and per-file SPDX headers. v0.3.0 → v0.4.0 unit tests grew **442 → 536**; live smoke matrix grew **250 → 336** assertions. Closing reviewer-trio audit (security + code + rust) ran 2026-04-21; 6 blocking findings closed.

### Added

- **`secretenv profile install|list|update|uninstall`** — distribution profile system. A "profile" is a TOML document (`[backends.*]` + `[registries.*]` fragments only) fetched over HTTPS and auto-merged into the active `config.toml` at load time. Profiles fill gaps, never override: the user's own `config.toml` always wins where both define the same key; among profiles, alphabetical filename order decides conflicts. Profiles land in `<config_dir>/profiles/<name>.toml` with a sidecar `<name>.meta.json` (source URL + `ETag` + install timestamp) that `profile update` uses for conditional `If-None-Match` re-fetch. Default base URL is `https://secretenv.io/profiles`; overridable globally via `SECRETENV_PROFILE_URL` or per-invocation via `--url <url>` (supports `file://` for offline / local-staging flows). Fetching uses `curl` (subprocess) — no new HTTP client dependency, consistent with every other backend's CLI-spawn pattern. Fetched bodies are validated as `Config` fragments before being written to disk, so a malformed profile never lands. Profile names go through a strict ASCII allowlist (`[A-Za-z0-9][A-Za-z0-9_-]*`) with 64-char cap and Windows reserved-name check; `curl --max-filesize 1MiB` + `--proto =https,file` cap response size and pin scheme. `profile list --json` emits a machine-readable array; `profile update` (no name) updates every installed profile with a per-row report. Full walkthrough at [`docs/profiles.md`](docs/profiles.md).
- **`Config::load` + `Config::load_from` auto-merge profiles** from the `profiles/` directory next to the active config. Behavior for callers with no profiles installed is unchanged. New public helpers `secretenv_core::default_config_path_xdg()` and `secretenv_core::profiles_dir_for(config_path)`. The merge path enforces a 1 MiB per-file size cap so a compromised local `profiles/` dir can't OOM the load.
- **`secretenv registry history <alias>`** — show version history for the secret an alias resolves to. Output is most-recent-first across all backends. New `Backend::history()` trait method returns `Vec<HistoryEntry>` (`version`, `timestamp`, `actor`, `description`); default impl reports the operation as unsupported. Native implementations:
  - `local`: shells out to `git log --follow --pretty=format:%h%x09%aI%x09%an <%ae>%x09%s -- <path>`. Surfaces "not under a git repo" / "untracked" errors verbatim from git.
  - `aws-ssm`: calls `aws ssm get-parameter-history --with-decryption --name <param> --output json` and reverses AWS's oldest-first ordering. The `Value` payload is deliberately NOT captured by the deserializer (`ParameterHistoryRecord` lacks a `value` field) so secret values can never leak into history rendering.
  - `vault`: calls `vault kv metadata get -format=json <path>` (KV v2 only — KV v1's "Metadata not supported" error is surfaced verbatim). Versions sorted numerically descending. Soft-deleted versions surface as `[soft-deleted]`; destroyed versions as `[destroyed]`.
  - `aws-secrets`, `1password`, `gcp`, `azure` report "history unsupported" via the trait default; native overrides deferred (each has a quirk).
- **`HistoryEntry`** struct exported from `secretenv_core` for backend authors and tooling outside the workspace. Fields are string-typed so backend-specific identifiers (git SHAs, AWS integer versions, Vault decimal-string versions, RFC-3339 vs raw native timestamps) all fit without forcing CLI parse.
- **`secretenv registry invite [--registry <name>] [--invitee <id>] [--json]`** — copy-pasteable onboarding payload for sharing a registry with a new collaborator. Three sections: the `config.toml` snippet the new user adds (mirrors every non-`type` field from the inviter's `[backends.<instance>]` block, sorted, with strict-mock test-only fields filtered); the per-backend IAM/RBAC grant command the inviter runs (`aws iam attach-user-policy ...`, `op vault user grant ...`, `vault policy write ...`, `gcloud secrets add-iam-policy-binding ...`, `az role assignment create ...`, etc.); and two universal verify steps the invitee runs (`secretenv doctor`, `secretenv registry list`). Local backend renders filesystem/git access guidance with no CLI grant. Unknown backend types render a generic "no canonical template" pointer.
- **`secretenv doctor --fix`** — when any backend reports `NotAuthenticated`, `--fix` shells out to the canonical remediation CLI for that backend type (`aws sso login`, `op signin`, `gcloud auth login`, `az login`, `vault login`) and inherits stdio so the user can complete the interactive flow. Re-runs `check()` once afterward and renders the post-remediation report. Audit trail (which command, exit success, any spawn-error) recorded as a `Remediation actions` section in human output and a `fix_actions` array in `--json` output. Local backend + unrecognized types are skipped without panicking.
- **`secretenv doctor --extensive`** — Level 3 depth probe. For each `Ok` backend, doctor reads every `[registries.*]` source whose scheme matches and runs `Backend::check_extensive(uri)`. Result (alias count or read-failure error) renders as an indented `depth probe` block under the backend's tree node and serializes into a `backends[*].depth` array. Source URIs are deduped across registries. Surfaces permission scope (`12 aliases readable` vs `read failed: permission denied`) so operators can verify IAM/RBAC scope without leaving doctor.
- **`--fix` and `--extensive` compose** — `secretenv doctor --fix --extensive` first remediates any auth gaps and then probes depth against the post-remediation backend set in a single invocation.
- **`DoctorOpts` struct** — flags pass to `run_doctor` via a struct rather than positional booleans so future knobs (e.g. `--quiet`, `--strict`) can be added without churning internal call sites. Implements `Default` so `setup`'s embedded post-write doctor run keeps the existing behavior unchanged.
- **Per-instance `timeout_secs` config override** (`[backends.<name>]`) — applies to every fetch-class operation (`get`, `set`, `delete`, `list`, `history`) on that backend instance. Optional integer, must be positive seconds; default stays at `DEFAULT_GET_TIMEOUT` (30 s). The `check` (doctor) timeout deliberately does NOT consult this — `DEFAULT_CHECK_TIMEOUT` (10 s) keeps doctor parallelism predictable across instances. New `Backend::timeout()` trait method (default returns `DEFAULT_GET_TIMEOUT`); call sites in `runner::fetch_one` and `resolver::fetch_layer` wrap their backend-op futures with `with_timeout(backend.timeout(), ...)`. All 7 backends read the field at factory time. New `optional_duration_secs` and `optional_bool` helpers exported from `secretenv_core::factory_helpers` for plugin authors.
- **`scripts/smoke-test/`** — promoted live-backend integration smoke into the repo (was `/tmp/secretenv-test/` since v0.2.0). Three scripts (`provision.sh`, `run-tests.sh`, `teardown.sh`) plus `lib/common.sh` (shared bootstrap, env-driven cloud IDs, fixture seeding), `fixtures/` (templated config + local secrets), and `README.md`. `run-tests.sh` gains three filter flags: `--sections N,M,P-Q` (range syntax supported), `--local-only` (subset that needs no cloud CLI — sections 1, 12, 18 — runs in <30s without auth), `--list-sections` (inventory). Selective gating via a `SECTION_ACTIVE` short-circuit on `run_test`/`assert_contains`/`record`. Full matrix remains the maintainer-run pre-tag gate.
- **`smoke-local` CI gate** in `.github/workflows/ci.yml` — runs `bash scripts/smoke-test/run-tests.sh --local-only` on every push and PR. ~30s, no cloud auth needed. Catches CLI / completions / registry-invite / config-knobs regressions cheaply.
- **SPDX + copyright headers** on every `crates/**/*.rs` (29 files): `// Copyright (C) 2026 Mandeep Patel` + `// SPDX-License-Identifier: AGPL-3.0-only` at the top of each file. SBOM-tooling clarity + per-file provenance for fork / vendored-subtree consumers.

### Changed

- **1Password `set` is now safe-by-default.** Previously the `set` path silently passed the secret value through `op item edit`'s `field=value` argv tokens (CV-1: visible via `/proc/<pid>/cmdline` on multi-user Linux hosts) — a known limitation deferred from v0.2.4 because the `op` CLI still has no portable stdin-fed value form across the 1.x and 2.x generations. v0.4 closes the TODO by flipping the safe default: `set` now refuses with a clear error explaining the exposure, instructing the operator to either edit the field manually or opt in by adding `op_unsafe_set = true` to `[backends.<name>]`. The opt-in retains the previous argv-based behavior (with the existing tracing warning). **This is a behavior change for anyone who was running `secretenv registry set` against 1Password backends**; the new error surfaces immediately on upgrade and the remediation is one config line. Documented as a pre-launch breaking change.
- **Canonical project domain renamed `secretenv.dev` → `secretenv.io`.** All `install.sh`, README, CHANGELOG, SECURITY, docs, and Cargo metadata updated. The shell-level `install.sh --profile <name>` flag is **removed** — it wrote fetched TOML directly into `config.toml` with zero validation, a regression vs the threat model documented in `docs/profiles.md`. Use the in-binary `secretenv profile install <name>` subcommand instead, which parses + validates as `Config` before writing. The shell flag now errors with a pointer to the new path.
- **`UpdateOutcome` and `UpdateReport` marked `#[non_exhaustive]`** to keep v0.5+ variant/field additions (signature verification, retry metadata) non-breaking.
- **`profile install` / `update` / `uninstall` status messages** flipped from `println!` → `eprintln!`. Stdout reserved for data-shaped output; symmetric with `registry set/unset`.
- **`deny.toml` AGPL allowance tightened.** Removed `AGPL-3.0-only` from the global `licenses.allow` list; first-party crates admitted via per-crate `[[licenses.exceptions]]`. A future transitive AGPL dep now surfaces as a `cargo deny check` failure → forced explicit review.
- **Profiles posture (v0.4):** unsigned + HTTPS only. Signing (minisign / sigstore / SHA256 manifests) + central index file are deliberate v0.5+ work — threat model + mitigations in [`docs/profiles.md`](docs/profiles.md) §"Security considerations".

### Tests

- Workspace unit tests **442 → 536** (+94): doctor (+11 for `--fix`/`--extensive`), registry history (+10 across core trait + 3 backend overrides), registry invite (+16 in new `crates/secretenv-cli/src/invite.rs`), profile (+19 across name-validation, body-validation, install/list/update/uninstall, ETag parser, RFC 3339 formatter), config merge (+5 for profile gap-fill, user-wins, alphabetical order, malformed-profile error, missing-dir noop), CLI integration (+6 for profile + doctor + registry-invite help-locks).
- Live smoke matrix **250 → 336** (+86): registry history (24), registry invite (35), doctor `--fix` + `--extensive` (15), `timeout_secs` + `op_unsafe_set` (12).

### Internal

- Workspace version `0.3.0` → `0.4.0`.
- GitHub Actions bumped for Node 24 readiness: `actions/checkout` v4 → v6, `actions/upload-artifact` v4 → v7, `actions/download-artifact` v4 → v8, `softprops/action-gh-release` v2 → v3.
- Phase 6 decision: `secretenv-testing` stays `publish = false` (zero external consumers; reversible any time via single-line Cargo.toml flip + `cargo publish`). The strict-mock harness is still consumed internally as a path-dependency.
- Closing reviewer-trio audit (security-engineer + code-reviewer + rust-engineer in parallel) on 2026-04-21 surfaced 6 blocking findings; all closed before tag. Non-blocking items captured in `kb/wiki/build-log.md`.

## [0.3.0] - 2026-04-19

**Headline:** two new cloud backends (GCP Secret Manager + Azure Key Vault), the canonical `#key=value` fragment grammar locked in (v0.2.1 work), strict-mode mock test harness retrofitted across every backend (v0.2.2 → v0.2.7 + Phase 0), shared factory helpers, parallel `check()` probes via `tokio::join!`, and a **relicensing from MIT → AGPL-3.0-only + Contributor License Agreement**. The entire v0.2.1 → v0.2.7 internal-dev arc ships as one cohesive `v0.3.0` release (the last public version was v0.2.0 on 2026-04-18; v0.2.x patches were dev-merged without separate publishes per the aggregate-release posture locked during the cycle). 7 backends live: local, aws-ssm, aws-secrets, 1password, vault, **gcp**, **azure**.

### Fixed

- **Azure vault URL regex accepted 1-char names but rejected 2-char names.** The original pattern `^https://[a-zA-Z0-9]([a-zA-Z0-9-]{1,22}[a-zA-Z0-9])?\.vault\...` made the middle+last group optional, allowing a 1-char vault name while disallowing 2-char. Azure's own rule is 3-24. Flipped to `^https://[a-zA-Z0-9][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]\.vault\...` (required middle+last, min 3 chars, max 24). Three new factory tests lock the boundary: `factory_rejects_one_char_vault_name`, `factory_rejects_two_char_vault_name`, `factory_accepts_three_char_vault_name`. Caught by the v0.3 closing code-review audit.

### Added (closing-audit fixes, same unreleased window)

- **`Response::with_stdin_fragment(impl Into<String>)`** chainable method on `secretenv-testing::Response`. Appends to `stdin_must_contain`, allowing fluent composition: `Response::success("ok\n").with_stdin_fragment("secret")`. The existing `success_with_stdin(stdout, Vec<String>)` constructor remains for back-compat.
- **`check_extensive_counts_registry_entries`** unit test added to both `secretenv-backend-gcp` and `secretenv-backend-azure`. Locks the trait-default `Ok(self.list(test_uri).await?.len())` behavior for both v0.3 backends.
- **`set_drift_catch_rejects_data_flag_on_argv`** unit test added to `secretenv-backend-gcp`. Positive CV-1 lock mirroring azure's `--value`-leak + `--encoding-utf-8` locks — declares the buggy argv form (`--data=<secret>`) so a regression emitting the secret on argv instead of via `--data-file=/dev/stdin` fails.
- **Fragment-error messages now link to `docs/fragment-vocabulary.md`** in both gcp and azure's `resolve_version` (matches the aws-secrets shorthand error). Tests extended with `msg.contains("fragment-vocabulary")` assertions.

### Changed (v0.3 closing audit polish)

- **`BackendUri::fragment_directives` return type: `HashMap<String, String>` → `IndexMap<String, String>`.** Insertion order now deterministic = URI-written order, removes the need for `sort_unstable` in backend error-message construction. Backend code calls `.shift_remove("<key>")` instead of `.remove(...)` per `IndexMap`'s deprecation guidance. Pre-launch breaking change per the [[feedback_prelaunch_breaking_changes]] policy. Touched: `secretenv-core/src/uri.rs`, `secretenv-backend-{aws-secrets,gcp,azure}/src/lib.rs`.
- **`strict::Rule` refactor:** `Rule` in `secretenv-testing::strict` used to flatten every `Response` field (`argv, stdin_must_contain, env_must_contain, env_must_not_contain, stdout, stderr, exit_code`). Now `Rule { argv, response: Response }` — thin `(argv, response)` pair. `StrictMock::on` copies one struct move instead of seven field moves. Internal refactor; `Rule` is private so no API break.
- **Drift-catch assertion bodies tightened** from `msg.contains("strict-mock-no-match") || msg.contains("azure")` (always-true tautology — every azure error begins with `azure backend '…'`) to `msg.contains("strict-mock-no-match")` only. The `.unwrap_err()` at the outer layer remains the load-bearing lock; the content check now specifically confirms mock-level divergence rather than any azure-named error. Applied to gcp + azure drift-catch tests. Caught by the v0.3 closing security review.

### Changed

- **LICENSE: MIT → AGPL-3.0-only** (pre-launch breaking change per the policy documented in the memory system). MIT was the license of v0.1 and v0.2.0 — the latter is the only version currently published to crates.io / Homebrew / GitHub Releases. v0.3.0 and all subsequent releases ship under GNU Affero General Public License v3.0 (AGPL-3.0-only). The published MIT releases (v0.1.x, v0.2.0) remain available under their original terms; AGPLv3 applies going forward. Rationale: v0.3.0 finalizes the big-3-cloud-providers story (AWS, GCP, Azure) and the install base at the time of this change is effectively zero. AGPLv3 closes the SaaS-wrapping loophole (§13 requires source availability to network users of modified versions) while preserving user freedom for direct installs.
- **Workspace `Cargo.toml` `license`** field flipped `"MIT"` → `"AGPL-3.0-only"`. Every crate that inherits via `license.workspace = true` picks this up automatically; no per-crate change needed.
- **README** badge + License section updated to reflect AGPLv3 + the MIT-era disclosure.

### Added

- **Contributor License Agreement (CLA).** New [`CLA.md`](CLA.md) (license grant — NOT copyright assignment), [`AUTHORS.md`](AUTHORS.md) (signed-contributor ledger), and expanded [`CONTRIBUTING.md`](CONTRIBUTING.md) §License-and-CLA. The CLA lets the project relicense contributions (e.g., offer commercial licenses alongside AGPL) while contributors retain ownership of their own work. Signing is via `git commit --signoff` on every commit plus adding your name to `AUTHORS.md` on first contribution. "No CLA = no merge" is enforced at review.

### Added

- **`secretenv-backend-azure` (new crate):** second v0.3 backend — Azure Key Vault via the `az` CLI. URI shape `azure-<instance>:///<secret-name>[#version=<32-char-hex>]`. Canonical `#version=<id>` directive accepts a 32-character lowercase-hex Azure version ID OR the literal `latest`; `latest` (and the absent-fragment default) normalizes to omitting the `--version` flag entirely. Required config: `azure_vault_url` — fully-qualified HTTPS URL, regex-validated at factory time across all four sovereign-cloud domains (`.vault.azure.net`, `.vault.azure.cn`, `.vault.usgovcloudapi.net`, `.vault.microsoftazure.de`) with explicit rejection of path traversal (anchored trailing `/?$`) and hyphen-edge vault names. Optional: `azure_tenant`, `azure_subscription` (each passed as `--tenant` / `--subscription` when set), `az_bin` (test hook). `set` pipes secret values via `--file /dev/stdin --encoding utf-8` — the `--encoding utf-8` flag is load-bearing: the default `base64` would corrupt stored text secrets. Fragment on `set` URI explicitly rejected before any network call. `check()` runs Level 1 (`az --version` — multi-line output, regex-extracted) + Level 2 (`az account show`) concurrently via `tokio::join!`. Identity format: `user=<name> tenant=<id> subscription=<name> vault=<short-name>`. Soft-delete semantics documented — `delete` soft-deletes (Azure default); operators wanting full purge must run `az keyvault secret purge` manually. Cert-bound secrets (`kid != null` in response) surface a distinct error. Strict-mode mocks from day one — 36 tests across factory URL regex (5 tests incl. sovereign-cloud accepts + hyphen-edge + path-traversal rejects), `check` probe pair (4), `get` (10 incl. cert-bound + `#version=latest` flag-omission), `set` (3), `delete` (2), `list` (2), tenant/subscription argv variants (3), drift-catch locks (4: missing `--vault-name`, CV-1 stdin, `--value`-leak lock, missing-`--encoding-utf-8` lock).
- **`secretenv setup` gains `--azure-vault-url` + `--azure-tenant` + `--azure-subscription` flags** for azure-scheme registry URIs. Scheme router accepts `azure` + `azure-*` suffix forms; registry serializer adds `azure` to the JSON arm.

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
  support (downloads config from `https://secretenv.io/profiles/<name>.toml`
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

[Unreleased]: https://github.com/TechAlchemistX/secretenv/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.12.0
[0.2.3]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.3
[0.2.2]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.2
[0.2.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.1
[0.2.0]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.2.0
[0.1.1]: https://github.com/TechAlchemistX/secretenv/releases/tag/v0.1.1
