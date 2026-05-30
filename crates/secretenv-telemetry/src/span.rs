// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`SecretEnvSpan`] typed attribute builder — the structural
//! enforcement point for the ALLOW/DENY matrix.
//!
//! Adding a new attribute requires adding a method on this struct.
//! There is no `set_attribute(&str, &str)` public method — call
//! sites cannot smuggle a new key past code review by typing a
//! string. v0.17 wires the methods to real OTel span attributes
//! 1:1 via the typed setters below.
//!
//! # Coverage today
//!
//! v0.17 ships real emission for the 26 setters that callers in
//! `secretenv-core` / `secretenv-migrate` / `secretenv-mcp` /
//! `secretenv-cli` actively need. The remaining attributes in
//! `docs/reference/opentelemetry.md` §2 (matrix entries with no
//! current setter) are reserved by the schema; the matching setters
//! are added as callers materialise — adding a new setter is a
//! PR-reviewed code change, which is the structural enforcement
//! point. There is never a generic `set_attribute(&str, &str)`
//! escape hatch on `SecretEnvSpan`.

use opentelemetry::global::{self, BoxedSpan};
use opentelemetry::trace::{Span as _, Tracer as _};
use opentelemetry::KeyValue;

use crate::metrics::{FetchOutcome, RedactMode, ResolutionOutcome};
use crate::{BackendErrorStderr, RedactionSource, RedactionStream, SecretEnvErrorKind};

/// OTel `Tracer` name. Single instance per process; the global
/// `TracerProvider` (installed by [`crate::init`]) hands back a
/// no-op `BoxedTracer` when telemetry is unconfigured, so calls
/// remain safe and cheap in the no-collector default.
const TRACER_NAME: &str = "secretenv";

/// RAII guard returned by [`SecretEnvSpan::start`]. Held by callers
/// alongside [`SecretEnvSpan`]; both drop at end of scope.
///
/// In v0.17 the OTel span lives inside [`SecretEnvSpan`] (its `Drop`
/// calls `span.end()`), so `SpanGuard` is structurally vestigial.
/// It is retained as a sealed marker type to keep the v0.14+ call
/// shape (`let (mut span, _guard) = SecretEnvSpan::start(...)`)
/// working without an API churn that would touch every call site.
///
/// The `_private` field is the sealed-construction marker — it
/// keeps `SpanGuard` un-constructible from outside this crate so
/// the only path to obtain one is through [`SecretEnvSpan::start`].
#[derive(Debug)]
#[must_use = "dropping the SpanGuard ends the surrounding span's scope"]
pub struct SpanGuard {
    _private: (),
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        // No-op. The OTel span ends via SecretEnvSpan's Drop; this
        // type exists to preserve the v0.14+ call-site shape.
    }
}

/// Builder for a SecretEnv span. Each `record_*` method corresponds
/// 1:1 with an ALLOW attribute in `docs/reference/opentelemetry.md`
/// §2.
///
/// When telemetry is unconfigured, the underlying `BoxedSpan` is the
/// SDK's no-op span and every `record_*` call is a cheap vtable
/// dispatch that does nothing.
#[derive(Debug)]
pub struct SecretEnvSpan {
    name: &'static str,
    span: BoxedSpan,
}

impl SecretEnvSpan {
    /// Start a new span with a static-str name (e.g. `"redact.match"`,
    /// `"resolve.alias"`, `"backend.get"`). Returns the typed builder
    /// alongside a [`SpanGuard`] kept by the caller for scope.
    #[must_use = "the span must be held for its scope; \
                  dropping it immediately ends the span"]
    pub fn start(name: &'static str) -> (Self, SpanGuard) {
        let tracer = global::tracer(TRACER_NAME);
        let span = tracer.start(name);
        (Self { name, span }, SpanGuard { _private: () })
    }

    /// `secretenv.version` — the SecretEnv release that produced
    /// the span. ALLOW.
    pub fn record_version(&mut self, v: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.version", v.to_owned()));
        self
    }

    /// `secretenv.run_id` — UUIDv4 per invocation. ALLOW.
    pub fn record_run_id(&mut self, id: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run_id", id.to_owned()));
        self
    }

    /// `secretenv.command` — `run` / `get` / `migrate` / `doctor` /
    /// `mcp` / `redact`. ALLOW.
    pub fn record_command(&mut self, cmd: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.command", cmd.to_owned()));
        self
    }

    /// `secretenv.exit_code`. ALLOW.
    pub fn record_exit_code(&mut self, code: i32) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.exit_code", i64::from(code)));
        self
    }

    /// `secretenv.duration_ms`. ALLOW.
    pub fn record_duration_ms(&mut self, ms: u64) -> &mut Self {
        // OTel attribute values use i64; ms beyond i64::MAX would mean
        // a span lasted ~292 million years, which is not a real case.
        self.span.set_attribute(KeyValue::new(
            "secretenv.duration_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.alias.name`. ALLOW.
    pub fn record_alias_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.alias.name", name.to_owned()));
        self
    }

    /// `secretenv.alias.env_var`. ALLOW.
    pub fn record_alias_env_var(&mut self, env: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.alias.env_var", env.to_owned()));
        self
    }

    /// `secretenv.alias.count`. ALLOW.
    pub fn record_alias_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.alias.count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.alias.cascade_layer_index`. ALLOW.
    pub fn record_cascade_layer_index(&mut self, idx: u32) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.alias.cascade_layer_index", i64::from(idx)));
        self
    }

    /// `secretenv.alias.outcome` — closed enum. ALLOW.
    pub fn record_alias_outcome(&mut self, outcome: AliasOutcome) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.alias.outcome", outcome.as_attribute_value()));
        self
    }

    /// `secretenv.backend.type`. ALLOW.
    pub fn record_backend_type(&mut self, ty: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.type", ty.to_owned()));
        self
    }

    /// `secretenv.backend.instance_name`. ALLOW.
    pub fn record_backend_instance(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.instance_name", name.to_owned()));
        self
    }

    /// `secretenv.backend.region`. ALLOW.
    pub fn record_backend_region(&mut self, region: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.region", region.to_owned()));
        self
    }

    /// `secretenv.backend.cli.name`. ALLOW.
    pub fn record_backend_cli_name(&mut self, cli: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.cli.name", cli.to_owned()));
        self
    }

    /// `secretenv.backend.cli.version`. ALLOW.
    pub fn record_backend_cli_version(&mut self, version: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.backend.cli.version", version.to_owned()));
        self
    }

    /// `secretenv.backend.auth_method` — closed enum. ALLOW.
    pub fn record_backend_auth_method(&mut self, m: AuthMethod) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.backend.auth_method", m.as_attribute_value()));
        self
    }

    /// `secretenv.backend.error.kind`. ALLOW. Closed enum
    /// [`SecretEnvErrorKind`] — emits the kebab-case attribute value.
    /// Method name kept as `record_error_kind` (no callers to break);
    /// emitted key matches `docs/reference/opentelemetry.md` §2.3.
    pub fn record_error_kind(&mut self, kind: SecretEnvErrorKind) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.error.kind",
            kind.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.backend.error.message` — opt-in scrubbed backend
    /// stderr text. Dual-state ALLOW per `docs/reference/opentelemetry.md`
    /// §2: default DENY (`opt_in = false` → attribute structurally
    /// absent); opt-in scrubbed-ALLOW (`opt_in = true` → emit the
    /// scrubbed payload). The opt-in is driven by the CLI flag
    /// `--otel-include-error-detail` on `secretenv run` (and the
    /// corresponding [`crate::init::RunOptions`] field). v0.18 D-5.1.
    ///
    /// SEC-INV-20 enforcement is structural: the `msg` parameter is
    /// `&BackendErrorStderr`, and that type's only constructor runs
    /// the shape-based scrubber (URI shapes / AWS 12-digit account
    /// IDs / high-entropy tokens). A caller that holds a
    /// `BackendErrorStderr` has, by construction, scrubbed the input.
    pub fn record_backend_error_message_scrubbed(
        &mut self,
        msg: &BackendErrorStderr,
        opt_in: bool,
    ) -> &mut Self {
        if opt_in {
            self.span.set_attribute(KeyValue::new(
                "secretenv.backend.error.message",
                msg.as_str().to_owned(),
            ));
        }
        self
    }

    /// `secretenv.run.command_name` — argv[0] only. ALLOW.
    pub fn record_process_command_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.command_name", name.to_owned()));
        self
    }

    /// `secretenv.run.env_var_count`. ALLOW.
    pub fn record_process_env_var_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.run.env_var_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.run.dry_run`. ALLOW.
    pub fn record_run_dry_run(&mut self, v: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.dry_run", v));
        self
    }

    /// `secretenv.run.verbose`. ALLOW.
    pub fn record_run_verbose(&mut self, v: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.run.verbose", v));
        self
    }

    /// `secretenv.run.outcome` — closed enum. ALLOW.
    pub fn record_run_outcome(&mut self, outcome: ResolutionOutcome) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.run.outcome", outcome.as_attribute_value()));
        self
    }

    /// `secretenv.run.failed_alias_count`. ALLOW. Aggregate, never per-alias.
    pub fn record_run_failed_alias_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.run.failed_alias_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.resolution.outcome` — closed enum. ALLOW.
    pub fn record_resolution_outcome(&mut self, outcome: ResolutionOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.resolution.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.resolution.latency_ms`. ALLOW.
    pub fn record_resolution_latency_ms(&mut self, ms: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.resolution.latency_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.backend.fetch.outcome` — closed enum. ALLOW.
    pub fn record_backend_fetch_outcome(&mut self, outcome: FetchOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.fetch.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.backend.fetch.duration_ms`. ALLOW.
    pub fn record_backend_fetch_duration_ms(&mut self, ms: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.backend.fetch.duration_ms",
            i64::try_from(ms).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.registry.name`. ALLOW.
    pub fn record_registry_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.registry.name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.tool_name`. ALLOW. Closed enum at the contract
    /// level (the 14 v0.16 tool names); call sites pass the tool's
    /// `&'static str` name from the tool registry.
    pub fn record_mcp_tool_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.mcp.tool_name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.client_name`. ALLOW. Closed enum of known IDE
    /// + agent clients (`claude-code`, `cursor`, ...) plus `unknown`.
    pub fn record_mcp_client_name(&mut self, name: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.mcp.client_name", name.to_owned()));
        self
    }

    /// `secretenv.mcp.argument_alias_name`. ALLOW. Mutation tools
    /// (`set_alias` / `delete_alias` / `migrate_alias`) record the
    /// alias-name argument here so the audit span carries WHICH alias
    /// was touched. Topology (`argument_uri`, `argument_reason`)
    /// stays DENY per SEC-INV-12.
    pub fn record_mcp_argument_alias_name(&mut self, name: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.mcp.argument_alias_name", name.to_owned()));
        self
    }

    /// `secretenv.redact.match_count`. ALLOW.
    pub fn record_redact_match_count(&mut self, n: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.redact.match_count",
            i64::try_from(n).unwrap_or(i64::MAX),
        ));
        self
    }

    /// `secretenv.redact.byte_count`. ALLOW.
    pub fn record_redact_byte_count(&mut self, bytes: u64) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.redact.byte_count",
            i64::try_from(bytes).unwrap_or(i64::MAX),
        ));
        self
    }

    // `record_redact_alias_name` was deliberately removed in v0.14
    // Phase 9 per SEC-INV-19. The redact alias name remains in the
    // operator-local terminal substitution token (`[redacted:<alias>]`,
    // rendered by `secretenv_core::redact::SubstitutionToken`) but is
    // DENY for OTel attribute emission. See
    // [[v0.14-plus-security-invariants]] §2.5 and §9 for the council
    // resolution that overruled the alternative ALLOW position.
    //
    // A compile-fail test at `tests/no_redact_alias_in_otel.rs`
    // verifies this method does not exist; adding it back without
    // also amending SEC-INV-19 will fail CI.

    /// `secretenv.redact.mode` — closed enum. ALLOW.
    pub fn record_redact_mode(&mut self, mode: RedactMode) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.mode", mode.as_attribute_value()));
        self
    }

    /// `secretenv.redact.stream`. ALLOW.
    pub fn record_redact_stream(&mut self, s: RedactionStream) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.stream", s.as_attribute_value()));
        self
    }

    /// `secretenv.redact.source`. ALLOW.
    pub fn record_redact_source(&mut self, src: RedactionSource) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.redact.source", src.as_attribute_value()));
        self
    }

    // ---- migrate surface (v0.15 — `secretenv registry migrate`) ----

    /// `secretenv.migrate.phase`. ALLOW. Closed enum
    /// [`MigratePhase`] — emits the kebab-case attribute value.
    pub fn record_migrate_phase(&mut self, phase: MigratePhase) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.phase", phase.as_attribute_value()));
        self
    }

    /// `secretenv.migrate.outcome`. ALLOW. Closed enum
    /// [`MigrateOutcome`] — emits the kebab-case attribute value.
    pub fn record_migrate_outcome(&mut self, outcome: MigrateOutcome) -> &mut Self {
        self.span.set_attribute(KeyValue::new(
            "secretenv.migrate.outcome",
            outcome.as_attribute_value(),
        ));
        self
    }

    /// `secretenv.migrate.source_backend_type`. ALLOW. Backend type
    /// strings like `"aws-ssm"`, `"vault"` — backend TYPE only, never
    /// the backend INSTANCE name (instance names can carry
    /// environment hints like `prod` that fingerprint the operator's
    /// infra topology and stay DENY).
    pub fn record_migrate_source_backend_type(&mut self, ty: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.source_backend_type", ty.to_owned()));
        self
    }

    /// `secretenv.migrate.dest_backend_type`. ALLOW. Same shape as
    /// source — TYPE only, not instance name.
    pub fn record_migrate_dest_backend_type(&mut self, ty: &str) -> &mut Self {
        self.span
            .set_attribute(KeyValue::new("secretenv.migrate.dest_backend_type", ty.to_owned()));
        self
    }

    /// `secretenv.migrate.delete_source`. ALLOW. Whether
    /// `--delete-source` was specified for this migration. The
    /// attribute is the flag's value, NOT the actual deletion
    /// outcome (success/failure surfaces via
    /// [`record_migrate_outcome`]).
    pub fn record_migrate_delete_source(&mut self, delete: bool) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.migrate.delete_source", delete));
        self
    }

    /// `secretenv.migrate.transaction_id`. ALLOW. Per-invocation
    /// UUIDv4-shaped id correlating the three-step transaction
    /// (read → write → pointer-flip) across spans. Operators use
    /// this to grep recovery logs after a partial-failure exit.
    pub fn record_migrate_transaction_id(&mut self, id: &str) -> &mut Self {
        self.span.set_attribute(KeyValue::new("secretenv.migrate.transaction_id", id.to_owned()));
        self
    }

    /// The span name, for tests + diagnostic logging.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    // NOTE: there is deliberately no `set_attribute(k: &str, v: &str)`
    // here. The v0.14+ synthesis §3 decision: set-site enforcement
    // is the only protection that holds under careless contributors
    // — exporter-side filtering is fail-open and trivially
    // bypassed by misnamed keys.
}

impl Drop for SecretEnvSpan {
    fn drop(&mut self) {
        // SEC-INV-22's per-span emission point. End() is the contract
        // the OTel `BatchSpanProcessor` listens on; without it the
        // span never enters the export queue.
        self.span.end();
    }
}

/// Closed enum for `secretenv.alias.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasOutcome {
    /// Resolved + fetched successfully.
    Ok,
    /// Resolved from a manifest default; no backend fetch.
    Default,
    /// Resolved but the backend fetch failed.
    Failed,
    /// Dry-run path; no fetch attempted.
    DryRun,
}

impl AliasOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Default => "default",
            Self::Failed => "failed",
            Self::DryRun => "dry-run",
        }
    }
}

/// Closed enum for `secretenv.backend.auth_method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// Bearer token in env var.
    EnvToken,
    /// CLI-managed session (`op signin`, `aws sso login`, etc.).
    CliSession,
    /// IAM role / metadata-server-discovered identity.
    InstanceRole,
    /// Service-account JSON key file.
    ServiceAccountKey,
    /// OAuth flow with refreshable token (e.g. wrangler).
    OauthRefresh,
    /// Local filesystem — no auth.
    None,
    /// Auth method unknown to the backend's introspection probe.
    Unknown,
}

impl AuthMethod {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::EnvToken => "env-token",
            Self::CliSession => "cli-session",
            Self::InstanceRole => "instance-role",
            Self::ServiceAccountKey => "service-account-key",
            Self::OauthRefresh => "oauth-refresh",
            Self::None => "none",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed enum for `secretenv.migrate.phase`. v0.15 — see
/// [[build-plan-v0.15-migrate]] for the three-step migrate transaction
/// (read → write → pointer-flip) plus the optional fourth cleanup step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MigratePhase {
    /// Step 0 — capability and write-permission probe on the
    /// destination backend.
    Probe,
    /// Step 1 — read the source value.
    Read,
    /// Step 2 — write the value to the destination.
    Write,
    /// Step 3 — atomically flip the registry pointer (commit).
    PointerFlip,
    /// Step 4 (opt-in) — delete the source value after a successful
    /// commit. Only reached when `--delete-source` is set.
    DeleteSource,
}

impl MigratePhase {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Read => "read",
            Self::Write => "write",
            Self::PointerFlip => "pointer-flip",
            Self::DeleteSource => "delete-source",
        }
    }
}

/// Closed enum for `secretenv.migrate.outcome`. v0.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MigrateOutcome {
    /// Three-step (or four-step under `--delete-source`) transaction
    /// committed successfully.
    Ok,
    /// Three-step transaction committed successfully but the opt-in
    /// fourth step (source-delete under `--delete-source`) failed.
    /// Migration itself is complete; cleanup is the operator's call.
    /// Distinct from `Ok` so OTel queries can surface "migrate
    /// succeeded but source cleanup failed" without scraping logs.
    OkWithCleanupFailure,
    /// Write succeeded but pointer-flip failed; operator must run
    /// recovery. NEVER auto-rollback by deletion per SEC-INV-09.
    PartialFailure,
    /// Source read failed; nothing was written; nothing to recover.
    SourceReadFailed,
    /// Destination write failed before commit; nothing to recover.
    DestWriteFailed,
    /// Destination probe failed up front (write capability missing or
    /// `Gated`-without-opt-in); no read or write attempted.
    ProbeFailed,
    /// Operator aborted the confirmation prompt.
    Aborted,
    /// Dry-run path; no read, write, or commit attempted.
    DryRun,
}

impl MigrateOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::OkWithCleanupFailure => "ok-with-cleanup-failure",
            Self::PartialFailure => "partial-failure",
            Self::SourceReadFailed => "source-read-failed",
            Self::DestWriteFailed => "dest-write-failed",
            Self::ProbeFailed => "probe-failed",
            Self::Aborted => "aborted",
            Self::DryRun => "dry-run",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_records_silently_when_no_provider() {
        // With no TracerProvider installed, the NoopTracer's BoxedSpan
        // accepts every record_* call without panic and without
        // allocating a real span.
        let (mut span, _guard) = SecretEnvSpan::start("redact.match");
        span.record_version("0.17.0")
            .record_run_id("11111111-1111-1111-1111-111111111111")
            .record_command("run")
            .record_redact_match_count(3)
            .record_alias_outcome(AliasOutcome::Ok);
        assert_eq!(span.name(), "redact.match");
    }

    #[test]
    fn enum_attribute_values_are_kebab_case() {
        assert_eq!(AliasOutcome::DryRun.as_attribute_value(), "dry-run");
        assert_eq!(AuthMethod::ServiceAccountKey.as_attribute_value(), "service-account-key");
        assert_eq!(MigratePhase::PointerFlip.as_attribute_value(), "pointer-flip");
        assert_eq!(MigratePhase::DeleteSource.as_attribute_value(), "delete-source");
        assert_eq!(MigrateOutcome::PartialFailure.as_attribute_value(), "partial-failure");
        assert_eq!(MigrateOutcome::SourceReadFailed.as_attribute_value(), "source-read-failed");
        assert_eq!(MigrateOutcome::ProbeFailed.as_attribute_value(), "probe-failed");
    }

    #[test]
    fn migrate_recorders_compile_and_chain() {
        let (mut span, _guard) = SecretEnvSpan::start("registry.migrate");
        span.record_migrate_phase(MigratePhase::Probe)
            .record_migrate_outcome(MigrateOutcome::Ok)
            .record_migrate_source_backend_type("aws-ssm")
            .record_migrate_dest_backend_type("vault")
            .record_migrate_delete_source(false)
            .record_migrate_transaction_id("11111111-1111-1111-1111-111111111111");
        assert_eq!(span.name(), "registry.migrate");
    }
}
