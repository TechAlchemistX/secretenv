// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`SecretEnvSpan`] typed attribute builder — the structural
//! enforcement point for the ALLOW/DENY matrix.
//!
//! Adding a new attribute requires adding a method on this struct.
//! There is no `set_attribute(&str, &str)` public method — call
//! sites cannot smuggle a new key past code review by typing a
//! string. v0.17 wires these methods to real OTel span attributes
//! 1:1.

use crate::{RedactionSource, RedactionStream, SecretEnvErrorKind};

/// RAII guard returned by [`SecretEnvSpan::start`]. Dropping it
/// closes the span and (in v0.17) emits the trace.
///
/// The `_private` field is the **sealed-construction marker** — it
/// keeps `SpanGuard` un-constructible from outside this crate so the
/// only path to obtain one is through [`SecretEnvSpan::start`]. The
/// field stays even after v0.17 wires real state because removing it
/// would silently re-open `SpanGuard {}` literals at downstream call
/// sites, bypassing the `start()` entry point that initialises OTel
/// span tracking. v0.14.x code-hygiene chip: documented, not removed.
#[derive(Debug)]
#[must_use = "dropping the SpanGuard immediately ends the span"]
pub struct SpanGuard {
    // Sealed-construction marker — see struct docs above.
    _private: (),
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        // v0.14: no-op. v0.17 ends the OTel span here and emits.
    }
}

/// Builder for a SecretEnv span. Each method corresponds 1:1 with
/// an ALLOW attribute in the v0.14+ synthesis §6 matrix.
///
/// In v0.14 the builder is a structural fixture — methods record
/// nothing. The set-site discipline they impose is the v0.14
/// deliverable; v0.17 wires every method to an OTel span attribute.
#[derive(Debug)]
pub struct SecretEnvSpan {
    name: &'static str,
}

// `missing_const_for_fn` would mark every recorder `const fn`; v0.17
// will replace these stubs with attribute-emission bodies that mutate
// shared state (cannot be `const`). Promoting them now and then
// un-promoting in v0.17 churns the public API for no v0.14 benefit.
#[allow(clippy::missing_const_for_fn, clippy::must_use_candidate, clippy::unused_self)]
impl SecretEnvSpan {
    /// Start a new span with a static-str name (e.g. `"redact.match"`,
    /// `"resolve.alias"`, `"backend.get"`).
    pub fn start(name: &'static str) -> (Self, SpanGuard) {
        (Self { name }, SpanGuard { _private: () })
    }

    /// `secretenv.version` — the SecretEnv release that produced
    /// the span. ALLOW.
    pub fn record_version(&mut self, _v: &str) -> &mut Self {
        self
    }

    /// `secretenv.run_id` — UUIDv4 per invocation. ALLOW.
    pub fn record_run_id(&mut self, _id: &str) -> &mut Self {
        self
    }

    /// `secretenv.command` — `run` / `get` / `migrate` / `doctor` /
    /// `mcp` / `redact`. ALLOW.
    pub fn record_command(&mut self, _cmd: &str) -> &mut Self {
        self
    }

    /// `secretenv.exit_code`. ALLOW.
    pub fn record_exit_code(&mut self, _code: i32) -> &mut Self {
        self
    }

    /// `secretenv.duration_ms`. ALLOW.
    pub fn record_duration_ms(&mut self, _ms: u64) -> &mut Self {
        self
    }

    /// `secretenv.alias.name`. ALLOW (operator's explicit rule —
    /// alias names are operator-chosen and treated as
    /// non-sensitive).
    pub fn record_alias_name(&mut self, _name: &str) -> &mut Self {
        self
    }

    /// `secretenv.alias.env_var`. ALLOW.
    pub fn record_alias_env_var(&mut self, _env: &str) -> &mut Self {
        self
    }

    /// `secretenv.alias.count`. ALLOW.
    pub fn record_alias_count(&mut self, _n: u64) -> &mut Self {
        self
    }

    /// `secretenv.alias.cascade_layer_index`. ALLOW.
    pub fn record_cascade_layer_index(&mut self, _idx: u32) -> &mut Self {
        self
    }

    /// `secretenv.alias.outcome` — closed enum. ALLOW.
    pub fn record_alias_outcome(&mut self, _outcome: AliasOutcome) -> &mut Self {
        self
    }

    /// `secretenv.backend.type`. ALLOW.
    pub fn record_backend_type(&mut self, _ty: &str) -> &mut Self {
        self
    }

    /// `secretenv.backend.instance_name`. ALLOW.
    pub fn record_backend_instance(&mut self, _name: &str) -> &mut Self {
        self
    }

    /// `secretenv.backend.region`. ALLOW.
    pub fn record_backend_region(&mut self, _region: &str) -> &mut Self {
        self
    }

    /// `secretenv.backend.cli.name`. ALLOW.
    pub fn record_backend_cli_name(&mut self, _cli: &str) -> &mut Self {
        self
    }

    /// `secretenv.backend.cli.version`. ALLOW.
    pub fn record_backend_cli_version(&mut self, _version: &str) -> &mut Self {
        self
    }

    /// `secretenv.backend.auth_method` — closed enum. ALLOW.
    pub fn record_backend_auth_method(&mut self, _m: AuthMethod) -> &mut Self {
        self
    }

    /// `secretenv.error.kind`. ALLOW.
    pub fn record_error_kind(&mut self, _kind: SecretEnvErrorKind) -> &mut Self {
        self
    }

    /// `secretenv.process.command_name` — argv[0] only. ALLOW.
    pub fn record_process_command_name(&mut self, _name: &str) -> &mut Self {
        self
    }

    /// `secretenv.process.env_var_count`. ALLOW.
    pub fn record_process_env_var_count(&mut self, _n: u64) -> &mut Self {
        self
    }

    /// `secretenv.redact.match_count`. ALLOW.
    pub fn record_redact_match_count(&mut self, _n: u64) -> &mut Self {
        self
    }

    /// `secretenv.redact.byte_count`. ALLOW.
    pub fn record_redact_byte_count(&mut self, _bytes: u64) -> &mut Self {
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

    /// `secretenv.redact.stream`. ALLOW.
    pub fn record_redact_stream(&mut self, _s: RedactionStream) -> &mut Self {
        self
    }

    /// `secretenv.redact.source`. ALLOW.
    pub fn record_redact_source(&mut self, _src: RedactionSource) -> &mut Self {
        self
    }

    // ---- migrate surface (v0.15 — `secretenv registry migrate`) ----
    //
    // The migrate command's typed-attribute methods. Each maps 1:1 to
    // an ALLOW row in the v0.14+ synthesis §6 attribute matrix
    // (migrate subset). Resolved alias names, destination URIs, and
    // in-flight values are NEVER routed through this surface — those
    // attribute names do not exist as methods, so no DENY-row escape
    // hatch is reachable from a call site. v0.17 fills in the no-op
    // bodies with OTLP emission without touching call sites.

    /// `secretenv.migrate.phase`. ALLOW. Closed enum
    /// [`MigratePhase`] — emits the kebab-case attribute value.
    pub fn record_migrate_phase(&mut self, _phase: MigratePhase) -> &mut Self {
        self
    }

    /// `secretenv.migrate.outcome`. ALLOW. Closed enum
    /// [`MigrateOutcome`] — emits the kebab-case attribute value.
    pub fn record_migrate_outcome(&mut self, _outcome: MigrateOutcome) -> &mut Self {
        self
    }

    /// `secretenv.migrate.source_backend_type`. ALLOW. Backend type
    /// strings like `"aws-ssm"`, `"vault"` — backend TYPE only, never
    /// the backend INSTANCE name (instance names can carry
    /// environment hints like `prod` that fingerprint the operator's
    /// infra topology and stay DENY).
    pub fn record_migrate_source_backend_type(&mut self, _ty: &str) -> &mut Self {
        self
    }

    /// `secretenv.migrate.dest_backend_type`. ALLOW. Same shape as
    /// source — TYPE only, not instance name.
    pub fn record_migrate_dest_backend_type(&mut self, _ty: &str) -> &mut Self {
        self
    }

    /// `secretenv.migrate.delete_source`. ALLOW. Whether
    /// `--delete-source` was specified for this migration. The
    /// attribute is the flag's value, NOT the actual deletion
    /// outcome (success/failure surfaces via
    /// [`record_migrate_outcome`]).
    pub fn record_migrate_delete_source(&mut self, _delete: bool) -> &mut Self {
        self
    }

    /// `secretenv.migrate.transaction_id`. ALLOW. Per-invocation
    /// UUIDv4-shaped id correlating the three-step transaction
    /// (read → write → pointer-flip) across spans. Operators use
    /// this to grep recovery logs after a partial-failure exit.
    pub fn record_migrate_transaction_id(&mut self, _id: &str) -> &mut Self {
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
    fn span_records_silently_at_v0_14() {
        let (mut span, _guard) = SecretEnvSpan::start("redact.match");
        span.record_version("0.14.0")
            .record_run_id("11111111-1111-1111-1111-111111111111")
            .record_command("run")
            .record_redact_match_count(3)
            .record_alias_outcome(AliasOutcome::Ok);
        assert_eq!(span.name(), "redact.match");
        // No assertions on emission — the v0.14 contract is "method
        // exists, accepts the typed argument, returns &Self for
        // chaining"; v0.17 will wire actual span attributes.
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
