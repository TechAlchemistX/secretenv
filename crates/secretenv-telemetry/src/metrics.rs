// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed metric instruments for SecretEnv (v0.17 Phase 4).
//!
//! Mirrors the structural enforcement pattern of [`crate::SecretEnvSpan`]:
//! every emit point goes through a typed function whose signature accepts
//! only closed-enum attribute values or pre-bucketed integers — so the
//! cardinality guardrails documented in `docs/reference/opentelemetry.md`
//! §5 are enforced at compile time, not by post-hoc filtering.
//!
//! # Critical cardinality rule
//!
//! `secretenv.alias.name` MUST NEVER appear as an attribute on any
//! histogram or gauge data point. This module exposes no API that
//! accepts an alias name in those slots; per-alias visibility lives on
//! span attributes only, plus the opt-in counter
//! `secretenv.alias.resolution.count` (gated on
//! `SECRETENV_OTEL_ALIAS_METRICS=1`; not implemented in v0.17).
//!
//! # Singleton behaviour
//!
//! [`init`] is called by [`crate::init`] once per process when a
//! [`opentelemetry_sdk::metrics::SdkMeterProvider`] has been installed
//! globally. When telemetry is unconfigured, [`init`] is not called and
//! every public function in this module is a cheap no-op.

use std::sync::OnceLock;

use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use opentelemetry::KeyValue;

use crate::span::{MigrateOutcome, MigratePhase};

/// All instruments registered against a single SecretEnv `Meter`.
/// Held behind the [`METRICS`] singleton; constructed once at init.
struct Metrics {
    resolution_duration: Histogram<u64>,
    resolution_count: Counter<u64>,
    backend_probe_count: Counter<u64>,
    backend_fetch_duration: Histogram<u64>,
    redact_events: Counter<u64>,
    mcp_tool_calls: Counter<u64>,
    mcp_tool_duration: Histogram<u64>,
    doctor_failure_count: Counter<u64>,
    migrate_operation_count: Counter<u64>,
    registry_alias_count: Gauge<u64>,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Resolution-duration histogram buckets in milliseconds. Tuned for
/// the dev-day mix where most resolutions complete under 500ms and
/// the long tail (>2s) is meaningful enough to deserve its own
/// bucket boundary for percentile work.
const RESOLUTION_BUCKETS_MS: &[f64] =
    &[50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 30000.0];

/// Backend-fetch duration buckets in milliseconds. Same tier table
/// without the 30s end-bucket since a single fetch over 10s already
/// indicates a backend-level problem.
const BACKEND_FETCH_BUCKETS_MS: &[f64] =
    &[50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0];

/// MCP tool-call duration buckets in milliseconds. Tighter low end
/// because the MCP path is local (no network) and any call over 1s
/// is an outlier worth separating from the 5s end-bucket cap.
const MCP_TOOL_BUCKETS_MS: &[f64] = &[10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0];

/// Build the instruments against a freshly-acquired `Meter`.
///
/// Called once by [`crate::init`] after the global `SdkMeterProvider`
/// is installed; subsequent calls (e.g. test re-init) are ignored
/// because [`METRICS`] is a [`OnceLock`].
///
/// Exposed `pub` so integration tests (in `tests/`) can bootstrap
/// against a custom `InMemoryMetricExporter`-backed meter without a
/// running `crate::init`. Production callers should never invoke
/// this directly; the [`OnceLock`] makes accidental double-init safe
/// but the right entry point is [`crate::init`].
pub fn init(meter: &Meter) {
    let metrics = Metrics {
        resolution_duration: meter
            .u64_histogram("secretenv.resolution.duration")
            .with_description("End-to-end alias resolution latency, per registry + outcome")
            .with_unit("ms")
            .with_boundaries(RESOLUTION_BUCKETS_MS.to_vec())
            .build(),
        resolution_count: meter
            .u64_counter("secretenv.resolution.count")
            .with_description("Total alias resolutions, per registry + outcome")
            .with_unit("{resolution}")
            .build(),
        backend_probe_count: meter
            .u64_counter("secretenv.backend.probe.count")
            .with_description("Doctor / pre-resolution probe outcomes per backend instance")
            .with_unit("{probe}")
            .build(),
        backend_fetch_duration: meter
            .u64_histogram("secretenv.backend.fetch.duration")
            .with_description("Per-backend per-fetch latency; alias.name explicitly excluded")
            .with_unit("ms")
            .with_boundaries(BACKEND_FETCH_BUCKETS_MS.to_vec())
            .build(),
        redact_events: meter
            .u64_counter("secretenv.redact.events")
            .with_description("Redaction match events; alias.name excluded per SEC-INV-19")
            .with_unit("{event}")
            .build(),
        mcp_tool_calls: meter
            .u64_counter("secretenv.mcp.tool.calls")
            .with_description("MCP tool-invocation count, per tool name + outcome")
            .with_unit("{call}")
            .build(),
        mcp_tool_duration: meter
            .u64_histogram("secretenv.mcp.tool.duration")
            .with_description("MCP tool-invocation duration, per tool name + outcome")
            .with_unit("ms")
            .with_boundaries(MCP_TOOL_BUCKETS_MS.to_vec())
            .build(),
        doctor_failure_count: meter
            .u64_counter("secretenv.doctor.failure.count")
            .with_description("Doctor backend-failure count; success is silent")
            .with_unit("{failure}")
            .build(),
        migrate_operation_count: meter
            .u64_counter("secretenv.migrate.operation.count")
            .with_description("Registry-migrate phase transitions, per phase + outcome")
            .with_unit("{operation}")
            .build(),
        registry_alias_count: meter
            .u64_gauge("secretenv.registry.alias_count")
            .with_description("Number of aliases visible in a registry source at observation time")
            .with_unit("{alias}")
            .build(),
    };
    // OnceLock::set returns Err if METRICS was already populated. We
    // tolerate that silently because tests may re-init across binaries.
    let _ = METRICS.set(metrics);
}

/// Internal accessor; returns `None` when telemetry is unconfigured.
fn metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

// ────────────────────────────────────────────────────────────────
// Public typed emission API
// ────────────────────────────────────────────────────────────────

/// `secretenv.resolution.duration` histogram point.
pub fn record_resolution_duration(
    ms: u64,
    registry_name: &str,
    outcome: ResolutionOutcome,
    alias_count_bucket: AliasCountBucket,
) {
    let Some(m) = metrics() else { return };
    m.resolution_duration.record(
        ms,
        &[
            KeyValue::new("secretenv.registry.name", registry_name.to_owned()),
            KeyValue::new("secretenv.run.outcome", outcome.as_attribute_value()),
            KeyValue::new("secretenv.alias.count_bucket", alias_count_bucket.as_attribute_value()),
        ],
    );
}

/// `secretenv.resolution.count` counter increment.
pub fn increment_resolution_count(registry_name: &str, outcome: ResolutionOutcome) {
    let Some(m) = metrics() else { return };
    m.resolution_count.add(
        1,
        &[
            KeyValue::new("secretenv.registry.name", registry_name.to_owned()),
            KeyValue::new("secretenv.run.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.backend.probe.count` counter increment.
pub fn increment_backend_probe(
    backend_type: &str,
    instance_name: &str,
    level: ProbeLevel,
    outcome: ProbeOutcome,
) {
    let Some(m) = metrics() else { return };
    m.backend_probe_count.add(
        1,
        &[
            KeyValue::new("secretenv.backend.type", backend_type.to_owned()),
            KeyValue::new("secretenv.backend.instance_name", instance_name.to_owned()),
            KeyValue::new("secretenv.backend.probe.level", level.as_attribute_value()),
            KeyValue::new("secretenv.backend.probe.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.backend.fetch.duration` histogram point. `alias.name`
/// is intentionally absent from the attribute set — see the
/// cardinality rule at the top of this module.
pub fn record_backend_fetch_duration(
    ms: u64,
    backend_type: &str,
    instance_name: &str,
    outcome: FetchOutcome,
) {
    let Some(m) = metrics() else { return };
    m.backend_fetch_duration.record(
        ms,
        &[
            KeyValue::new("secretenv.backend.type", backend_type.to_owned()),
            KeyValue::new("secretenv.backend.instance_name", instance_name.to_owned()),
            KeyValue::new("secretenv.backend.fetch.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.redact.events` counter increment. `alias.name` is
/// intentionally absent per SEC-INV-19.
pub fn increment_redact_event(mode: RedactMode, context: MatchContext) {
    let Some(m) = metrics() else { return };
    m.redact_events.add(
        1,
        &[
            KeyValue::new("secretenv.redact.mode", mode.as_attribute_value()),
            KeyValue::new("secretenv.redact.match_context", context.as_attribute_value()),
        ],
    );
}

/// `secretenv.mcp.tool.calls` counter increment.
pub fn increment_mcp_tool_call(tool: McpToolName, outcome: McpOutcome) {
    let Some(m) = metrics() else { return };
    m.mcp_tool_calls.add(
        1,
        &[
            KeyValue::new("secretenv.mcp.tool_name", tool.as_attribute_value()),
            KeyValue::new("secretenv.mcp.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.mcp.tool.duration` histogram point.
pub fn record_mcp_tool_duration(ms: u64, tool: McpToolName, outcome: McpOutcome) {
    let Some(m) = metrics() else { return };
    m.mcp_tool_duration.record(
        ms,
        &[
            KeyValue::new("secretenv.mcp.tool_name", tool.as_attribute_value()),
            KeyValue::new("secretenv.mcp.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.doctor.failure.count` counter increment. Successful
/// probes are intentionally silent; this is failure-only.
pub fn increment_doctor_failure(backend_type: &str, instance_name: &str, outcome: ProbeOutcome) {
    let Some(m) = metrics() else { return };
    m.doctor_failure_count.add(
        1,
        &[
            KeyValue::new("secretenv.backend.type", backend_type.to_owned()),
            KeyValue::new("secretenv.backend.instance_name", instance_name.to_owned()),
            KeyValue::new("secretenv.backend.probe.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.migrate.operation.count` counter increment.
pub fn increment_migrate_operation(phase: MigratePhase, outcome: MigrateOutcome) {
    let Some(m) = metrics() else { return };
    m.migrate_operation_count.add(
        1,
        &[
            KeyValue::new("secretenv.migrate.phase", phase.as_attribute_value()),
            KeyValue::new("secretenv.migrate.outcome", outcome.as_attribute_value()),
        ],
    );
}

/// `secretenv.registry.alias_count` synchronous gauge observation.
///
/// v0.17 ships a synchronous gauge for implementation simplicity;
/// an observed-gauge variant (callback-driven, polled by the
/// MetricReader) is a v0.18 follow-up if push-pull tradeoffs make
/// the change worthwhile in real operator deployments.
pub fn observe_registry_alias_count(count: u64, registry_name: &str, source_index: u32) {
    let Some(m) = metrics() else { return };
    m.registry_alias_count.record(
        count,
        &[
            KeyValue::new("secretenv.registry.name", registry_name.to_owned()),
            KeyValue::new("secretenv.registry.source_index", i64::from(source_index)),
        ],
    );
}

// ────────────────────────────────────────────────────────────────
// Closed-enum attribute values
//
// One enum per categorical attribute that appears as a metric
// dimension. Keeping these closed at the Rust type level makes
// cardinality bounded by construction.
// ────────────────────────────────────────────────────────────────

/// Closed enum for `secretenv.run.outcome` (metrics use site).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionOutcome {
    /// All required aliases resolved; child process started (or
    /// dry-run completed).
    Success,
    /// At least one alias failed to resolve; child never started.
    Failure,
    /// Dry-run pass — no fetches, no exec.
    DryRun,
}

impl ResolutionOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::DryRun => "dry-run",
        }
    }
}

/// Bucketed alias-count for the resolution-duration histogram, so
/// the same alias-count tier doesn't explode cardinality when the
/// operator's manifest grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AliasCountBucket {
    /// 1–5 aliases.
    Small,
    /// 6–10 aliases.
    Medium,
    /// 11–20 aliases.
    Large,
    /// 21+ aliases.
    XLarge,
}

impl AliasCountBucket {
    /// Compute the bucket from a raw alias count.
    #[must_use]
    pub const fn from_count(n: u64) -> Self {
        if n <= 5 {
            Self::Small
        } else if n <= 10 {
            Self::Medium
        } else if n <= 20 {
            Self::Large
        } else {
            Self::XLarge
        }
    }

    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Small => "1-5",
            Self::Medium => "6-10",
            Self::Large => "11-20",
            Self::XLarge => "20+",
        }
    }
}

/// Closed enum for `secretenv.backend.probe.level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeLevel {
    /// L1 — backend CLI installed and on `$PATH`.
    L1Cli,
    /// L2 — backend authenticated.
    L2Auth,
    /// L3 — registry readable (counts aliases, surfaces permission scope).
    L3Read,
}

impl ProbeLevel {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::L1Cli => "l1-cli",
            Self::L2Auth => "l2-auth",
            Self::L3Read => "l3-read",
        }
    }
}

/// Closed enum for `secretenv.backend.probe.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeOutcome {
    /// Probe succeeded.
    Ok,
    /// Backend CLI not installed.
    CliMissing,
    /// Backend CLI installed but not authenticated.
    NotAuthenticated,
    /// Registry not reachable (permission denied, network, etc.).
    RegistryUnreachable,
    /// Probe timed out.
    Timeout,
    /// Catch-all for unmodelled probe failures.
    Unknown,
}

impl ProbeOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::CliMissing => "cli-missing",
            Self::NotAuthenticated => "not-authenticated",
            Self::RegistryUnreachable => "registry-unreachable",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed enum for `secretenv.backend.fetch.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchOutcome {
    /// Fetch returned a value.
    Ok,
    /// Backend reports the alias is not present.
    NotFound,
    /// Backend authenticated but denied read.
    Denied,
    /// Fetch exceeded its bounded timeout.
    Timeout,
    /// Catch-all for unmodelled fetch failures.
    Error,
}

impl FetchOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not-found",
            Self::Denied => "denied",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

/// Closed enum for `secretenv.redact.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactMode {
    /// Mode A — runtime pipe redaction during `secretenv run`.
    Runtime,
    /// Mode B — post-hoc file rewrite.
    PostHoc,
    /// Operator disabled redaction (`--no-redact` or similar).
    Disabled,
}

impl RedactMode {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::PostHoc => "post-hoc",
            Self::Disabled => "disabled",
        }
    }
}

/// Closed enum for `secretenv.redact.match_context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchContext {
    /// Secret string matched verbatim.
    Exact,
    /// Secret matched as a substring inside a larger token.
    Substring,
    /// Secret matched in its base64-encoded form.
    Base64Form,
}

impl MatchContext {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Substring => "substring",
            Self::Base64Form => "base64-form",
        }
    }
}

/// Closed enum for `secretenv.mcp.tool_name`.
///
/// Members correspond to registered MCP tools in `secretenv-mcp`.
/// Adding a new tool requires extending this enum, which is the
/// PR-reviewed audit-surface expansion event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpToolName {
    /// `resolve_alias` — read-only alias lookup.
    ResolveAlias,
    /// `list_aliases` — read-only registry listing.
    ListAliases,
    /// `list_backends` — read-only backend introspection.
    ListBackends,
    /// `doctor` — read-only operational health.
    Doctor,
    /// `gen_password` — value-producing; non-droppable.
    GenPassword,
    /// `set_alias` — mutation; non-droppable.
    SetAlias,
    /// `delete_alias` — mutation; non-droppable.
    DeleteAlias,
    /// `migrate_alias` — mutation; non-droppable.
    MigrateAlias,
    /// `redact_file` — value-touching (no mutation to registry).
    RedactFile,
    /// `init_project` — scaffolding; modifies cwd files only.
    InitProject,
    /// `detect_password_managers` — read-only discovery.
    DetectPasswordManagers,
    /// `getting_started` — purely informational.
    GettingStarted,
    /// `redact_status` — read-only redaction-state introspection.
    RedactStatus,
    /// `resolve_status` — read-only resolve-state introspection.
    ResolveStatus,
    /// `version_info` — read-only build metadata.
    VersionInfo,
}

impl McpToolName {
    /// Stable snake-case attribute value (matches the tool's registered name).
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::ResolveAlias => "resolve_alias",
            Self::ListAliases => "list_aliases",
            Self::ListBackends => "list_backends",
            Self::Doctor => "doctor",
            Self::GenPassword => "gen_password",
            Self::SetAlias => "set_alias",
            Self::DeleteAlias => "delete_alias",
            Self::MigrateAlias => "migrate_alias",
            Self::RedactFile => "redact_file",
            Self::InitProject => "init_project",
            Self::DetectPasswordManagers => "detect_password_managers",
            Self::GettingStarted => "getting_started",
            Self::RedactStatus => "redact_status",
            Self::ResolveStatus => "resolve_status",
            Self::VersionInfo => "version_info",
        }
    }
}

/// Closed enum for `secretenv.mcp.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpOutcome {
    /// Tool returned a successful response.
    Success,
    /// Tool returned a structured error.
    Error,
    /// Mutation tool was denied by policy (`allow_mutations=never`,
    /// elicitation cancelled, etc.).
    Denied,
}

impl McpOutcome {
    /// Stable kebab-case attribute value.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Denied => "denied",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_count_bucket_thresholds() {
        assert_eq!(AliasCountBucket::from_count(0), AliasCountBucket::Small);
        assert_eq!(AliasCountBucket::from_count(5), AliasCountBucket::Small);
        assert_eq!(AliasCountBucket::from_count(6), AliasCountBucket::Medium);
        assert_eq!(AliasCountBucket::from_count(10), AliasCountBucket::Medium);
        assert_eq!(AliasCountBucket::from_count(11), AliasCountBucket::Large);
        assert_eq!(AliasCountBucket::from_count(20), AliasCountBucket::Large);
        assert_eq!(AliasCountBucket::from_count(21), AliasCountBucket::XLarge);
        assert_eq!(AliasCountBucket::from_count(9999), AliasCountBucket::XLarge);
    }

    #[test]
    fn enum_attribute_values_are_kebab_or_snake_case() {
        assert_eq!(ResolutionOutcome::DryRun.as_attribute_value(), "dry-run");
        assert_eq!(AliasCountBucket::XLarge.as_attribute_value(), "20+");
        assert_eq!(ProbeLevel::L1Cli.as_attribute_value(), "l1-cli");
        assert_eq!(ProbeOutcome::RegistryUnreachable.as_attribute_value(), "registry-unreachable");
        assert_eq!(FetchOutcome::NotFound.as_attribute_value(), "not-found");
        assert_eq!(RedactMode::PostHoc.as_attribute_value(), "post-hoc");
        assert_eq!(MatchContext::Base64Form.as_attribute_value(), "base64-form");
        // MCP tool names use snake_case to match registered tool names.
        assert_eq!(McpToolName::SetAlias.as_attribute_value(), "set_alias");
        assert_eq!(McpOutcome::Denied.as_attribute_value(), "denied");
    }

    #[test]
    fn emission_is_noop_when_provider_unconfigured() {
        // METRICS may have been set by another integration test in
        // this process; either way the calls must not panic.
        record_resolution_duration(
            123,
            "default",
            ResolutionOutcome::Success,
            AliasCountBucket::Small,
        );
        increment_resolution_count("default", ResolutionOutcome::Failure);
        increment_backend_probe("aws-ssm", "payments", ProbeLevel::L2Auth, ProbeOutcome::Ok);
        record_backend_fetch_duration(45, "vault", "prod", FetchOutcome::Ok);
        increment_redact_event(RedactMode::Runtime, MatchContext::Exact);
        increment_mcp_tool_call(McpToolName::Doctor, McpOutcome::Success);
        record_mcp_tool_duration(7, McpToolName::Doctor, McpOutcome::Success);
        increment_doctor_failure("vault", "prod", ProbeOutcome::Timeout);
        increment_migrate_operation(MigratePhase::Write, MigrateOutcome::Ok);
        observe_registry_alias_count(42, "default", 0);
    }
}
