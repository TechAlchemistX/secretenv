// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Shape-typed projection of [`crate::MigrateReport`] for the MCP
//! boundary. v0.16.1 D.4 carry-forward — moves the projection that
//! `secretenv-mcp` was doing per-field into a centralized type so:
//!
//! 1. The "what's safe to serialize" decision lives next to the
//!    source type, not at every boundary.
//! 2. Downstream consumers can't accidentally reach for raw
//!    [`crate::MigrateReport`] fields like `delete_hint` or
//!    `probe_results` that may contain backend stderr / paths / CLI
//!    recovery commands embedding URI bodies.
//! 3. `MigrateReport` stays non-`Serialize` (it never derived
//!    `Serialize`, but the rule was implicit — now it's structural).
//!
//! The MCP layer ([`secretenv_mcp::boundary::MigrateAliasResponse`])
//! continues to add its own MCP-specific framing (`outcome`,
//! `decision`, `error_message`, …) on top of this projection — this
//! type is the migrate-engine's contribution to that response, not
//! the whole response.
//!
//! # Sanitization commitments
//!
//! The fields NOT exposed here:
//! - `MigrateReport::delete_hint` — contains a copy-paste shell
//!   command that embeds the destination URI body. Operators see it
//!   on the CLI; MCP agents do not.
//! - `MigrateReport::probe_results` — per-backend probe diagnostics,
//!   some of whose `Err` messages may include backend stderr or
//!   resolved paths.
//!
//! If a future tool needs either of these, add a sanitized projection
//! to this module rather than exposing the raw field.

use serde::Serialize;

use crate::{MigrateReport, MigrateReportOutcome, PhaseDurations};

/// Per-phase timings, serializable copy of [`PhaseDurations`].
///
/// Surfaced because backend latency is a useful diagnostic for the
/// agent and doesn't disclose any value content. `None` for the
/// `source_delete_ms` phase when `--delete-source` was not requested.
#[derive(Debug, Default, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PhaseDurationsSafe {
    /// Time spent probing backend liveness during plan-build.
    pub probe_ms: u64,
    /// Time spent reading the value from the source backend.
    pub read_ms: u64,
    /// Time spent writing the value to the destination backend.
    pub write_ms: u64,
    /// Time spent flipping the registry pointer (or pinning it on
    /// dry-run).
    pub pointer_flip_ms: u64,
    /// Time spent on the optional source-delete leg. `None` when
    /// `--delete-source` was not requested.
    pub source_delete_ms: Option<u64>,
}

impl From<PhaseDurations> for PhaseDurationsSafe {
    fn from(p: PhaseDurations) -> Self {
        Self {
            probe_ms: p.probe_ms,
            read_ms: p.read_ms,
            write_ms: p.write_ms,
            pointer_flip_ms: p.pointer_flip_ms,
            source_delete_ms: p.source_delete_ms,
        }
    }
}

/// Sanitized projection of [`MigrateReport`] safe to serialize across
/// the MCP boundary. See module docs for what's intentionally
/// excluded.
#[derive(Debug, Clone, Serialize)]
pub struct McpSafeReport {
    /// Registry alias that was migrated.
    pub alias: String,
    /// Source backend type label (e.g. `"vault"`, `"aws-ssm"`).
    pub source_backend_type: String,
    /// Destination backend type label.
    pub dest_backend_type: String,
    /// Final outcome — mirrors [`MigrateReportOutcome`] exactly.
    /// Kept as the same `#[non_exhaustive]` enum so a future migrate
    /// patch that adds a variant produces the same `_` arm pressure
    /// on consumers regardless of whether they're holding a
    /// `MigrateReport` or an `McpSafeReport`.
    pub outcome: MigrateReportOutcome,
    /// Recorded per-phase durations.
    pub phase_durations: PhaseDurationsSafe,
    /// Whether `--delete-source` was requested.
    pub delete_source: bool,
    /// Stable per-invocation transaction identifier.
    pub transaction_id: String,
}

impl From<MigrateReport> for McpSafeReport {
    fn from(r: MigrateReport) -> Self {
        Self {
            alias: r.alias,
            source_backend_type: r.source_backend_type,
            dest_backend_type: r.dest_backend_type,
            outcome: r.outcome,
            phase_durations: r.phase_durations.into(),
            delete_source: r.delete_source,
            transaction_id: r.transaction_id,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_report() -> MigrateReport {
        MigrateReport {
            alias: "stripe-key".to_owned(),
            source_backend_type: "vault".to_owned(),
            dest_backend_type: "aws-ssm".to_owned(),
            outcome: MigrateReportOutcome::Success,
            phase_durations: PhaseDurations {
                probe_ms: 12,
                read_ms: 34,
                write_ms: 56,
                pointer_flip_ms: 7,
                source_delete_ms: Some(8),
            },
            delete_source: true,
            delete_hint: Some(
                // The whole point of McpSafeReport: this string must
                // NOT appear in any serialized output.
                "vault kv delete secret/stripe-api-key  # DO NOT SHIP".to_owned(),
            ),
            transaction_id: "tx-abc123".to_owned(),
            probe_results: vec![
                ("vault".to_owned(), "ok".to_owned()),
                (
                    "aws-ssm".to_owned(),
                    "error: aws sts get-caller-identity stderr leaked".to_owned(),
                ),
            ],
        }
    }

    #[test]
    fn safe_report_serializes() {
        let safe: McpSafeReport = sample_report().into();
        let body = serde_json::to_string(&safe).unwrap();
        assert!(body.contains("\"alias\":\"stripe-key\""));
        assert!(body.contains("\"transaction_id\":\"tx-abc123\""));
    }

    #[test]
    fn safe_report_excludes_delete_hint() {
        let safe: McpSafeReport = sample_report().into();
        let body = serde_json::to_string(&safe).unwrap();
        assert!(
            !body.contains("DO NOT SHIP"),
            "delete_hint must not appear in serialized McpSafeReport: {body}"
        );
        assert!(!body.contains("delete_hint"), "delete_hint field name must not appear");
    }

    #[test]
    fn safe_report_excludes_probe_results() {
        let safe: McpSafeReport = sample_report().into();
        let body = serde_json::to_string(&safe).unwrap();
        assert!(
            !body.contains("stderr leaked"),
            "probe_results error content must not appear: {body}"
        );
        assert!(!body.contains("probe_results"), "probe_results field name must not appear");
    }

    #[test]
    fn outcome_round_trips() {
        for outcome in [
            MigrateReportOutcome::Success,
            MigrateReportOutcome::DryRun,
            MigrateReportOutcome::PartialFailurePointerFlip,
            MigrateReportOutcome::SourceDeleteFailedPostCommit,
        ] {
            let mut r = sample_report();
            r.outcome = outcome;
            let safe: McpSafeReport = r.into();
            assert_eq!(safe.outcome, outcome);
        }
    }

    #[test]
    fn phase_durations_round_trip() {
        let r = sample_report();
        let safe: McpSafeReport = r.clone().into();
        assert_eq!(safe.phase_durations.probe_ms, r.phase_durations.probe_ms);
        assert_eq!(safe.phase_durations.read_ms, r.phase_durations.read_ms);
        assert_eq!(safe.phase_durations.source_delete_ms, r.phase_durations.source_delete_ms);
    }
}
