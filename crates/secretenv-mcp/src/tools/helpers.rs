// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Small audit / time / decision-mapping helpers used by the
//! `#[tool_router]`-annotated impl block in `tools/mod.rs`. Lifted
//! out in v0.16.1 Phase D.1 so the impl block reads as
//! tool-handlers-only.
//!
//! The `migrate_alias` helper here lives at module scope (rather
//! than inside the impl block) because the handler has 6 return
//! paths that each need to log on non-dry-run; a free function keeps
//! the call sites readable.

use rmcp::service::Peer;
use rmcp::RoleServer;

use crate::audit_log::{
    Decision, MigrateOperatorDecision, MutationLog, MutationLogEntry, OperatorDecision,
};
use crate::boundary::OperatorDecisionEcho;
use crate::tools::args::MigrateAliasArgs;

/// Resolve the MCP client's identifier from the rmcp `initialize`
/// handshake's `clientInfo.name`, falling back to `"unknown"` when
/// the peer info hasn't been initialised yet (only happens during
/// the handshake itself, never inside a tool handler).
///
/// v0.16.0 Phase 8b finding F-7 — every audit-log entry and `OTel`
/// `mcp.client_name` span attribute that previously hardcoded
/// `"unknown"` now resolves through this helper so the audit /
/// telemetry surface carries the real client name (`claude-code`,
/// `cursor`, `vscode-copilot`, etc.).
#[must_use]
pub fn client_id_from_peer(peer: &Peer<RoleServer>) -> String {
    peer.peer_info().map_or_else(|| "unknown".to_owned(), |p| p.client_info.name.clone())
}

/// Emit a `migrate_alias` audit-log entry. Pulled out into a helper
/// because the handler has 6 return paths that each need to log on
/// non-dry-run.
pub fn audit_migrate(
    mutation_log: &MutationLog,
    args: &MigrateAliasArgs,
    decision: MigrateOperatorDecision,
    client_id: &str,
) {
    let entry = MutationLogEntry {
        ts_unix_secs: now_secs(),
        tool_name: "migrate_alias".to_owned(),
        alias_name: Some(args.alias.clone()),
        backend_instance: Some(
            secretenv_core::BackendUri::parse(&args.dest_uri)
                .map_or_else(|_| "<invalid-uri>".to_owned(), |u| u.scheme),
        ),
        agent_reason: args.reason.clone(),
        // v0.19 Arch-W-1: `audit_migrate` is the ONLY audit path that
        // accepts a `DryRun`-capable decision; project to the on-disk
        // form here. A non-migrate tool cannot reach this function.
        operator_decision: decision.to_audit(),
        mcp_client_id: client_id.to_owned(),
    };
    // v0.16.2 audit Sec F-1: surface audit-log append failures via
    // tracing instead of silently swallowing.
    if let Err(e) = mutation_log.append(&entry) {
        tracing::error!(error = ?e, "audit-log append failed");
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Map any per-tool [`Decision`] to its agent-facing
/// [`OperatorDecisionEcho`] twin in `boundary.rs`. Two enums because
/// the audit-log set is shared with future non-tool surfaces, and
/// adding `PolicyRefusal` to it would force every audit-log writer
/// to handle a never-emitted variant.
///
/// v0.19 Arch-W-1: generic over [`Decision`] so it accepts the
/// `MutationOperatorDecision` / `MigrateOperatorDecision` marker types
/// (and the on-disk [`OperatorDecision`]) without per-type overloads.
/// The mapping is driven by [`Decision::to_audit`], so the echo and
/// the audit-log entry can never classify the same decision
/// differently. No longer `const` (trait methods are not const-stable);
/// all callers are runtime handlers.
pub fn echo_decision(decision: impl Decision) -> OperatorDecisionEcho {
    match decision.to_audit() {
        OperatorDecision::Approved => OperatorDecisionEcho::Approved,
        OperatorDecision::Denied => OperatorDecisionEcho::Denied,
        OperatorDecision::Timeout => OperatorDecisionEcho::Timeout,
        OperatorDecision::AutoApproved => OperatorDecisionEcho::AutoApproved,
        // v0.18 M-12.
        OperatorDecision::DryRun => OperatorDecisionEcho::DryRun,
    }
}

// `should_audit` retired in v0.16.2 D.2a — the run_mutation
// combinator unconditionally appends one audit entry per branch, so
// the abstraction is no longer load-bearing. Per v0.16 Phase 7
// code-review Medium ("misleading abstraction"), the function was
// either called inconsistently or returned `true` unconditionally;
// dropping it removes a class of drift without changing behavior.
