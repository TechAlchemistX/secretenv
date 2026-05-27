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

use crate::audit_log::{MutationLog, MutationLogEntry, OperatorDecision};
use crate::boundary::OperatorDecisionEcho;
use crate::tools::args::MigrateAliasArgs;

/// Emit a `migrate_alias` audit-log entry. Pulled out into a helper
/// because the handler has 6 return paths that each need to log on
/// non-dry-run.
pub fn audit_migrate(
    mutation_log: &MutationLog,
    args: &MigrateAliasArgs,
    decision: OperatorDecision,
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
        operator_decision: decision,
        mcp_client_id: "unknown".to_owned(),
    };
    let _ = mutation_log.append(&entry);
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Map [`OperatorDecision`] (audit-log enum) to its agent-facing
/// [`OperatorDecisionEcho`] twin in `boundary.rs`. Two enums because
/// the audit-log set is shared with future non-tool surfaces, and
/// adding `PolicyRefusal` to it would force every audit-log writer
/// to handle a never-emitted variant.
pub const fn echo_decision(decision: OperatorDecision) -> OperatorDecisionEcho {
    match decision {
        OperatorDecision::Approved => OperatorDecisionEcho::Approved,
        OperatorDecision::Denied => OperatorDecisionEcho::Denied,
        OperatorDecision::Timeout => OperatorDecisionEcho::Timeout,
        OperatorDecision::AutoApproved => OperatorDecisionEcho::AutoApproved,
    }
}

// `should_audit` retired in v0.16.2 D.2a — the run_mutation
// combinator unconditionally appends one audit entry per branch, so
// the abstraction is no longer load-bearing. Per v0.16 Phase 7
// code-review Medium ("misleading abstraction"), the function was
// either called inconsistently or returned `true` unconditionally;
// dropping it removes a class of drift without changing behavior.
