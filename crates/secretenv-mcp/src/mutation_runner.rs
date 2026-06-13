// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation-handler combinator.
//!
//! Collapses the ~80 LOC of policy-gate + audit-log boilerplate
//! that every mutation tool handler in [`crate::tools`] used to
//! carry inline.
//!
//! # Why a module, not a crate
//!
//! v0.16 Phase 7 code-review High-1 recommended this lift; v0.16.1
//! mid-cycle survey caught that bundling it with the
//! `secretenv-registry-mutate` writers extract (Phase 7 architecture
//! C-2) would force ~1000 LOC of `secretenv-mcp` internals
//! ([`crate::policy`] + [`crate::audit_log`] + the boundary types)
//! to move into a new crate just to avoid circular deps. v0.16.2
//! ships the combinator as a module inside `secretenv-mcp` (where
//! its dependencies live) and the writers extract as a sibling
//! crate that depends on `secretenv-core` only.
//!
//! # Shape
//!
//! Each mutation handler now constructs three small inputs
//! ([`MutationContext`], [`MutationRequest`], [`AuditMeta`]) and a
//! write closure, then awaits one call to [`run_mutation`]. The
//! returned [`MutationResolution`] carries the three fields every
//! mutation response surfaces: `outcome`, `decision`, `error_message`.
//!
//! # SEC-INV preservation
//!
//! The combinator preserves the same SEC-INV invariants the
//! per-handler boilerplate satisfied:
//!
//! - SEC-INV-12 — `agent_reason` is recorded verbatim in the audit
//!   log on every decision branch (refused / denied / timeout /
//!   approved / auto-approved / write-failed) and is NEVER
//!   surfaced in the [`MutationResolution::error_message`] returned
//!   to the agent.
//! - SEC-INV-20 — errors flow through [`safe_error_message`] before
//!   they reach `error_message`, scrubbing URI bodies and other
//!   privileged content.
//! - Audit-log fidelity — every branch writes exactly one
//!   [`MutationLogEntry`]; nothing is double-logged and nothing is
//!   missed. The unit tests in [`crate::audit_log`] continue to
//!   cover this from below.

use std::future::Future;

use anyhow::Result;
use rmcp::service::Peer;
use rmcp::RoleServer;

use crate::audit_log::{
    Decision, MutationLog, MutationLogEntry, MutationOperatorDecision, OperatorDecision,
};
use crate::boundary::{MutationOutcome, OperatorDecisionEcho};
use crate::config::McpConfig;
use crate::error::safe_error_message;
use crate::policy::{enforce_mutation_policy, MutationRequest};
use crate::tools::helpers;

/// Borrowed handle to the per-server state a mutation handler needs.
/// Constructed once at the call site and passed to [`run_mutation`].
pub struct MutationContext<'a> {
    /// Operator policy stance read at handler dispatch time.
    pub mcp_config: &'a McpConfig,
    /// Audit-log writer shared across handlers (`Mutex<File>` under
    /// the hood). Every decision branch appends exactly one entry.
    pub mutation_log: &'a MutationLog,
    /// `rmcp` peer for the in-flight tool call. `Some` for every
    /// real handler dispatch; `None` is reserved for unit-test
    /// fixtures that drive the combinator without a live elicit
    /// channel.
    pub peer: Option<&'a Peer<RoleServer>>,
}

/// Metadata baked into every [`MutationLogEntry`] written by the
/// combinator. Owned strings because the entry construction
/// outlives the borrow of the handler's `args`.
///
/// **`tool_name` is intentionally absent** — the audit-log entry
/// reads it from [`MutationRequest::tool_name`] passed alongside
/// this struct so the policy gate + the audit-log entry can never
/// drift via a copy-paste typo at the call site (v0.16.2 Phase 7
/// code-review Low-2).
pub struct AuditMeta {
    /// `Some(alias_name)` for alias-keyed mutations (set / delete /
    /// `gen_password` / migrate); `None` for `init_project` /
    /// `redact_file` which don't carry an alias identity.
    pub alias_name: Option<String>,
    /// Backend instance the mutation targets (extracted from a URI
    /// scheme when relevant). `None` for tools that don't touch a
    /// backend (`init_project`) or where the URI hadn't been parsed
    /// yet (`delete_alias` surfaces the alias's resolved backend in
    /// a follow-up cycle).
    pub backend_instance: Option<String>,
    /// MCP client identity (e.g. `"claude-code/0.6.2"`). Today
    /// hardcoded to `"unknown"` per the v0.16 Phase 7 code-review
    /// Medium carry-forward (full client-id threading is a v0.17
    /// item).
    pub mcp_client_id: String,
}

/// Tuple-shaped resolution returned to the per-tool handler.
///
/// Each response struct in [`crate::boundary`] carries these three
/// fields under different field names; the handler maps the
/// resolution into its tool-specific response.
pub struct MutationResolution {
    /// Bucketed outcome surfaced to the agent.
    pub outcome: MutationOutcome,
    /// Operator-decision echo (audit-log decision projected for
    /// agent consumption).
    pub decision: OperatorDecisionEcho,
    /// `Some` on `PolicyRefusal` / `WriteFailed` / any error path;
    /// always passes through [`safe_error_message`] first.
    pub error_message: Option<String>,
}

/// Run a mutation through the policy gate + write closure + audit
/// log.
///
/// # Behavior
///
/// 1. Calls [`enforce_mutation_policy`] with `ctx.mcp_config`,
///    `request`, and `ctx.peer`.
/// 2. **On `Err`** (policy refused / no surface): writes one audit
///    entry with `OperatorDecision::Denied`, returns
///    [`OperatorDecisionEcho::PolicyRefusal`] +
///    [`MutationOutcome::Refused`] + a scrubbed error message.
/// 3. **On `Ok(Denied | Timeout)`**: writes one audit entry with
///    that decision, returns the matching outcome (`Refused` /
///    `Timeout`) and no error message.
/// 4. **On `Ok(Approved | Auto)`**: awaits `write()`, then writes
///    one audit entry with the decision (regardless of write
///    outcome). Returns `Applied` on `Ok(())` or `WriteFailed +
///    scrubbed error` on `Err`.
///
/// `agent_reason` is taken as an owned `String` because the entry
/// builder needs to clone it once per branch — passing it owned
/// avoids requiring the caller to clone at every call site.
pub async fn run_mutation<F, Fut>(
    ctx: MutationContext<'_>,
    request: MutationRequest<'_>,
    audit: AuditMeta,
    agent_reason: String,
    write: F,
) -> MutationResolution
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mk_entry = |decision: OperatorDecision| MutationLogEntry {
        ts_unix_secs: helpers::now_secs(),
        // SoT for tool_name is MutationRequest — never AuditMeta
        // (v0.16.2 Phase 7 code-review Low-2: prevents drift if a
        // call site mistypes the tool name in one of two places).
        tool_name: request.tool_name.to_owned(),
        alias_name: audit.alias_name.clone(),
        backend_instance: audit.backend_instance.clone(),
        agent_reason: agent_reason.clone(),
        operator_decision: decision,
        mcp_client_id: audit.mcp_client_id.clone(),
    };

    match enforce_mutation_policy(ctx.mcp_config, &request, ctx.peer).await {
        Err(e) => {
            // v0.16.2 audit Sec F-1: surface audit-log append failures
            // via tracing instead of silently swallowing. Agent-visible
            // behavior is unchanged (the error is operator-side only);
            // SEC-INV-12 still satisfied because no agent_reason or
            // adjacent prompt-injection-shaped context appears in the
            // tracing call. Same pattern at the other two call sites
            // in this function.
            if let Err(append_err) = ctx.mutation_log.append(&mk_entry(OperatorDecision::Denied)) {
                tracing::error!(error = ?append_err, "audit-log append failed");
            }
            MutationResolution {
                outcome: MutationOutcome::Refused,
                decision: OperatorDecisionEcho::PolicyRefusal,
                error_message: Some(safe_error_message(&e)),
            }
        }
        Ok(decision @ (MutationOperatorDecision::Denied | MutationOperatorDecision::Timeout)) => {
            let outcome = if decision == MutationOperatorDecision::Timeout {
                MutationOutcome::Timeout
            } else {
                MutationOutcome::Refused
            };
            if let Err(append_err) = ctx.mutation_log.append(&mk_entry(decision.to_audit())) {
                tracing::error!(error = ?append_err, "audit-log append failed");
            }
            MutationResolution {
                outcome,
                decision: helpers::echo_decision(decision),
                error_message: None,
            }
        }
        Ok(
            decision
            @ (MutationOperatorDecision::Approved | MutationOperatorDecision::AutoApproved),
        ) => {
            let write_result = write().await;
            let (outcome, error_message) = match write_result {
                Ok(()) => (MutationOutcome::Applied, None),
                Err(e) => (MutationOutcome::WriteFailed, Some(safe_error_message(&e))),
            };
            if let Err(append_err) = ctx.mutation_log.append(&mk_entry(decision.to_audit())) {
                tracing::error!(error = ?append_err, "audit-log append failed");
            }
            MutationResolution {
                outcome,
                decision: helpers::echo_decision(decision),
                error_message,
            }
        } // v0.19 Arch-W-1: `enforce_mutation_policy` now returns
          // `MutationOperatorDecision`, which has no `DryRun` variant — so
          // the match above is exhaustive WITHOUT a DryRun arm. The v0.18
          // "structurally unreachable but defensively matched" DryRun arm
          // is gone: DryRun is unrepresentable here at the type level, not
          // guarded at runtime. Migrate dry-run logging happens at the
          // tools/mod.rs call site via `MigrateOperatorDecision::DryRun`.
    }
}
