// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation policy enforcement.
//!
//! Every mutation tool handler (Phases 4c–6) calls
//! [`enforce_mutation_policy`] at entry. The function returns
//! `Ok(OperatorDecision)` describing how the call was approved (or
//! `Err` if the policy refused / no surface was available). The
//! returned decision is what the handler writes to the audit log via
//! [`crate::audit_log::MutationLog::append`] — the policy module owns
//! the decision; the audit-log module owns the persistence.
//!
//! The TTY confirmation prompt opens `/dev/tty` for both read and
//! write. This bypasses the agent's stdio + the IDE's "approve all
//! this session" gate — the operator gets a real prompt at their
//! terminal regardless of how the MCP server was launched.

use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::time::timeout;

use crate::audit_log::OperatorDecision;
use crate::config::{AllowMutations, ConfirmVia, McpConfig};

/// TTY prompt wall-clock timeout. No response = treated as deny per
/// the existing [`OperatorDecision::Timeout`] semantics.
const TTY_PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Description of a pending mutation passed to [`enforce_mutation_policy`].
///
/// Field set is the minimum needed for a useful TTY prompt + a
/// complete audit-log entry. The `agent_reason` field is recorded
/// verbatim in the audit log but NEVER echoed back to the agent in
/// the response payload and NEVER set as an `OTel` attribute (SEC-INV-12).
#[derive(Debug, Clone)]
pub struct MutationRequest<'a> {
    /// Tool name (e.g. `"set_alias"`). Used in the prompt and the
    /// audit-log entry.
    pub tool_name: &'a str,
    /// One-line summary of what the tool will do if approved (e.g.
    /// `"create alias `stripe-key` → `vault-prod://...`"`). Used in
    /// the prompt only.
    pub action_summary: &'a str,
    /// The agent's stated reason for requesting the mutation.
    /// Verbatim in the audit log; never echoed back.
    pub agent_reason: &'a str,
}

/// Apply the [`McpConfig::allow_mutations`] policy to one mutation
/// request. Returns the [`OperatorDecision`] the handler should write
/// to the audit log, or an error if the policy refuses outright.
///
/// # Errors
///
/// - [`AllowMutations::Never`] — returns an error describing the
///   policy. Handler should surface this back to the agent as a
///   structured refusal.
/// - [`ConfirmVia::None`] when policy is `Confirm` — returns an
///   error (`Confirm` without a surface is a config bug).
/// - [`ConfirmVia::Notification`] — currently a stub (deferred to a
///   later phase); returns an error so a config setting it doesn't
///   silently auto-approve.
/// - TTY open / read failure when policy is `Confirm` + surface is
///   `Tty` — returns an error so the mutation does not proceed.
///
/// On `AllowMutations::Always` returns `Ok(AutoApproved)` without
/// any I/O.
///
/// On `Confirm` + `Tty` opens `/dev/tty`, writes a y/N prompt to it
/// (NOT stderr — stderr is consumed by the MCP transport), reads one
/// line with a 30s timeout, and returns `Approved` / `Denied` /
/// `Timeout` accordingly.
pub async fn enforce_mutation_policy(
    mcp_config: &McpConfig,
    request: &MutationRequest<'_>,
) -> Result<OperatorDecision> {
    match mcp_config.allow_mutations {
        AllowMutations::Never => {
            bail!(
                "MCP server policy `allow_mutations = \"never\"` refuses tool `{}`. \
                 Set `[mcp].allow_mutations = \"confirm\"` or `\"always\"` to enable.",
                request.tool_name
            );
        }
        AllowMutations::Always => Ok(OperatorDecision::AutoApproved),
        AllowMutations::Confirm => match mcp_config.confirm_via {
            ConfirmVia::Tty => prompt_via_tty(request).await,
            ConfirmVia::Notification => bail!(
                "MCP server policy is `confirm` with `confirm_via = \"notification\"`, \
                 which is not yet implemented. Set `confirm_via = \"tty\"` for now."
            ),
            ConfirmVia::None => bail!(
                "MCP server policy is `confirm` with `confirm_via = \"none\"` — no \
                 confirmation surface is configured, so the mutation cannot proceed. \
                 Set `confirm_via = \"tty\"` or `allow_mutations = \"always\"`."
            ),
        },
    }
}

async fn prompt_via_tty(request: &MutationRequest<'_>) -> Result<OperatorDecision> {
    let prompt = format!(
        "\n[secretenv mcp] Tool `{}` wants to: {}\n  Approve? [y/N] ",
        request.tool_name, request.action_summary
    );

    match timeout(TTY_PROMPT_TIMEOUT, read_tty_line(prompt)).await {
        Err(_) => Ok(OperatorDecision::Timeout),
        Ok(Err(e)) => Err(e),
        Ok(Ok(line)) => {
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
                Ok(OperatorDecision::Approved)
            } else {
                Ok(OperatorDecision::Denied)
            }
        }
    }
}

/// Open `/dev/tty` for both write (prompt) and read (response).
/// Writes the prompt, reads exactly one line, returns it.
///
/// Runs the blocking I/O on a `tokio::task::spawn_blocking` so it
/// integrates with the `timeout` wrapper above without holding a
/// runtime thread.
async fn read_tty_line(prompt: String) -> Result<String> {
    tokio::task::spawn_blocking(move || -> Result<String> {
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("opening /dev/tty for prompt write — is this an interactive session?")?;
        writer.write_all(prompt.as_bytes()).context("writing prompt to /dev/tty")?;
        writer.flush().context("flushing /dev/tty")?;

        let reader = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/tty")
            .context("opening /dev/tty for read")?;
        let mut buf = String::new();
        BufReader::new(reader).read_line(&mut buf).context("reading line from /dev/tty")?;
        Ok(buf)
    })
    .await
    .map_err(|e| anyhow!("tokio join error during TTY prompt: {e}"))?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn req<'a>() -> MutationRequest<'a> {
        MutationRequest {
            tool_name: "set_alias",
            action_summary: "create alias `test`",
            agent_reason: "unit test",
        }
    }

    #[tokio::test]
    async fn never_refuses() {
        let cfg = McpConfig { allow_mutations: AllowMutations::Never, ..McpConfig::default() };
        let err = enforce_mutation_policy(&cfg, &req()).await.unwrap_err();
        assert!(format!("{err:#}").contains("refuses tool"));
    }

    #[tokio::test]
    async fn always_auto_approves_without_io() {
        let cfg = McpConfig { allow_mutations: AllowMutations::Always, ..McpConfig::default() };
        let decision = enforce_mutation_policy(&cfg, &req()).await.unwrap();
        assert_eq!(decision, OperatorDecision::AutoApproved);
    }

    #[tokio::test]
    async fn confirm_notification_is_unimplemented() {
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::Notification,
            ..McpConfig::default()
        };
        let err = enforce_mutation_policy(&cfg, &req()).await.unwrap_err();
        assert!(format!("{err:#}").contains("not yet implemented"));
    }

    #[tokio::test]
    async fn confirm_none_refuses() {
        let cfg = McpConfig {
            allow_mutations: AllowMutations::Confirm,
            confirm_via: ConfirmVia::None,
            ..McpConfig::default()
        };
        let err = enforce_mutation_policy(&cfg, &req()).await.unwrap_err();
        assert!(format!("{err:#}").contains("no confirmation surface"));
    }
}
