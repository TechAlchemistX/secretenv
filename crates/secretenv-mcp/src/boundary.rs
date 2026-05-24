// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! MCP boundary types — the closed surface of structs that may be
//! serialized into a tool response payload.
//!
//! Every struct defined here is subject to the
//! [`tests/boundary_test.rs`](../tests/boundary_test.rs) field-name
//! exhaustiveness check — no field named `value`, `secret`, `password`,
//! `token`, or `raw` may appear in any type reachable from this module.
//!
//! Per-tool response structs land alongside their handler across
//! Phases 3-6. Phase 3 ships the eight read-only tools.

use schemars::JsonSchema;
use serde::Serialize;

/// Three-bucket authentication status for a backend instance.
///
/// `list_backends` always reports [`Unknown`](Self::Unknown) — auth
/// probing is the dedicated job of `doctor` / `detect_password_managers`.
/// Splitting "is configured" from "is reachable + authed" keeps
/// `list_backends` a config-only tool with deterministic output.
#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    /// Auth state has not been probed. Call `doctor` or
    /// `detect_password_managers` to find out.
    Unknown,
    /// CLI present and a live credential check succeeded.
    Authenticated,
    /// CLI present but no valid credential — e.g., session expired
    /// or the env var is missing.
    NotAuthenticated,
    /// Backend CLI is not installed on this machine.
    CliNotInstalled,
}

/// One entry in [`ListBackendsResponse::backends`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackendListing {
    /// `[backends.<name>]` instance name from `config.toml`.
    pub name: String,
    /// `type = "..."` field from the backend block (e.g., `"1password"`,
    /// `"vault"`, `"aws-ssm"`).
    pub backend_type: String,
    /// Three-bucket auth state. Always [`AuthStatus::Unknown`] for
    /// this tool — `doctor` is the auth probe.
    pub auth_status: AuthStatus,
    /// Human-readable hint pointing at the tool that would actually
    /// probe auth state.
    pub auth_status_hint: String,
}

/// Response payload for the `list_backends` tool.
///
/// Config-only: enumerates the `[backends.*]` tables in the loaded
/// config without contacting any backend CLI. Live auth + reachability
/// probing belongs to `doctor`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListBackendsResponse {
    /// One listing per `[backends.*]` table, sorted by name for
    /// deterministic output.
    pub backends: Vec<BackendListing>,
    /// `backends.len()` — convenience field so a consumer that
    /// `select`s a subset can still know the configured total.
    pub total: usize,
}

/// One entry in [`VersionInfoResponse::tools`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolListing {
    /// Tool name as registered with the MCP router.
    pub name: String,
    /// Short tool description from the `#[tool(description = "...")]`
    /// attribute, if present.
    pub description: Option<String>,
}

/// Response payload for the `version_info` tool.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionInfoResponse {
    /// `SecretEnv` workspace version (`secretenv-mcp` shares the
    /// workspace version so this is also the CLI release line).
    pub secretenv_version: String,
    /// `MCP` wire protocol version this server advertises.
    pub mcp_protocol_version: String,
    /// `rmcp` SDK version powering the transport + handler routing.
    pub rmcp_sdk_version: String,
    /// All `MCP` tools registered on this server, in router-iteration
    /// order. Mirrors `tools/list` but adds nothing the client would
    /// not already have after the handshake; provided as a convenience
    /// for agents that did not retain the list.
    pub tools: Vec<ToolListing>,
}

/// Response payload for the `redact_status` tool.
///
/// Reports configuration, not running-process state — the `MCP` server
/// itself never has a child process to redact. Runtime redaction lives
/// in the `secretenv run` pipeline. This tool exists so an agent can
/// answer "if I ran the CLI now, would values be masked?" without
/// invoking it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedactStatusResponse {
    /// `secretenv run`'s default redaction mode at this build. `"auto"`
    /// in v0.14+ (Phase 1).
    pub default_redact_mode: String,
    /// Every redaction mode `secretenv run` accepts. Useful for an
    /// agent suggesting a `--redact <mode>` flag to the operator.
    pub available_redact_modes: Vec<String>,
    /// Count of `[registries.*]` tables loaded — bounds the number of
    /// alias sources that could potentially be masked. Exact alias
    /// count requires `list_aliases` (which is the tool that touches
    /// registry storage).
    pub registries_loaded: usize,
    /// Note clarifying that the `MCP` boundary itself never returns
    /// values, so the redact concept is a CLI-runtime concern surfaced
    /// here only for agent convenience.
    pub note: String,
}

/// Response payload for the `getting_started` tool.
///
/// Pure-static overview: ships counts (never names, never values) of
/// what's currently configured plus a deterministic suggested-next-tool
/// hint. Never reaches a backend — safe to call as the agent's first
/// MCP request even before authentication.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GettingStartedResponse {
    /// One-paragraph overview of what `SecretEnv` is and what the `MCP`
    /// server exposes.
    pub overview: String,
    /// `secretenv-mcp` crate version (from `CARGO_PKG_VERSION`).
    pub mcp_server_version: String,
    /// Count of `[registries.*]` tables in the loaded config. Names
    /// intentionally omitted — `list_aliases` is the tool that exposes
    /// alias data.
    pub registries_configured: usize,
    /// Count of `[backends.*]` tables in the loaded config. Names
    /// intentionally omitted — `list_backends` is the tool that exposes
    /// backend instance data.
    pub backend_instances_configured: usize,
    /// Name of the MCP tool the caller should invoke next, chosen
    /// deterministically from the current config shape.
    pub suggested_next_tool: String,
    /// Human-readable rationale for the suggestion above.
    pub suggested_next_tool_reason: String,
    /// All MCP tool names registered on this server. Matches the
    /// `tools/list` JSON-RPC reply.
    pub all_tools: Vec<String>,
}
