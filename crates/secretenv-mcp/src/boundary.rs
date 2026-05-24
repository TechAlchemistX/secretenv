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
