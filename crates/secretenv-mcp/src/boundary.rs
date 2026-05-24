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

/// One alias listing in [`ListAliasesResponse::aliases`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AliasListing {
    /// Operator-chosen alias name (e.g. `STRIPE_API_KEY`).
    pub alias_name: String,
    /// `[backends.<name>]` instance name the alias resolves through.
    pub backend_instance: String,
    /// `type = "..."` field on that backend block (e.g.
    /// `"1password"`, `"vault"`). Convenient so the agent does not
    /// have to cross-reference `list_backends` to know how the alias
    /// is stored.
    pub backend_type: String,
    /// Name of the `[registries.<name>]` block this alias was found
    /// under. With cascade, the alias may also appear in lower-priority
    /// layers; this field reports the *winning* layer.
    pub registry_name: String,
}

/// One per-registry result block in [`ListAliasesResponse::registries`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryAliasesProbe {
    /// `[registries.<name>]` registry name.
    pub registry_name: String,
    /// How many aliases were enumerated from this registry (after
    /// cascade merge if multiple sources).
    pub alias_count: usize,
    /// Error message if alias enumeration failed for this registry
    /// (typically because the backing backend was unreachable or
    /// unauthenticated — see `doctor` for context).
    pub error: Option<String>,
}

/// Response payload for the `list_aliases` tool.
///
/// Enumerates alias *names* and their backing backend instance from
/// every `[registries.*]` block. The path portion of each alias's
/// target URI is intentionally OMITTED — surfacing it would reveal
/// secret naming conventions (e.g.
/// `Production/Stripe/api-key`). Per build-plan §1: "Never URIs,
/// never values."
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListAliasesResponse {
    /// All aliases across all registries, sorted by alias name then
    /// registry name (so deterministic ordering even with cascade
    /// overrides).
    pub aliases: Vec<AliasListing>,
    /// Per-registry summary (counts + any enumeration error). Useful
    /// for an agent that needs to know which registry contributed
    /// which alias subset, or which registry failed to enumerate.
    pub registries: Vec<RegistryAliasesProbe>,
    /// `aliases.len()`.
    pub total_aliases: usize,
}

/// One entry in [`DoctorResponse::backends`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorBackendStatus {
    /// `[backends.<name>]` instance name from `config.toml`.
    pub instance_name: String,
    /// `type = "..."` field from the backend block.
    pub backend_type: String,
    /// Three-bucket status (always one of `Authenticated`,
    /// `NotAuthenticated`, `CliNotInstalled`; `Unknown` is reserved
    /// for tools that don't probe live state, so it never appears
    /// here).
    pub status: AuthStatus,
    /// `cli_version` when the backend's `check()` returned `Ok`.
    pub cli_version: Option<String>,
    /// Backend's CLI-reported identity string (e.g. `profile=dev
    /// account=123 region=us-east-1`) when `check()` returned `Ok`.
    /// Mirrors `secretenv doctor --json`; never a secret value.
    pub identity_hint: Option<String>,
    /// Short remediation hint (e.g. `op signin`, `aws sso login`)
    /// when the status is not `Authenticated`.
    pub remediation_hint: Option<String>,
    /// Error message when `check()` returned `Error` — typically a
    /// network failure, permission denied, or a wedged backend.
    pub error_message: Option<String>,
}

/// Response payload for the `doctor` tool.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorResponse {
    /// Per-backend status, sorted by `instance_name`.
    pub backends: Vec<DoctorBackendStatus>,
    /// `backends.len()`.
    pub total: usize,
    /// Count of `status == Authenticated`.
    pub ok: usize,
    /// Count of `status != Authenticated`.
    pub failures: usize,
}

/// One entry in [`ResolveStatusResponse::registries`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveStatusRegistryProbe {
    /// `[registries.<name>]` registry name.
    pub registry_name: String,
    /// Number of source URIs listed under this registry.
    pub source_count: usize,
    /// Backend instance name backing the primary source URI
    /// (`sources[0]`'s scheme), if it parses + resolves to a
    /// configured backend instance.
    pub primary_source_backend_instance: Option<String>,
    /// Status of the primary backend's `check()` — `Authenticated`
    /// means alias lookups against this registry should succeed.
    pub primary_source_status: AuthStatus,
    /// Human-readable summary of the probe outcome.
    pub status_hint: String,
}

/// Response payload for the `resolve_status` tool.
///
/// Per-registry probe (not per-alias). Per-alias resolution requires
/// enumerating aliases from the registry document, which lives behind
/// a separate value-free helper coming in Phase 3g (`list_aliases`).
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveStatusResponse {
    /// Per-registry probe results, sorted by `registry_name`.
    pub registries: Vec<ResolveStatusRegistryProbe>,
    /// `registries.len()`.
    pub total_registries: usize,
    /// Count of registries whose primary source backend is
    /// `Authenticated`.
    pub resolvable_registries: usize,
    /// Note clarifying that this is a registry-level probe — per-alias
    /// resolution lands with `list_aliases` in Phase 3g.
    pub note: String,
}

/// One detection in [`DetectPasswordManagersResponse::detections`].
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasswordManagerDetection {
    /// Backend type label matching the `type = "..."` value in
    /// `[backends.*]` (e.g., `"1password"`, `"vault"`, `"aws-ssm"`).
    pub backend_type: String,
    /// The CLI binary probed (e.g., `"op"`, `"vault"`, `"aws"`).
    pub cli_binary: String,
    /// Result bucket. Reuses the shared [`AuthStatus`] enum so
    /// `list_backends` / `doctor` can mix detections + listings into
    /// the same enum-keyed UI.
    pub auth_status: AuthStatus,
    /// The argv that was executed to probe authentication. Exposed so
    /// an operator can re-run it manually for diagnosis. Output of
    /// the probe is intentionally NOT captured — could leak data.
    pub auth_probe_argv: Vec<String>,
}

/// Response payload for the `detect_password_managers` tool.
///
/// Probes every backend CLI this build supports — not just the ones
/// in `[backends.*]` — so an agent can suggest "you have `doppler`
/// installed but no `[backends.<name>] type = "doppler"` block" or
/// vice versa. Each probe runs concurrently with a short timeout
/// bound; probe output bytes are never returned, only exit status.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectPasswordManagersResponse {
    /// One entry per supported backend type.
    pub detections: Vec<PasswordManagerDetection>,
    /// Total supported backend types this build knows about.
    pub total_supported: usize,
    /// Count of detections with [`AuthStatus`] in
    /// `{Authenticated, NotAuthenticated}` — i.e. the CLI was found.
    pub installed: usize,
    /// Count of detections with [`AuthStatus::Authenticated`].
    pub authenticated: usize,
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
