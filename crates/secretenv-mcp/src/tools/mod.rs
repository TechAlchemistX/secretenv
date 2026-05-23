// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `MCP` tool handlers.
//!
//! Phase 2a registers all 14 tools per `tools-inventory.yaml` as
//! stubs that return a "not yet implemented" error. Real
//! implementations land per-phase across Phases 3-6:
//!
//! - **Phase 3 (read-only, 8 tools):** `getting_started`,
//!   `version_info`, `list_aliases`, `list_backends`,
//!   `resolve_status`, `detect_password_managers`, `doctor`,
//!   `redact_status`.
//! - **Phase 4 (mutation, 4 tools):** `set_alias`, `delete_alias`,
//!   `init_project`, `redact_file`.
//! - **Phase 5:** `gen_password` (highest-risk; ships last).
//! - **Phase 6:** `migrate_alias` (wraps the v0.16 Phase 1a
//!   `secretenv-migrate` library).
//!
//! Every handler entry function must call
//! `secretenv_telemetry::span::SecretEnvSpan` (the v0.17 `OTel` seam)
//! at its entry point — even before tool logic exists. Phase 2a stubs
//! intentionally do NOT yet open spans (no logic to attribute); the
//! pattern lands in Phase 3 with the first real handler.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Empty argument record used by every Phase 2a stub. Real per-tool
/// argument types land with the tool's Phase-3-6 handler — at which
/// point the stub's parameterless signature is replaced.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct StubArgs {}

/// The `SecretEnv` `MCP` server handler.
///
/// Owns a [`ToolRouter`] populated by the `#[tool_router]` macro
/// expansion below. Stateless in Phase 2a; future phases will add
/// shared `Config` / `BackendRegistry` / `AuditLog` handles.
#[derive(Debug, Clone, Default)]
pub struct Server {
    /// Tool dispatch table — populated by the `#[tool_router]` macro.
    pub tool_router: ToolRouter<Self>,
}

impl Server {
    /// Build a server with the tool router materialized from the
    /// `#[tool_router]`-annotated impl block below.
    #[must_use]
    pub fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }
}

fn not_yet_implemented(tool: &str, phase: u8) -> String {
    // Phase 2a stubs return a string marker rather than a typed
    // `McpError::internal_error` so the `#[tool_router]` macro
    // accepts the signature without per-stub `Result` wiring. Real
    // handlers (Phases 3-6) replace these with typed responses.
    format!("tool `{tool}` not yet implemented (lands in Phase {phase})")
}

#[tool_router(router = tool_router)]
impl Server {
    // ----- Phase 3: read-only (8) ----------------------------------

    /// Overview of `SecretEnv` + suggested next tool given current state.
    #[tool(
        name = "getting_started",
        description = "Overview of SecretEnv + suggested next tool given current state."
    )]
    pub async fn getting_started(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("getting_started", 3)
    }

    /// `SecretEnv` version, `MCP` protocol version, available tools.
    #[tool(
        name = "version_info",
        description = "SecretEnv version, MCP protocol version, available tools."
    )]
    pub async fn version_info(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("version_info", 3)
    }

    /// All alias names + backend type/instance in the registry. Never URIs, never values.
    #[tool(
        name = "list_aliases",
        description = "All alias names + backend type/instance in the registry. Never URIs, never values."
    )]
    pub async fn list_aliases(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("list_aliases", 3)
    }

    /// All configured backend instances + auth status + native-gen support.
    #[tool(
        name = "list_backends",
        description = "All configured backend instances + auth status + native-gen support."
    )]
    pub async fn list_backends(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("list_backends", 3)
    }

    /// Whether aliases can currently be resolved. NEVER returns the value.
    #[tool(
        name = "resolve_status",
        description = "Whether aliases can currently be resolved. NEVER returns the value. No flag makes this return a value."
    )]
    pub async fn resolve_status(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("resolve_status", 3)
    }

    /// Installed + authenticated secret backend CLIs on this machine.
    #[tool(
        name = "detect_password_managers",
        description = "Installed + authenticated secret backend CLIs on this machine."
    )]
    pub async fn detect_password_managers(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("detect_password_managers", 3)
    }

    /// Three-level health check: CLI installed, authenticated, registry reachable.
    #[tool(
        name = "doctor",
        description = "Three-level health check: CLI installed, authenticated, registry reachable. Hint strings for remediation; no --fix."
    )]
    pub async fn doctor(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("doctor", 3)
    }

    /// Whether runtime redaction is active; count of values that would be masked.
    #[tool(
        name = "redact_status",
        description = "Whether runtime redaction is active; count of values that would be masked. No alias names, no values."
    )]
    pub async fn redact_status(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("redact_status", 3)
    }

    // ----- Phase 4: mutation (4) -----------------------------------

    /// Create or update alias → backend-URI mapping. CONFIRM WITH USER before calling.
    #[tool(
        name = "set_alias",
        description = "Create or update alias → backend-URI mapping. CONFIRM WITH USER before calling. Does not create the backend secret."
    )]
    pub async fn set_alias(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("set_alias", 4)
    }

    /// Remove alias from registry. Backend secret NOT deleted. ALWAYS CONFIRM PER ALIAS.
    #[tool(
        name = "delete_alias",
        description = "Remove alias from registry. Backend secret NOT deleted. ALWAYS CONFIRM PER ALIAS. Never batch without per-alias gates."
    )]
    pub async fn delete_alias(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("delete_alias", 4)
    }

    /// Scaffold secretenv.toml; detect .env key names (NOT values).
    #[tool(
        name = "init_project",
        description = "Scaffold secretenv.toml; detect .env key names (NOT values). Default: propose without writing (apply: false)."
    )]
    pub async fn init_project(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("init_project", 4)
    }

    /// Scan file for resolvable secret values and redact.
    #[tool(
        name = "redact_file",
        description = "Scan file for resolvable secret values and redact. Writes count, not matched bytes. CONFIRM before writing."
    )]
    pub async fn redact_file(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("redact_file", 4)
    }

    // ----- Phase 5: password generation (1) ------------------------

    /// Generate secret, store in backend, register alias. Value NEVER returned.
    #[tool(
        name = "gen_password",
        description = "Generate secret, store in backend, register alias. Value NEVER returned. Wrapper-first (native gen preferred). CONFIRM backend + path + length before calling."
    )]
    pub async fn gen_password(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("gen_password", 5)
    }

    // ----- Phase 6: migrate (1) ------------------------------------

    /// Move secret to new backend; atomically repoint alias.
    #[tool(
        name = "migrate_alias",
        description = "Move secret to new backend; atomically repoint alias. Value transits server-side only. Source NOT deleted by default. CONFIRM before calling."
    )]
    pub async fn migrate_alias(&self, _args: Parameters<StubArgs>) -> String {
        not_yet_implemented("migrate_alias", 6)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` (alias of `InitializeResult`) and `Implementation`
        // are both `#[non_exhaustive]` in `rmcp` — we build via
        // `..Default::default()` so future field additions don't break
        // the call site.
        let mut implementation = Implementation::new("secretenv-mcp", env!("CARGO_PKG_VERSION"));
        implementation.title = Some("SecretEnv MCP Server".into());
        implementation.website_url = Some("https://secretenv.io".into());

        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = implementation;
        info.instructions = Some(
            "SecretEnv MCP server. Inspects and manages aliases for secrets stored in \
             backends like 1password, vault, AWS SSM, etc. NEVER returns resolved secret \
             values — value access is structurally forbidden across the MCP boundary."
                .into(),
        );
        info
    }
}
