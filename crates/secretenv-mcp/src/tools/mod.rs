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

pub mod aliases;
pub mod doctor;
pub mod init_project;
pub mod password_managers;
pub mod registry_writer;

use std::sync::Arc;

use anyhow::Context;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use secretenv_core::Config;
use secretenv_telemetry::span::SecretEnvSpan;
use serde::{Deserialize, Serialize};

use crate::audit_log::{MutationLog, MutationLogEntry, OperatorDecision};
use crate::boundary::{
    AuthStatus, BackendListing, DeleteAliasResponse, DetectPasswordManagersResponse,
    DoctorResponse, GettingStartedResponse, InitProjectResponse, ListAliasesResponse,
    ListBackendsResponse, MutationOutcome, OperatorDecisionEcho, RedactFileResponse,
    RedactStatusResponse, ResolveStatusRegistryProbe, ResolveStatusResponse, SetAliasResponse,
    ToolListing, VersionInfoResponse,
};
use crate::config::McpConfig;
use crate::policy::{enforce_mutation_policy, MutationRequest};

/// `rmcp` SDK version pinned in this crate's `Cargo.toml`. Surfaced by
/// `version_info`; kept in sync manually with the `[dependencies]`
/// `rmcp = { version = "X.Y", ... }` pin (single source of truth is
/// `Cargo.toml`; no `cargo metadata` call at runtime).
const RMCP_SDK_VERSION: &str = "1.7";

/// All redaction modes `secretenv run` accepts — kept in sync with
/// `secretenv_core::runner::RedactMode` (which lives behind the
/// `value-access` feature so `secretenv-mcp` cannot name the enum
/// directly per SEC-INV-02). String-list duplication is intentional.
const AVAILABLE_REDACT_MODES: &[&str] = &["auto", "force_pipe", "force_exec"];

/// Default redaction mode for `secretenv run` since v0.14 Phase 1.
const DEFAULT_REDACT_MODE: &str = "auto";

/// Empty argument record used by every Phase 2a stub. Real per-tool
/// argument types land with the tool's Phase-3-6 handler — at which
/// point the stub's parameterless signature is replaced.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct StubArgs {}

/// Argument record for `getting_started` — the tool takes no inputs.
/// Defined as its own type (rather than reusing [`StubArgs`]) so the
/// generated JSON Schema names a tool-specific input shape.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct GettingStartedArgs {}

/// Argument record for `version_info` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct VersionInfoArgs {}

/// Argument record for `redact_status` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct RedactStatusArgs {}

/// Argument record for `list_backends` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListBackendsArgs {}

/// Argument record for `detect_password_managers` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct DetectPasswordManagersArgs {}

/// Argument record for `doctor` — no inputs (the MCP boundary
/// intentionally drops `--fix` from the CLI equivalent; remediation
/// is the agent + operator's joint decision).
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct DoctorArgs {}

/// Argument record for `resolve_status` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ResolveStatusArgs {}

/// Argument record for `list_aliases` — no inputs.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ListAliasesArgs {}

/// Argument record for `set_alias`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetAliasArgs {
    /// Alias name to create or update (e.g. `"STRIPE_API_KEY"`).
    pub alias: String,
    /// Target URI the alias should resolve to (e.g.
    /// `"vault-prod:///secret/stripe/api-key"`). Must be a direct
    /// backend URI; `secretenv://` chains are rejected.
    pub target_uri: String,
    /// Optional registry name; defaults to `"default"` when omitted.
    #[serde(default)]
    pub registry: Option<String>,
    /// The agent's stated reason. Recorded verbatim in the mutation
    /// audit log. NEVER echoed back in the response. NEVER set as an
    /// `OTel` attribute. Per SEC-INV-12.
    pub reason: String,
}

/// Argument record for `delete_alias`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteAliasArgs {
    /// Alias name to remove from the registry.
    pub alias: String,
    /// Optional registry name; defaults to `"default"` when omitted.
    #[serde(default)]
    pub registry: Option<String>,
    /// The agent's stated reason. Audit-log only; never echoed.
    pub reason: String,
}

/// Argument record for `redact_file`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RedactFileArgs {
    /// Path of the file to scan + (optionally) rewrite in-place.
    pub file_path: String,
    /// Optional registry name; defaults to `"default"` when omitted.
    /// Every resolvable alias in this registry contributes one
    /// pattern to the redaction set.
    #[serde(default)]
    pub registry: Option<String>,
    /// When `true`, rewrite the file in-place with matches replaced
    /// by the redaction token. When `false` (default), only count
    /// matches — the file is not modified. Apply mode is gated by
    /// `[mcp].allow_mutations`.
    #[serde(default)]
    pub apply: bool,
    /// When `true`, accept files owned by a UID other than the
    /// caller. Off by default — defense against scrubbing a
    /// file the operator does not own.
    #[serde(default)]
    pub allow_foreign_owner: bool,
    /// The agent's stated reason. Audit-log only; never echoed.
    pub reason: String,
}

/// Argument record for `init_project`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct InitProjectArgs {
    /// Working directory to scaffold under (absolute or relative to
    /// the server process's CWD). When omitted, uses the server's
    /// own CWD.
    #[serde(default)]
    pub cwd: Option<String>,
    /// When `true`, actually writes `secretenv.toml`. When `false`
    /// (default), returns the proposed body without writing — the
    /// proposal IS the deliverable. Apply mode is gated by
    /// `[mcp].allow_mutations`.
    #[serde(default)]
    pub apply: bool,
    /// The agent's stated reason. Audit-log only; never echoed.
    pub reason: String,
}

/// Pick a deterministic next-tool suggestion from current config shape.
/// Pure function — exposed for unit tests.
#[must_use]
pub const fn suggest_next_tool(registries: usize, backends: usize) -> (&'static str, &'static str) {
    if backends == 0 {
        (
            "doctor",
            "No backend instances are configured. Run `doctor` to see which secret-backend \
             CLIs are installed and authenticated on this machine.",
        )
    } else if registries == 0 {
        (
            "list_backends",
            "Backend instances are configured but no registries point at them yet. \
             `list_backends` shows which backends are reachable for alias storage.",
        )
    } else {
        (
            "list_aliases",
            "Registries and backends are configured. `list_aliases` enumerates the \
             alias → backend mappings without ever returning a resolved value.",
        )
    }
}

/// The `SecretEnv` `MCP` server handler.
///
/// Owns a [`ToolRouter`] populated by the `#[tool_router]` macro
/// expansion below, plus the loaded [`Config`] read at startup.
/// Phase 4 will add the `[mcp]` typed config + `BackendRegistry` +
/// `AuditLog` handles; Phase 3 only needs the core config for the
/// backend-touching read-only tools.
#[derive(Debug, Clone)]
pub struct Server {
    /// Tool dispatch table — populated by the `#[tool_router]` macro.
    pub tool_router: ToolRouter<Self>,
    /// Machine-level config loaded at startup. `Arc` so handlers can
    /// cheaply borrow without cloning the underlying `HashMap` tables.
    pub config: Arc<Config>,
    /// Typed `[mcp]` config. Drives `allow_mutations` enforcement +
    /// `disabled_tools` filtering + audit-log path resolution. Phase
    /// 4 mutation handlers read from here; Phase 3 read-only handlers
    /// don't reference it.
    pub mcp_config: Arc<McpConfig>,
    /// Mutation audit-log writer, opened at startup from
    /// `mcp_config.mutation_log` (or the XDG default). `Arc` so every
    /// mutation handler's `append` call shares the same `Mutex<File>`
    /// and serializes writes.
    pub mutation_log: Arc<MutationLog>,
}

impl Server {
    /// Build a server with the tool router materialized from the
    /// `#[tool_router]`-annotated impl block below, plus the loaded
    /// [`Config`] / [`McpConfig`] / [`MutationLog`] handles.
    ///
    /// `mcp_config.disabled_tools` is applied to the router at
    /// construction time — any name listed there is removed from the
    /// dispatch table AND therefore from `tools/list`. Disabling a
    /// non-existent name is a no-op (logs a warning via `tracing`).
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        mcp_config: Arc<McpConfig>,
        mutation_log: Arc<MutationLog>,
    ) -> Self {
        let mut tool_router = Self::tool_router();
        let known: std::collections::BTreeSet<String> =
            tool_router.list_all().into_iter().map(|t| t.name.into_owned()).collect();
        for name in &mcp_config.disabled_tools {
            if known.contains(name) {
                tool_router.remove_route(name);
            } else {
                tracing::warn!(
                    "[mcp].disabled_tools includes `{name}` which is not a registered tool — \
                     ignoring (typo? renamed? this list is operator-maintained)"
                );
            }
        }
        Self { tool_router, config, mcp_config, mutation_log }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Map [`OperatorDecision`] (audit-log enum) to its agent-facing
/// [`OperatorDecisionEcho`] twin in `boundary.rs`. Two enums because
/// the audit-log set is shared with future non-tool surfaces, and
/// adding `PolicyRefusal` to it would force every audit-log writer
/// to handle a never-emitted variant.
const fn echo_decision(decision: OperatorDecision) -> OperatorDecisionEcho {
    match decision {
        OperatorDecision::Approved => OperatorDecisionEcho::Approved,
        OperatorDecision::Denied => OperatorDecisionEcho::Denied,
        OperatorDecision::Timeout => OperatorDecisionEcho::Timeout,
        OperatorDecision::AutoApproved => OperatorDecisionEcho::AutoApproved,
    }
}

/// Map a [`MutationOutcome`] to whether the audit log should record
/// the call. Every outcome lands in the audit log (even refusals);
/// the function exists so the call site reads as an explicit policy
/// rather than an unconditional write.
const fn should_audit(_outcome: MutationOutcome) -> bool {
    true
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
    ///
    /// Pure-static: counts the `[registries.*]` and `[backends.*]`
    /// tables in the loaded config and picks a deterministic
    /// next-tool hint. Never reaches a backend; safe to call as the
    /// agent's first MCP request.
    #[tool(
        name = "getting_started",
        description = "Overview of SecretEnv + suggested next tool given current state."
    )]
    pub async fn getting_started(
        &self,
        _args: Parameters<GettingStartedArgs>,
    ) -> Json<GettingStartedResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.getting_started");

        let registries = self.config.registries.len();
        let backends = self.config.backends.len();
        let (next_tool, reason) = suggest_next_tool(registries, backends);

        let all_tools: Vec<String> =
            self.tool_router.list_all().into_iter().map(|t| t.name.into_owned()).collect();

        Json(GettingStartedResponse {
            overview: "SecretEnv is a registry of aliases that point at secrets stored in \
                       backends such as 1Password, Vault, AWS SSM, GCP Secret Manager, and \
                       similar systems. This MCP server lets agents inspect and manage that \
                       registry; it never returns a resolved secret value — that surface is \
                       structurally absent. Use `run` from the SecretEnv CLI when a child \
                       process actually needs the value as an environment variable."
                .to_owned(),
            mcp_server_version: env!("CARGO_PKG_VERSION").to_owned(),
            registries_configured: registries,
            backend_instances_configured: backends,
            suggested_next_tool: next_tool.to_owned(),
            suggested_next_tool_reason: reason.to_owned(),
            all_tools,
        })
    }

    /// `SecretEnv` version, `MCP` protocol version, available tools.
    #[tool(
        name = "version_info",
        description = "SecretEnv version, MCP protocol version, available tools."
    )]
    pub async fn version_info(
        &self,
        _args: Parameters<VersionInfoArgs>,
    ) -> Json<VersionInfoResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.version_info");

        let tools = self
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| ToolListing {
                name: t.name.into_owned(),
                description: t.description.map(std::borrow::Cow::into_owned),
            })
            .collect();

        Json(VersionInfoResponse {
            secretenv_version: env!("CARGO_PKG_VERSION").to_owned(),
            mcp_protocol_version: rmcp::model::ProtocolVersion::LATEST.as_str().to_owned(),
            rmcp_sdk_version: RMCP_SDK_VERSION.to_owned(),
            tools,
        })
    }

    /// All alias names + backend type/instance in the registry. Never URIs, never values.
    #[tool(
        name = "list_aliases",
        description = "All alias names + backing backend instance/type for every \
                       `[registries.*]` block. URI paths and resolved values are NEVER \
                       returned — only alias names + how to reach them."
    )]
    pub async fn list_aliases(
        &self,
        _args: Parameters<ListAliasesArgs>,
    ) -> Json<ListAliasesResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.list_aliases");

        let enumeration = aliases::enumerate_all(&self.config).await;
        let total_aliases = enumeration.aliases.len();

        Json(ListAliasesResponse {
            aliases: enumeration.aliases,
            registries: enumeration.registries,
            total_aliases,
        })
    }

    /// All configured backend instances. Config-only; auth probing
    /// is the dedicated job of `doctor`.
    #[tool(
        name = "list_backends",
        description = "All configured backend instances. Reports name + type from config.toml; \
                       auth status is always `unknown` here — call `doctor` or \
                       `detect_password_managers` for live auth probing."
    )]
    pub async fn list_backends(
        &self,
        _args: Parameters<ListBackendsArgs>,
    ) -> Json<ListBackendsResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.list_backends");

        let mut backends: Vec<BackendListing> = self
            .config
            .backends
            .iter()
            .map(|(name, cfg)| BackendListing {
                name: name.clone(),
                backend_type: cfg.backend_type.clone(),
                auth_status: AuthStatus::Unknown,
                auth_status_hint: "Call `doctor` or `detect_password_managers` for a live \
                                   auth probe of this backend's CLI."
                    .to_owned(),
            })
            .collect();
        backends.sort_by(|a, b| a.name.cmp(&b.name));
        let total = backends.len();

        Json(ListBackendsResponse { backends, total })
    }

    /// Whether aliases can currently be resolved. NEVER returns the value.
    #[tool(
        name = "resolve_status",
        description = "Per-registry probe of whether alias resolution would succeed. \
                       Reports the backend instance backing each registry's primary source \
                       URI and that backend's auth status. NEVER returns alias values. \
                       Per-alias resolution lands with `list_aliases` in a follow-up."
    )]
    pub async fn resolve_status(
        &self,
        _args: Parameters<ResolveStatusArgs>,
    ) -> Json<ResolveStatusResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.resolve_status");

        // Run a single doctor probe and reuse its per-instance status
        // map; cheaper than re-probing each backend per registry.
        let probes = doctor::probe_all_backends(&self.config).await;
        let status_by_instance: std::collections::HashMap<_, _> =
            probes.iter().map(|p| (p.instance_name.clone(), p.status.clone())).collect();

        let mut registries: Vec<ResolveStatusRegistryProbe> = self
            .config
            .registries
            .iter()
            .map(|(name, rc)| {
                let primary_instance = rc
                    .sources
                    .first()
                    .and_then(|raw| secretenv_core::BackendUri::parse(raw).ok())
                    .map(|u| u.scheme);

                let (status, hint) = primary_instance.as_deref().map_or_else(
                    || {
                        (
                            AuthStatus::Unknown,
                            format!(
                                "registry `{name}` has no source URIs or the primary URI \
                                 failed to parse"
                            ),
                        )
                    },
                    |inst| match status_by_instance.get(inst) {
                        Some(AuthStatus::Authenticated) => (
                            AuthStatus::Authenticated,
                            format!("registry `{name}` resolvable: backend `{inst}` ok"),
                        ),
                        Some(s) => (
                            s.clone(),
                            format!(
                                "registry `{name}` not resolvable: backend `{inst}` status \
                                 `{s:?}` — call `doctor` for remediation hints"
                            ),
                        ),
                        None => (
                            AuthStatus::Unknown,
                            format!(
                                "registry `{name}` references backend instance `{inst}` \
                                 which is not configured under `[backends.{inst}]`"
                            ),
                        ),
                    },
                );

                ResolveStatusRegistryProbe {
                    registry_name: name.clone(),
                    source_count: rc.sources.len(),
                    primary_source_backend_instance: primary_instance,
                    primary_source_status: status,
                    status_hint: hint,
                }
            })
            .collect();
        registries.sort_by(|a, b| a.registry_name.cmp(&b.registry_name));

        let total_registries = registries.len();
        let resolvable_registries = registries
            .iter()
            .filter(|r| r.primary_source_status == AuthStatus::Authenticated)
            .count();

        Json(ResolveStatusResponse {
            registries,
            total_registries,
            resolvable_registries,
            note: "Per-registry probe only — checks the primary source backend's auth state. \
                   Per-alias resolution requires reading the registry document and lands with \
                   `list_aliases`."
                .to_owned(),
        })
    }

    /// Installed + authenticated secret backend CLIs on this machine.
    #[tool(
        name = "detect_password_managers",
        description = "Installed + authenticated secret backend CLIs on this machine. Probes \
                       every backend type this build supports — not just configured ones — so \
                       an agent can suggest CLIs to install or `[backends.*]` blocks to add."
    )]
    pub async fn detect_password_managers(
        &self,
        _args: Parameters<DetectPasswordManagersArgs>,
    ) -> Json<DetectPasswordManagersResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.detect_password_managers");

        let detections = password_managers::run_all_probes().await;
        let total_supported = detections.len();
        let installed = detections
            .iter()
            .filter(|d| {
                matches!(d.auth_status, AuthStatus::Authenticated | AuthStatus::NotAuthenticated)
            })
            .count();
        let authenticated =
            detections.iter().filter(|d| d.auth_status == AuthStatus::Authenticated).count();

        Json(DetectPasswordManagersResponse {
            detections,
            total_supported,
            installed,
            authenticated,
        })
    }

    /// Three-level health check: CLI installed, authenticated, registry reachable.
    #[tool(
        name = "doctor",
        description = "Three-level health check across every configured `[backends.*]` \
                       instance: CLI installed, authenticated, reachable. Returns \
                       remediation hints; no --fix flag — the agent + operator decide \
                       whether to act on the hints."
    )]
    pub async fn doctor(&self, _args: Parameters<DoctorArgs>) -> Json<DoctorResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.doctor");

        let backends = doctor::probe_all_backends(&self.config).await;
        let total = backends.len();
        let ok = backends.iter().filter(|b| b.status == AuthStatus::Authenticated).count();
        let failures = total.saturating_sub(ok);

        Json(DoctorResponse { backends, total, ok, failures })
    }

    /// Whether runtime redaction is active; count of values that would be masked.
    #[tool(
        name = "redact_status",
        description = "Whether runtime redaction is active; count of values that would be masked. No alias names, no values."
    )]
    pub async fn redact_status(
        &self,
        _args: Parameters<RedactStatusArgs>,
    ) -> Json<RedactStatusResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.redact_status");

        Json(RedactStatusResponse {
            default_redact_mode: DEFAULT_REDACT_MODE.to_owned(),
            available_redact_modes: AVAILABLE_REDACT_MODES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            registries_loaded: self.config.registries.len(),
            note: "MCP tools structurally never return resolved secret values. Runtime \
                   redaction is a `secretenv run` child-process concern, reported here so \
                   an agent can suggest the right `--redact <mode>` flag to an operator \
                   without invoking the CLI."
                .to_owned(),
        })
    }

    // ----- Phase 4: mutation (4) -----------------------------------

    /// Create or update alias → backend-URI mapping. CONFIRM WITH USER before calling.
    #[tool(
        name = "set_alias",
        description = "Create or update an alias → backend-URI mapping in a registry. \
                       CONFIRM WITH USER before calling. Does NOT create or modify the \
                       backend secret itself — only the registry pointer. Subject to \
                       [mcp].allow_mutations policy + recorded in the mutation audit log."
    )]
    pub async fn set_alias(&self, args: Parameters<SetAliasArgs>) -> Json<SetAliasResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.set_alias");
        let args = args.0;

        // Best-effort backend-instance extraction for the response
        // (target_uri may be invalid; the writer below will surface
        // a structured error in that case).
        let backend_instance = secretenv_core::BackendUri::parse(&args.target_uri)
            .map_or_else(|_| "<invalid-uri>".to_owned(), |u| u.scheme);
        let registry_name = args.registry.clone().unwrap_or_else(|| "default".to_owned());

        let policy_request = MutationRequest {
            tool_name: "set_alias",
            action_summary: &format!(
                "set alias `{}` → `{}` in registry `{}`",
                args.alias, args.target_uri, registry_name
            ),
            agent_reason: &args.reason,
        };

        let (decision_echo, outcome, error_message) =
            match enforce_mutation_policy(&self.mcp_config, &policy_request).await {
                Err(e) => {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "set_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: Some(backend_instance.clone()),
                        agent_reason: args.reason.clone(),
                        operator_decision: OperatorDecision::Denied,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    if should_audit(MutationOutcome::Refused) {
                        let _ = self.mutation_log.append(&entry);
                    }
                    (
                        OperatorDecisionEcho::PolicyRefusal,
                        MutationOutcome::Refused,
                        Some(format!("{e:#}")),
                    )
                }
                Ok(decision @ (OperatorDecision::Denied | OperatorDecision::Timeout)) => {
                    let outcome = if decision == OperatorDecision::Timeout {
                        MutationOutcome::Timeout
                    } else {
                        MutationOutcome::Refused
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "set_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: Some(backend_instance.clone()),
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, None)
                }
                Ok(decision @ (OperatorDecision::Approved | OperatorDecision::AutoApproved)) => {
                    let write_result = match secretenv_backends_init::build_registry(&self.config) {
                        Ok(backends) => {
                            registry_writer::set_alias_in_registry(
                                &args.alias,
                                &args.target_uri,
                                args.registry.as_deref(),
                                &self.config,
                                &backends,
                            )
                            .await
                        }
                        Err(e) => Err(e.context("building backend registry for set_alias")),
                    };
                    let (outcome, err) = match write_result {
                        Ok(()) => (MutationOutcome::Applied, None),
                        Err(e) => (MutationOutcome::WriteFailed, Some(format!("{e:#}"))),
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "set_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: Some(backend_instance.clone()),
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, err)
                }
            };

        Json(SetAliasResponse {
            alias_name: args.alias,
            backend_instance,
            registry_name,
            outcome,
            decision: decision_echo,
            error_message,
        })
    }

    /// Remove alias from registry. Backend secret NOT deleted. ALWAYS CONFIRM PER ALIAS.
    #[tool(
        name = "delete_alias",
        description = "Remove an alias from a registry. The underlying backend secret is \
                       NOT deleted — call the backend's native delete CLI for that. \
                       ALWAYS CONFIRM PER ALIAS; never batch without per-alias gates. \
                       Subject to [mcp].allow_mutations + recorded in the audit log."
    )]
    pub async fn delete_alias(
        &self,
        args: Parameters<DeleteAliasArgs>,
    ) -> Json<DeleteAliasResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.delete_alias");
        let args = args.0;
        let registry_name = args.registry.clone().unwrap_or_else(|| "default".to_owned());

        let policy_request = MutationRequest {
            tool_name: "delete_alias",
            action_summary: &format!(
                "remove alias `{}` from registry `{}`",
                args.alias, registry_name
            ),
            agent_reason: &args.reason,
        };

        let (decision_echo, outcome, error_message) =
            match enforce_mutation_policy(&self.mcp_config, &policy_request).await {
                Err(e) => {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "delete_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: OperatorDecision::Denied,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (
                        OperatorDecisionEcho::PolicyRefusal,
                        MutationOutcome::Refused,
                        Some(format!("{e:#}")),
                    )
                }
                Ok(decision @ (OperatorDecision::Denied | OperatorDecision::Timeout)) => {
                    let outcome = if decision == OperatorDecision::Timeout {
                        MutationOutcome::Timeout
                    } else {
                        MutationOutcome::Refused
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "delete_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, None)
                }
                Ok(decision @ (OperatorDecision::Approved | OperatorDecision::AutoApproved)) => {
                    let write_result = match secretenv_backends_init::build_registry(&self.config) {
                        Ok(backends) => {
                            registry_writer::delete_alias_in_registry(
                                &args.alias,
                                args.registry.as_deref(),
                                &self.config,
                                &backends,
                            )
                            .await
                        }
                        Err(e) => Err(e.context("building backend registry for delete_alias")),
                    };
                    let (outcome, err) = match write_result {
                        Ok(()) => (MutationOutcome::Applied, None),
                        Err(e) => (MutationOutcome::WriteFailed, Some(format!("{e:#}"))),
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "delete_alias".to_owned(),
                        alias_name: Some(args.alias.clone()),
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, err)
                }
            };

        Json(DeleteAliasResponse {
            alias_name: args.alias,
            registry_name,
            outcome,
            decision: decision_echo,
            error_message,
        })
    }

    /// Scaffold secretenv.toml; detect .env key names (NOT values).
    #[tool(
        name = "init_project",
        description = "Scaffold a `secretenv.toml` manifest from a `.env` file's KEY NAMES \
                       (values are never read). Default `apply = false` returns the \
                       proposed body without writing. `apply = true` writes the file and \
                       is gated by [mcp].allow_mutations + audit-logged."
    )]
    pub async fn init_project(
        &self,
        args: Parameters<InitProjectArgs>,
    ) -> Json<InitProjectResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.init_project");
        let args = args.0;
        let cwd = args
            .cwd
            .as_deref()
            .map_or_else(|| std::env::current_dir().unwrap_or_default(), std::path::PathBuf::from);

        // Always scaffold (no value access; safe regardless of policy).
        let scaffold = match init_project::scaffold(&cwd) {
            Ok(s) => s,
            Err(e) => {
                return Json(InitProjectResponse {
                    working_directory: cwd.display().to_string(),
                    manifest_path: cwd.join("secretenv.toml").display().to_string(),
                    applied: false,
                    detected_env_keys: Vec::new(),
                    env_file_found: false,
                    manifest_already_existed: false,
                    proposed_manifest_toml: String::new(),
                    outcome: MutationOutcome::WriteFailed,
                    decision: OperatorDecisionEcho::Approved,
                    error_message: Some(format!("{e:#}")),
                });
            }
        };

        // Dry-run (`apply = false`): no mutation, no policy gate, no
        // audit-log entry — proposing is read-only behaviour.
        if !args.apply {
            return Json(InitProjectResponse {
                working_directory: cwd.display().to_string(),
                manifest_path: scaffold.manifest_path.display().to_string(),
                applied: false,
                detected_env_keys: scaffold.detected_keys,
                env_file_found: scaffold.env_file_found,
                manifest_already_existed: scaffold.manifest_already_existed,
                proposed_manifest_toml: scaffold.proposed_toml,
                outcome: MutationOutcome::Applied,
                decision: OperatorDecisionEcho::AutoApproved,
                error_message: None,
            });
        }

        // Apply mode — policy gate + write + audit log.
        let policy_request = MutationRequest {
            tool_name: "init_project",
            action_summary: &format!(
                "write `secretenv.toml` at `{}` (manifest_already_existed={})",
                scaffold.manifest_path.display(),
                scaffold.manifest_already_existed
            ),
            agent_reason: &args.reason,
        };

        let (decision_echo, outcome, error_message) =
            match enforce_mutation_policy(&self.mcp_config, &policy_request).await {
                Err(e) => {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "init_project".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: OperatorDecision::Denied,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (
                        OperatorDecisionEcho::PolicyRefusal,
                        MutationOutcome::Refused,
                        Some(format!("{e:#}")),
                    )
                }
                Ok(decision @ (OperatorDecision::Denied | OperatorDecision::Timeout)) => {
                    let outcome = if decision == OperatorDecision::Timeout {
                        MutationOutcome::Timeout
                    } else {
                        MutationOutcome::Refused
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "init_project".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, None)
                }
                Ok(decision @ (OperatorDecision::Approved | OperatorDecision::AutoApproved)) => {
                    let write_result =
                        std::fs::write(&scaffold.manifest_path, scaffold.proposed_toml.as_bytes())
                            .with_context(|| {
                                format!("writing `{}`", scaffold.manifest_path.display())
                            });
                    let (outcome, err) = match write_result {
                        Ok(()) => (MutationOutcome::Applied, None),
                        Err(e) => (MutationOutcome::WriteFailed, Some(format!("{e:#}"))),
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "init_project".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    (echo_decision(decision), outcome, err)
                }
            };

        Json(InitProjectResponse {
            working_directory: cwd.display().to_string(),
            manifest_path: scaffold.manifest_path.display().to_string(),
            applied: matches!(outcome, MutationOutcome::Applied),
            detected_env_keys: scaffold.detected_keys,
            env_file_found: scaffold.env_file_found,
            manifest_already_existed: scaffold.manifest_already_existed,
            proposed_manifest_toml: scaffold.proposed_toml,
            outcome,
            decision: decision_echo,
            error_message,
        })
    }

    /// Scan file for resolvable secret values and redact.
    #[tool(
        name = "redact_file",
        description = "Scan a file for resolved secret values from a registry's aliases \
                       and (optionally) rewrite in-place with each match replaced by an \
                       alias-aware token. Returns COUNTS only — never the matched bytes. \
                       Apply mode (`apply = true`) is gated by [mcp].allow_mutations + \
                       audit-logged. Default `apply = false` only counts."
    )]
    pub async fn redact_file(&self, args: Parameters<RedactFileArgs>) -> Json<RedactFileResponse> {
        let (_span, _guard) = SecretEnvSpan::start("mcp.tool.redact_file");
        let args = args.0;
        let registry_name = args.registry.clone().unwrap_or_else(|| "default".to_owned());
        let file_path = std::path::PathBuf::from(&args.file_path);

        let mut response = RedactFileResponse {
            file_path: file_path.display().to_string(),
            applied: false,
            registry_name: registry_name.clone(),
            aliases_loaded: 0,
            matches_found: 0,
            bytes_replaced: 0,
            outcome: MutationOutcome::Refused,
            decision: OperatorDecisionEcho::AutoApproved,
            error_message: None,
        };

        // Apply mode → policy gate + audit log. Dry-run mode → no
        // policy gate (counting matches doesn't mutate state) and no
        // audit log (read-only).
        let (allowed_decision, allowed_outcome_on_success) = if args.apply {
            match enforce_mutation_policy(
                &self.mcp_config,
                &MutationRequest {
                    tool_name: "redact_file",
                    action_summary: &format!(
                        "scrub `{}` in-place using registry `{}` aliases",
                        args.file_path, registry_name
                    ),
                    agent_reason: &args.reason,
                },
            )
            .await
            {
                Err(e) => {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "redact_file".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: OperatorDecision::Denied,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    response.outcome = MutationOutcome::Refused;
                    response.decision = OperatorDecisionEcho::PolicyRefusal;
                    response.error_message = Some(format!("{e:#}"));
                    return Json(response);
                }
                Ok(decision @ (OperatorDecision::Denied | OperatorDecision::Timeout)) => {
                    let outcome = if decision == OperatorDecision::Timeout {
                        MutationOutcome::Timeout
                    } else {
                        MutationOutcome::Refused
                    };
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "redact_file".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                    response.outcome = outcome;
                    response.decision = echo_decision(decision);
                    return Json(response);
                }
                Ok(decision @ (OperatorDecision::Approved | OperatorDecision::AutoApproved)) => {
                    (decision, MutationOutcome::Applied)
                }
            }
        } else {
            // Dry-run: pretend AutoApproved so the decision-echo
            // surfaces consistently in the response (no audit log
            // entry written below in this branch).
            (OperatorDecision::AutoApproved, MutationOutcome::Applied)
        };

        // Both branches converge here: build the tainted set + run
        // either the in-place scrub or the dry-run scan. All
        // value-handling lives inside `crate::internal::redact_file`.
        let backends = match secretenv_backends_init::build_registry(&self.config) {
            Ok(r) => r,
            Err(e) => {
                response.outcome = MutationOutcome::WriteFailed;
                response.decision = echo_decision(allowed_decision);
                response.error_message =
                    Some(format!("building backend registry for redact_file: {e:#}"));
                if args.apply {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "redact_file".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: allowed_decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                }
                return Json(response);
            }
        };

        let tainted = match crate::internal::redact_file::build_tainted_set(
            &self.config,
            &backends,
            args.registry.as_deref(),
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                response.outcome = MutationOutcome::WriteFailed;
                response.decision = echo_decision(allowed_decision);
                response.error_message = Some(format!("loading tainted set: {e:#}"));
                if args.apply {
                    let entry = MutationLogEntry {
                        ts_unix_secs: now_secs(),
                        tool_name: "redact_file".to_owned(),
                        alias_name: None,
                        backend_instance: None,
                        agent_reason: args.reason.clone(),
                        operator_decision: allowed_decision,
                        mcp_client_id: "unknown".to_owned(),
                    };
                    let _ = self.mutation_log.append(&entry);
                }
                return Json(response);
            }
        };
        response.aliases_loaded = tainted.len();

        let scrub_result = if args.apply {
            crate::internal::redact_file::scrub_to_file(
                &tainted,
                &file_path,
                args.allow_foreign_owner,
            )
        } else {
            crate::internal::redact_file::scrub_dry_run(
                &tainted,
                &file_path,
                args.allow_foreign_owner,
            )
        };

        match scrub_result {
            Ok(report) => {
                response.outcome = allowed_outcome_on_success;
                response.decision = echo_decision(allowed_decision);
                response.matches_found = report.match_count;
                response.bytes_replaced = report.byte_count;
                response.applied = args.apply;
            }
            Err(e) => {
                response.outcome = MutationOutcome::WriteFailed;
                response.decision = echo_decision(allowed_decision);
                response.error_message = Some(format!("{e:#}"));
            }
        }

        if args.apply {
            let entry = MutationLogEntry {
                ts_unix_secs: now_secs(),
                tool_name: "redact_file".to_owned(),
                alias_name: None,
                backend_instance: None,
                agent_reason: args.reason.clone(),
                operator_decision: allowed_decision,
                mcp_client_id: "unknown".to_owned(),
            };
            let _ = self.mutation_log.append(&entry);
        }

        Json(response)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn suggest_next_tool_no_backends_picks_doctor() {
        let (name, _) = suggest_next_tool(0, 0);
        assert_eq!(name, "doctor");

        let (name, _) = suggest_next_tool(3, 0);
        assert_eq!(name, "doctor", "no backends always picks doctor regardless of registries");
    }

    #[test]
    fn suggest_next_tool_backends_no_registries_picks_list_backends() {
        let (name, _) = suggest_next_tool(0, 2);
        assert_eq!(name, "list_backends");
    }

    #[test]
    fn suggest_next_tool_full_config_picks_list_aliases() {
        let (name, _) = suggest_next_tool(1, 1);
        assert_eq!(name, "list_aliases");

        let (name, _) = suggest_next_tool(5, 10);
        assert_eq!(name, "list_aliases");
    }
}
