// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Tool argument records — one struct per MCP tool the server
//! exposes. Lifted out of `tools/mod.rs` in v0.16.1 Phase D.1 so the
//! `#[tool_router]`-annotated impl block reads as
//! handler-bodies-only, not "arg structs + handler bodies".
//!
//! These structs are referenced by name only — the rmcp `#[tool]`
//! macro reads them via the `Parameters<T>` wrapper at each handler
//! signature, and the per-handler logic lives in `tools/mod.rs`'s
//! impl block (constrained by rmcp's one-impl-block-per-server-type
//! requirement). When v0.16.2 lands the `run_mutation` combinator
//! (carry-forward D.2), the impl block's mutation methods will
//! shrink to one-liners that hand the arg struct + a closure to the
//! combinator.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

/// Argument record for `migrate_alias`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MigrateAliasArgs {
    /// Alias to migrate.
    pub alias: String,
    /// Destination backend URI (e.g.
    /// `"vault-prod:///secret/stripe/api-key"`). Must be a direct
    /// backend URI; `secretenv://` chains are rejected.
    pub dest_uri: String,
    /// Override the resolved source URI. When `None` (default), the
    /// source is the alias's current registry pointer. Used by
    /// recovery flows where the registry already points at the
    /// destination but the value is still in the old backend.
    #[serde(default)]
    pub from: Option<String>,
    /// Optional registry name; defaults to `"default"` when omitted.
    #[serde(default)]
    pub registry: Option<String>,
    /// When `true`, probe destination + source liveness, render the
    /// plan, exit without mutation. Skips policy gate + audit log
    /// (read-only behavior).
    #[serde(default)]
    pub dry_run: bool,
    /// When `true`, delete the source value after a successful
    /// migration commit. Default `false` (Phase 4 mutation
    /// philosophy: dual-control destructive ops). Per build-plan
    /// §1: "Source NOT deleted by default."
    #[serde(default)]
    pub delete_source: bool,
    /// The agent's stated reason. Audit-log only; never echoed.
    pub reason: String,
}

/// Argument record for `gen_password`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GenPasswordArgs {
    /// Alias name to register for the generated value.
    pub alias: String,
    /// Backend URI where the value will be written (e.g.
    /// `"vault-prod:///secret/stripe/api-key"`). Must be a direct
    /// backend URI; `secretenv://` chains are rejected.
    pub target_uri: String,
    /// Charset for the generated value. One of: `"alphanumeric"`,
    /// `"alphanumeric_symbols"`, `"hex"`, `"base64_url_safe"`.
    /// Defaults to `"alphanumeric_symbols"`.
    #[serde(default = "default_charset")]
    pub charset: String,
    /// Number of characters / bytes in the generated value. Must be
    /// between 16 and 1024 (the engine's `MIN_PASSWORD_LEN` and
    /// `MAX_PASSWORD_LEN`). Defaults to 32.
    ///
    /// The schema override below drops schemars' default
    /// `"format": "uint"` annotation (a schemars-specific JSON
    /// Schema extension) — OpenCode's stricter validator rejects
    /// the `uint` format (Phase 8b FINDING-15). All other tested
    /// MCP clients accept the plain `integer` schema with explicit
    /// `minimum`/`maximum` bounds.
    #[serde(default = "default_length")]
    #[schemars(schema_with = "schema_for_length")]
    pub length: usize,
    /// Optional registry name to register the alias under. Defaults
    /// to `"default"`.
    #[serde(default)]
    pub registry: Option<String>,
    /// Force the universal fallback even if the backend supports
    /// native generation (Phase 5b). Phase 5a always uses the
    /// fallback regardless of this flag.
    #[serde(default)]
    pub use_native_generator: Option<bool>,
    /// The agent's stated reason. Audit-log only; never echoed.
    pub reason: String,
}

#[allow(clippy::unnecessary_wraps)]
fn default_charset() -> String {
    "alphanumeric_symbols".to_owned()
}

const fn default_length() -> usize {
    32
}

/// Custom JSON Schema for `GenPasswordArgs::length`. Emits a plain
/// `integer` schema with explicit `minimum`/`maximum` bounds and NO
/// `format` keyword — schemars' default for `usize` is
/// `{"type": "integer", "format": "uint", "minimum": 0}` and the
/// non-standard `"uint"` format trips OpenCode's stricter validator
/// (Phase 8b FINDING-15).
fn schema_for_length(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "integer",
        "minimum": 16,
        "maximum": 1024,
    })
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
