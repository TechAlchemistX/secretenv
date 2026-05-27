// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed `[mcp]` config-section schema for the SecretEnv MCP server.
//!
//! Extracted from `secretenv-mcp` in v0.16.2 Phase 3 D.5 per the
//! v0.16 Phase 7 architecture audit (C-1).
//!
//! Hosts the data definitions:
//!   - the enums [`AllowMutations`] + [`ConfirmVia`];
//!   - the typed [`McpConfig`] struct;
//!   - [`PolicyOverrides`] for per-launch CLI overrides;
//!   - the `toml::Value` ↔ typed `McpConfig` parser.
//!
//! Does NOT pull the rmcp / runtime / audit-log / I/O surface — so a
//! consumer that only needs the config types pays a small dep cost.
//!
//! Future consumers (e.g. a slimmer `secretenv doctor` validating the
//! `[mcp]` table at config-load time without spinning up the MCP
//! server) can depend on this crate alone. `secretenv-mcp` continues
//! to re-export every type at its previous path for backward
//! compatibility.
//!
//! # Two-stage parse model
//!
//! The `[mcp]` table is carried opaquely by `secretenv_core::Config`
//! as `Option<toml::Value>` so the core's
//! `#[serde(deny_unknown_fields)]` loader does not reject it. This
//! crate re-parses the opaque value into a typed [`McpConfig`] via
//! [`McpConfig::from_core_value`] (or [`McpConfig::from_toml_str`]
//! for tests + standalone parsers).
//!
//! ```toml
//! [mcp]
//! allow_mutations              = "confirm"   # never | confirm | always
//! confirm_via                  = "auto"      # auto | elicitation | tty | notification | none
//! disabled_tools               = []
//! mutation_log                 = "$XDG_STATE_HOME/secretenv/mcp-mutations.log"
//! audit_log_max_bytes          = 10485760    # 10 MiB
//! audit_log_max_rotations      = 5
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;

/// Policy for tools that mutate registry / filesystem state.
///
/// Default: [`AllowMutations::Confirm`] — every mutation tool call
/// surfaces a per-call confirmation prompt before proceeding.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AllowMutations {
    /// Refuse every mutation tool call. Mutation tools are absent
    /// from `tools/list` when this is set.
    Never,
    /// Default. Each mutation tool call gates on an operator
    /// confirmation surfaced per [`McpConfig::confirm_via`].
    #[default]
    Confirm,
    /// Auto-approve every mutation. Use ONLY in air-gapped /
    /// trusted-agent environments — the mutation audit log still
    /// records every call.
    Always,
}

/// Where the per-call confirmation prompt is surfaced when
/// [`AllowMutations::Confirm`] is active.
///
/// **Default since v0.16 Phase 7c: [`ConfirmVia::Auto`]** — runtime
/// detection picks the right surface based on client capabilities.
/// This replaces the previous v0.16-pre-Phase-7c default of
/// [`ConfirmVia::Tty`] which deadlocked inside TUI host IDEs
/// (Claude Code, Cline, etc.) that own the controlling terminal.
///
/// Phase 7c FINDING-4: a stdio child process opening `/dev/tty`
/// while the parent IDE owns the same TTY in raw mode causes the
/// parent's UI to freeze (the child's blocking read contends with
/// the parent's raw-mode read; the kernel only delivers input to
/// the foreground process group; neither process can make
/// progress). [`ConfirmVia::Elicitation`] uses MCP's server→client
/// elicit RPC to surface the prompt through the IDE's own approval
/// UI — same dialog mechanism the IDE uses to gate arbitrary tool
/// calls. The variant is gated by the rmcp `elicitation` feature
/// and only works against clients that declare the elicitation
/// capability at the initialize handshake.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ConfirmVia {
    /// Default since v0.16 Phase 7c. Resolved at runtime per request:
    /// - If the client declared the MCP elicitation capability at
    ///   the initialize handshake, use [`ConfirmVia::Elicitation`].
    /// - Else if `stdin` is a TTY (the server is running standalone
    ///   in an interactive shell, not as an IDE-spawned subprocess),
    ///   use [`ConfirmVia::Tty`].
    /// - Else refuse the mutation with a clear error pointing at
    ///   `allow_mutations = "always"` or installing an IDE that
    ///   supports MCP elicitation.
    #[default]
    Auto,
    /// MCP server→client elicit RPC. Surfaces an approval prompt in
    /// the host IDE's native UI (the same dialog the IDE uses to
    /// gate tool calls). The client must declare the elicitation
    /// capability at the initialize handshake; otherwise the
    /// mutation is refused with a clear error message. **Preferred
    /// for any IDE-driven MCP host since v0.16 Phase 7c.**
    Elicitation,
    /// Prompt on the controlling TTY's stderr with a 30s timeout.
    /// **DEADLOCKS inside TUI host IDEs that own the controlling
    /// terminal in raw mode** (Claude Code, Cline, `OpenCode` TUI,
    /// Codex REPL, etc.); only safe for standalone `secretenv mcp
    /// serve` from an interactive shell. [`ConfirmVia::Auto`]
    /// picks this when the client doesn't advertise elicitation
    /// AND `stdin` is a TTY.
    Tty,
    /// Desktop notification (via the host OS); the operator
    /// approves in the notification UI. Implementation lands in a
    /// follow-up cycle; currently returns an error if selected.
    Notification,
    /// No confirmation surface — equivalent to
    /// [`AllowMutations::Always`] but emitted as a distinct flag so
    /// the mutation audit log captures the explicit operator
    /// choice.
    None,
}

/// Typed `[mcp]` config section.
///
/// All fields have defaults; an absent `[mcp]` table or any missing
/// field is equivalent to [`McpConfig::default`].
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Mutation tool policy. Default: [`AllowMutations::Confirm`].
    pub allow_mutations: AllowMutations,
    /// Confirmation surface for [`AllowMutations::Confirm`].
    /// Default: [`ConfirmVia::Auto`].
    pub confirm_via: ConfirmVia,
    /// Per-tool disable list — tools listed here are absent from
    /// `tools/list` regardless of `allow_mutations`. Use to disable
    /// a single tool surgically (e.g. ban `gen_password` in
    /// production).
    pub disabled_tools: Vec<String>,
    /// Path for the mutation audit log. `None` falls back to
    /// `$XDG_STATE_HOME/secretenv/mcp-mutations.log` at runtime
    /// (the fallback is computed by the audit-log writer in
    /// `secretenv-mcp`, not this config parser, so the default
    /// value here stays config-agnostic).
    pub mutation_log: Option<String>,
    /// Maximum size (bytes) the audit log may reach before the
    /// `MutationLog` writer in `secretenv-mcp` rotates. Default
    /// 10 MiB (10 * 1024 * 1024). Set to `0` to disable size-based
    /// rotation (the log grows unbounded; the operator is
    /// responsible for external rotation). v0.16.2 D.3.
    #[serde(default = "default_audit_log_max_bytes")]
    pub audit_log_max_bytes: u64,
    /// Maximum number of rotated audit-log files to retain (e.g. a
    /// value of 5 keeps `mcp-mutations.log.1` through
    /// `mcp-mutations.log.5`; older files are removed at rotation
    /// time). Default 5. Set to `0` to disable retention (each
    /// rotation truncates the current log without writing a `.1`
    /// archive). v0.16.2 D.3.
    #[serde(default = "default_audit_log_max_rotations")]
    pub audit_log_max_rotations: u32,
}

const fn default_audit_log_max_bytes() -> u64 {
    10 * 1024 * 1024
}

const fn default_audit_log_max_rotations() -> u32 {
    5
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            allow_mutations: AllowMutations::default(),
            confirm_via: ConfirmVia::default(),
            disabled_tools: Vec::new(),
            mutation_log: None,
            audit_log_max_bytes: default_audit_log_max_bytes(),
            audit_log_max_rotations: default_audit_log_max_rotations(),
        }
    }
}

/// Top-level wrapper used to extract just `[mcp]` from an arbitrary
/// `config.toml` body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigWrapper {
    mcp: Option<McpConfig>,
}

impl McpConfig {
    /// Parse the `[mcp]` table out of a `config.toml` body.
    ///
    /// Other tables (`[registries]`, `[backends]`, etc.) are
    /// ignored — this parser is a strict subset that owns only the
    /// `[mcp]` schema. Returns [`McpConfig::default`] if the table
    /// is absent.
    ///
    /// Unknown fields WITHIN `[mcp]` are rejected — this keeps
    /// `disabled_tools` typos like `disabled_tool` from silently
    /// passing through.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid TOML, or if the
    /// `[mcp]` table contains an unknown field or an invalid enum
    /// value (e.g. `allow_mutations = "maybe"`).
    pub fn from_toml_str(body: &str) -> Result<Self> {
        // The outer parse treats every non-[mcp] field as Unknown
        // but we explicitly allow them by using a wrapper struct
        // with only the `mcp` field declared. `#[serde(default)]`
        // on the wrapper drops unknown top-level tables silently
        // — that's intentional: this parser is a single-section
        // reader, not a full-config validator.
        let parsed: ConfigWrapper =
            toml::from_str(body).context("parsing config.toml for [mcp] section")?;
        Ok(parsed.mcp.unwrap_or_default())
    }

    /// Parse a typed [`McpConfig`] out of the `toml::Value` that
    /// `secretenv_core::Config` carries in its `mcp` field.
    ///
    /// `None` → [`McpConfig::default`].
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a TOML table or
    /// contains an unknown field / invalid enum value.
    pub fn from_core_value(value: Option<&toml::Value>) -> Result<Self> {
        value.map_or_else(
            || Ok(Self::default()),
            |v| {
                v.clone()
                    .try_into::<Self>()
                    .context("parsing [mcp] section from secretenv_core::Config")
            },
        )
    }
}

/// Per-launch policy overrides applied AFTER the `[mcp]` section.
///
/// Loaded from `config.toml`, then overlaid with these per-launch
/// values. Used by per-IDE setup blocks (e.g. `secretenv mcp setup
/// --ide gemini` emits `--allow-mutations always` in its `args[]`
/// because Gemini CLI 0.43.0 does not advertise the MCP elicitation
/// capability).
///
/// `None` means "use the config value (or default if absent)".
/// `Some` overrides it.
///
/// # Layering — three sources, in increasing precedence
///
/// 1. **[`McpConfig::default`]** — built-in defaults
///    (`allow_mutations = Confirm`, `confirm_via = Auto`, no
///    disabled tools, default audit-log path).
/// 2. **`[mcp]` table in `config.toml`** — operator-global stance,
///    parsed via [`McpConfig::from_core_value`].
/// 3. **`PolicyOverrides`** — per-launch / per-IDE override layer
///    threaded in from `secretenv mcp serve --allow-mutations <X>`
///    / `--confirm-via <Y>`. This is what the v0.16 Phase 7f
///    per-IDE `extra_args` mechanism uses to scope a workaround to
///    a specific IDE without contaminating the operator's global
///    config.
///
/// Future drift to watch: v0.17 may add an `allow_cli_overrides =
/// false` knob to `[mcp]` (carry-forward F-3) so an operator can
/// veto the per-launch layer from user-scope config. If that
/// lands, the precedence chain becomes 4-stage with the new knob
/// sitting between stages 2 and 3.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverrides {
    /// Override for `[mcp].allow_mutations`. `None` = inherit from
    /// the config layer (which itself falls back to
    /// [`AllowMutations::Confirm`]).
    pub allow_mutations: Option<AllowMutations>,
    /// Override for `[mcp].confirm_via`. `None` = inherit from the
    /// config layer (which itself falls back to
    /// [`ConfirmVia::Auto`]).
    pub confirm_via: Option<ConfirmVia>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_gives_default() {
        let cfg = McpConfig::from_toml_str("").unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Confirm);
        assert_eq!(cfg.confirm_via, ConfirmVia::Auto);
        assert!(cfg.disabled_tools.is_empty());
        assert_eq!(cfg.mutation_log, None);
        assert_eq!(cfg.audit_log_max_bytes, 10 * 1024 * 1024);
        assert_eq!(cfg.audit_log_max_rotations, 5);
    }

    #[test]
    fn parses_full_table() {
        let body = r#"
            [mcp]
            allow_mutations         = "always"
            confirm_via             = "tty"
            disabled_tools          = ["gen_password"]
            mutation_log            = "/tmp/m.log"
            audit_log_max_bytes     = 65536
            audit_log_max_rotations = 3
        "#;
        let cfg = McpConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Always);
        assert_eq!(cfg.confirm_via, ConfirmVia::Tty);
        assert_eq!(cfg.disabled_tools, vec!["gen_password".to_owned()]);
        assert_eq!(cfg.mutation_log.as_deref(), Some("/tmp/m.log"));
        assert_eq!(cfg.audit_log_max_bytes, 65536);
        assert_eq!(cfg.audit_log_max_rotations, 3);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let body = r#"
            [mcp]
            allow_mutations = "confirm"
            mystery_field   = "oops"
        "#;
        assert!(McpConfig::from_toml_str(body).is_err());
    }

    #[test]
    fn invalid_enum_is_rejected() {
        let body = r#"
            [mcp]
            allow_mutations = "maybe"
        "#;
        assert!(McpConfig::from_toml_str(body).is_err());
    }

    #[test]
    fn ignores_non_mcp_top_level_tables() {
        let body = r#"
            [registries.default]
            sources = ["local:///nope"]
            [mcp]
            allow_mutations = "never"
        "#;
        let cfg = McpConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Never);
    }

    #[test]
    fn from_core_value_round_trip() {
        // Parse a [mcp] table into a toml::Value, then run it
        // through from_core_value — should match from_toml_str.
        let body = r#"
            [mcp]
            allow_mutations = "always"
        "#;
        let parsed: toml::Value = toml::from_str(body).unwrap();
        let mcp_val = parsed.get("mcp").cloned();
        let cfg = McpConfig::from_core_value(mcp_val.as_ref()).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Always);
    }

    #[test]
    fn from_core_value_none_gives_default() {
        let cfg = McpConfig::from_core_value(None).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Confirm);
    }
}
