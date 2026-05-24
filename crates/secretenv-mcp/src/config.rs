// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `[mcp]` config-section parsing for the `SecretEnv` `MCP` server.
//!
//! Phase 2c: typed schema + standalone `from_toml_str` parser. The
//! schema is consumed in Phase 4 by the mutation tools (`set_alias`,
//! `delete_alias`, `init_project`, `redact_file`) to decide whether
//! to gate on operator confirmation and where to write the mutation
//! audit log.
//!
//! ```toml
//! [mcp]
//! allow_mutations = "confirm"   # never | confirm | always
//! confirm_via     = "tty"       # tty | notification | none
//! disabled_tools  = []
//! mutation_log    = "$XDG_STATE_HOME/secretenv/mcp-mutations.log"
//! ```
//!
//! Phase 4 will thread this through `secretenv_mcp::serve` so each
//! tool handler can read it. The integration with the shared
//! [`secretenv_core::Config`] (which currently has
//! `#[serde(deny_unknown_fields)]` and would reject an `[mcp]` table)
//! lands in Phase 4 — until then, this module accepts a raw TOML
//! string from the caller.

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
/// Default: [`ConfirmVia::Tty`] — the operator's own terminal handles
/// the prompt, bypassing the IDE's batch-approval gates (which some
/// IDEs surface as "approve all this session").
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmVia {
    /// Default. Prompt on the controlling TTY's stderr with a 30s
    /// timeout. If no TTY is available, the mutation tool returns a
    /// `PermissionDenied` error with a hint string.
    #[default]
    Tty,
    /// Desktop notification (via the host OS); the operator approves
    /// in the notification UI. Implementation lands in Phase 4.
    Notification,
    /// No confirmation surface — equivalent to
    /// [`AllowMutations::Always`] but emitted as a distinct flag so
    /// the mutation audit log captures the explicit operator choice.
    None,
}

/// Typed `[mcp]` config section.
///
/// All fields have defaults; an absent `[mcp]` table or any missing
/// field is equivalent to [`McpConfig::default`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Mutation tool policy. Default: [`AllowMutations::Confirm`].
    pub allow_mutations: AllowMutations,
    /// Confirmation surface for [`AllowMutations::Confirm`]. Default:
    /// [`ConfirmVia::Tty`].
    pub confirm_via: ConfirmVia,
    /// Per-tool disable list — tools listed here are absent from
    /// `tools/list` regardless of `allow_mutations`. Use to disable a
    /// single tool surgically (e.g. ban `gen_password` in production).
    pub disabled_tools: Vec<String>,
    /// Path for the mutation audit log. `None` falls back to
    /// `$XDG_STATE_HOME/secretenv/mcp-mutations.log` at runtime (the
    /// fallback is computed by the audit-log writer, not this config
    /// parser, so the default value here stays config-agnostic).
    pub mutation_log: Option<String>,
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
    /// Other tables (`[registries]`, `[backends]`, etc.) are ignored
    /// — this parser is a strict subset that owns only the `[mcp]`
    /// schema. Returns [`McpConfig::default`] if the table is absent.
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
        // The outer parse treats every non-[mcp] field as Unknown but
        // we explicitly allow them by using a wrapper struct with
        // only the `mcp` field declared. `#[serde(default)]` on the
        // wrapper drops unknown top-level tables silently — that's
        // intentional: this parser is a single-section reader, not a
        // full-config validator.
        let parsed: ConfigWrapper =
            toml::from_str(body).context("parsing config.toml for [mcp] section")?;
        Ok(parsed.mcp.unwrap_or_default())
    }

    /// Parse a typed [`McpConfig`] out of the `toml::Value` that
    /// `secretenv_core::Config` carries in its `mcp` field.
    ///
    /// `None` → [`McpConfig::default`] (`allow_mutations = Confirm`,
    /// `confirm_via = Tty`, no disabled tools, default audit-log
    /// path).
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a TOML table or contains
    /// an unknown field / invalid enum value.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_gives_default() {
        let cfg = McpConfig::from_toml_str("").unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Confirm);
        assert_eq!(cfg.confirm_via, ConfirmVia::Tty);
        assert!(cfg.disabled_tools.is_empty());
        assert!(cfg.mutation_log.is_none());
    }

    #[test]
    fn no_mcp_section_gives_default() {
        let body = r#"
            [registries.dev]
            sources = ["local://./registry.toml"]
        "#;
        let cfg = McpConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Confirm);
    }

    #[test]
    fn full_mcp_section_parses() {
        let body = r#"
            [mcp]
            allow_mutations = "never"
            confirm_via = "notification"
            disabled_tools = ["gen_password", "redact_file"]
            mutation_log = "/var/log/secretenv-mcp.log"
        "#;
        let cfg = McpConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Never);
        assert_eq!(cfg.confirm_via, ConfirmVia::Notification);
        assert_eq!(cfg.disabled_tools, vec!["gen_password", "redact_file"]);
        assert_eq!(cfg.mutation_log.as_deref(), Some("/var/log/secretenv-mcp.log"));
    }

    #[test]
    fn partial_mcp_section_inherits_defaults() {
        let body = r#"
            [mcp]
            allow_mutations = "always"
        "#;
        let cfg = McpConfig::from_toml_str(body).unwrap();
        assert_eq!(cfg.allow_mutations, AllowMutations::Always);
        assert_eq!(cfg.confirm_via, ConfirmVia::Tty); // default
        assert!(cfg.disabled_tools.is_empty());
    }

    #[test]
    fn unknown_field_in_mcp_rejected() {
        let body = r#"
            [mcp]
            disabled_tool = ["typo"]
        "#;
        assert!(McpConfig::from_toml_str(body).is_err(), "typo should be rejected");
    }

    #[test]
    fn invalid_enum_value_rejected() {
        let body = r#"
            [mcp]
            allow_mutations = "maybe"
        "#;
        assert!(McpConfig::from_toml_str(body).is_err());
    }
}
