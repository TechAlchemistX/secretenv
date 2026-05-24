// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-IDE MCP client configuration helper.
//!
//! Backs `secretenv mcp setup --ide <name>`. Holds the per-IDE
//! config-file path + on-disk format + JSON/TOML shape needed to
//! register `secretenv mcp serve` as an MCP server with each
//! supported IDE.
//!
//! This module is pure metadata + templating — no filesystem I/O at
//! the module level. The CLI dispatcher (`cmd_mcp::Setup`) decides
//! whether to print to stdout or write the rendered config to disk.
//!
//! # IDEs supported (v0.16)
//!
//! 1. `Claude Code` (Anthropic)
//! 2. `Cursor`
//! 3. `Codex` (`OpenAI` CLI)
//! 4. VS Code + `GitHub Copilot`
//! 5. `Continue` (VS Code / `JetBrains`)
//! 6. `Cline` (VS Code)
//! 7. `Gemini Code Assist` (Google)
//! 8. `OpenCode`
//!
//! Adding a new IDE: append to [`IDE_PROFILES`] and pick the best
//! matching [`ConfigShape`] (or add a new variant if it doesn't fit).

use std::path::PathBuf;

/// MCP server registration name written into each IDE's config file.
/// Stable across IDEs so an operator running across 8 IDEs sees the
/// same server name everywhere.
const SERVER_KEY: &str = "secretenv";

/// Argv used by every IDE config: `secretenv mcp serve`.
const SERVE_ARGV: &[&str] = &["mcp", "serve"];

/// On-disk file format the IDE expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// IDE's config file is JSON.
    Json,
    /// IDE's config file is TOML.
    Toml,
}

/// The "shape" of the MCP-server registration block inside the IDE's
/// config file. Different IDEs nest the server entry under different
/// keys + use slightly different field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigShape {
    /// `{ "mcpServers": { "secretenv": { "command": "secretenv", "args": ["mcp","serve"] } } }`
    /// — used by Claude Code, Cursor, Cline, Gemini Code Assist.
    JsonMcpServers,
    /// `{ "servers": { "secretenv": { "type": "stdio", "command": "secretenv", "args": ["mcp","serve"] } } }`
    /// — VS Code Copilot's `.vscode/mcp.json` workspace form.
    JsonVsCodeServers,
    /// `{ "experimental": { "modelContextProtocolServers": [ { "transport": { "type": "stdio", "command": "secretenv", "args": ["mcp","serve"] } } ] } }`
    /// — Continue's nested array form.
    JsonContinueExperimental,
    /// `{ "mcp": { "secretenv": { "type": "local", "command": ["secretenv","mcp","serve"] } } }`
    /// — `OpenCode`'s `command-as-list` shape.
    JsonOpenCode,
    /// `[mcp_servers.secretenv]` with `command = "secretenv"` + `args = ["mcp","serve"]`.
    /// — Codex CLI's `~/.codex/config.toml` form.
    TomlMcpServersTable,
}

/// IDE profile — metadata for one supported IDE.
///
/// Stable across releases: a stored config file written by v0.16's
/// helper continues to work with v0.17+ as long as the IDE doesn't
/// change its config shape. The helper writes a self-contained block,
/// not a generated file — operator-owned content alongside the
/// registration block is preserved by the merge logic in the CLI
/// dispatcher (`cmd_mcp::Setup`).
#[derive(Debug, Clone)]
pub struct IdeProfile {
    /// CLI-facing key (kebab-case). Used as the `--ide <key>` value.
    pub key: &'static str,
    /// Human-readable name for help/listing output.
    pub display_name: &'static str,
    /// Config-file path with `~` for the user's home directory. The
    /// CLI dispatcher expands this via [`expand_home`].
    pub config_path: &'static str,
    /// File format the IDE expects on disk.
    pub format: FileFormat,
    /// Block shape to render under [`SERVER_KEY`].
    pub shape: ConfigShape,
    /// One-line note shown alongside the rendered block (e.g. "VS
    /// Code: place under `.vscode/` in the workspace, not `$HOME`").
    pub note: &'static str,
}

/// All 8 IDEs supported by v0.16's setup helper.
pub const IDE_PROFILES: &[IdeProfile] = &[
    IdeProfile {
        key: "claude-code",
        display_name: "Claude Code (Anthropic)",
        config_path: "~/.config/claude-code/mcp.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "Per-project override: `.claude/mcp.json` at the repo root.",
    },
    IdeProfile {
        key: "cursor",
        display_name: "Cursor",
        config_path: "~/.cursor/mcp.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "Per-project override: `.cursor/mcp.json` at the repo root.",
    },
    IdeProfile {
        key: "codex",
        display_name: "Codex (OpenAI CLI)",
        config_path: "~/.codex/config.toml",
        format: FileFormat::Toml,
        shape: ConfigShape::TomlMcpServersTable,
        note: "Codex CLI config is TOML; merge under existing tables if present.",
    },
    IdeProfile {
        key: "vscode-copilot",
        display_name: "VS Code + GitHub Copilot",
        config_path: ".vscode/mcp.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonVsCodeServers,
        note: "Workspace-scoped: place at `.vscode/mcp.json` in the repo, not $HOME.",
    },
    IdeProfile {
        key: "continue",
        display_name: "Continue",
        config_path: "~/.continue/config.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonContinueExperimental,
        note: "Continue nests MCP servers under `experimental.modelContextProtocolServers` (array).",
    },
    IdeProfile {
        key: "cline",
        display_name: "Cline (VS Code)",
        config_path: "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "macOS path. Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`.",
    },
    IdeProfile {
        key: "gemini",
        display_name: "Gemini Code Assist (Google)",
        config_path: "~/.gemini/settings.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "Restart your editor after editing this file for Gemini to re-scan.",
    },
    IdeProfile {
        key: "opencode",
        display_name: "OpenCode",
        config_path: "~/.config/opencode/opencode.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonOpenCode,
        note: "OpenCode uses a `command`-as-list form; safe to merge under an existing `mcp` block.",
    },
];

/// Look up an IDE profile by its `--ide` key.
#[must_use]
pub fn find_profile(key: &str) -> Option<&'static IdeProfile> {
    IDE_PROFILES.iter().find(|p| p.key == key)
}

/// Expand a leading `~/` to the user's home directory. Returns the
/// path unchanged if no `~` prefix is present.
///
/// # Errors
///
/// Returns an error if the path starts with `~/` but `$HOME` is
/// unset / unreadable.
pub fn expand_home(p: &str) -> Result<PathBuf, std::io::Error> {
    if let Some(rest) = p.strip_prefix("~/") {
        let home =
            std::env::var_os("HOME").ok_or_else(|| std::io::Error::other("$HOME is not set"))?;
        Ok(PathBuf::from(home).join(rest))
    } else if p == "~" {
        let home =
            std::env::var_os("HOME").ok_or_else(|| std::io::Error::other("$HOME is not set"))?;
        Ok(PathBuf::from(home))
    } else {
        Ok(PathBuf::from(p))
    }
}

/// Render the MCP-server registration block for `profile`.
///
/// Output is the COMPLETE file body suitable for writing to
/// [`IdeProfile::config_path`] when the file does not already exist.
/// When merging with an existing file, the CLI dispatcher reads the
/// existing JSON/TOML, splices the `secretenv` key under the
/// shape-appropriate path, and writes back.
///
/// The `binary_path` argument is the absolute path (or `secretenv`
/// as a `$PATH`-resolved name) to the `secretenv` binary that the
/// IDE will spawn. Defaults to `"secretenv"` (relies on the user's
/// `$PATH`); pass an absolute path for portable per-IDE setup that
/// works regardless of shell init.
#[must_use]
pub fn render_config(profile: &IdeProfile, binary_path: &str) -> String {
    let args_json = SERVE_ARGV.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", ");

    match profile.shape {
        ConfigShape::JsonMcpServers => format!(
            "{{\n  \"mcpServers\": {{\n    \"{SERVER_KEY}\": {{\n      \"command\": \"{binary_path}\",\n      \"args\": [{args_json}]\n    }}\n  }}\n}}\n"
        ),
        ConfigShape::JsonVsCodeServers => format!(
            "{{\n  \"servers\": {{\n    \"{SERVER_KEY}\": {{\n      \"type\": \"stdio\",\n      \"command\": \"{binary_path}\",\n      \"args\": [{args_json}]\n    }}\n  }}\n}}\n"
        ),
        ConfigShape::JsonContinueExperimental => format!(
            "{{\n  \"experimental\": {{\n    \"modelContextProtocolServers\": [\n      {{\n        \"transport\": {{\n          \"type\": \"stdio\",\n          \"command\": \"{binary_path}\",\n          \"args\": [{args_json}]\n        }}\n      }}\n    ]\n  }}\n}}\n"
        ),
        ConfigShape::JsonOpenCode => {
            let argv_with_bin = std::iter::once(binary_path)
                .chain(SERVE_ARGV.iter().copied())
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{{\n  \"mcp\": {{\n    \"{SERVER_KEY}\": {{\n      \"type\": \"local\",\n      \"command\": [{argv_with_bin}]\n    }}\n  }}\n}}\n"
            )
        }
        ConfigShape::TomlMcpServersTable => format!(
            "[mcp_servers.{SERVER_KEY}]\ncommand = \"{binary_path}\"\nargs = [{args_json}]\n"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_ide_key_unique() {
        let mut keys: Vec<_> = IDE_PROFILES.iter().map(|p| p.key).collect();
        keys.sort_unstable();
        let n_before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), n_before, "duplicate IDE keys");
    }

    #[test]
    fn lookup_returns_matching_profile() {
        assert_eq!(find_profile("claude-code").unwrap().key, "claude-code");
        assert_eq!(find_profile("cursor").unwrap().key, "cursor");
        assert!(find_profile("nonexistent").is_none());
    }

    #[test]
    fn renders_claude_code_block() {
        let profile = find_profile("claude-code").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"mcpServers\""));
        assert!(body.contains("\"secretenv\""));
        assert!(body.contains("\"command\": \"secretenv\""));
        assert!(body.contains("\"mcp\""));
        assert!(body.contains("\"serve\""));
    }

    #[test]
    fn renders_vscode_copilot_with_type_stdio() {
        let profile = find_profile("vscode-copilot").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"servers\""));
        assert!(body.contains("\"type\": \"stdio\""));
        assert!(!body.contains("\"mcpServers\""));
    }

    #[test]
    fn renders_codex_toml_table() {
        let profile = find_profile("codex").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("[mcp_servers.secretenv]"));
        assert!(body.contains("command = \"secretenv\""));
        assert!(body.contains("args = [\"mcp\", \"serve\"]"));
    }

    #[test]
    fn renders_continue_nested_array() {
        let profile = find_profile("continue").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"experimental\""));
        assert!(body.contains("\"modelContextProtocolServers\""));
        assert!(body.contains("\"transport\""));
    }

    #[test]
    fn renders_opencode_command_as_list() {
        let profile = find_profile("opencode").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"mcp\""));
        assert!(body.contains("\"type\": \"local\""));
        assert!(body.contains("\"command\": [\"secretenv\", \"mcp\", \"serve\"]"));
    }

    #[test]
    fn renders_cline_with_macos_path() {
        let profile = find_profile("cline").unwrap();
        assert!(profile.config_path.contains("saoudrizwan.claude-dev"));
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"mcpServers\""));
    }

    #[test]
    fn renders_gemini_with_basic_shape() {
        let profile = find_profile("gemini").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"mcpServers\""));
        assert!(body.contains("\"secretenv\""));
    }

    #[test]
    fn render_honors_absolute_binary_path() {
        let profile = find_profile("claude-code").unwrap();
        let body = render_config(profile, "/usr/local/bin/secretenv");
        assert!(body.contains("\"command\": \"/usr/local/bin/secretenv\""));
    }

    #[test]
    fn render_for_every_profile_is_nonempty_and_mentions_secretenv() {
        for profile in IDE_PROFILES {
            let body = render_config(profile, "secretenv");
            assert!(!body.is_empty(), "{} rendered empty", profile.key);
            assert!(
                body.contains("secretenv"),
                "{} rendering missing `secretenv` string",
                profile.key,
            );
        }
    }

    #[test]
    fn expand_home_basic() {
        if std::env::var_os("HOME").is_none() {
            return;
        }
        let expanded = expand_home("~/.config/foo").unwrap();
        assert!(!expanded.to_string_lossy().starts_with('~'));
        assert!(expanded.to_string_lossy().contains(".config/foo"));
    }

    #[test]
    fn expand_home_passes_absolute_unchanged() {
        let expanded = expand_home("/etc/something").unwrap();
        assert_eq!(expanded, PathBuf::from("/etc/something"));
    }

    #[test]
    fn expand_home_passes_relative_unchanged() {
        let expanded = expand_home(".vscode/mcp.json").unwrap();
        assert_eq!(expanded, PathBuf::from(".vscode/mcp.json"));
    }
}
