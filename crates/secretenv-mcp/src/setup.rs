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

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value as JsonValue;

/// MCP server registration name written into each IDE's config file.
/// Stable across IDEs so an operator running across 8 IDEs sees the
/// same server name everywhere.
const SERVER_KEY: &str = "secretenv";

/// Base argv used by every IDE config: `secretenv mcp serve`. Per-IDE
/// profiles may APPEND extra args via [`IdeProfile::extra_args`] —
/// e.g. Gemini CLI 0.43.0 doesn't advertise MCP elicitation capability
/// so its profile appends `--allow-mutations=always` to bypass the
/// confirmation gate (mutations still audit-logged) without weakening
/// the operator's global `[mcp]` config (v0.16 Phase 7f addition).
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
    /// Shell command form: `claude mcp add -s user secretenv -- secretenv mcp serve`.
    /// Claude Code's official CLI mechanism — safely merges into the
    /// large `~/.claude.json` config without overwriting other keys
    /// (which a `JsonMcpServers` write would risk). Print-only;
    /// `--write` is refused for this shape (the operator runs the
    /// command themselves).
    ShellClaudeMcpAdd,
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
    /// Per-IDE extra args APPENDED after [`SERVE_ARGV`]. Used to
    /// scope CLI-flag policy overrides to specific IDEs without
    /// touching the operator's global `[mcp]` config. Default empty
    /// for IDEs that work with the default policy stack.
    ///
    /// # Evolution trap (READ before adding/removing entries)
    ///
    /// Every non-empty `extra_args` here is a workaround for a
    /// specific gap in an upstream IDE — usually that the IDE does
    /// not advertise the MCP `elicitation` capability at the
    /// initialize handshake (so [`crate::config::ConfirmVia::Auto`]
    /// cannot use elicitation, and `/dev/tty` deadlocks inside the
    /// IDE's raw-mode terminal). The current `--allow-mutations,
    /// always` overrides on Gemini / Cline / Codex / `OpenCode` /
    /// VS Code Copilot / Cursor / Continue are all Phase 8b
    /// empirical findings; see `reference_v0.16_phase8b_results`.
    ///
    /// **When an IDE ships elicitation upstream**, REMOVE its
    /// override here in the next hygiene cycle — the safer
    /// per-mutation confirmation modal fires instead. Run
    /// `secretenv mcp setup --ide <key> --dry-run` after each IDE
    /// version bump to verify; or build a `--check-overrides`
    /// detector (v0.17 R-3 carry-forward).
    ///
    /// **When adding a new IDE**, default to `&[]` and only add an
    /// override after testing end-to-end that the IDE refuses or
    /// hangs on a mutation with the default stack — don't
    /// pre-emptively widen the trust surface.
    pub extra_args: &'static [&'static str],
}

/// All 8 IDEs supported by v0.16's setup helper.
pub const IDE_PROFILES: &[IdeProfile] = &[
    IdeProfile {
        key: "claude-code",
        display_name: "Claude Code (Anthropic)",
        // The actual user-scope config lives at `~/.claude.json` (a
        // large file with many other Claude Code state keys). v0.16
        // Phase 7c FINDING-1: the official safe mechanism is
        // `claude mcp add` which merges in-place. Per-project
        // alternative: `.mcp.json` at the repo root (smaller scope,
        // safer to write).
        config_path: "(run the shell command below — no file to edit by hand)",
        format: FileFormat::Json,
        shape: ConfigShape::ShellClaudeMcpAdd,
        note: "User-scope config is `~/.claude.json` — never edit by hand (1000+ lines of Claude Code state). Per-project alternative: paste an `mcpServers` block into `.mcp.json` at the repo root, or use `--ide generic` for the JSON shape.",
        extra_args: &[],
    },
    IdeProfile {
        key: "cursor",
        display_name: "Cursor",
        config_path: "~/.cursor/mcp.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "Per-project override: `.cursor/mcp.json` at the repo root. **Phase 8b empirical default**: 5 of 6 tested non-Claude IDEs in v0.16 needed `--allow-mutations=always` because they don't fully support MCP elicitation; Cursor was UNTESTED but ships with the same override speculatively. If your Cursor install does support MCP elicitation (test by removing the flag + restarting), remove the override and the safer per-mutation confirmation modal will fire instead.",
        extra_args: &["--allow-mutations", "always"],
    },
    IdeProfile {
        key: "codex",
        display_name: "Codex (OpenAI CLI)",
        config_path: "~/.codex/config.toml",
        format: FileFormat::Toml,
        shape: ConfigShape::TomlMcpServersTable,
        note: "Codex CLI config is TOML; merge under existing tables if present.",
        extra_args: &[],
    },
    IdeProfile {
        key: "vscode-copilot",
        display_name: "VS Code + GitHub Copilot",
        config_path: ".vscode/mcp.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonVsCodeServers,
        note: "Workspace-scoped: place at `.vscode/mcp.json` in the repo, not $HOME.",
        extra_args: &[],
    },
    IdeProfile {
        key: "continue",
        display_name: "Continue",
        config_path: "~/.continue/config.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonContinueExperimental,
        note: "Continue nests MCP servers under `experimental.modelContextProtocolServers` (array). **Phase 8b empirical default**: 5 of 6 tested non-Claude IDEs in v0.16 needed `--allow-mutations=always` because they don't fully support MCP elicitation; Continue was UNTESTED but ships with the same override speculatively. If your Continue install does support MCP elicitation (test by removing the flag + restarting), remove the override and the safer per-mutation confirmation modal will fire instead.",
        extra_args: &["--allow-mutations", "always"],
    },
    IdeProfile {
        key: "cline",
        display_name: "Cline (VS Code)",
        config_path: "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "macOS path. Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`.",
        extra_args: &[],
    },
    IdeProfile {
        key: "gemini",
        display_name: "Gemini CLI + Gemini Code Assist (Google)",
        config_path: "~/.gemini/settings.json",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "FINDING-9 (Phase 8b): Gemini CLI 0.43.0 does NOT advertise MCP elicitation capability — the `--allow-mutations=always` flag below bypasses the per-mutation confirmation gate (mutations still appear in the audit log). REMOVE that flag once Gemini ships elicitation support (track via `gemini --version` against their release notes). Config covers both standalone CLI and Gemini Code Assist IDE extension; restart the editor/CLI to pick up changes.",
        extra_args: &["--allow-mutations", "always"],
    },
    IdeProfile {
        key: "opencode",
        display_name: "OpenCode",
        config_path: "~/.config/opencode/opencode.jsonc",
        format: FileFormat::Json,
        shape: ConfigShape::JsonOpenCode,
        note: "OpenCode uses a `command`-as-list form. Config file is JSONC (JSON with comments) at `opencode.jsonc` — NOT `opencode.json` (FINDING-14 fix). **Phase 8b FINDING-16**: OpenCode does NOT advertise MCP elicitation capability — the `--allow-mutations=always` flag below bypasses the per-mutation confirmation gate (mutations still audit-logged). Note: OpenCode AND the agent running inside it BOTH provide their own confirmation surfaces (operator-typed `confirm` in chat per Phase 8b POSITIVE OBSERVATION #3) — defense-in-depth at the IDE + model layer even when MCP-protocol elicitation is silenced.",
        extra_args: &["--allow-mutations", "always"],
    },
    IdeProfile {
        key: "generic",
        display_name: "Generic (Claude-shape `mcpServers` block)",
        config_path: "(paste into the IDE's MCP config file)",
        format: FileFormat::Json,
        shape: ConfigShape::JsonMcpServers,
        note: "Drop-in for ANY IDE that adopts the de-facto Claude `mcpServers` shape: Claude Code, Cursor, Cline, Gemini CLI / Code Assist, and emerging clients. NOT compatible with VS Code Copilot (needs `\"type\": \"stdio\"`), Continue (`experimental.modelContextProtocolServers`), OpenCode (`command`-as-list), or Codex (TOML).",
        extra_args: &[],
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
    // Existing public API — preserves v0.16 behavior (overrides
    // always applied). v0.18 callers that need to honor the
    // user-scope `allow_cli_overrides` knob use
    // [`render_config_with_overrides`].
    render_config_with_overrides(profile, binary_path, true)
}

/// Like [`render_config`] but honors the user-scope F-3 veto.
///
/// When `allow_cli_overrides` is `false`, the per-IDE
/// [`IdeProfile::extra_args`] are stripped from the rendered
/// config — operator user-scope choice overrides the workspace-
/// scope profile default. v0.18 F-3.
#[must_use]
pub fn render_config_with_overrides(
    profile: &IdeProfile,
    binary_path: &str,
    allow_cli_overrides: bool,
) -> String {
    // `extra_args` (Phase 7f) appends per-IDE CLI overrides like
    // `--allow-mutations=always` for IDEs that don't advertise MCP
    // elicitation capability (e.g. Gemini CLI 0.43.0). Renders into
    // the JSON / TOML `args` array right after `mcp serve`.
    let extra_args: &[&str] = if allow_cli_overrides {
        profile.extra_args
    } else {
        if !profile.extra_args.is_empty() {
            tracing::warn!(
                ide = profile.key,
                suppressed_args = ?profile.extra_args,
                "[mcp].allow_cli_overrides = false; stripping IDE profile extra_args from rendered config"
            );
        }
        &[]
    };
    let full_argv: Vec<&str> = SERVE_ARGV.iter().chain(extra_args.iter()).copied().collect();
    let args_json = full_argv.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(", ");

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
                .chain(extra_args.iter().copied())
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
        ConfigShape::ShellClaudeMcpAdd => {
            // `-s user` makes the registration user-scope (available
            // in every project). The `--` separator passes the rest
            // through as the spawned subprocess argv. Print the
            // command + the verify step so the operator gets a
            // copy-paste-ready snippet.
            let argv_tail = full_argv.join(" ");
            format!(
                "# Run this command in your shell to register secretenv with Claude Code:\nclaude mcp add -s user {SERVER_KEY} -- {binary_path} {argv_tail}\n\n# Verify the registration (should report `Status: ✓ Connected`):\nclaude mcp get {SERVER_KEY}\n",
            )
        }
    }
}

/// Outcome of [`merge_config_into_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// File didn't exist — the merged body was written as the new
    /// initial content (same as a plain `--write` would have done).
    Created,
    /// File existed and the `secretenv` server entry was added.
    Added,
    /// File existed and the `secretenv` server entry was already
    /// present with the same shape — nothing written.
    AlreadyPresent,
    /// File existed and the `secretenv` server entry was already
    /// present with a DIFFERENT shape. Caller decides whether to
    /// honor `--force` and overwrite.
    Conflict,
}

/// Merge the rendered MCP-server registration block for `profile`
/// into the existing file at `target`. Preserves sibling keys (the
/// whole point of `--merge` over `--force`).
///
/// Behavior matrix per [`ConfigShape`]:
///
/// | Shape | Merge support | Conflict signal |
/// |---|---|---|
/// | `JsonMcpServers` | ✓ insert at `.mcpServers.secretenv` | existing `secretenv` value ≠ proposed |
/// | `JsonVsCodeServers` | ✓ insert at `.servers.secretenv` | same |
/// | `JsonContinueExperimental` | ✓ push to `.experimental.modelContextProtocolServers` array (by `.transport.command` identity) | array entry with matching `transport.command` but different other fields |
/// | `JsonOpenCode` | ✗ JSONC has comments — parse rejects them; defer to v0.16.2 | n/a |
/// | `TomlMcpServersTable` | ✗ TOML round-trip strips formatting + comments — defer to v0.16.2 | n/a |
/// | `ShellClaudeMcpAdd` | n/a — print-only profile, never reaches this code path | n/a |
///
/// On unsupported shape returns an error pointing the operator at
/// `--write --force` (overwrite) or manual paste.
///
/// # Errors
///
/// Returns an error if the target file cannot be read, the existing
/// content is not valid JSON for a JSON shape, the proposed body is
/// internally inconsistent (this would be a bug in
/// [`render_config`]), the shape is unsupported for merge, or the
/// write-back fails.
pub fn merge_config_into_file(
    profile: &IdeProfile,
    binary_path: &str,
    target: &Path,
    allow_cli_overrides: bool,
) -> Result<MergeOutcome> {
    if !target.exists() {
        let body = render_config_with_overrides(profile, binary_path, allow_cli_overrides);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("creating parent directory `{}` for IDE config", parent.display())
            })?;
        }
        std::fs::write(target, body)
            .with_context(|| format!("writing MCP config to `{}`", target.display()))?;
        return Ok(MergeOutcome::Created);
    }

    let existing = std::fs::read_to_string(target)
        .with_context(|| format!("reading existing IDE config `{}`", target.display()))?;
    let proposed = render_config_with_overrides(profile, binary_path, allow_cli_overrides);

    match profile.shape {
        ConfigShape::JsonMcpServers => merge_json_keyed(target, &existing, &proposed, "mcpServers"),
        ConfigShape::JsonVsCodeServers => merge_json_keyed(target, &existing, &proposed, "servers"),
        ConfigShape::JsonContinueExperimental => merge_continue_array(target, &existing, &proposed),
        ConfigShape::JsonOpenCode => bail!(
            "`--merge` does not support OpenCode's JSONC config yet (comments would be lost \
             on a round-trip). Use `--write --force` to overwrite, or paste the block \
             from `secretenv mcp setup --ide opencode` into the existing file manually.",
        ),
        ConfigShape::TomlMcpServersTable => bail!(
            "`--merge` does not support Codex's TOML config yet (formatting + comments \
             would be lost on a round-trip). Use `--write --force` to overwrite, or paste \
             the block from `secretenv mcp setup --ide codex` into the existing file \
             manually.",
        ),
        ConfigShape::ShellClaudeMcpAdd => bail!(
            "`--merge` is not applicable to `--ide claude-code` (the profile emits a \
             `claude mcp add` shell command, not a file write). Run the printed command in \
             your shell.",
        ),
    }
}

/// Merge a `JsonMcpServers`-style or `JsonVsCodeServers`-style file —
/// both have shape `{ "<servers_key>": { "<server_name>": { ... } } }`.
fn merge_json_keyed(
    target: &Path,
    existing: &str,
    proposed: &str,
    servers_key: &str,
) -> Result<MergeOutcome> {
    let mut existing_v: JsonValue = serde_json::from_str(existing)
        .with_context(|| format!("parsing existing IDE config as JSON: `{}`", target.display()))?;
    let proposed_v: JsonValue =
        serde_json::from_str(proposed).context("parsing proposed MCP config block as JSON")?;
    let proposed_server = proposed_v
        .get(servers_key)
        .and_then(|s| s.get(SERVER_KEY))
        .ok_or_else(|| anyhow!("proposed block missing `{servers_key}.{SERVER_KEY}` key"))?
        .clone();

    let root = existing_v
        .as_object_mut()
        .ok_or_else(|| anyhow!("existing config at `{}` is not a JSON object", target.display()))?;
    let servers = root
        .entry(servers_key.to_owned())
        .or_insert_with(|| JsonValue::Object(serde_json::Map::new()));
    let servers_obj = servers.as_object_mut().ok_or_else(|| {
        anyhow!(
            "existing config at `{}` has `{servers_key}` but it is not a JSON object",
            target.display()
        )
    })?;

    let outcome = match servers_obj.get(SERVER_KEY) {
        Some(existing_entry) if existing_entry == &proposed_server => MergeOutcome::AlreadyPresent,
        Some(_) => MergeOutcome::Conflict,
        None => {
            servers_obj.insert(SERVER_KEY.to_owned(), proposed_server);
            MergeOutcome::Added
        }
    };

    if outcome == MergeOutcome::Added {
        let body = serde_json::to_string_pretty(&existing_v)
            .context("re-serializing merged IDE config")?;
        std::fs::write(target, format!("{body}\n"))
            .with_context(|| format!("writing merged IDE config to `{}`", target.display()))?;
    }

    Ok(outcome)
}

/// Merge a Continue-style file with shape
/// `{ "experimental": { "modelContextProtocolServers": [ ... ] } }`.
/// Identity for deduplication is `transport.command`.
fn merge_continue_array(target: &Path, existing: &str, proposed: &str) -> Result<MergeOutcome> {
    let mut existing_v: JsonValue = serde_json::from_str(existing).with_context(|| {
        format!("parsing existing Continue config as JSON: `{}`", target.display())
    })?;
    let proposed_v: JsonValue = serde_json::from_str(proposed)
        .context("parsing proposed Continue MCP config block as JSON")?;
    let proposed_entry = proposed_v
        .get("experimental")
        .and_then(|e| e.get("modelContextProtocolServers"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("proposed block missing the Continue MCP entry"))?
        .clone();
    let proposed_command = proposed_entry
        .get("transport")
        .and_then(|t| t.get("command"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow!("proposed Continue entry missing `transport.command`"))?
        .to_owned();

    let root = existing_v
        .as_object_mut()
        .ok_or_else(|| anyhow!("existing config at `{}` is not a JSON object", target.display()))?;
    let experimental = root
        .entry("experimental".to_owned())
        .or_insert_with(|| JsonValue::Object(serde_json::Map::new()));
    let experimental_obj = experimental.as_object_mut().ok_or_else(|| {
        anyhow!("existing `experimental` at `{}` is not a JSON object", target.display())
    })?;
    let servers = experimental_obj
        .entry("modelContextProtocolServers".to_owned())
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    let servers_arr = servers.as_array_mut().ok_or_else(|| {
        anyhow!(
            "existing `experimental.modelContextProtocolServers` at `{}` is not a JSON array",
            target.display()
        )
    })?;

    let outcome = match servers_arr.iter().position(|entry| {
        entry.get("transport").and_then(|t| t.get("command")).and_then(|c| c.as_str())
            == Some(proposed_command.as_str())
    }) {
        Some(idx) if servers_arr[idx] == proposed_entry => MergeOutcome::AlreadyPresent,
        Some(_) => MergeOutcome::Conflict,
        None => {
            servers_arr.push(proposed_entry);
            MergeOutcome::Added
        }
    };

    if outcome == MergeOutcome::Added {
        let body = serde_json::to_string_pretty(&existing_v)
            .context("re-serializing merged Continue config")?;
        std::fs::write(target, format!("{body}\n"))
            .with_context(|| format!("writing merged Continue config to `{}`", target.display()))?;
    }

    Ok(outcome)
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
    fn renders_claude_code_as_shell_command() {
        // v0.16 Phase 7c FINDING-1: claude-code emits the official
        // `claude mcp add` shell command rather than a JSON block —
        // because the actual user config is `~/.claude.json` which
        // is a 1000+ line shared file. The CLI's built-in add
        // command handles the safe merge.
        let profile = find_profile("claude-code").unwrap();
        let body = render_config(profile, "secretenv");
        assert!(body.contains("claude mcp add"));
        assert!(body.contains("-s user"));
        assert!(body.contains("secretenv"));
        assert!(body.contains("mcp serve"));
        assert!(body.contains("claude mcp get secretenv"));
        // Should NOT be a JSON block (that's `generic`'s job).
        assert!(!body.contains("\"mcpServers\""));
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

    // v0.18 F-3 regression: when allow_cli_overrides = false, the
    // per-IDE extra_args (e.g. Gemini's --allow-mutations=always)
    // must be stripped from the rendered config. Picking Gemini
    // because its profile carries non-empty extra_args.
    #[test]
    fn render_config_with_overrides_false_strips_extra_args_for_gemini() {
        let profile = find_profile("gemini").unwrap();
        assert!(
            !profile.extra_args.is_empty(),
            "Gemini profile must carry extra_args for this test to be meaningful"
        );

        let with_overrides = render_config_with_overrides(profile, "secretenv", true);
        let without = render_config_with_overrides(profile, "secretenv", false);

        // Overrides ON: every extra_arg appears in the body.
        for arg in profile.extra_args {
            assert!(
                with_overrides.contains(arg),
                "extra_arg `{arg}` missing from overrides-on body: {with_overrides}"
            );
        }

        // Overrides OFF: --allow-mutations must NOT appear (would
        // mean the F-3 veto failed and the workspace override
        // smuggled past).
        assert!(
            !without.contains("--allow-mutations"),
            "F-3 veto failed: --allow-mutations still present in overrides-off body: {without}"
        );
        assert!(!without.contains("always"), "F-3 veto failed: `always` still present: {without}");

        // Mandatory base argv still present even with veto.
        assert!(without.contains("mcp"));
        assert!(without.contains("serve"));
    }

    #[test]
    fn render_config_with_overrides_false_is_noop_for_profiles_without_extra_args() {
        // Walk every profile, find the ones with empty extra_args,
        // and assert that overriding the toggle changes nothing
        // (the per-IDE override surface is the only thing the toggle
        // gates).
        let mut tested = 0;
        for profile in IDE_PROFILES {
            if !profile.extra_args.is_empty() {
                continue;
            }
            let with_overrides = render_config_with_overrides(profile, "secretenv", true);
            let without = render_config_with_overrides(profile, "secretenv", false);
            assert_eq!(
                with_overrides, without,
                "profile `{}` (no extra_args) renders should match",
                profile.key
            );
            tested += 1;
        }
        assert!(tested > 0, "at least one profile must have empty extra_args for this test");
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
        // OpenCode profile ships with the Phase 7f --allow-mutations
        // override per FINDING-16 (no elicitation support).
        assert!(body.contains(
            "\"command\": [\"secretenv\", \"mcp\", \"serve\", \"--allow-mutations\", \"always\"]"
        ));
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
    fn gemini_profile_includes_allow_mutations_override() {
        // v0.16 Phase 7f FINDING-9: Gemini CLI 0.43.0 doesn't
        // advertise MCP elicitation. The setup helper auto-emits
        // `--allow-mutations=always` in the args[] to bypass the
        // confirmation gate WITHOUT weakening the operator's global
        // `[mcp]` config. Remove this when Gemini ships elicitation.
        let profile = find_profile("gemini").unwrap();
        assert_eq!(profile.extra_args, &["--allow-mutations", "always"]);
        let body = render_config(profile, "secretenv");
        assert!(body.contains("\"--allow-mutations\""));
        assert!(body.contains("\"always\""));
        // Should appear in the rendered args array AFTER `serve`.
        let serve_idx = body.find("\"serve\"").expect("serve in args");
        let flag_idx = body.find("\"--allow-mutations\"").expect("flag in args");
        assert!(serve_idx < flag_idx, "extra_args must come after SERVE_ARGV");
    }

    #[test]
    fn no_elicitation_ides_ship_with_override() {
        // Phase 8b empirical pattern: Gemini (FINDING-9) + OpenCode
        // (FINDING-16) confirmed to need `--allow-mutations=always`
        // because they don't advertise MCP elicitation. Cursor +
        // Continue (untested in v0.16) ship with the same override
        // speculatively per Phase 7g — 5 of 5 same-bucket IDEs failed
        // so the safer default for untested IDEs is "needs override".
        // If a future Cursor / Continue install actually supports
        // elicitation, the operator removes the flag and the safer
        // per-mutation confirmation modal fires instead.
        for key in ["gemini", "cursor", "continue", "opencode"] {
            let profile = find_profile(key).expect("profile present");
            assert_eq!(
                profile.extra_args,
                &["--allow-mutations", "always"],
                "{key} should ship with --allow-mutations=always per Phase 7f/7g defaults",
            );
        }
    }

    #[test]
    fn elicitation_supporting_or_passthrough_ides_have_no_extra_args() {
        // - claude-code: elicitation works (Phase 8b IDE #1 sign-off).
        // - codex + cline + vscode-copilot: also need the override,
        //   but their config-edit mechanisms (`claude mcp add`, jq
        //   merge into globalStorage settings.json, `.vscode/mcp.json`
        //   paste) are operator-driven; helper print mode is
        //   informational + operator pastes the override per Phase 8b
        //   per-IDE notes. Keeping these profiles with empty
        //   `extra_args` means a future IDE-side elicitation fix is
        //   automatically picked up.
        // - generic: not an IDE — pure paste-target.
        for key in ["claude-code", "codex", "cline", "vscode-copilot", "generic"] {
            let profile = find_profile(key).expect("profile present");
            assert!(profile.extra_args.is_empty(), "{key} should not have extra_args");
        }
    }

    #[test]
    fn generic_profile_matches_other_claude_shape_ides() {
        // Post-Phase-7g, the only `JsonMcpServers` IDE that ships
        // byte-identical to `generic` is `cline` (no extra_args).
        // Gemini + Cursor get `--allow-mutations=always` extra_args
        // per FINDING-9 (confirmed) + Phase 7g speculative default
        // for untested IDEs.
        let generic = find_profile("generic").unwrap();
        let cline = find_profile("cline").unwrap();
        assert_eq!(generic.shape, cline.shape, "shape match expected");
        assert_eq!(
            render_config(generic, "secretenv"),
            render_config(cline, "secretenv"),
            "rendering should match cline byte-for-byte",
        );
        // Gemini + Cursor share SHAPE but rendering differs (extra_args).
        for divergent in ["gemini", "cursor"] {
            assert_eq!(generic.shape, find_profile(divergent).unwrap().shape);
            assert_ne!(
                render_config(generic, "secretenv"),
                render_config(find_profile(divergent).unwrap(), "secretenv"),
                "{divergent} should render differently due to extra_args",
            );
        }
    }

    #[test]
    fn generic_profile_note_lists_compatible_ides() {
        let generic = find_profile("generic").unwrap();
        // The note documents which IDEs accept the generic block
        // as-is, and which ones need their own per-IDE profile.
        for compat in ["Claude Code", "Cursor", "Cline", "Gemini"] {
            assert!(generic.note.contains(compat), "generic note missing compatible IDE: {compat}");
        }
        for incompat in ["VS Code Copilot", "Continue", "OpenCode", "Codex"] {
            assert!(
                generic.note.contains(incompat),
                "generic note missing incompatible-IDE warning: {incompat}",
            );
        }
    }

    #[test]
    fn render_honors_absolute_binary_path() {
        // Use a JSON-shape IDE — claude-code now emits the shell
        // command form per Phase 7c FINDING-1.
        let profile = find_profile("cursor").unwrap();
        let body = render_config(profile, "/usr/local/bin/secretenv");
        assert!(body.contains("\"command\": \"/usr/local/bin/secretenv\""));
    }

    #[test]
    fn shell_claude_mcp_add_honors_absolute_binary_path() {
        // claude-code's shell-command shape interpolates the binary
        // path directly into the command line after the `--`
        // separator.
        let profile = find_profile("claude-code").unwrap();
        let body = render_config(profile, "/opt/homebrew/bin/secretenv");
        assert!(body.contains("-- /opt/homebrew/bin/secretenv mcp serve"));
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

    #[test]
    fn merge_creates_when_target_missing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nonexistent").join("mcp.json");
        let profile = find_profile("gemini").unwrap();
        let outcome = merge_config_into_file(profile, "secretenv", &target, true).unwrap();
        assert_eq!(outcome, MergeOutcome::Created);
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(body.contains("\"mcpServers\""));
        assert!(body.contains("\"secretenv\""));
    }

    #[test]
    fn merge_adds_secretenv_to_existing_json_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("settings.json");
        std::fs::write(
            &target,
            r#"{
  "theme": "dark",
  "mcpServers": {
    "other-server": { "command": "other", "args": [] }
  }
}
"#,
        )
        .unwrap();

        let profile = find_profile("gemini").unwrap();
        let outcome = merge_config_into_file(profile, "secretenv", &target, true).unwrap();
        assert_eq!(outcome, MergeOutcome::Added);

        let body = std::fs::read_to_string(&target).unwrap();
        let parsed: JsonValue = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.get("theme").and_then(|v| v.as_str()), Some("dark"));
        let servers = parsed.get("mcpServers").unwrap().as_object().unwrap();
        assert!(servers.contains_key("other-server"));
        assert!(servers.contains_key("secretenv"));
    }

    #[test]
    fn merge_is_idempotent_when_entry_already_present() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("settings.json");
        let profile = find_profile("gemini").unwrap();

        // Seed the file with the same body that render_config would
        // produce — a second merge should be AlreadyPresent.
        let initial = render_config(profile, "secretenv");
        std::fs::write(&target, &initial).unwrap();

        let outcome = merge_config_into_file(profile, "secretenv", &target, true).unwrap();
        assert_eq!(outcome, MergeOutcome::AlreadyPresent);
    }

    #[test]
    fn merge_reports_conflict_when_existing_differs() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("settings.json");
        std::fs::write(
            &target,
            r#"{
  "mcpServers": {
    "secretenv": { "command": "/some/other/path/secretenv", "args": ["mcp", "serve"] }
  }
}
"#,
        )
        .unwrap();

        let profile = find_profile("gemini").unwrap();
        let outcome =
            merge_config_into_file(profile, "/expected/path/secretenv", &target, true).unwrap();
        assert_eq!(outcome, MergeOutcome::Conflict);
    }

    #[test]
    fn merge_continue_pushes_into_array() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.json");
        std::fs::write(
            &target,
            r#"{
  "experimental": {
    "modelContextProtocolServers": [
      { "transport": { "type": "stdio", "command": "other", "args": [] } }
    ]
  }
}
"#,
        )
        .unwrap();

        let profile = find_profile("continue").unwrap();
        let outcome = merge_config_into_file(profile, "secretenv", &target, true).unwrap();
        assert_eq!(outcome, MergeOutcome::Added);

        let body = std::fs::read_to_string(&target).unwrap();
        let parsed: JsonValue = serde_json::from_str(&body).unwrap();
        let arr = parsed
            .get("experimental")
            .and_then(|e| e.get("modelContextProtocolServers"))
            .and_then(|a| a.as_array())
            .unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn merge_rejects_jsonc_opencode() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("opencode.jsonc");
        std::fs::write(&target, "// hi\n{}\n").unwrap();
        let profile = find_profile("opencode").unwrap();
        let err = merge_config_into_file(profile, "secretenv", &target, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--merge"));
        assert!(msg.contains("OpenCode"));
    }

    #[test]
    fn merge_rejects_toml_codex() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "# comment\n[other]\nkey = \"value\"\n").unwrap();
        let profile = find_profile("codex").unwrap();
        let err = merge_config_into_file(profile, "secretenv", &target, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--merge"));
        assert!(msg.contains("Codex"));
    }
}
