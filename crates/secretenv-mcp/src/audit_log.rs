// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation audit log writer.
//!
//! Phase 2c: append-only JSON Lines writer with mode `0600` on Unix.
//! Phase 4 wires this into every mutation tool (`set_alias`,
//! `delete_alias`, `init_project`, `redact_file`); Phase 5 + 6 wire
//! `gen_password` and `migrate_alias` respectively.
//!
//! ```json
//! {
//!   "ts": "2026-05-23T14:00:00Z",
//!   "tool_name": "set_alias",
//!   "alias_name": "stripe-key",
//!   "backend_instance": "vault-prod",
//!   "agent_reason": "<the agent's stated reason>",
//!   "operator_decision": "approved",
//!   "mcp_client_id": "<rmcp client identifier>"
//! }
//! ```
//!
//! `agent_reason` is recorded here but NEVER echoed back to the agent
//! and NEVER set as an `OTel` attribute (SEC-INV-12).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// What the operator decided when the mutation confirmation prompt
/// fired. Recorded verbatim in the audit log.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperatorDecision {
    /// Operator approved the mutation.
    Approved,
    /// Operator denied the mutation (typed `n`, etc.).
    Denied,
    /// No response before the prompt timeout — treated as deny.
    Timeout,
    /// `[mcp].allow_mutations = "always"` was in effect, so no
    /// prompt fired; the mutation auto-approved.
    AutoApproved,
}

/// One audit-log entry. JSON-Lines serialization on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationLogEntry {
    /// UNIX timestamp in seconds when the mutation was decided.
    pub ts_unix_secs: u64,
    /// Tool name (kebab-case, matches `tools-inventory.yaml`).
    pub tool_name: String,
    /// Alias the mutation targets (when applicable; tools like
    /// `init_project` may leave this `None`).
    pub alias_name: Option<String>,
    /// Backend instance the mutation targets (when applicable).
    pub backend_instance: Option<String>,
    /// The reason field the agent supplied with the call. Recorded
    /// verbatim. NEVER echoed back to the agent and NEVER attached
    /// as an `OTel` attribute (SEC-INV-12).
    pub agent_reason: String,
    /// Operator's decision when the confirmation prompt fired.
    pub operator_decision: OperatorDecision,
    /// `rmcp` client identifier (from the `initialize` handshake's
    /// `clientInfo`). Lets the audit log distinguish Claude Code
    /// from Cursor from a smoke harness.
    pub mcp_client_id: String,
}

impl MutationLogEntry {
    /// Stamp `ts_unix_secs` with `SystemTime::now`.
    #[must_use]
    pub fn now(
        tool_name: impl Into<String>,
        agent_reason: impl Into<String>,
        operator_decision: OperatorDecision,
        mcp_client_id: impl Into<String>,
    ) -> Self {
        let ts_unix_secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        Self {
            ts_unix_secs,
            tool_name: tool_name.into(),
            alias_name: None,
            backend_instance: None,
            agent_reason: agent_reason.into(),
            operator_decision,
            mcp_client_id: mcp_client_id.into(),
        }
    }
}

/// Compute the default audit-log path used when `[mcp].mutation_log`
/// is unset.
///
/// On Linux: `$XDG_STATE_HOME/secretenv/mcp-mutations.log`
/// (defaulting `XDG_STATE_HOME` to `~/.local/state`).
/// On macOS / other platforms with no XDG state dir: falls back to
/// `<data_local_dir>/secretenv/mcp-mutations.log`
/// (`~/Library/Application Support/secretenv/...` on macOS).
fn default_audit_log_path() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("could not determine a home directory for audit-log path lookup"))?;
    let dir = base.state_dir().unwrap_or_else(|| base.data_local_dir());
    Ok(dir.join("secretenv").join("mcp-mutations.log"))
}

/// Append-only mutation audit log. One file handle, guarded by a
/// `Mutex` so concurrent tool handlers (Phases 4-6) serialize their
/// writes without interleaving JSON Lines.
#[derive(Debug)]
pub struct MutationLog {
    path: PathBuf,
    file: Mutex<File>,
}

impl MutationLog {
    /// Open (create-or-append) the audit log at `path`. On Unix the
    /// file mode is forced to `0o600` whether the file already
    /// existed or is freshly created — the writer is the source of
    /// truth on permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created,
    /// the file cannot be opened, or the mode cannot be set.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        Self::open_at(path)
    }

    /// Resolve [`McpConfig::mutation_log`] to a concrete path, then
    /// [`Self::open`] it. When the config field is `None`, computes
    /// `$XDG_STATE_HOME/secretenv/mcp-mutations.log` (falling back to
    /// `~/.local/state/...` on platforms without `XDG_STATE_HOME`).
    ///
    /// # Errors
    ///
    /// Returns an error if no home directory can be determined for
    /// the XDG default lookup (only when `configured_path` is `None`),
    /// or if [`Self::open`] fails.
    pub fn open_with_default(configured_path: Option<&str>) -> Result<Self> {
        let path = match configured_path {
            Some(p) => PathBuf::from(p),
            None => default_audit_log_path()?,
        };
        Self::open(path)
    }

    fn open_at(path: PathBuf) -> Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let file = opts.open(&path).with_context(|| format!("opening {}", path.display()))?;

        // Force-tighten the mode even if the file already existed
        // with looser permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perm)
                .with_context(|| format!("setting 0600 on {}", path.display()))?;
        }

        Ok(Self { path, file: Mutex::new(file) })
    }

    /// Append one entry as a JSON line. The newline is the
    /// JSON-Lines record separator.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the write fails.
    pub fn append(&self, entry: &MutationLogEntry) -> Result<()> {
        let mut line =
            serde_json::to_string(entry).context("serializing MutationLogEntry to JSON")?;
        line.push('\n');

        let mut guard = self.file.lock().map_err(|_| anyhow!("mutation-log mutex poisoned"))?;
        guard
            .write_all(line.as_bytes())
            .with_context(|| format!("appending to {}", self.path.display()))?;
        guard.flush().with_context(|| format!("flushing {}", self.path.display()))?;
        drop(guard);
        Ok(())
    }

    /// The on-disk path this log writes to. Useful for the operator
    /// confirmation prompt's "your decision is recorded at …" line.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = MutationLog::open(&path).unwrap();

        let entry = MutationLogEntry::now(
            "set_alias",
            "the agent wanted to update the stripe key",
            OperatorDecision::Approved,
            "claude-code/0.0",
        );
        log.append(&entry).unwrap();
        log.append(&MutationLogEntry::now(
            "delete_alias",
            "cleaning up old test alias",
            OperatorDecision::Denied,
            "claude-code/0.0",
        ))
        .unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 JSON lines, got body: {body}");
        let parsed_0: MutationLogEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed_0.tool_name, "set_alias");
        assert_eq!(parsed_0.operator_decision, OperatorDecision::Approved);
        let parsed_1: MutationLogEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed_1.tool_name, "delete_alias");
        assert_eq!(parsed_1.operator_decision, OperatorDecision::Denied);
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("perm.log");
        let _ = MutationLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log must be 0600; got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_reopen_tightens_loose_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("loose.log");
        // Pre-create the file with a too-loose mode.
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _ = MutationLog::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "open() must tighten 0644 → 0600; got {mode:o}");
    }
}
