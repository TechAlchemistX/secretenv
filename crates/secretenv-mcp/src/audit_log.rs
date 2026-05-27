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

/// Cross-process advisory lock + size-rotation parameters for
/// [`MutationLog`]. Mirrors the [`crate::config::McpConfig`]
/// `audit_log_max_bytes` / `audit_log_max_rotations` fields.
///
/// Constructed by the caller (typically `MutationLog::open_with_default`
/// at server startup) so the audit log applies the operator's
/// configured limits.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// Rotate when the file's on-disk size exceeds this many bytes.
    /// `0` disables size-based rotation (the log grows unbounded).
    pub max_bytes: u64,
    /// Retain this many rotated files (`audit.log.1` ..
    /// `audit.log.{max_rotations}`). Older files are removed at
    /// rotation. `0` disables retention — each rotation truncates
    /// the current log without writing a `.1` archive.
    pub max_rotations: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self { max_bytes: 10 * 1024 * 1024, max_rotations: 5 }
    }
}

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

/// Compute the default audit-log path used when no explicit path
/// is supplied (CLI `mcp audit tail` + `mcp serve` startup with an
/// unset `[mcp].mutation_log`).
///
/// On Linux: `$XDG_STATE_HOME/secretenv/mcp-mutations.log`
/// (defaulting `XDG_STATE_HOME` to `~/.local/state`). On macOS:
/// `~/Library/Application Support/secretenv/mcp-mutations.log`
/// (via `directories::BaseDirs::data_local_dir`).
///
/// # Errors
///
/// Returns an error if no home directory can be determined for the
/// platform.
pub fn default_audit_log_path() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("could not determine a home directory for audit-log path lookup"))?;
    let dir = base.state_dir().unwrap_or_else(|| base.data_local_dir());
    Ok(dir.join("secretenv").join("mcp-mutations.log"))
}

/// Create `parent` and every missing ancestor with mode `0o700` on
/// Unix. Existing directories are left as-is (we don't tighten the
/// operator's existing layout — only freshly-created components get
/// the restrictive mode).
///
/// v0.16.1 item 13: closes a disclosure gap where
/// `std::fs::create_dir_all` would let the freshly-created
/// `~/.local/state/secretenv` inherit the process umask and possibly
/// land world-readable on a system with `umask 022`.
fn ensure_audit_parent_dir(parent: &Path) -> Result<()> {
    // Determine which components are missing so we only chmod the
    // freshly-created ones. Walk from `parent` upward until we find
    // an existing ancestor (or hit the root).
    let mut to_create: Vec<PathBuf> = Vec::new();
    let mut cursor: Option<&Path> = Some(parent);
    while let Some(p) = cursor {
        if p.exists() {
            break;
        }
        to_create.push(p.to_path_buf());
        cursor = p.parent();
    }

    std::fs::create_dir_all(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Walk the freshly-created components from outermost-existing
        // down to `parent` and force 0o700 on each.
        for component in to_create.into_iter().rev() {
            let perm = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&component, perm)
                .with_context(|| format!("setting 0700 on {}", component.display()))?;
        }
    }
    #[cfg(not(unix))]
    {
        // Suppress unused-variable warning when not building for unix.
        let _ = to_create;
    }

    Ok(())
}

/// Append-only mutation audit log. One file handle, guarded by a
/// `Mutex` so concurrent tool handlers (Phases 4-6) serialize their
/// writes without interleaving JSON Lines.
///
/// v0.16.2 D.3 additions:
///
/// - **Cross-process locking** — every [`Self::append`] acquires
///   `flock(LOCK_EX)` on the file handle for the duration of the
///   write, preventing interleaved JSON Lines when two MCP servers
///   (e.g. one per IDE) race on the same `mutation_log` path.
/// - **Size-based rotation** — when the file exceeds
///   [`RotationConfig::max_bytes`], the writer shifts
///   `audit.log.{n-1}` → `audit.log.{n}` (capped at
///   [`RotationConfig::max_rotations`]; oldest is dropped) and
///   reopens at the original path. Rotation runs inside the same
///   in-process Mutex + cross-process flock, so concurrent writers
///   don't double-rotate.
#[derive(Debug)]
pub struct MutationLog {
    path: PathBuf,
    file: Mutex<File>,
    rotation: RotationConfig,
}

impl MutationLog {
    /// Open (create-or-append) the audit log at `path` with the
    /// default [`RotationConfig`]. On Unix the file mode is forced
    /// to `0o600` whether the file already existed or is freshly
    /// created — the writer is the source of truth on permissions.
    /// Any parent directories created by this call land at `0o700`
    /// on Unix (v0.16.1 item 13: closes a disclosure gap where an
    /// auto-created parent could inherit the process umask and land
    /// world-readable).
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created,
    /// the file cannot be opened, or the mode cannot be set.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_rotation(path, RotationConfig::default())
    }

    /// As [`Self::open`] but with explicit rotation limits.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`].
    pub fn open_with_rotation(path: impl AsRef<Path>, rotation: RotationConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            ensure_audit_parent_dir(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        Self::open_at(path, rotation)
    }

    /// Resolve [`McpConfig::mutation_log`] to a concrete path, then
    /// [`Self::open_with_rotation`] with the operator-configured
    /// limits. When the config field is `None`, computes
    /// `$XDG_STATE_HOME/secretenv/mcp-mutations.log` (falling back to
    /// `~/.local/state/...` on platforms without `XDG_STATE_HOME`).
    ///
    /// # Errors
    ///
    /// Returns an error if no home directory can be determined for
    /// the XDG default lookup (only when `configured_path` is `None`),
    /// or if [`Self::open_with_rotation`] fails.
    pub fn open_with_default(
        configured_path: Option<&str>,
        rotation: RotationConfig,
    ) -> Result<Self> {
        let path = match configured_path {
            Some(p) => PathBuf::from(p),
            None => default_audit_log_path()?,
        };
        Self::open_with_rotation(path, rotation)
    }

    fn open_at(path: PathBuf, rotation: RotationConfig) -> Result<Self> {
        let file = open_log_file(&path)?;
        Ok(Self { path, file: Mutex::new(file), rotation })
    }

    /// Append one entry as a JSON line. The newline is the
    /// JSON-Lines record separator.
    ///
    /// Concurrency model:
    ///
    /// 1. In-process [`Mutex`] is acquired (handlers within one
    ///    server serialize).
    /// 2. `flock(LOCK_EX)` is acquired on the file handle (writers
    ///    across processes serialize — relevant when an operator
    ///    points multiple MCP servers at the same `mutation_log`).
    /// 3. If the file exceeds [`RotationConfig::max_bytes`], the
    ///    rotation chain is shifted and a fresh file is opened
    ///    in-place. The new handle is re-flock'd before writing.
    /// 4. The JSON line is written + flushed.
    /// 5. `flock` is released (implicit on the next `flock(UNLOCK)`).
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails, the cross-process
    /// lock cannot be acquired, rotation fails, or the write fails.
    pub fn append(&self, entry: &MutationLogEntry) -> Result<()> {
        let mut line =
            serde_json::to_string(entry).context("serializing MutationLogEntry to JSON")?;
        line.push('\n');

        let mut guard = self.file.lock().map_err(|_| anyhow!("mutation-log mutex poisoned"))?;

        flock_exclusive(&guard)?;

        // Rotation check. `metadata().len()` is the on-disk size; if
        // we're past the configured threshold, rotate before writing
        // so the post-write file stays under the cap.
        if self.rotation.max_bytes > 0 {
            let size =
                guard.metadata().with_context(|| format!("stat {}", self.path.display()))?.len();
            if size + line.len() as u64 > self.rotation.max_bytes {
                // Drop the lock before renaming so any waiter sees a
                // consistent state. POSIX-rename of the held file is
                // safe (open fd still references the renamed inode);
                // we then reopen at the original path + re-flock.
                flock_unlock(&guard)?;
                let new_file = rotate(&self.path, self.rotation)
                    .with_context(|| format!("rotating {}", self.path.display()))?;
                *guard = new_file;
                flock_exclusive(&guard)?;
            }
        }

        guard
            .write_all(line.as_bytes())
            .with_context(|| format!("appending to {}", self.path.display()))?;
        guard.flush().with_context(|| format!("flushing {}", self.path.display()))?;
        let _ = flock_unlock(&guard);
        drop(guard);
        Ok(())
    }

    /// The on-disk path this log writes to. Useful for the operator
    /// confirmation prompt's "your decision is recorded at …" line.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The rotation config in effect.
    #[must_use]
    pub const fn rotation(&self) -> RotationConfig {
        self.rotation
    }
}

// ---- helpers ---------------------------------------------------------

fn open_log_file(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let file = opts.open(path).with_context(|| format!("opening {}", path.display()))?;

    // Force-tighten the mode even if the file already existed with
    // looser permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perm)
            .with_context(|| format!("setting 0600 on {}", path.display()))?;
    }

    Ok(file)
}

#[cfg(unix)]
fn flock_exclusive(file: &File) -> Result<()> {
    use std::os::fd::AsFd;
    rustix::fs::flock(file.as_fd(), rustix::fs::FlockOperation::LockExclusive)
        .context("flock(LOCK_EX) on audit log")?;
    Ok(())
}

#[cfg(unix)]
fn flock_unlock(file: &File) -> Result<()> {
    use std::os::fd::AsFd;
    rustix::fs::flock(file.as_fd(), rustix::fs::FlockOperation::Unlock)
        .context("flock(UNLOCK) on audit log")?;
    Ok(())
}

#[cfg(not(unix))]
fn flock_exclusive(_file: &File) -> Result<()> {
    // No-op on non-unix targets. The in-process Mutex still
    // serializes writers within one process; cross-process
    // protection is unavailable.
    Ok(())
}

#[cfg(not(unix))]
fn flock_unlock(_file: &File) -> Result<()> {
    Ok(())
}

/// Shift `audit.log.{n-1}` → `audit.log.{n}` up to `max_rotations`,
/// dropping the oldest, then move the current `path` → `audit.log.1`
/// (or delete it when `max_rotations == 0`), and reopen at `path`.
///
/// Returns the freshly-opened file handle at the canonical `path`.
fn rotate(path: &Path, rotation: RotationConfig) -> Result<File> {
    if rotation.max_rotations == 0 {
        // No retention — truncate the current log by removing it,
        // then reopen.
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("removing {} during rotation", path.display()))?;
        }
        return open_log_file(path);
    }

    // Drop the oldest rotated file if it exists — it would
    // otherwise shift past the cap.
    let oldest =
        path.with_file_name(format!("{}.{}", file_name_str(path)?, rotation.max_rotations));
    if oldest.exists() {
        std::fs::remove_file(&oldest)
            .with_context(|| format!("removing {} (oldest rotation slot)", oldest.display()))?;
    }

    // Shift max_rotations-1 → max_rotations, ..., 1 → 2.
    let stem = file_name_str(path)?;
    for n in (1..rotation.max_rotations).rev() {
        let from = path.with_file_name(format!("{stem}.{n}"));
        let to = path.with_file_name(format!("{stem}.{}", n + 1));
        if from.exists() {
            std::fs::rename(&from, &to)
                .with_context(|| format!("rotating {} → {}", from.display(), to.display()))?;
        }
    }

    // Move current → .1.
    let to = path.with_file_name(format!("{stem}.1"));
    std::fs::rename(path, &to)
        .with_context(|| format!("rotating {} → {}", path.display(), to.display()))?;

    // Reopen at the original path with fresh 0o600 mode.
    open_log_file(path)
}

fn file_name_str(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("audit-log path `{}` has no file name", path.display()))
}

/// Read the last `lines` entries from the audit log at `path`.
///
/// Returns the entries in chronological (oldest-first) order
/// within the tail window. Rotated files (`audit.log.1`,
/// `audit.log.2`, ...) are NOT consulted — callers wanting full
/// history merge them externally.
///
/// Used by the `secretenv mcp audit tail` subcommand.
///
/// # Errors
///
/// Returns an error if `path` doesn't exist, cannot be read, or any
/// line of the requested tail is not valid JSON.
pub fn tail_entries(path: &Path, lines: usize) -> Result<Vec<MutationLogEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // Iterate lines from the end, collect up to `lines`, reverse for
    // chronological order on the way out.
    let mut collected: Vec<&str> =
        body.lines().rev().filter(|s| !s.is_empty()).take(lines).collect();
    collected.reverse();
    collected
        .into_iter()
        .map(|s| serde_json::from_str::<MutationLogEntry>(s).map_err(anyhow::Error::from))
        .collect()
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
    fn unix_auto_created_parent_is_0700() {
        // v0.16.1 item 13: when MutationLog::open auto-creates the
        // parent directory, it must land at 0o700 — never inheriting
        // a permissive umask.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let missing_parent = dir.path().join("layer-a").join("layer-b");
        let path = missing_parent.join("audit.log");
        let _ = MutationLog::open(&path).unwrap();

        let mode_a =
            std::fs::metadata(dir.path().join("layer-a")).unwrap().permissions().mode() & 0o777;
        let mode_b = std::fs::metadata(&missing_parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_a, 0o700, "freshly-created intermediate dir must be 0700; got {mode_a:o}");
        assert_eq!(mode_b, 0o700, "freshly-created leaf parent must be 0700; got {mode_b:o}");
    }

    #[cfg(unix)]
    #[test]
    fn unix_pre_existing_parent_keeps_mode() {
        // We must NOT tighten a parent dir the operator already
        // created. Only freshly-created components get 0o700.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let pre = dir.path().join("operator-owned");
        std::fs::create_dir_all(&pre).unwrap();
        std::fs::set_permissions(&pre, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = pre.join("audit.log");
        let _ = MutationLog::open(&path).unwrap();

        let mode = std::fs::metadata(&pre).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "pre-existing parent must not be re-permed; got {mode:o}");
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

    // v0.16.2 D.3 tests: size-based rotation + tail reader.

    fn entry(tool: &str) -> MutationLogEntry {
        MutationLogEntry::now(tool, "test reason", OperatorDecision::Approved, "test/0.0")
    }

    #[test]
    fn rotation_shifts_files_and_drops_oldest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rotate.log");
        // Tiny threshold so a single entry rotates.
        let cfg = RotationConfig { max_bytes: 64, max_rotations: 3 };
        let log = MutationLog::open_with_rotation(&path, cfg).unwrap();

        // 5 appends → expected files: rotate.log (newest, 1 entry),
        // rotate.log.1, rotate.log.2, rotate.log.3. The first append
        // doesn't trigger rotation (empty file). Each subsequent
        // append checks size BEFORE writing; the entry is ~150 bytes
        // serialized so every-other-write rotates.
        for i in 0..6 {
            log.append(&entry(&format!("tool_{i}"))).unwrap();
        }

        // Current log exists.
        assert!(path.exists(), "active log must exist after rotations");
        // Up to .3 may exist; .4 + must NOT exist (cap is 3).
        for n in 1..=3 {
            let rotated = dir.path().join(format!("rotate.log.{n}"));
            assert!(rotated.exists(), "rotate.log.{n} should exist");
        }
        let beyond = dir.path().join("rotate.log.4");
        assert!(!beyond.exists(), "rotation cap=3 should prevent rotate.log.4");
    }

    #[test]
    fn rotation_zero_max_rotations_truncates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("truncate.log");
        let cfg = RotationConfig { max_bytes: 64, max_rotations: 0 };
        let log = MutationLog::open_with_rotation(&path, cfg).unwrap();

        log.append(&entry("first")).unwrap();
        log.append(&entry("second")).unwrap();
        log.append(&entry("third")).unwrap();

        // With max_rotations=0, no .1 file is ever written.
        assert!(!dir.path().join("truncate.log.1").exists());
        // The active log is the latest write only (max one entry of size).
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(
            lines.len() <= 1,
            "max_rotations=0 should keep at most 1 entry in active log (got {}): {body}",
            lines.len()
        );
    }

    #[test]
    fn rotation_zero_max_bytes_disables_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unbounded.log");
        // max_bytes=0 → never rotate.
        let cfg = RotationConfig { max_bytes: 0, max_rotations: 5 };
        let log = MutationLog::open_with_rotation(&path, cfg).unwrap();

        for i in 0..10 {
            log.append(&entry(&format!("t{i}"))).unwrap();
        }
        assert!(!dir.path().join("unbounded.log.1").exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 10);
    }

    #[test]
    fn tail_returns_last_n_chronological() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tail.log");
        let log = MutationLog::open(&path).unwrap();
        for i in 0..5 {
            log.append(&entry(&format!("tool_{i}"))).unwrap();
        }

        let tail = tail_entries(&path, 3).unwrap();
        assert_eq!(tail.len(), 3);
        // Chronological (oldest first within the tail window): tool_2, tool_3, tool_4.
        assert_eq!(tail[0].tool_name, "tool_2");
        assert_eq!(tail[1].tool_name, "tool_3");
        assert_eq!(tail[2].tool_name, "tool_4");
    }

    #[test]
    fn tail_clamps_to_actual_count() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.log");
        let log = MutationLog::open(&path).unwrap();
        log.append(&entry("only")).unwrap();

        let tail = tail_entries(&path, 100).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].tool_name, "only");
    }

    #[test]
    fn tail_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent.log");
        let tail = tail_entries(&path, 10).unwrap();
        assert!(tail.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_writers_interleave_cleanly() {
        // Two threads simulating two MCP servers race on append.
        // The in-process Mutex serializes inside this process; the
        // flock would serialize across processes. Test asserts no
        // half-written JSON lines emerge.
        use std::sync::Arc as StdArc;
        use std::thread;

        let dir = tempdir().unwrap();
        let path = dir.path().join("race.log");
        let log = StdArc::new(MutationLog::open(&path).unwrap());

        let writers: Vec<_> = (0..4)
            .map(|w| {
                let log = StdArc::clone(&log);
                thread::spawn(move || {
                    for i in 0..25 {
                        log.append(&entry(&format!("w{w}_i{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }

        // Every line must parse — no torn writes.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4 * 25);
        for line in lines {
            serde_json::from_str::<MutationLogEntry>(line).unwrap_or_else(|e| {
                panic!("torn JSON line `{line}`: {e}");
            });
        }
    }
}
