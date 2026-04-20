//! Local filesystem backend for SecretEnv.
//!
//! # URI shape
//!
//! `local:///<absolute/path/to/file.toml>` — the path portion is
//! interpreted as a filesystem path. A leading `/` is prepended if
//! missing, so `local:///foo/bar.toml` and `local://foo/bar.toml` both
//! resolve to `/foo/bar.toml`.
//!
//! # v0.1 semantics: whole-file, not key-level
//!
//! The `local` backend operates on whole files:
//!
//! - [`get`](LocalBackend::get) reads the file and returns its contents
//!   as a UTF-8 string. Used by the registry resolver to fetch the
//!   registry document verbatim.
//! - [`set`](LocalBackend::set) writes the supplied `value` as the
//!   entire file body, creating parent directories as needed. On Unix,
//!   the file is `chmod 600` to keep world/group off the data.
//! - [`delete`](LocalBackend::delete) removes the file.
//! - [`list`](LocalBackend::list) parses the file as a flat
//!   `HashMap<String, String>` TOML document and returns the entries.
//!
//! Key-level operations (multiple secrets stored as keys inside a
//! single file) are intentionally out of scope for v0.1. The intended
//! use case is a registry source or a single-secret-per-file store.
//! Revisit in v0.2 if solo-dev workflows demand it.
//!
//! # Security
//!
//! - Writes chmod 600 on Unix. Windows has no equivalent; writes there
//!   use the inherited directory permissions and leave a note for
//!   `doctor` to flag in v0.3+.
//! - `doctor` (Phase 10) will warn if a file referenced by a `local://`
//!   URI is world- or group-readable. v0.1 only enforces on write.
//!
//! # v0.2.2 strict-mode mock audit
//!
//! The strict-mode mock harness ([`secretenv_testing::StrictMock`])
//! targets backends that shell out to a child CLI — it validates the
//! exact argv secretenv sends to `aws` / `op` / `vault` / `gcloud` /
//! `az`. `local` does NOT shell out: every operation is a direct
//! `std::fs` call against the configured path. There is no argv surface
//! to validate and no CLI to mock, so strict-mode has no applicability
//! here. The v0.2.2 retrofit covers `local` by documentation only; no
//! test changes are required or meaningful. Subsequent patches in the
//! series (v0.2.3 aws-ssm, v0.2.4 1password, v0.2.5 vault, v0.2.6
//! aws-secrets) each migrate their backend's mock-CLI tests to the
//! strict harness.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, Backend, BackendFactory, BackendStatus, BackendUri, HistoryEntry,
    DEFAULT_GET_TIMEOUT,
};

/// A live instance of the local filesystem backend.
pub struct LocalBackend {
    backend_type: &'static str,
    instance_name: String,
    timeout: Duration,
}

impl LocalBackend {
    fn file_path(uri: &BackendUri) -> PathBuf {
        if uri.path.starts_with('/') {
            PathBuf::from(&uri.path)
        } else {
            PathBuf::from(format!("/{}", uri.path))
        }
    }
}

#[async_trait]
impl Backend for LocalBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn check(&self) -> BackendStatus {
        BackendStatus::Ok { cli_version: "local".into(), identity: "filesystem".into() }
    }

    // `check_extensive` uses the `Backend` trait's default (list().len()).

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let path = Self::file_path(uri);
        tokio::fs::read_to_string(&path).await.with_context(|| {
            format!(
                "local backend '{}': failed to read '{}' (uri='{}')",
                self.instance_name,
                path.display(),
                uri.raw
            )
        })
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let path = Self::file_path(uri);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "local backend '{}': failed to create parent directory '{}'",
                    self.instance_name,
                    parent.display()
                )
            })?;
        }

        // Open with mode 0o600 on Unix so a newly-created file never goes
        // through a world-readable state. On Unix open(O_CREAT) only applies
        // the mode to new files, so pre-existing files keep their current
        // mode; the chmod below handles those as defense-in-depth.
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&path).await.with_context(|| {
            format!(
                "local backend '{}': failed to open '{}' for write (uri='{}')",
                self.instance_name,
                path.display(),
                uri.raw
            )
        })?;
        f.write_all(value.as_bytes()).await.with_context(|| {
            format!(
                "local backend '{}': failed to write '{}' (uri='{}')",
                self.instance_name,
                path.display(),
                uri.raw
            )
        })?;
        // Flush + close via drop.
        f.flush().await.with_context(|| {
            format!("local backend '{}': failed to flush '{}'", self.instance_name, path.display())
        })?;
        drop(f);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&path, perms).await.with_context(|| {
                format!(
                    "local backend '{}': failed to chmod 600 on '{}'",
                    self.instance_name,
                    path.display()
                )
            })?;
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        let path = Self::file_path(uri);
        tokio::fs::remove_file(&path).await.with_context(|| {
            format!(
                "local backend '{}': failed to delete '{}' (uri='{}')",
                self.instance_name,
                path.display(),
                uri.raw
            )
        })
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        let contents = self.get(uri).await?;
        let parsed: HashMap<String, String> = toml::from_str(&contents).with_context(|| {
            format!(
                "local backend '{}': file at '{}' is not a flat TOML key→string map",
                self.instance_name, uri.raw
            )
        })?;
        Ok(parsed.into_iter().collect())
    }

    /// Shell out to `git log --follow` against the registry file.
    /// The repo lookup walks upward from the file's parent directory;
    /// if no repo is found we surface a clean "not under git" error
    /// so the CLI can render it without dumping a stack trace.
    async fn history(&self, uri: &BackendUri) -> Result<Vec<HistoryEntry>> {
        let path = Self::file_path(uri);
        if !path.exists() {
            bail!(
                "local backend '{}': cannot read history of '{}' — file does not exist",
                self.instance_name,
                path.display()
            );
        }
        let parent = path.parent().ok_or_else(|| {
            anyhow!(
                "local backend '{}': '{}' has no parent directory",
                self.instance_name,
                path.display()
            )
        })?;

        // git log fields are tab-separated to keep parsing robust
        // against whitespace in author names and commit subjects.
        // Field order: short-sha, ISO-8601 author date, author name
        // <email>, subject. The author "name <email>" form is what
        // git produces with %an + %ae; we keep it as a single Actor
        // string so the CLI doesn't need to reconstruct.
        let mut cmd = tokio::process::Command::new("git");
        cmd.arg("-C").arg(parent);
        cmd.args(["log", "--follow", "--pretty=format:%h%x09%aI%x09%an <%ae>%x09%s", "--"]);
        cmd.arg(&path);
        let output = cmd.output().await.with_context(|| {
            format!(
                "local backend '{}': failed to spawn `git log` for '{}'",
                self.instance_name,
                path.display()
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            // The two we care about: not under a git repo, and the
            // path being untracked. git emits both via stderr+nonzero.
            // Pass through verbatim so the user sees git's own message.
            bail!(
                "local backend '{}': `git log` failed for '{}': {stderr}",
                self.instance_name,
                path.display()
            );
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "local backend '{}': non-UTF-8 `git log` output for '{}'",
                self.instance_name,
                path.display()
            )
        })?;
        Ok(parse_git_log(&stdout))
    }
}

/// Parse the tab-separated git-log payload into `HistoryEntry` rows.
/// Empty input returns an empty Vec (a tracked-but-never-modified file
/// is unusual but possible). Malformed lines are skipped; we trust git
/// to emit our format reliably and prefer "drop weird line" over
/// "fail the whole call" for partial parses.
fn parse_git_log(stdout: &str) -> Vec<HistoryEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.splitn(4, '\t');
        let (Some(version), Some(timestamp), Some(actor), description) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        out.push(HistoryEntry {
            version: version.to_owned(),
            timestamp: timestamp.to_owned(),
            actor: Some(actor.to_owned()),
            description: description.map(str::to_owned),
        });
    }
    out
}

/// Factory for the local filesystem backend. No config fields required.
pub struct LocalFactory(&'static str);

impl LocalFactory {
    /// Construct the factory. Equivalent to `LocalFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("local")
    }
}

impl Default for LocalFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for LocalFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let timeout = optional_duration_secs(config, "timeout_secs", "local", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(Box::new(LocalBackend {
            backend_type: "local",
            instance_name: instance_name.to_owned(),
            timeout,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn local_instance() -> LocalBackend {
        LocalBackend {
            backend_type: "local",
            instance_name: "local".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn uri_for(path: &std::path::Path) -> BackendUri {
        BackendUri::parse(&format!("local://{}", path.display())).unwrap()
    }

    #[test]
    fn factory_builds_backend_with_instance_name() {
        let factory = LocalFactory::new();
        assert_eq!(factory.backend_type(), "local");
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let backend = factory.create("local-main", &cfg).unwrap();
        assert_eq!(backend.backend_type(), "local");
        assert_eq!(backend.instance_name(), "local-main");
    }

    #[test]
    fn factory_ignores_unknown_config_fields() {
        let factory = LocalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("unexpected".to_owned(), toml::Value::String("value".to_owned()));
        // No error — factory ignores all fields.
        assert!(factory.create("local", &cfg).is_ok());
    }

    #[tokio::test]
    async fn check_is_always_ok() {
        let b = local_instance();
        assert!(matches!(b.check().await, BackendStatus::Ok { .. }));
    }

    #[tokio::test]
    async fn set_then_get_roundtrips_exact_bytes() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let uri = uri_for(&dir.path().join("reg.toml"));

        b.set(&uri, "DATABASE = \"secretenv://db\"\n").await.unwrap();
        let got = b.get(&uri).await.unwrap();
        assert_eq!(got, "DATABASE = \"secretenv://db\"\n");
    }

    #[tokio::test]
    async fn set_creates_missing_parent_directories() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c").join("reg.toml");
        let b = local_instance();
        let uri = uri_for(&nested);

        b.set(&uri, "KEY = \"value\"\n").await.unwrap();
        assert!(nested.exists());
    }

    #[tokio::test]
    async fn list_parses_flat_toml_map() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let uri = uri_for(&dir.path().join("reg.toml"));

        b.set(
            &uri,
            r#"
stripe-key = "aws-ssm-prod:///stripe/api-key"
db-url     = "1password-personal://Engineering/Prod DB/url"
"#,
        )
        .await
        .unwrap();

        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("db-url".to_owned(), "1password-personal://Engineering/Prod DB/url".to_owned(),),
                ("stripe-key".to_owned(), "aws-ssm-prod:///stripe/api-key".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn delete_removes_file() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let path = dir.path().join("reg.toml");
        let uri = uri_for(&path);

        b.set(&uri, "k = \"v\"\n").await.unwrap();
        assert!(path.exists());
        b.delete(&uri).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn get_missing_file_errors_with_path_and_instance() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let uri = uri_for(&dir.path().join("nonexistent.toml"));

        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nonexistent.toml"), "error names path: {msg}");
        assert!(msg.contains("local"), "error names instance: {msg}");
    }

    #[tokio::test]
    async fn list_on_non_toml_file_errors() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let path = dir.path().join("garbage.toml");
        let uri = uri_for(&path);

        // Invalid TOML (parses, but value isn't a string — `list` requires
        // every value to be a string).
        b.set(&uri, "[table]\nnested = \"ok\"\n").await.unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("flat TOML") || msg.contains("string"), "specific error: {msg}");
    }

    #[tokio::test]
    async fn list_on_non_utf8_errors() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let path = dir.path().join("bin.toml");
        let uri = uri_for(&path);

        tokio::fs::write(&path, [0xFF, 0xFE, 0xFD, 0xFC]).await.unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bin.toml"), "error mentions path: {msg}");
    }

    #[tokio::test]
    async fn check_extensive_counts_entries() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let uri = uri_for(&dir.path().join("reg.toml"));

        b.set(&uri, "a = \"1\"\nb = \"2\"\nc = \"3\"\n").await.unwrap();
        let count = b.check_extensive(&uri).await.unwrap();
        assert_eq!(count, 3);
    }

    // ---- history() ----

    #[test]
    fn parse_git_log_handles_well_formed_input() {
        // Two commits, tab-delimited per the format string. Most-recent-first
        // is the expected git-log default; the parser preserves order.
        let stdout = "abc1234\t2026-04-19T11:00:00+00:00\tBot <bot@example.com>\tAdd alias\n\
                      def5678\t2026-04-19T10:00:00+00:00\tHuman <h@example.com>\tInitial registry\n";
        let entries = parse_git_log(stdout);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].version, "abc1234");
        assert_eq!(entries[0].timestamp, "2026-04-19T11:00:00+00:00");
        assert_eq!(entries[0].actor.as_deref(), Some("Bot <bot@example.com>"));
        assert_eq!(entries[0].description.as_deref(), Some("Add alias"));
        assert_eq!(entries[1].description.as_deref(), Some("Initial registry"));
    }

    #[test]
    fn parse_git_log_skips_malformed_lines_without_failing_call() {
        // Lines with fewer than 3 tabs (no actor / no timestamp) are
        // skipped silently; we trust git's format string but defend
        // against a future schema drift by not panicking.
        let stdout = "good\t2026\tactor\tdesc\n\
             malformed-no-tabs\n\
             also\t2026\tjust-actor\n";
        let entries = parse_git_log(stdout);
        assert_eq!(entries.len(), 2, "1 well-formed + 1 with optional desc absent");
        assert_eq!(entries[0].description.as_deref(), Some("desc"));
        assert!(entries[1].description.is_none(), "missing description → None");
    }

    #[test]
    fn parse_git_log_empty_input_returns_empty() {
        assert!(parse_git_log("").is_empty());
        assert!(parse_git_log("\n").is_empty());
    }

    #[tokio::test]
    async fn history_errors_when_file_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let uri = uri_for(&dir.path().join("ghost.toml"));
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does not exist"), "error names absence: {msg}");
        assert!(msg.contains("ghost.toml"), "error names path: {msg}");
    }

    #[tokio::test]
    async fn history_errors_when_path_is_not_under_a_git_repo() {
        // Tempdir under /tmp is (usually) not inside a git repo. The
        // git binary should fail with a "not a git repository" stderr;
        // we surface that verbatim so the user can react.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reg.toml");
        let b = local_instance();
        let uri = uri_for(&path);
        b.set(&uri, "k = \"v\"\n").await.unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("git log") || msg.contains("not a git repository") || msg.contains("git"),
            "git error surfaced: {msg}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn set_chmods_file_to_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let b = local_instance();
        let path = dir.path().join("reg.toml");
        let uri = uri_for(&path);

        b.set(&uri, "k = \"v\"\n").await.unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }
}
