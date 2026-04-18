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
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use secretenv_core::{Backend, BackendFactory, BackendStatus, BackendUri};

/// A live instance of the local filesystem backend.
pub struct LocalBackend {
    backend_type: &'static str,
    instance_name: String,
}

impl LocalBackend {
    const fn new(instance_name: String) -> Self {
        Self { backend_type: "local", instance_name }
    }

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

    async fn check(&self) -> BackendStatus {
        BackendStatus::Ok { cli_version: "local".into(), identity: "filesystem".into() }
    }

    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        let entries = self.list(test_uri).await?;
        Ok(entries.len())
    }

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
        _config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        Ok(Box::new(LocalBackend::new(instance_name.to_owned())))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn local_instance() -> LocalBackend {
        LocalBackend::new("local".to_owned())
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
