//! The runner — Phase 8's final piece of the resolution flow.
//!
//! Given a slice of [`ResolvedSecret`]s from
//! [`resolve_manifest`](crate::resolve_manifest) and a loaded
//! [`BackendRegistry`], the runner:
//!
//! 1. Fetches the value for every `ResolvedSource::Uri` via
//!    [`Backend::get`](crate::Backend::get).
//! 2. Builds an env map containing every fetched value plus every
//!    `ResolvedSource::Default` literal.
//! 3. On Unix, `exec()`s the target command — **replacing** the
//!    current process. The child inherits the parent's TTY, stdio,
//!    signal dispositions, and process group. On non-Unix, the
//!    runner spawns and propagates the child's exit code via
//!    [`std::process::exit`] (v0.3+; today the runner is Unix-first).
//!
//! # Dry-run mode
//!
//! In dry-run mode the runner prints `KEY ← <uri>` to stdout for each
//! [`ResolvedSource::Uri`] (never the value) and does **not** invoke
//! `Backend::get`. `ResolvedSource::Default` entries are also printed
//! in the form `KEY = <value>` because defaults are non-secret by
//! contract ([[secretenv-toml]] explicitly documents defaults are for
//! non-sensitive config like log levels).
//!
//! # Zeroization
//!
//! Fetched values are wrapped in [`zeroize::Zeroizing`] so the
//! plaintext is zeroed on drop in the non-exec paths (dry-run,
//! error short-circuit). On the happy path, `exec()` replaces the
//! process entirely — the heap is discarded, which is strictly more
//! aggressive than zeroization.
//!
//! # Errors
//!
//! The runner fails fast on the first fetch error and propagates it
//! with context (the env-var name plus the upstream error chain).
//! If `exec()` itself fails (e.g., the target command is missing),
//! the function returns with an error; it never silently crashes.
#![allow(clippy::module_name_repetitions)]

use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

use crate::backend::Backend;
use crate::registry::BackendRegistry;
use crate::resolver::{ResolvedSecret, ResolvedSource};

/// A fully-resolved env-var pair, ready for injection into the child
/// process. The value is zeroed on drop via [`zeroize::Zeroizing`].
pub struct EnvEntry {
    /// The environment variable name.
    pub key: String,
    value: Zeroizing<String>,
}

impl EnvEntry {
    /// Borrow the value as a `&str`. The underlying string is zeroed
    /// on drop.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Fetch every secret and run `command` with the resolved env merged
/// into the process environment.
///
/// On Unix this is a classic `exec()` — the current process is
/// replaced. On success, this function does not return. It only
/// returns to signal an error (fetch failure, missing backend, failed
/// exec, dry-run success).
///
/// # Errors
/// - `command` is empty.
/// - Any `ResolvedSource::Uri` targets a backend instance not
///   registered in `backends`.
/// - Any [`Backend::get`] call fails.
/// - `exec()` itself fails (non-existent command, permission denied,
///   etc.).
pub async fn run(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    command: &[String],
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    if command.is_empty() {
        bail!("no command specified — 'secretenv run' needs a program to execute");
    }

    let env = build_env(resolved, backends, dry_run, verbose).await?;

    if dry_run {
        return Ok(());
    }

    exec_with_env(command, &env)
}

/// Fetch every secret and build the env map. Visible to tests and
/// callers that want the env map without executing (e.g., `doctor`
/// pre-flight validation).
///
/// # Errors
/// Same as [`run`] minus the empty-command and exec-failure cases.
pub async fn build_env(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    dry_run: bool,
    verbose: bool,
) -> Result<Vec<EnvEntry>> {
    let mut env: Vec<EnvEntry> = Vec::with_capacity(resolved.len());

    for secret in resolved {
        match &secret.source {
            ResolvedSource::Default(value) => {
                if dry_run {
                    println!("{} = {value}  (default)", secret.env_var);
                }
                env.push(EnvEntry {
                    key: secret.env_var.clone(),
                    value: Zeroizing::new(value.clone()),
                });
            }
            ResolvedSource::Uri(uri) => {
                if dry_run {
                    println!("{} ← {}", secret.env_var, uri.raw);
                    continue;
                }
                if verbose {
                    // Log scheme (instance name) only — never `uri.raw`
                    // which contains the full backend path and would
                    // leak registry topology into CI build logs on any
                    // `--verbose` run. Full URI is reserved for
                    // `--dry-run` output, which is user-explicit.
                    eprintln!(
                        "secretenv: fetching {} from instance '{}'",
                        secret.env_var, uri.scheme
                    );
                }
                let backend: &dyn Backend = backends.get(&uri.scheme).ok_or_else(|| {
                    anyhow!(
                        "secret '{}': no backend instance '{}' is registered — \
                         add it to [backends.{}] in config.toml",
                        secret.env_var,
                        uri.scheme,
                        uri.scheme
                    )
                })?;
                let op_label = format!("{}::get (secret '{}')", uri.scheme, secret.env_var);
                let value =
                    crate::with_timeout(crate::DEFAULT_GET_TIMEOUT, &op_label, backend.get(uri))
                        .await
                        .with_context(|| {
                            format!(
                                "secret '{}': failed to fetch from '{}'",
                                secret.env_var, uri.raw
                            )
                        })?;
                env.push(EnvEntry { key: secret.env_var.clone(), value: Zeroizing::new(value) });
            }
        }
    }

    Ok(env)
}

/// SecretEnv-reserved env vars scrubbed from the child process
/// environment before `exec`/`spawn`. These carry CLI-layer
/// configuration (registry selection, config path) and should not leak
/// their provenance into whatever command the user ran.
const RESERVED_ENV_VARS: &[&str] = &["SECRETENV_REGISTRY", "SECRETENV_CONFIG"];

#[cfg(unix)]
fn exec_with_env(command: &[String], env: &[EnvEntry]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let program = &command[0];
    let args = &command[1..];
    let mut cmd = Command::new(program);
    cmd.args(args);
    for reserved in RESERVED_ENV_VARS {
        cmd.env_remove(reserved);
    }
    for entry in env {
        cmd.env(&entry.key, entry.value.as_str());
    }
    // exec() replaces the current process on success and only returns
    // on failure — so the io::Error it produces is always a real one.
    let err = cmd.exec();
    Err(anyhow!("failed to exec '{program}': {err}"))
}

#[cfg(not(unix))]
fn exec_with_env(command: &[String], env: &[EnvEntry]) -> Result<()> {
    let program = &command[0];
    let args = &command[1..];
    let mut cmd = Command::new(program);
    cmd.args(args);
    for reserved in RESERVED_ENV_VARS {
        cmd.env_remove(reserved);
    }
    for entry in env {
        cmd.env(&entry.key, entry.value.as_str());
    }
    let status = cmd.status().with_context(|| format!("failed to spawn '{program}'"))?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::backend::BackendFactory;
    use crate::config::{BackendConfig, Config};
    use crate::status::BackendStatus;
    use crate::uri::BackendUri;

    /// Fake backend that returns canned `get()` values keyed by
    /// URI.path, and counts `get()` invocations so dry-run tests
    /// can assert no fetch happened.
    struct FakeValueBackend {
        backend_type: String,
        instance_name: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Option<String>,
    }

    #[async_trait]
    impl Backend for FakeValueBackend {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn instance_name(&self) -> &str {
            &self.instance_name
        }
        async fn check(&self) -> BackendStatus {
            BackendStatus::Ok { cli_version: "fake/1.0".into(), identity: "fake".into() }
        }
        async fn check_extensive(&self, _: &BackendUri) -> Result<usize> {
            Ok(0)
        }
        async fn get(&self, uri: &BackendUri) -> Result<String> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_on.as_deref() == Some(&uri.path) {
                bail!("simulated backend error for path '{}'", uri.path);
            }
            self.values
                .get(&uri.path)
                .cloned()
                .ok_or_else(|| anyhow!("no canned value for path '{}'", uri.path))
        }
        async fn set(&self, _: &BackendUri, _: &str) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &BackendUri) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: &BackendUri) -> Result<Vec<(String, String)>> {
            Ok(vec![])
        }
    }

    struct FakeValueFactory {
        backend_type: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Option<String>,
    }

    impl BackendFactory for FakeValueFactory {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn create(
            &self,
            instance_name: &str,
            _: &HashMap<String, toml::Value>,
        ) -> Result<Box<dyn Backend>> {
            Ok(Box::new(FakeValueBackend {
                backend_type: self.backend_type.clone(),
                instance_name: instance_name.to_owned(),
                values: self.values.clone(),
                get_count: self.get_count.clone(),
                fail_on: self.fail_on.clone(),
            }))
        }
    }

    fn set_up(
        values: &[(&str, &str)],
        fail_on: Option<&str>,
    ) -> (BackendRegistry, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut backends = BackendRegistry::new();
        backends.register_factory(Box::new(FakeValueFactory {
            backend_type: "fake".into(),
            values: values.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            get_count: counter.clone(),
            fail_on: fail_on.map(ToOwned::to_owned),
        }));
        let config = Config {
            backends: std::iter::once((
                "fake".to_owned(),
                BackendConfig { backend_type: "fake".into(), raw_fields: HashMap::new() },
            ))
            .collect(),
            ..Default::default()
        };
        backends.load_from_config(&config).unwrap();
        (backends, counter)
    }

    fn secret_alias(env_var: &str, uri: &str) -> ResolvedSecret {
        ResolvedSecret {
            env_var: env_var.to_owned(),
            source: ResolvedSource::Uri(BackendUri::parse(uri).unwrap()),
        }
    }

    fn secret_default(env_var: &str, value: &str) -> ResolvedSecret {
        ResolvedSecret {
            env_var: env_var.to_owned(),
            source: ResolvedSource::Default(value.to_owned()),
        }
    }

    // ---- build_env happy path ----

    #[tokio::test]
    async fn build_env_fetches_uris_and_passes_defaults_through() {
        let (backends, count) =
            set_up(&[("/prod/stripe", "sk_live_123"), ("/prod/db", "postgres://x")], None);
        let resolved = vec![
            secret_alias("STRIPE", "fake:///prod/stripe"),
            secret_default("LOG_LEVEL", "info"),
            secret_alias("DATABASE_URL", "fake:///prod/db"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();

        assert_eq!(env.len(), 3);
        assert_eq!(env[0].key, "STRIPE");
        assert_eq!(env[0].value(), "sk_live_123");
        assert_eq!(env[1].key, "LOG_LEVEL");
        assert_eq!(env[1].value(), "info");
        assert_eq!(env[2].key, "DATABASE_URL");
        assert_eq!(env[2].value(), "postgres://x");
        assert_eq!(count.load(Ordering::SeqCst), 2, "fetched both Uris, default skipped");
    }

    // ---- dry-run never calls Backend::get ----

    #[tokio::test]
    async fn dry_run_skips_backend_get_entirely() {
        let (backends, count) = set_up(&[("/prod/stripe", "sk_live_123")], None);
        let resolved = vec![
            secret_alias("STRIPE", "fake:///prod/stripe"),
            secret_default("LOG_LEVEL", "info"),
        ];
        let env = build_env(&resolved, &backends, true, false).await.unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 0, "dry-run must not fetch");
        // Env still includes Default entries (they're non-secret manifest data).
        let default = env.iter().find(|e| e.key == "LOG_LEVEL").unwrap();
        assert_eq!(default.value(), "info");
        // Uri entries are omitted in dry-run mode.
        assert!(env.iter().all(|e| e.key != "STRIPE"));
    }

    // ---- Missing backend instance ----

    #[tokio::test]
    async fn missing_backend_instance_errors_with_env_var_name() {
        let (backends, _) = set_up(&[("/x", "v")], None);
        let resolved = vec![secret_alias("KEY", "nonexistent:///x")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("KEY"), "error names env-var: {msg}");
        assert!(msg.contains("nonexistent"), "error names missing instance: {msg}");
    }

    // ---- Backend fetch error propagates ----

    #[tokio::test]
    async fn backend_get_error_propagates_with_context() {
        let (backends, _) = set_up(&[], Some("/locked"));
        let resolved = vec![secret_alias("LOCKED", "fake:///locked")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("LOCKED"), "env-var in context: {msg}");
        assert!(msg.contains("fake:///locked"), "uri in context: {msg}");
        assert!(msg.contains("simulated backend error"), "root cause preserved: {msg}");
    }

    // ---- Fail fast ----

    #[tokio::test]
    async fn build_env_fails_fast_on_first_fetch_error() {
        let (backends, count) = set_up(&[("/good", "v")], Some("/bad"));
        let resolved = vec![secret_alias("A", "fake:///bad"), secret_alias("B", "fake:///good")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        assert!(format!("{err:#}").contains('A'));
        assert_eq!(count.load(Ordering::SeqCst), 1, "should stop after first failure");
    }

    // ---- run() command-level errors ----

    #[tokio::test]
    async fn run_errors_when_command_is_empty() {
        let (backends, _) = set_up(&[], None);
        let resolved: Vec<ResolvedSecret> = vec![];
        let Err(err) = run(&resolved, &backends, &[], false, false).await else {
            panic!("expected run to error on empty command");
        };
        assert!(format!("{err:#}").contains("no command"));
    }

    #[tokio::test]
    async fn run_errors_when_exec_target_is_missing() {
        // Use a path guaranteed not to exist. On exec-failure, run()
        // returns; it doesn't replace our test process.
        let (backends, _) = set_up(&[], None);
        let resolved: Vec<ResolvedSecret> = vec![];
        let bogus = "/definitely/not/a/real/binary-abc123".to_owned();
        let Err(err) = run(&resolved, &backends, std::slice::from_ref(&bogus), false, false).await
        else {
            panic!("expected run to error on bogus program");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains(&bogus), "error names bogus program: {msg}");
    }

    // ---- Order preservation ----

    #[tokio::test]
    async fn build_env_preserves_declaration_order() {
        let (backends, _) = set_up(&[("/a", "1"), ("/b", "2"), ("/c", "3")], None);
        let resolved = vec![
            secret_alias("FIRST", "fake:///a"),
            secret_alias("SECOND", "fake:///b"),
            secret_alias("THIRD", "fake:///c"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let keys: Vec<_> = env.iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, vec!["FIRST", "SECOND", "THIRD"]);
    }

    // ---- Zeroizing smoke test ----

    #[tokio::test]
    async fn env_entries_can_be_consumed_as_str() {
        let (backends, _) = set_up(&[("/k", "the-secret-value")], None);
        let resolved = vec![secret_alias("K", "fake:///k")];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        // Sanity: value() returns &str without touching Zeroizing's
        // public API; the wrapper lives only inside the struct.
        let s: &str = env[0].value();
        assert_eq!(s, "the-secret-value");
    }

    // ---- Reserved env-var scrub (CV-7 / SEC-1) ----

    #[test]
    fn reserved_env_vars_contains_registry_and_config() {
        // Ensures any future SECRETENV_* var intended to pass CLI config
        // into the process is added here before it leaks to child procs.
        assert!(RESERVED_ENV_VARS.contains(&"SECRETENV_REGISTRY"));
        assert!(RESERVED_ENV_VARS.contains(&"SECRETENV_CONFIG"));
    }
}
