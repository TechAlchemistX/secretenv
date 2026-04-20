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
//! A single alias failure propagates its error as-is (env-var name +
//! URI + upstream error chain). **Multiple** alias failures are
//! aggregated into one error that lists every failed alias — operators
//! troubleshooting a misconfigured environment see every broken alias
//! in one pass. If `exec()` itself fails (e.g., the target command is
//! missing), the function returns with an error; it never silently
//! crashes.
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
/// `Default`-sourced entries resolve inline with zero I/O.
/// `Uri`-sourced entries are fetched concurrently via
/// [`futures::future::join_all`]. On dry-run, no backend is invoked.
///
/// # Errors
///
/// If a single alias fetch fails, its error is returned as-is (with
/// the backend error chain plus an alias/URI context line).
///
/// If **multiple** alias fetches fail, the returned error aggregates
/// every failure — one per line, each naming the env-var, the target
/// URI, and the upstream error. This is intentional: operators
/// troubleshooting a misconfigured environment see every broken alias
/// in one pass rather than fixing one, re-running, fixing the next,
/// and so on.
pub async fn build_env(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    dry_run: bool,
    verbose: bool,
) -> Result<Vec<EnvEntry>> {
    // Output preserves `resolved`'s declaration order. We collect into
    // a `Vec<Option<EnvEntry>>` of the same length and then drop the
    // dry-run `None`s at the end.
    let mut slots: Vec<Option<EnvEntry>> = (0..resolved.len()).map(|_| None).collect();

    // First pass: handle `Default` inline (no I/O) and collect indices
    // for the `Uri` branch.
    let mut uri_indices: Vec<usize> = Vec::new();
    for (idx, secret) in resolved.iter().enumerate() {
        match &secret.source {
            ResolvedSource::Default(value) => {
                if dry_run {
                    println!("{} = {value}  (default)", secret.env_var);
                }
                slots[idx] = Some(EnvEntry {
                    key: secret.env_var.clone(),
                    value: Zeroizing::new(value.clone()),
                });
            }
            ResolvedSource::Uri { .. } => uri_indices.push(idx),
        }
    }

    // Second pass: dispatch all URI fetches concurrently. `fetch_one`
    // returns `Ok(None)` in dry-run mode (printed the placeholder,
    // nothing to inject), `Ok(Some(entry))` on success.
    let fetches =
        uri_indices.iter().map(|&idx| fetch_one(&resolved[idx], backends, dry_run, verbose));
    let results = futures::future::join_all(fetches).await;

    // Collect successes into their original slots; aggregate every
    // failure's error message. Multi-failure returns a single joined
    // anyhow error so one CLI run surfaces every broken alias.
    let mut errors: Vec<anyhow::Error> = Vec::new();
    for (idx, result) in uri_indices.iter().zip(results) {
        match result {
            Ok(Some(entry)) => slots[*idx] = Some(entry),
            Ok(None) => { /* dry-run; nothing to place */ }
            Err(err) => errors.push(err),
        }
    }

    if !errors.is_empty() {
        return Err(aggregate_errors(errors));
    }

    Ok(slots.into_iter().flatten().collect())
}

/// Fetch a single `Uri`-sourced secret. Returns `Ok(None)` in dry-run
/// (placeholder printed, caller should not inject anything). Returns
/// `Ok(Some(entry))` on a successful fetch.
///
/// Runs under the global `DEFAULT_GET_TIMEOUT` via
/// [`crate::with_timeout`].
async fn fetch_one(
    secret: &ResolvedSecret,
    backends: &BackendRegistry,
    dry_run: bool,
    verbose: bool,
) -> Result<Option<EnvEntry>> {
    let target = match &secret.source {
        ResolvedSource::Uri { target, .. } => target,
        ResolvedSource::Default(_) => {
            // Unreachable: `build_env` only calls `fetch_one` for
            // `Uri` entries. Kept as defensive no-op rather than a
            // panic because one-shot helper misuse should not abort.
            return Ok(None);
        }
    };

    if dry_run {
        println!("{} ← {}", secret.env_var, target.raw);
        return Ok(None);
    }

    if verbose {
        // Log scheme (instance name) only — never `target.raw`, which
        // contains the full backend path and would leak registry
        // topology into CI build logs on any `--verbose` run. Full
        // URI is reserved for `--dry-run` output, which is explicit.
        eprintln!("secretenv: fetching {} from instance '{}'", secret.env_var, target.scheme);
    }

    let backend: &dyn Backend = backends.get(&target.scheme).ok_or_else(|| {
        anyhow!(
            "secret '{}': no backend instance '{}' is registered — \
             add it to [backends.{}] in config.toml",
            secret.env_var,
            target.scheme,
            target.scheme
        )
    })?;
    let op_label = format!("{}::get (secret '{}')", target.scheme, secret.env_var);
    let value =
        crate::with_timeout(backend.timeout(), &op_label, backend.get(target)).await.with_context(
            || format!("secret '{}': failed to fetch from '{}'", secret.env_var, target.raw),
        )?;
    Ok(Some(EnvEntry { key: secret.env_var.clone(), value: Zeroizing::new(value) }))
}

/// Combine N>1 fetch failures into a single anyhow error whose
/// `{:#}` rendering lists every failure on its own line. For N=1
/// returns the original error unwrapped so single-failure messages
/// don't get decorated with a misleading "2 aliases failed" header.
fn aggregate_errors(mut errors: Vec<anyhow::Error>) -> anyhow::Error {
    if errors.len() == 1 {
        // Single-failure path: preserve the original error chain
        // intact so operators see the same shape as v0.1 when only
        // one alias was broken. `swap_remove(0)` is bounds-safe by
        // the just-checked len.
        return errors.swap_remove(0);
    }
    let count = errors.len();
    let body = errors.iter().map(|e| format!("  - {e:#}")).collect::<Vec<_>>().join("\n");
    anyhow!("{count} secrets failed to resolve:\n{body}")
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
    /// URI.path, counts `get()` invocations, and optionally sleeps
    /// (for parallelism-regression tests) or fails on a set of paths
    /// (for multi-error aggregation tests).
    struct FakeValueBackend {
        backend_type: String,
        instance_name: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Vec<String>,
        delay: std::time::Duration,
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
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail_on.iter().any(|p| p == &uri.path) {
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

    #[derive(Clone)]
    struct FakeValueFactory {
        backend_type: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Vec<String>,
        delay: std::time::Duration,
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
                delay: self.delay,
            }))
        }
    }

    fn set_up(
        values: &[(&str, &str)],
        fail_on: Option<&str>,
    ) -> (BackendRegistry, Arc<AtomicUsize>) {
        set_up_full(
            values,
            &fail_on.map_or_else(Vec::new, |p| vec![p.to_owned()]),
            std::time::Duration::ZERO,
        )
    }

    fn set_up_full(
        values: &[(&str, &str)],
        fail_on: &[String],
        delay: std::time::Duration,
    ) -> (BackendRegistry, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut backends = BackendRegistry::new();
        backends.register_factory(Box::new(FakeValueFactory {
            backend_type: "fake".into(),
            values: values.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            get_count: counter.clone(),
            fail_on: fail_on.to_vec(),
            delay,
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
        let parsed = BackendUri::parse(uri).unwrap();
        ResolvedSecret {
            env_var: env_var.to_owned(),
            // Tests don't exercise cascade-source surfacing; use the
            // target URI as the source placeholder.
            source: ResolvedSource::Uri { target: parsed.clone(), source: parsed },
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

    // ---- Parallel fetch + multi-error aggregation (Phase 2) ----

    /// Parallelism regression: 5 aliases, each with a 50 ms simulated
    /// backend round-trip. Serial execution would take ≥ 250 ms; a
    /// healthy concurrent path finishes in close to 50 ms. We assert
    /// "well under the serial bound" rather than a tight wall-time —
    /// CI machines are noisy and a flaky timing assertion is worse
    /// than a loose one.
    #[tokio::test]
    async fn build_env_fetches_aliased_secrets_concurrently() {
        let values: Vec<(&str, &str)> = (0..5)
            .map(|i| match i {
                0 => ("/a", "va"),
                1 => ("/b", "vb"),
                2 => ("/c", "vc"),
                3 => ("/d", "vd"),
                _ => ("/e", "ve"),
            })
            .collect();
        let (backends, count) = set_up_full(&values, &[], std::time::Duration::from_millis(50));
        let resolved = vec![
            secret_alias("A", "fake:///a"),
            secret_alias("B", "fake:///b"),
            secret_alias("C", "fake:///c"),
            secret_alias("D", "fake:///d"),
            secret_alias("E", "fake:///e"),
        ];

        let start = std::time::Instant::now();
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(env.len(), 5, "every alias returned");
        assert_eq!(count.load(Ordering::SeqCst), 5, "every alias fetched exactly once");
        // Serial lower bound would be 5 × 50 = 250 ms. Anything under
        // 200 ms proves fetches overlapped. Generous upper bound to
        // avoid CI flakes.
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "expected concurrent fetch (< 200 ms), elapsed = {elapsed:?}"
        );
    }

    /// Declaration order must be preserved even when backends return
    /// out of dispatch order (which they can in concurrent mode).
    #[tokio::test]
    async fn build_env_preserves_declaration_order_with_parallel_fetch() {
        let (backends, _) =
            set_up_full(&[("/a", "1"), ("/b", "2"), ("/c", "3")], &[], std::time::Duration::ZERO);
        let resolved = vec![
            secret_alias("FIRST", "fake:///a"),
            secret_default("MIDDLE", "middle"),
            secret_alias("THIRD", "fake:///b"),
            secret_alias("LAST", "fake:///c"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let keys: Vec<_> = env.iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, vec!["FIRST", "MIDDLE", "THIRD", "LAST"]);
    }

    /// When multiple aliases fail, the returned error enumerates
    /// **every** failure in one message — not just the first one
    /// the concurrent dispatch happened to complete.
    #[tokio::test]
    async fn build_env_aggregates_all_fetch_errors() {
        let (backends, count) = set_up_full(
            &[("/ok", "good")],
            &["/bad1".to_owned(), "/bad2".to_owned()],
            std::time::Duration::ZERO,
        );
        let resolved = vec![
            secret_alias("ALPHA", "fake:///bad1"),
            secret_alias("BETA", "fake:///ok"),
            secret_alias("GAMMA", "fake:///bad2"),
        ];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error on two failing aliases");
        };
        let msg = format!("{err:#}");

        assert!(msg.contains("ALPHA"), "error names first failing env-var: {msg}");
        assert!(msg.contains("GAMMA"), "error names second failing env-var: {msg}");
        assert!(msg.contains("fake:///bad1"), "error includes first bad URI: {msg}");
        assert!(msg.contains("fake:///bad2"), "error includes second bad URI: {msg}");
        assert!(msg.contains("2 secrets failed"), "header surfaces the count: {msg}");
        // GAMMA-after-ALPHA preserves `resolved`'s declaration order
        // in the aggregated message (regardless of completion order).
        assert!(
            msg.find("ALPHA").unwrap() < msg.find("GAMMA").unwrap(),
            "aggregation preserves declaration order: {msg}"
        );
        // Every alias was dispatched — aggregation does not short-circuit.
        assert_eq!(count.load(Ordering::SeqCst), 3, "all 3 alias fetches dispatched");
    }

    /// Single failure: the aggregation path should NOT wrap the error
    /// in a "1 secrets failed:" header. Preserves v0.1-style single-
    /// failure error shape for operators with one broken alias.
    #[tokio::test]
    async fn build_env_single_failure_passes_error_through_unwrapped() {
        let (backends, _) = set_up_full(&[], &["/only".to_owned()], std::time::Duration::ZERO);
        let resolved = vec![secret_alias("ONLY", "fake:///only")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("ONLY"), "env-var present: {msg}");
        assert!(msg.contains("fake:///only"), "uri present: {msg}");
        assert!(msg.contains("simulated backend error"), "root cause preserved: {msg}");
        assert!(!msg.contains("secrets failed to resolve"), "no aggregation header: {msg}");
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
