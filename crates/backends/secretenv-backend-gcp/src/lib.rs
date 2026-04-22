// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Google Cloud Secret Manager backend for SecretEnv.
//!
//! Wraps the `gcloud` CLI — **never** a GCP SDK. Every credential
//! chain `gcloud` supports (user login, service-account key file,
//! Workload Identity, metadata server, impersonation) works
//! transparently because the CLI resolves auth the way the user
//! already configured it.
//!
//! # URI shape
//!
//! `<instance>:///<secret-name>[#version=<n>]` — scheme is the
//! instance name (e.g. `gcp-prod`); path is the Secret Manager secret
//! name. The optional `#version=<n>` directive pins a specific
//! version ID; `<n>` is either a positive integer or the literal
//! `latest`. When absent or `latest`, the flag is omitted and
//! `gcloud` defaults to the newest enabled version.
//!
//! # Config fields
//!
//! - `gcp_project` (required) — passed via `--project` on every call
//! - `gcp_impersonate_service_account` (optional) — appended as
//!   `--impersonate-service-account <sa>` when set
//! - `gcloud_bin` (test hook) — overrides the `gcloud` binary path
//!
//! # Safety
//!
//! Every CLI call goes through `Command::args([...])` with individual
//! `&str`s — never `sh -c`, never `format!` into a shell string. The
//! `set` path pipes secret values via child stdin (CV-1 discipline).
//! The `OAuth2` bearer token returned by
//! `gcloud auth print-access-token` is **discarded immediately** —
//! never logged, never interpolated into identity strings, never
//! included in error messages. A dedicated canary test locks this.
//!
//! See [[backends/gcp]] in the kb for the full implementation spec.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, optional_string, required_string, Backend, BackendFactory,
    BackendStatus, BackendUri, DEFAULT_GET_TIMEOUT,
};
use tokio::process::Command;

const CLI_NAME: &str = "gcloud";
const INSTALL_HINT: &str =
    "brew install --cask google-cloud-sdk  OR  https://cloud.google.com/sdk/docs/install";

/// A live instance of the GCP Secret Manager backend.
pub struct GcpBackend {
    backend_type: &'static str,
    instance_name: String,
    gcp_project: String,
    gcp_impersonate_service_account: Option<String>,
    /// Path or name of the `gcloud` binary. Defaults to `"gcloud"`
    /// (PATH lookup); tests override to point at a mock script.
    gcloud_bin: String,
    /// Per-instance fetch deadline; from `timeout_secs` config field.
    timeout: Duration,
}

impl GcpBackend {
    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        format!(
            "gcp backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `gcloud <args...> --project <proj> --quiet
    /// [--impersonate-service-account <sa>]` command. The positional
    /// subcommand tokens (e.g. `secrets versions access`) go in
    /// `args`; the trailing scoping flags are appended here so every
    /// call site emits a consistent shape that strict mocks can lock.
    fn gcloud_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.gcloud_bin);
        cmd.args(args);
        cmd.args(["--project", &self.gcp_project]);
        cmd.arg("--quiet");
        if let Some(sa) = &self.gcp_impersonate_service_account {
            cmd.args(["--impersonate-service-account", sa]);
        }
        cmd
    }

    /// Strip exactly one leading `/` from `uri.path` to produce the
    /// post-strip secret name. GCP Secret Manager names CANNOT begin
    /// with `/`; triple-slash URIs (`gcp-prod:///stripe_key`) yield
    /// `uri.path = "/stripe_key"` which we strip to `stripe_key`.
    fn secret_name(uri: &BackendUri) -> &str {
        uri.path.strip_prefix('/').unwrap_or(&uri.path)
    }

    /// Resolve the `#version=<n>` directive into the positional
    /// argument `gcloud secrets versions access` expects. Returns
    /// `"latest"` when the fragment is absent OR the directive value
    /// is literally `latest`. Rejects shorthand, extras, malformed
    /// grammar, and non-integer version IDs BEFORE any network I/O.
    fn resolve_version(&self, uri: &BackendUri) -> Result<String> {
        let directives = uri.fragment_directives()?;
        let Some(mut directives) = directives else {
            return Ok("latest".to_owned());
        };
        if !directives.contains_key("version") {
            let mut unsupported: Vec<&str> = directives.keys().map(String::as_str).collect();
            unsupported.sort_unstable();
            bail!(
                "gcp backend '{}': URI '{}' has unsupported fragment directive(s) [{}]; \
                 gcp recognizes only 'version' (example: '#version=5'). \
                 See docs/fragment-vocabulary.md",
                self.instance_name,
                uri.raw,
                unsupported.join(", ")
            );
        }
        if directives.len() > 1 {
            let mut extra: Vec<&str> =
                directives.keys().filter(|k| k.as_str() != "version").map(String::as_str).collect();
            extra.sort_unstable();
            bail!(
                "gcp backend '{}': URI '{}' has unsupported directive(s) [{}] alongside \
                 'version'; gcp recognizes only 'version'. \
                 See docs/fragment-vocabulary.md",
                self.instance_name,
                uri.raw,
                extra.join(", ")
            );
        }
        let Some(value) = directives.shift_remove("version") else {
            unreachable!("version presence was checked above")
        };
        if value == "latest" {
            return Ok("latest".to_owned());
        }
        let parsed: u64 = value.parse().map_err(|_| {
            anyhow!(
                "gcp backend '{}': URI '{}' has invalid version value '{}'; \
                 expected positive integer or 'latest'",
                self.instance_name,
                uri.raw,
                value
            )
        })?;
        if parsed == 0 {
            bail!(
                "gcp backend '{}': URI '{}' has invalid version value '0'; \
                 versions start at 1",
                self.instance_name,
                uri.raw
            );
        }
        Ok(parsed.to_string())
    }

    /// Fetch the latest version with no fragment dispatch. Used by
    /// `list` (registry documents) and reused by `get` after fragment
    /// resolution.
    async fn get_raw(&self, uri: &BackendUri, version: &str) -> Result<String> {
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;
        let mut cmd =
            self.gcloud_command(&["secrets", "versions", "access", version, "--secret", name]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "gcp backend '{}': failed to invoke 'gcloud secrets versions access' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "gcp backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }
}

/// Validate that `name` matches the GCP Secret Manager name charset
/// `[a-zA-Z0-9_-]{1,255}`. Cheap check performed BEFORE any `gcloud`
/// invocation so copy-paste mistakes fail locally instead of burning
/// an IAM permission check + subprocess.
fn validate_secret_name(instance_name: &str, uri: &BackendUri, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        bail!(
            "gcp backend '{instance_name}': URI '{}' has invalid secret name \
             (length {}); must be 1..=255 chars",
            uri.raw,
            name.len()
        );
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        bail!(
            "gcp backend '{instance_name}': URI '{}' has invalid secret name '{}'; \
             GCP Secret Manager names allow only [a-zA-Z0-9_-]",
            uri.raw,
            name
        );
    }
    Ok(())
}

#[async_trait]
impl Backend for GcpBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    #[allow(clippy::similar_names)]
    async fn check(&self) -> BackendStatus {
        // Level 1 (--version) + Level 2 proof (auth print-access-token)
        // + identity enrichment (config get-value account) run
        // concurrently. `print-access-token` stdout is the real OAuth2
        // bearer token — we read ONLY its exit status and drop
        // `output.stdout` without ever interpolating it into logs or
        // error messages. Canary test `check_level2_auth_ok_never_logs_token_body`
        // locks this.
        let version_fut = Command::new(&self.gcloud_bin).arg("--version").output();

        let mut token_cmd = Command::new(&self.gcloud_bin);
        token_cmd.args(["auth", "print-access-token"]);
        if let Some(sa) = &self.gcp_impersonate_service_account {
            token_cmd.args(["--impersonate-service-account", sa]);
        }
        let token_fut = token_cmd.output();

        let mut account_cmd = Command::new(&self.gcloud_bin);
        account_cmd.args(["config", "get-value", "account"]);
        if let Some(sa) = &self.gcp_impersonate_service_account {
            account_cmd.args(["--impersonate-service-account", sa]);
        }
        let account_fut = account_cmd.output();

        let (version_res, token_res, account_res) =
            tokio::join!(version_fut, token_fut, account_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "gcp backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.gcloud_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "gcp backend '{}': 'gcloud --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let cli_version = String::from_utf8_lossy(&version_out.stdout)
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_owned();

        // --- Level 2 (token) ---
        let token_out = match token_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "gcp backend '{}': failed to invoke auth print-access-token: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !token_out.status.success() {
            let stderr = String::from_utf8_lossy(&token_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: gcloud auth login  OR  gcloud auth activate-service-account \
                     --key-file <path> (stderr: {stderr})"
                ),
            };
        }
        // Bearer token: drop without reading. Never log.
        drop(token_out);

        // --- Identity enrichment ---
        let account = match account_res {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_owned();
                if s.is_empty() {
                    "(unset)".to_owned()
                } else {
                    s
                }
            }
            _ => "(unset)".to_owned(),
        };

        let identity = self.gcp_impersonate_service_account.as_ref().map_or_else(
            || format!("account={account} project={}", self.gcp_project),
            |sa| format!("account={account} project={} impersonate={sa}", self.gcp_project),
        );

        BackendStatus::Ok { cli_version, identity }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        // Fragment + secret-name validation happen BEFORE any network
        // call so invalid URIs surface locally without burning IAM
        // permissions, latency, or a `gcloud` subprocess. v0.2.6
        // aws-secrets pattern.
        let version = self.resolve_version(uri)?;
        self.get_raw(uri, &version).await
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        // `versions add` creates a NEW version on an EXISTING secret.
        // A fragment (`#version=N`) on a `set` URI is nonsensical —
        // you cannot add a specific-numbered version. Reject before
        // shelling out.
        uri.reject_any_fragment("gcp")?;
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;

        // Secret value is piped via child stdin — NEVER on argv. The
        // `--data-file=/dev/stdin` sentinel tells `gcloud` to read
        // from fd 0. Mirrors aws-secrets / vault CV-1 pattern.
        let mut cmd =
            self.gcloud_command(&["secrets", "versions", "add", name, "--data-file=/dev/stdin"]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "gcp backend '{}': failed to spawn 'gcloud secrets versions add' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "gcp backend '{}': failed to write secret value to gcloud stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "gcp backend '{}': 'gcloud secrets versions add' exited abnormally \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("gcp")?;
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;
        // v0.3 `delete` removes the WHOLE SECRET (all versions). `--quiet`
        // suppresses the confirmation prompt; the helper already appends it.
        let mut cmd = self.gcloud_command(&["secrets", "delete", name]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "gcp backend '{}': failed to invoke 'gcloud secrets delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        // Fetch the registry document (whole JSON map stored as a
        // single secret value). Fragment is ignored — registry docs
        // are always "latest".
        let body = self.get_raw(uri, "latest").await?;
        let map: HashMap<String, String> = serde_json::from_str(&body).with_context(|| {
            format!(
                "gcp backend '{}': secret body at '{}' is not a JSON alias→URI map",
                self.instance_name, uri.raw
            )
        })?;
        Ok(map.into_iter().collect())
    }
}

/// Factory for the GCP Secret Manager backend.
pub struct GcpFactory(&'static str);

impl GcpFactory {
    /// Construct the factory. Equivalent to `GcpFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("gcp")
    }
}

impl Default for GcpFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for GcpFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let gcp_project = required_string(config, "gcp_project", "gcp", instance_name)?;
        let gcp_impersonate_service_account =
            optional_string(config, "gcp_impersonate_service_account", "gcp", instance_name)?;
        if let Some(sa) = &gcp_impersonate_service_account {
            validate_impersonate_email("gcp", instance_name, sa)?;
        }
        let gcloud_bin = optional_string(config, "gcloud_bin", "gcp", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "gcp", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(Box::new(GcpBackend {
            backend_type: "gcp",
            instance_name: instance_name.to_owned(),
            gcp_project,
            gcp_impersonate_service_account,
            gcloud_bin,
            timeout,
        }))
    }
}

/// Plausibility check on the service-account email. Full validation
/// happens server-side; we just want to catch typos before the first
/// `gcloud` invocation.
fn validate_impersonate_email(backend_type: &str, instance_name: &str, sa: &str) -> Result<()> {
    if !sa.contains('@') || !sa.ends_with(".iam.gserviceaccount.com") {
        bail!(
            "{backend_type} instance '{instance_name}': field \
             'gcp_impersonate_service_account' value '{sa}' does not look like a \
             service-account email (expected '<name>@<project>.iam.gserviceaccount.com')"
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    const PROJECT: &str = "my-project-prod";
    const SA: &str = "secretenv-reader@my-proj.iam.gserviceaccount.com";

    fn backend(mock_path: &Path, impersonate: Option<&str>) -> GcpBackend {
        GcpBackend {
            backend_type: "gcp",
            instance_name: "gcp-prod".to_owned(),
            gcp_project: PROJECT.to_owned(),
            gcp_impersonate_service_account: impersonate.map(ToOwned::to_owned),
            gcloud_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_gcloud() -> GcpBackend {
        GcpBackend {
            backend_type: "gcp",
            instance_name: "gcp-prod".to_owned(),
            gcp_project: PROJECT.to_owned(),
            gcp_impersonate_service_account: None,
            gcloud_bin: "/definitely/not/a/real/path/to/gcloud-binary-XYZ".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    /// `secrets versions access <version> --secret <name> --project
    /// <proj> --quiet`. Shared scoping tail (`--project ... --quiet`)
    /// is part of every argv so strict mocks implicitly lock
    /// `--project` presence — a regression dropping it would diverge
    /// from the declared shape and produce exit 97.
    fn get_argv<'a>(name: &'a str, version: &'a str) -> [&'a str; 9] {
        [
            "secrets",
            "versions",
            "access",
            version,
            "--secret",
            name,
            "--project",
            PROJECT,
            "--quiet",
        ]
    }

    fn add_argv(name: &str) -> [&str; 8] {
        [
            "secrets",
            "versions",
            "add",
            name,
            "--data-file=/dev/stdin",
            "--project",
            PROJECT,
            "--quiet",
        ]
    }

    fn delete_argv(name: &str) -> [&str; 6] {
        ["secrets", "delete", name, "--project", PROJECT, "--quiet"]
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const AUTH_ARGV: &[&str] = &["auth", "print-access-token"];
    const ACCOUNT_ARGV: &[&str] = &["config", "get-value", "account"];

    /// Install a mock that satisfies all three `check()` probes with
    /// defaults callers can override by chaining additional rules.
    /// `check_level1_*`/`check_level2_*` tests use this as a baseline.
    fn check_mock_ok(_dir: &Path) -> StrictMock {
        StrictMock::new("gcloud")
            .on(VERSION_ARGV, Response::success("Google Cloud SDK 468.0.0\nbq 2.0\n"))
            .on(AUTH_ARGV, Response::success("ya29.dummy-token\n"))
            .on(ACCOUNT_ARGV, Response::success("alice@example.com\n"))
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_gcp() {
        assert_eq!(GcpFactory::new().backend_type(), "gcp");
    }

    #[test]
    fn factory_errors_when_gcp_project_missing() {
        let factory = GcpFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("gcp-prod", &cfg) else {
            panic!("expected error when gcp_project is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("gcp_project"), "names missing field: {msg}");
        assert!(msg.contains("gcp-prod"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_project_and_no_impersonate() {
        let factory = GcpFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("gcp_project".to_owned(), toml::Value::String(PROJECT.to_owned()));
        let b = factory.create("gcp-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "gcp");
        assert_eq!(b.instance_name(), "gcp-prod");
    }

    #[test]
    fn factory_rejects_non_string_gcp_project() {
        let factory = GcpFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("gcp_project".to_owned(), toml::Value::Integer(1));
        let Err(err) = factory.create("gcp-prod", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    #[test]
    fn factory_rejects_malformed_impersonate_email() {
        let factory = GcpFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("gcp_project".to_owned(), toml::Value::String(PROJECT.to_owned()));
        cfg.insert(
            "gcp_impersonate_service_account".to_owned(),
            toml::Value::String("not-an-email".to_owned()),
        );
        let Err(err) = factory.create("gcp-prod", &cfg) else {
            panic!("expected error when gcp_impersonate_service_account is malformed");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("gcp_impersonate_service_account"), "names field: {msg}");
        assert!(msg.contains("service-account email"), "explains shape: {msg}");
    }

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_gcloud();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "gcloud");
                assert!(install_hint.contains("google-cloud-sdk"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level1_version_ok() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, .. } => {
                // First line only — component list discarded.
                assert_eq!(cli_version, "Google Cloud SDK 468.0.0");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_auth_ok() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("account=alice@example.com"), "identity: {identity}");
                assert!(identity.contains("project=my-project-prod"), "identity: {identity}");
                assert!(!identity.contains("impersonate"), "no impersonation: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_auth_ok_never_logs_token_body() {
        // Canary-token defense-in-depth lock. The stdout of
        // `gcloud auth print-access-token` is a real OAuth2 bearer
        // token in prod. This test routes a sentinel through the
        // mock and asserts the resulting `BackendStatus::Ok.identity`
        // never contains the sentinel substring. A regression that
        // format!()'d the token into the identity string (or
        // anywhere else the status surfaces) would surface the
        // canary and fail.
        const CANARY: &str = "CANARY-TOKEN-NEVER-IN-LOGS";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(VERSION_ARGV, Response::success("Google Cloud SDK 468.0.0\n"))
            .on(AUTH_ARGV, Response::success(format!("ya29.{CANARY}\n")))
            .on(ACCOUNT_ARGV, Response::success("alice@example.com\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let status = b.check().await;
        let BackendStatus::Ok { cli_version, identity } = status else {
            panic!("expected Ok, got {status:?}");
        };
        assert!(
            !cli_version.contains(CANARY),
            "canary must not leak into cli_version: {cli_version}"
        );
        assert!(!identity.contains(CANARY), "canary must not leak into identity: {identity}");
    }

    #[tokio::test]
    async fn check_level2_not_authenticated() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(VERSION_ARGV, Response::success("Google Cloud SDK 468.0.0\n"))
            .on(
                AUTH_ARGV,
                Response::failure(
                    1,
                    "ERROR: (gcloud.auth.print-access-token) You do not currently have \
                     an active account selected.\n",
                ),
            )
            .on(ACCOUNT_ARGV, Response::success("(unset)\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("gcloud auth login"), "hint: {hint}");
                assert!(hint.contains("activate-service-account"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_secret_latest() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("stripe_key", "latest"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_returns_secret_at_version_5() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("stripe_key", "5"), Response::success("older\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key#version=5").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "older");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        // Two trailing newlines in — only the LAST one is stripped.
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("multi_line", "latest"), Response::success("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///multi_line").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("empty_secret", "latest"), Response::success("\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///empty_secret").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_not_found_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &get_argv("missing", "latest"),
                Response::failure(
                    1,
                    "ERROR: (gcloud.secrets.versions.access) NOT_FOUND: \
                     Secret [projects/my-project-prod/secrets/missing] not found.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gcp-prod"), "names instance: {msg}");
        assert!(msg.contains("NOT_FOUND"), "passes through: {msg}");
    }

    #[tokio::test]
    async fn get_failed_precondition_destroyed_version() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &get_argv("rotated", "5"),
                Response::failure(
                    1,
                    "ERROR: (gcloud.secrets.versions.access) FAILED_PRECONDITION: \
                     Secret version [projects/p/secrets/rotated/versions/5] is in \
                     state DESTROYED.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///rotated#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("DESTROYED"));
    }

    #[tokio::test]
    async fn get_rejects_shorthand_fragment() {
        // Empty-rule mock: any gcloud invocation would produce exit 97
        // with `strict-mock-no-match`. The error MUST come from the
        // fragment parser BEFORE any gcloud call.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key#password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shorthand"), "error names the problem: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from fragment parser, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_unsupported_directive() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key#json-key=password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"), "error names the problem: {msg}");
        assert!(msg.contains("json-key"), "lists offender: {msg}");
        assert!(msg.contains("version"), "names the supported directive: {msg}");
        assert!(msg.contains("fragment-vocabulary"), "error links to canonical doc: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from backend, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_invalid_version_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key#version=abc").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid version value"), "error names the problem: {msg}");
        assert!(msg.contains("'abc'"), "quotes the bad value: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from backend, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_invalid_secret_name() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud").install(dir.path());
        let b = backend(&mock, None);
        // Path contains a `.` which is outside [a-zA-Z0-9_-].
        let uri = BackendUri::parse("gcp-prod:///bad.name").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid secret name"), "error names the problem: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from backend, not mock: {msg}"
        );
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &add_argv("rotate_me"),
                Response::success_with_stdin(
                    "Created version [6] of the secret [rotate_me].\n",
                    vec!["new-val".to_owned()],
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///rotate_me").unwrap();
        b.set(&uri, "new-val").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 discipline: argv carries `--data-file=/dev/stdin` sentinel
        // (NOT the secret), and the stdin-fragment check requires the
        // secret in stdin. Strict match on both implies "secret on
        // stdin, NOT on argv" declaratively.
        let very_sensitive = "sk_live_TOP_SECRET_gcp_never_argv_XYZ";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &add_argv("stripe_key"),
                Response::success_with_stdin("ok\n", vec![very_sensitive.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_rejects_fragment_on_uri() {
        // Empty-rule mock: any gcloud invocation → exit 97. The
        // fragment-reject happens BEFORE shelling out.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///stripe_key#version=5").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gcp"), "names backend: {msg}");
        assert!(msg.contains("version"), "names offending directive: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from fragment-reject, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn set_propagates_not_found() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &add_argv("nonexistent"),
                Response::failure(
                    1,
                    "ERROR: (gcloud.secrets.versions.add) NOT_FOUND: Secret \
                     [nonexistent] not found.\n",
                )
                .with_env_absent("NEVER_SET_SENTINEL"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///nonexistent").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("NOT_FOUND"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_succeeds() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&delete_argv("retired"), Response::success("Deleted secret [retired].\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///retired").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_already_gone_surfaces_not_found() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &delete_argv("retired"),
                Response::failure(1, "ERROR: (gcloud.secrets.delete) NOT_FOUND: ...\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///retired").unwrap();
        assert!(format!("{:#}", b.delete(&uri).await.unwrap_err()).contains("NOT_FOUND"));
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_json_registry() {
        let dir = TempDir::new().unwrap();
        let body =
            "{\"alpha\":\"gcp-prod:///alpha_secret\",\"beta\":\"gcp-prod:///beta_secret\"}\n";
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("registry_doc", "latest"), Response::success(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///registry_doc").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("alpha".to_owned(), "gcp-prod:///alpha_secret".to_owned()),
                ("beta".to_owned(), "gcp-prod:///beta_secret".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_body_is_not_json() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("bad_registry", "latest"), Response::success("not-json\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///bad_registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gcp-prod"), "names instance: {msg}");
        assert!(msg.contains("alias→URI map"), "specific error: {msg}");
    }

    // ---- impersonation ----

    #[tokio::test]
    async fn command_omits_impersonate_when_not_configured() {
        // Declared argv has NO `--impersonate-service-account` suffix.
        // A regression emitting the flag would diverge from this shape.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("x", "latest"), Response::success("v\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_impersonate_when_configured() {
        // Declared argv MUST include the impersonation flag pair at
        // the tail; regression dropping it produces exit 97.
        let dir = TempDir::new().unwrap();
        let argv_with_sa: Vec<&str> = get_argv("x", "latest")
            .iter()
            .copied()
            .chain(["--impersonate-service-account", SA])
            .collect();
        let mock = StrictMock::new("gcloud")
            .on(&argv_with_sa, Response::success("v\n"))
            .install(dir.path());
        let b = backend(&mock, Some(SA));
        let uri = BackendUri::parse("gcp-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    // ---- drift-catch regression locks ----

    #[tokio::test]
    async fn get_drift_catch_rejects_missing_project_flag() {
        // Declared argv INTENTIONALLY omits `--project <proj>`. The
        // real backend emits it, so the declared shape WON'T match
        // and exit 97 surfaces as a backend error. If a regression
        // ever dropped `--project` from the helper, this rule would
        // start matching and the test would falsely pass — the
        // `.await.unwrap_err()` would flip to `.unwrap()`.
        let buggy_argv: [&str; 6] = ["secrets", "versions", "access", "latest", "--secret", "x"];
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(&buggy_argv, Response::success("never-matches-post-fix\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///x").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        // `unwrap_err` is the load-bearing regression lock. The content
        // check narrows to strict-mock-divergence specifically — a
        // weakened `msg.contains("gcp")` fallback would pass on any
        // unrelated gcp error and mask a different class of regression.
        assert!(msg.contains("strict-mock-no-match"), "must be mock-level divergence, got: {msg}");
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_data_flag_on_argv() {
        // POSITIVE lock mirroring azure's `--value`-leak test. The
        // CV-1 sentinel on this backend is `--data-file=/dev/stdin`;
        // the BUGGY form would carry the secret directly on argv via
        // `--data=<secret>` or `--data-file=<inline-value>`. Declared
        // argv carries the buggy `--data=<secret>` form so the real
        // post-fix backend (which emits `--data-file=/dev/stdin`)
        // diverges, exit 97, surfacing as an error.
        let secret = "sk_live_would_leak_via_data_flag_gcp";
        let dir = TempDir::new().unwrap();
        let buggy_argv: Vec<&str> = vec![
            "secrets",
            "versions",
            "add",
            "rotate_me",
            "--data",
            secret,
            "--project",
            PROJECT,
            "--quiet",
        ];
        let mock = StrictMock::new("gcloud")
            .on(&buggy_argv, Response::success("ok\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///rotate_me").unwrap();
        let err = b.set(&uri, secret).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("strict-mock-no-match"),
            "must be mock-level divergence — regression emitting --data=<secret> would match: {msg}"
        );
    }

    #[tokio::test]
    async fn check_extensive_counts_registry_entries() {
        // Locks the Backend-trait-default `check_extensive` behavior
        // (list().len()) for gcp. A regression that overrode the
        // method with a broken impl would be caught here.
        let dir = TempDir::new().unwrap();
        let body = "{\"alpha\":\"gcp-prod:///a\",\"beta\":\"gcp-prod:///b\",\"gamma\":\"gcp-prod:///c\"}\n";
        let mock = StrictMock::new("gcloud")
            .on(&get_argv("reg_doc", "latest"), Response::success(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///reg_doc").unwrap();
        assert_eq!(b.check_extensive(&uri).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        let secret = "sk_live_CV1_gcp_regression_lock";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("gcloud")
            .on(
                &add_argv("rotate_me"),
                Response::success_with_stdin("ok\n", vec![secret.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("gcp-prod:///rotate_me").unwrap();
        b.set(&uri, secret).await.unwrap();
    }
}
