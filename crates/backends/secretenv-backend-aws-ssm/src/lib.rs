//! AWS SSM Parameter Store backend for SecretEnv.
//!
//! Wraps the `aws` CLI — **never** the AWS SDK. This keeps credentials
//! out of our process, keeps our dep graph tiny, and inherits every
//! auth flow the user's CLI already supports (SSO, MFA, profiles,
//! instance roles, `aws-vault`, etc.).
//!
//! # URI shape
//!
//! `<instance>:///<path>` — scheme is the instance name (e.g.
//! `aws-ssm-prod`), path is the SSM parameter name (e.g.
//! `/prod/api-key`). The leading slash is re-prepended if missing so
//! both `aws-ssm-prod:///prod/foo` and `aws-ssm-prod://prod/foo`
//! resolve to the parameter `/prod/foo`.
//!
//! # Config fields
//!
//! - `aws_region` (required)
//! - `aws_profile` (optional — falls back to whatever the CLI's
//!   default credential chain picks up)
//!
//! # Semantics
//!
//! - [`get`](AwsSsmBackend) reads a single parameter with
//!   `--with-decryption`, returning its value verbatim.
//! - [`set`](AwsSsmBackend) writes a `SecureString` parameter with
//!   `--overwrite`.
//! - [`delete`](AwsSsmBackend) removes a parameter.
//! - [`list`](AwsSsmBackend) fetches the parameter value and parses
//!   it as a JSON `{ alias: uri }` map. v0.1 only uses `list` on
//!   registry documents; prefix listing (`get-parameters-by-path`)
//!   is deferred to v0.2.
//! - [`check`](AwsSsmBackend) runs `aws --version` (Level 1) and
//!   `aws sts get-caller-identity` (Level 2).
//!
//! # Safety
//!
//! Every argv call goes through `tokio::process::Command::args(&[…])`
//! with individual `&str`s — **never** through `sh -c` or `format!`
//! into a shell string. URI-derived values never touch a shell
//! interpreter.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{Backend, BackendFactory, BackendStatus, BackendUri};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "aws";
const INSTALL_HINT: &str = "brew install awscli  OR  https://aws.amazon.com/cli/";

/// A live instance of the AWS SSM Parameter Store backend.
pub struct AwsSsmBackend {
    backend_type: &'static str,
    instance_name: String,
    aws_region: String,
    aws_profile: Option<String>,
    /// Path or name of the `aws` binary. Defaults to `"aws"` (PATH
    /// lookup); tests override to point at a mock script.
    aws_bin: String,
}

#[derive(Deserialize)]
struct CallerIdentity {
    #[serde(rename = "Account")]
    account: String,
    #[serde(rename = "Arn")]
    arn: String,
}

impl AwsSsmBackend {
    fn parameter_name(uri: &BackendUri) -> String {
        if uri.path.starts_with('/') {
            uri.path.clone()
        } else {
            format!("/{}", uri.path)
        }
    }

    fn append_region_and_profile(&self, cmd: &mut Command) {
        cmd.args(["--region", &self.aws_region]);
        if let Some(profile) = &self.aws_profile {
            cmd.args(["--profile", profile]);
        }
    }

    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        format!(
            "aws-ssm backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    fn ssm_command(&self, subcommand: &str, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.aws_bin);
        cmd.args(["ssm", subcommand]);
        cmd.args(extra_args);
        self.append_region_and_profile(&mut cmd);
        cmd
    }
}

#[async_trait]
impl Backend for AwsSsmBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    async fn check(&self) -> BackendStatus {
        // Level 1: `aws --version`
        let version_out = match Command::new(&self.aws_bin).arg("--version").output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "aws-ssm backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.aws_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "aws-ssm backend '{}': 'aws --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        // aws --version prints to either stdout (CLI v2) or stderr (CLI v1).
        // Prefer stdout, fall back to stderr.
        let cli_version = {
            let stdout = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();
            if stdout.is_empty() {
                String::from_utf8_lossy(&version_out.stderr).trim().to_owned()
            } else {
                stdout
            }
        };

        // Level 2: `aws sts get-caller-identity`
        let mut sts_cmd = Command::new(&self.aws_bin);
        sts_cmd.args(["sts", "get-caller-identity", "--output", "json"]);
        self.append_region_and_profile(&mut sts_cmd);
        let sts_out = match sts_cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "aws-ssm backend '{}': failed to invoke sts: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !sts_out.status.success() {
            let stderr = String::from_utf8_lossy(&sts_out.stderr).trim().to_owned();
            let profile = self.aws_profile.as_deref().unwrap_or("default");
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: aws configure --profile {profile}  OR  aws sso login --profile {profile} (stderr: {stderr})"
                ),
            };
        }
        let caller: CallerIdentity = match serde_json::from_slice(&sts_out.stdout) {
            Ok(c) => c,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "aws-ssm backend '{}': parsing sts JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        BackendStatus::Ok {
            cli_version,
            identity: format!(
                "profile={} account={} arn={} region={}",
                self.aws_profile.as_deref().unwrap_or("default"),
                caller.account,
                caller.arn,
                self.aws_region
            ),
        }
    }

    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        Ok(self.list(test_uri).await?.len())
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let name = Self::parameter_name(uri);
        let mut cmd = self.ssm_command(
            "get-parameter",
            &[
                "--with-decryption",
                "--name",
                &name,
                "--query",
                "Parameter.Value",
                "--output",
                "text",
            ],
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "aws-ssm backend '{}': failed to invoke 'aws ssm get-parameter' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "aws-ssm backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        // Secret value is piped via child stdin — NEVER on argv. `aws`
        // supports `--value file:///dev/stdin` which tells it to read
        // the value from the file at that path, and on Unix `/dev/stdin`
        // resolves to the fd-0 we hand it via `Stdio::piped()`.
        //
        // Review finding CV-1 (Phase 0.5 preflight): previously we
        // passed `--value <value>` on argv, making secrets readable via
        // `/proc/<pid>/cmdline` to every local user for the lifetime
        // of the aws subprocess.
        let name = Self::parameter_name(uri);
        let mut cmd = self.ssm_command(
            "put-parameter",
            &[
                "--type",
                "SecureString",
                "--overwrite",
                "--name",
                &name,
                "--value",
                "file:///dev/stdin",
            ],
        );
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "aws-ssm backend '{}': failed to spawn 'aws ssm put-parameter' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                // Linux produces EPIPE if the child exits before reading
                // stdin; macOS's larger pipe buffer can swallow the write
                // silently. Either way, the real signal is the child's
                // exit status, which `wait_with_output` reports below.
                // A legitimately-failed `aws ssm put-parameter` will
                // still surface via the non-zero exit path + stderr.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "aws-ssm backend '{}': failed to write secret value to aws stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "aws-ssm backend '{}': 'aws ssm put-parameter' exited abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        let name = Self::parameter_name(uri);
        let mut cmd = self.ssm_command("delete-parameter", &["--name", &name]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "aws-ssm backend '{}': failed to invoke 'aws ssm delete-parameter' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        let body = self.get(uri).await?;
        let map: HashMap<String, String> = serde_json::from_str(&body).with_context(|| {
            format!(
                "aws-ssm backend '{}': parameter body at '{}' is not a JSON string-map \
                 (v0.1 only supports registry-document shape)",
                self.instance_name, uri.raw
            )
        })?;
        Ok(map.into_iter().collect())
    }
}

/// Factory for the AWS SSM Parameter Store backend.
pub struct AwsSsmFactory(&'static str);

impl AwsSsmFactory {
    /// Construct the factory. Equivalent to `AwsSsmFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("aws-ssm")
    }
}

impl Default for AwsSsmFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for AwsSsmFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let aws_region = required_string(config, "aws_region", instance_name)?;
        let aws_profile = optional_string(config, "aws_profile", instance_name)?;
        Ok(Box::new(AwsSsmBackend {
            backend_type: "aws-ssm",
            instance_name: instance_name.to_owned(),
            aws_region,
            aws_profile,
            aws_bin: CLI_NAME.to_owned(),
        }))
    }
}

/// Extract a required string field from the raw backend config. Returns
/// a typed error naming the instance + field when missing or when the
/// value has the wrong TOML type.
fn required_string(
    config: &HashMap<String, toml::Value>,
    field: &str,
    instance_name: &str,
) -> Result<String> {
    let value = config.get(field).ok_or_else(|| {
        anyhow!(
            "aws-ssm instance '{instance_name}': missing required field '{field}' \
             (set {field} = \"...\" under [backends.{instance_name}])"
        )
    })?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        anyhow!(
            "aws-ssm instance '{instance_name}': field '{field}' must be a string, got {}",
            value.type_str()
        )
    })
}

/// Extract an optional string field. `Ok(None)` when absent; error when
/// present with the wrong type.
fn optional_string(
    config: &HashMap<String, toml::Value>,
    field: &str,
    instance_name: &str,
) -> Result<Option<String>> {
    config.get(field).map_or(Ok(None), |value| {
        value.as_str().map(|s| Some(s.to_owned())).ok_or_else(|| {
            anyhow!(
                "aws-ssm instance '{instance_name}': field '{field}' must be a string, got {}",
                value.type_str()
            )
        })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    /// Full argv the aws-ssm backend's `get()` emits with no profile
    /// set. Kept as a const so the seven get-related tests stay in
    /// lockstep if the backend's argv shape ever changes.
    const GET_ARGV_NO_PROFILE: &[&str] = &[
        "ssm",
        "get-parameter",
        "--with-decryption",
        "--name",
        "/prod/api-key",
        "--query",
        "Parameter.Value",
        "--output",
        "text",
        "--region",
        "us-east-1",
    ];

    fn backend(mock_path: &Path, profile: Option<&str>) -> AwsSsmBackend {
        AwsSsmBackend {
            backend_type: "aws-ssm",
            instance_name: "aws-ssm-prod".to_owned(),
            aws_region: "us-east-1".to_owned(),
            aws_profile: profile.map(ToOwned::to_owned),
            aws_bin: mock_path.to_str().unwrap().to_owned(),
        }
    }

    fn backend_with_nonexistent_aws() -> AwsSsmBackend {
        AwsSsmBackend {
            backend_type: "aws-ssm",
            instance_name: "aws-ssm-prod".to_owned(),
            aws_region: "us-east-1".to_owned(),
            aws_profile: None,
            aws_bin: "/definitely/not/a/real/path/to/aws-binary-12345".to_owned(),
        }
    }

    // ---- Factory tests ----

    #[test]
    fn factory_errors_when_aws_region_missing() {
        let factory = AwsSsmFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        // Box<dyn Backend> isn't Debug, so we can't .unwrap_err(). Destructure.
        let Err(err) = factory.create("aws-ssm-prod", &cfg) else {
            panic!("expected error when aws_region is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("aws_region"), "names missing field: {msg}");
        assert!(msg.contains("aws-ssm-prod"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_region_and_no_profile() {
        let factory = AwsSsmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        let b = factory.create("aws-ssm-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "aws-ssm");
        assert_eq!(b.instance_name(), "aws-ssm-prod");
    }

    #[test]
    fn factory_accepts_region_and_profile() {
        let factory = AwsSsmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        cfg.insert("aws_profile".to_owned(), toml::Value::String("prod".to_owned()));
        assert!(factory.create("aws-ssm-prod", &cfg).is_ok());
    }

    #[test]
    fn factory_rejects_non_string_aws_region() {
        let factory = AwsSsmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::Integer(30));
        let Err(err) = factory.create("aws-ssm-prod", &cfg) else {
            panic!("expected error for non-string aws_region");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("aws_region"), "names the field: {msg}");
        assert!(msg.contains("string"), "explains expected type: {msg}");
    }

    #[test]
    fn factory_backend_type_is_aws_ssm() {
        assert_eq!(AwsSsmFactory::new().backend_type(), "aws-ssm");
    }

    // ---- URI normalization ----

    #[test]
    fn parameter_name_prepends_leading_slash_when_missing() {
        let uri = BackendUri::parse("aws-ssm-prod://prod/api-key").unwrap();
        assert_eq!(AwsSsmBackend::parameter_name(&uri), "/prod/api-key");
    }

    #[test]
    fn parameter_name_preserves_existing_leading_slash() {
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        assert_eq!(AwsSsmBackend::parameter_name(&uri), "/prod/api-key");
    }

    // ---- get happy path ----

    #[tokio::test]
    async fn get_returns_parameter_value_no_profile() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(GET_ARGV_NO_PROFILE, Response::success("super-secret-value\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        let v = b.get(&uri).await.unwrap();
        assert_eq!(v, "super-secret-value");
    }

    #[tokio::test]
    async fn get_returns_parameter_value_with_profile() {
        let dir = TempDir::new().unwrap();
        // With `aws_profile = "prod"` the backend appends `--profile prod`
        // after `--region us-east-1` via `append_region_and_profile`.
        // Strict matching enforces the flag is both present AND in the
        // expected position — so this test doubles as a regression lock
        // for profile propagation.
        let argv: Vec<&str> = [GET_ARGV_NO_PROFILE, &["--profile", "prod"][..]].concat();
        let mock = StrictMock::new("aws")
            .on(&argv, Response::success("value-from-prod\n"))
            .install(dir.path());
        let b = backend(&mock, Some("prod"));
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        let v = b.get(&uri).await.unwrap();
        assert_eq!(v, "value-from-prod");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        // AWS CLI emits single trailing newline — backend strips it.
        let argv = &[
            "ssm",
            "get-parameter",
            "--with-decryption",
            "--name",
            "/k",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--region",
            "us-east-1",
        ];
        let mock =
            StrictMock::new("aws").on(argv, Response::success("raw-value\n")).install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///k").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "raw-value");
    }

    // ---- get error paths ----

    #[tokio::test]
    async fn get_access_denied_error_includes_stderr_and_uri() {
        let dir = TempDir::new().unwrap();
        let argv = &[
            "ssm",
            "get-parameter",
            "--with-decryption",
            "--name",
            "/prod/locked",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--region",
            "us-east-1",
        ];
        let mock = StrictMock::new("aws")
            .on(
                argv,
                Response::failure(
                    255,
                    "An error occurred (AccessDeniedException) when calling the GetParameter operation: User: arn:aws:iam::123:user/x is not authorized to perform: ssm:GetParameter\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/locked").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AccessDeniedException"), "stderr propagates: {msg}");
        assert!(msg.contains("aws-ssm-prod:///prod/locked"), "uri in context: {msg}");
        assert!(msg.contains("aws-ssm-prod"), "instance in context: {msg}");
    }

    #[tokio::test]
    async fn get_fails_fast_when_binary_missing() {
        let b = backend_with_nonexistent_aws();
        let uri = BackendUri::parse("aws-ssm-prod:///anything").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-ssm-prod"), "instance in context: {msg}");
    }

    // ---- set, delete, list ----

    /// The full argv aws-ssm's `set()` emits (no profile). `--value`
    /// carries the `file:///dev/stdin` sentinel — per CV-1 the secret
    /// value never appears here.
    const PUT_ARGV_NO_PROFILE: &[&str] = &[
        "ssm",
        "put-parameter",
        "--type",
        "SecureString",
        "--overwrite",
        "--name",
        "/prod/api-key",
        "--value",
        "file:///dev/stdin",
        "--region",
        "us-east-1",
    ];

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                PUT_ARGV_NO_PROFILE,
                // Stdin-fragment check doubles as a CV-1 regression lock:
                // the secret value MUST appear in stdin. Combined with the
                // strict argv match (which has only `file:///dev/stdin`
                // after `--value`, not the secret itself), this is a
                // tighter assertion than the v0.2.0 `install_mock_aws`
                // shape could ever express.
                Response::success_with_stdin(r#"{"Version":1}"#, vec!["new-secret".to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        b.set(&uri, "new-secret").await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                PUT_ARGV_NO_PROFILE,
                Response::failure(
                    255,
                    "ParameterAlreadyExists: already exists without --overwrite\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("ParameterAlreadyExists"));
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 regression lock (v0.2.3 strict-mode form). Two assertions
        // expressed through the strict harness, which is tighter than the
        // v0.2.0 "log argv + stdin to a file, grep after" pattern:
        //
        //   (1) Declared argv has `--value file:///dev/stdin` with the
        //       literal sentinel — NOT the secret value. If the backend
        //       ever regresses to `--value <secret>` on argv, StrictMock
        //       exits 97 because the argv no longer matches.
        //
        //   (2) `success_with_stdin` asserts the secret value arrives on
        //       stdin as a literal substring. If the backend writes
        //       nothing to stdin (or writes the wrong thing), the mock
        //       exits 97.
        //
        // Combined, the two bounds prove the secret is in stdin AND not
        // in argv. No file I/O, no grep-after — the argv contract itself
        // carries the CV-1 discipline.
        let dir = TempDir::new().unwrap();
        let very_sensitive = "sk_live_top_SECRET_never_on_argv_987";
        let mock = StrictMock::new("aws")
            .on(
                PUT_ARGV_NO_PROFILE,
                Response::success_with_stdin(r#"{"Version":1}"#, vec![very_sensitive.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn delete_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let argv = &["ssm", "delete-parameter", "--name", "/prod/gone", "--region", "us-east-1"];
        let mock = StrictMock::new("aws").on(argv, Response::success("")).install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn list_parses_json_registry_document() {
        let dir = TempDir::new().unwrap();
        let argv = &[
            "ssm",
            "get-parameter",
            "--with-decryption",
            "--name",
            "/registries/shared",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--region",
            "us-east-1",
        ];
        let body = r#"{"stripe-key":"aws-ssm-prod:///prod/stripe","db-url":"1password-personal://Engineering/Prod DB/url"}
"#;
        let mock = StrictMock::new("aws").on(argv, Response::success(body)).install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("db-url".to_owned(), "1password-personal://Engineering/Prod DB/url".to_owned(),),
                ("stripe-key".to_owned(), "aws-ssm-prod:///prod/stripe".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_body_is_not_json_map() {
        let dir = TempDir::new().unwrap();
        let argv = &[
            "ssm",
            "get-parameter",
            "--with-decryption",
            "--name",
            "/r",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--region",
            "us-east-1",
        ];
        let mock = StrictMock::new("aws")
            .on(argv, Response::success("not-json-at-all\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///r").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("JSON"), "specific error: {msg}");
    }

    // ---- check ----

    #[tokio::test]
    async fn check_returns_cli_missing_when_binary_not_found() {
        let b = backend_with_nonexistent_aws();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, .. } => assert_eq!(cli_name, "aws"),
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    /// Full argv for `aws sts get-caller-identity` as emitted by `check()`
    /// (`append_region_and_profile` applies). Profile-suffix appended when
    /// the test uses `Some("...")`.
    const STS_ARGV_NO_PROFILE: &[&str] =
        &["sts", "get-caller-identity", "--output", "json", "--region", "us-east-1"];

    #[tokio::test]
    async fn check_returns_ok_when_version_and_sts_succeed() {
        let dir = TempDir::new().unwrap();
        let sts_argv: Vec<&str> = [STS_ARGV_NO_PROFILE, &["--profile", "prod"][..]].concat();
        let mock = StrictMock::new("aws")
            .on(
                &["--version"],
                Response::success("aws-cli/2.15.17 Python/3.11.8 Darwin/23.0.0 source/x86_64 prompt/off\n"),
            )
            .on(
                &sts_argv,
                Response::success(
                    r#"{"UserId":"AIDA","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}
"#,
                ),
            )
            .install(dir.path());
        let b = backend(&mock, Some("prod"));
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("aws-cli/2.15.17"));
                assert!(identity.contains("profile=prod"));
                assert!(identity.contains("account=123456789012"));
                assert!(identity.contains("region=us-east-1"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_non_utf8_response_errors_with_context() {
        let dir = TempDir::new().unwrap();
        // Raw non-UTF-8 bytes. The strict mock's `printf '%s'` renderer
        // writes the stdout field verbatim, and since Response holds a
        // `String` (which is UTF-8), we'd normally be stuck. The four
        // high-bit bytes below are chosen as a UTF-8-invalid sequence
        // that `String::from_utf8_lossy` would replace — but `String`
        // construction from these bytes via `unsafe` isn't worth the
        // complexity. Instead we fall back to the raw-shell harness here
        // because the assertion is specifically about a non-UTF-8
        // response path; the strict harness's UTF-8-only stdout field
        // is incompatible by design. This is the one and only aws-ssm
        // test that intentionally stays on the v0.2 raw harness.
        let mock = secretenv_testing::install_mock(
            dir.path(),
            "aws",
            r#"
if [ "$1 $2" = "ssm get-parameter" ]; then
  printf '\377\376\375\374'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/garbage").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("non-UTF-8"), "specific error: {msg}");
        assert!(msg.contains("aws-ssm-prod"), "instance in context: {msg}");
    }

    #[tokio::test]
    async fn check_version_falls_back_to_stderr_for_cli_v1() {
        let dir = TempDir::new().unwrap();
        // AWS CLI v1 writes `--version` output to stderr, not stdout.
        // `Response::success("").with_stderr(...)` expresses this
        // exactly — empty stdout, version on stderr, 0 exit.
        let mock = StrictMock::new("aws")
            .on(
                &["--version"],
                Response::success("")
                    .with_stderr("aws-cli/1.18.69 Python/2.7.16 Darwin/19.6.0 botocore/1.17.0\n"),
            )
            .on(
                STS_ARGV_NO_PROFILE,
                Response::success(
                    r#"{"UserId":"AIDA","Account":"123","Arn":"arn:aws:iam::123:user/t"}
"#,
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, .. } => {
                assert!(
                    cli_version.contains("aws-cli/1.18.69"),
                    "stderr-origin version: {cli_version}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_not_authenticated_when_sts_fails() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&["--version"], Response::success("aws-cli/2.15.17\n"))
            .on(STS_ARGV_NO_PROFILE, Response::failure(255, "Unable to locate credentials.\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("Unable to locate credentials"), "stderr in hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- v0.2.3 drift-catch regression locks ----
    //
    // Each test below declares an argv and uses StrictMock's exit-97
    // behavior as a positive assertion: IF a future aws-ssm refactor
    // drops a flag, reorders argv, or mis-quotes a value, the drift-catch
    // surfaces as a test failure rather than silent passthrough.

    #[tokio::test]
    async fn get_drift_catch_rejects_missing_with_decryption_flag() {
        // The strict harness's no-match-exits-97 contract is what the
        // retrofit buys us. Declaring argv WITHOUT `--with-decryption`
        // and verifying that secretenv's real call (which always adds
        // the flag) fails end-to-end proves the harness is doing its
        // job. Mirrors the v0.2.2 e2e drift-catch.
        let dir = TempDir::new().unwrap();
        let drifted = &[
            "ssm",
            "get-parameter",
            "--name",
            "/prod/api-key",
            "--query",
            "Parameter.Value",
            "--output",
            "text",
            "--region",
            "us-east-1",
        ];
        let mock = StrictMock::new("aws")
            .on(drifted, Response::success("should-not-be-seen"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("get failed"), "strict-mock failure surfaced: {msg}");
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        // If a future refactor regresses to `--value <secret>` on argv
        // (pre-CV-1 shape), StrictMock's declared argv — which still
        // has `--value file:///dev/stdin` — won't match, and the mock
        // exits 97. This test asserts that specific CV-1 regression is
        // caught, not just any argv drift: the DECLARED argv has the
        // `file:///dev/stdin` sentinel, and we're about to call set()
        // with a secret. If the backend somehow put the secret on argv
        // instead, the mock declares no such rule — exit 97 — and set
        // fails.
        //
        // This is the same assertion set_succeeds_on_zero_exit makes
        // implicitly; this test spells it out as an explicit regression
        // lock with a more aggressive secret value that would be very
        // visible in any leak.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                PUT_ARGV_NO_PROFILE,
                Response::success_with_stdin(
                    r#"{"Version":1}"#,
                    vec!["CV1_REGRESSION_CANARY_2026".to_owned()],
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        // Succeeds only if argv exactly matches PUT_ARGV_NO_PROFILE AND
        // stdin contains the canary — any CV-1 regression causes 97.
        b.set(&uri, "CV1_REGRESSION_CANARY_2026").await.unwrap();
    }
}
