//! AWS Secrets Manager backend for SecretEnv.
//!
//! Wraps the `aws` CLI (v2 recommended) — **never** the AWS SDK.
//! Same auth story as `secretenv-backend-aws-ssm`: every credential
//! chain the user's `aws` CLI supports (SSO, MFA, profiles, instance
//! roles, `aws-vault`, cross-account assumption) works transparently.
//!
//! # URI shape
//!
//! `<instance>:///<secret-id>[#<json-key>]` — scheme is the instance
//! name (e.g. `aws-secrets-prod`); path is the Secret ARN or friendly
//! name passed verbatim to `--secret-id`. The optional `#<json-key>`
//! fragment selects a top-level field of a JSON-shaped secret.
//!
//! # Config fields
//!
//! - `aws_region` (required) — passed via `--region`
//! - `aws_profile` (optional) — passed via `--profile` when set
//! - `aws_bin` (test hook) — overrides the `aws` binary path
//!
//! # Semantics
//!
//! - [`get`](AwsSecretsBackend) runs
//!   `aws secretsmanager get-secret-value --query SecretString --output text`
//!   and then:
//!   - `uri.fragment == None` → returns the value verbatim (plain
//!     string OR whole JSON blob — user's choice).
//!   - `uri.fragment == Some(key)` → parses the value as a JSON
//!     object and extracts the top-level `key` field.
//! - [`set`](AwsSecretsBackend) runs
//!   `aws secretsmanager put-secret-value --secret-string file:///dev/stdin`
//!   and pipes the secret through child stdin — **never** argv.
//!   Update-only; creating new secrets requires `aws secretsmanager
//!   create-secret` (deferred to v0.3).
//! - [`delete`](AwsSecretsBackend) runs
//!   `aws secretsmanager delete-secret --force-delete-without-recovery`
//!   unconditionally — keeps "deleted means gone" semantics symmetric
//!   with aws-ssm/vault.
//! - [`list`](AwsSecretsBackend) reads one secret and parses it as a
//!   JSON alias→URI map (registry-document shape).
//! - [`check`](AwsSecretsBackend) runs `aws --version` (Level 1) and
//!   `aws sts get-caller-identity` (Level 2) — identical to aws-ssm.
//!
//! # Safety
//!
//! Every CLI call goes through `Command::args([...])` with individual
//! `&str`s — never `sh -c`, never `format!` into a shell string. The
//! `set` path pipes secret values via child stdin (CV-1 discipline).
//!
//! # v0.3 TODO
//!
//! - Factor shared `AwsCli` helper across `backend-aws-ssm` +
//!   `backend-aws-secrets` (identity checks, region/profile argv,
//!   version parsing). Phase 6 plan explicitly deferred this to keep
//!   the v0.2 diff small.
//! - Support `SecretBinary` + `create-secret` + nested JSON field
//!   extraction (`#<key.nested>`).
//!
//! See [[backends/aws-secrets]] in the kb for the full implementation
//! spec (harness table, IAM, open design questions).
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

/// A live instance of the AWS Secrets Manager backend.
pub struct AwsSecretsBackend {
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

impl AwsSecretsBackend {
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
            "aws-secrets backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build an `aws secretsmanager <subcommand> ...` command with
    /// `--region` + optional `--profile` appended at the end.
    ///
    /// Argv shape mirrors `AwsSsmBackend::ssm_command`:
    /// `aws secretsmanager <subcommand> <extra...> --region <r> [--profile <p>]`
    /// so mocks can assert `$1 $2 = secretsmanager <sub>`.
    fn secrets_command(&self, subcommand: &str, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.aws_bin);
        cmd.args(["secretsmanager", subcommand]);
        cmd.args(extra_args);
        self.append_region_and_profile(&mut cmd);
        cmd
    }

    /// Map the URI path onto the secret ID AWS Secrets Manager will
    /// accept. Unlike SSM (which requires a leading `/`), Secrets
    /// Manager secret names must NOT start with `/` — the `describe`
    /// and `get-secret-value` APIs reject slash-prefixed IDs as
    /// `ResourceNotFoundException`. [`BackendUri::parse`] preserves
    /// the leading slash when the URI uses triple-slash form (the
    /// documented example), so strip it here before handing to the
    /// CLI. ARNs (which don't start with `/` and begin with `arn:`)
    /// pass through unchanged.
    ///
    /// Bug caught in integration validation 2026-04-18; mock tests
    /// didn't cover this because mocks don't validate AWS naming rules.
    fn secret_id(uri: &BackendUri) -> &str {
        uri.path.strip_prefix('/').unwrap_or(&uri.path)
    }

    /// Fetch the raw `SecretString` value with no fragment dispatch.
    /// Strips exactly one trailing `\n` (mirrors aws-ssm).
    async fn get_raw(&self, uri: &BackendUri) -> Result<String> {
        let mut cmd = self.secrets_command(
            "get-secret-value",
            &["--secret-id", Self::secret_id(uri), "--query", "SecretString", "--output", "text"],
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "aws-secrets backend '{}': failed to invoke 'aws secretsmanager \
                 get-secret-value' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "aws-secrets backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }
}

#[async_trait]
impl Backend for AwsSecretsBackend {
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
                        "aws-secrets backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.aws_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "aws-secrets backend '{}': 'aws --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        // aws --version prints to stdout (v2) or stderr (v1). Prefer stdout.
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
                        "aws-secrets backend '{}': failed to invoke sts: {e}",
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
                        "aws-secrets backend '{}': parsing sts JSON: {e}",
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
        let raw = self.get_raw(uri).await?;
        match &uri.fragment {
            // No fragment: return the raw SecretString verbatim.
            None => Ok(raw),
            // Fragment: parse as JSON object and extract the named field.
            Some(key) => extract_json_field(&self.instance_name, uri, &raw, key),
        }
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        // Secret value is piped via child stdin — NEVER on argv. The
        // `file:///dev/stdin` sentinel tells `aws` to read from fd 0.
        // Mirrors the Phase 0.5 CV-1 fix for aws-ssm and the Phase 5
        // Vault backend.
        let mut cmd = self.secrets_command(
            "put-secret-value",
            &["--secret-id", Self::secret_id(uri), "--secret-string", "file:///dev/stdin"],
        );
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "aws-secrets backend '{}': failed to spawn 'aws secretsmanager \
                 put-secret-value' for URI '{}'",
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
                        "aws-secrets backend '{}': failed to write secret value to aws stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "aws-secrets backend '{}': 'aws secretsmanager put-secret-value' exited \
                 abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        // `--force-delete-without-recovery` is unconditional: the
        // default 30-day recovery window makes `delete` look like it
        // worked but the secret is still there (as pending-deletion).
        // Skipping it keeps semantics symmetric with aws-ssm/vault.
        let mut cmd = self.secrets_command(
            "delete-secret",
            &["--secret-id", Self::secret_id(uri), "--force-delete-without-recovery"],
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "aws-secrets backend '{}': failed to invoke 'aws secretsmanager \
                 delete-secret' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        // Fetch the raw body (ignoring any fragment — registry docs are
        // whole-JSON) and parse as a flat alias→URI map.
        let body = self.get_raw(uri).await?;
        let map: HashMap<String, String> = serde_json::from_str(&body).with_context(|| {
            format!(
                "aws-secrets backend '{}': secret body at '{}' is not a JSON \
                 alias→URI map",
                self.instance_name, uri.raw
            )
        })?;
        Ok(map.into_iter().collect())
    }
}

/// Parse `raw` as a JSON object and extract the top-level `key` field
/// as a string. Returns an error with useful context if the body isn't
/// a JSON object, the field is absent, or the field's value is an
/// array/object (unconvertible to string).
fn extract_json_field(
    instance_name: &str,
    uri: &BackendUri,
    raw: &str,
    key: &str,
) -> Result<String> {
    let map: HashMap<String, serde_json::Value> = serde_json::from_str(raw).with_context(|| {
        format!(
            "aws-secrets backend '{instance_name}': URI '{}' has #{key} fragment but \
                 secret value at '{}' is not a JSON object",
            uri.raw, uri.path
        )
    })?;
    let value = map.get(key).ok_or_else(|| {
        let mut fields: Vec<&str> = map.keys().map(String::as_str).collect();
        fields.sort_unstable();
        anyhow!(
            "aws-secrets backend '{instance_name}': URI '{}' field '{key}' not found; \
             secret at '{}' has fields: [{}]",
            uri.raw,
            uri.path,
            fields.join(", ")
        )
    })?;
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok("null".to_owned()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => bail!(
            "aws-secrets backend '{instance_name}': URI '{}' field '{key}' is a JSON \
             {} — only scalar fields (string/number/boolean/null) can be extracted",
            uri.raw,
            if value.is_array() { "array" } else { "object" }
        ),
    }
}

/// Factory for the AWS Secrets Manager backend.
pub struct AwsSecretsFactory(&'static str);

impl AwsSecretsFactory {
    /// Construct the factory. Equivalent to `AwsSecretsFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("aws-secrets")
    }
}

impl Default for AwsSecretsFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for AwsSecretsFactory {
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
        let aws_bin = optional_string(config, "aws_bin", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        Ok(Box::new(AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: instance_name.to_owned(),
            aws_region,
            aws_profile,
            aws_bin,
        }))
    }
}

/// Required string field. Errors if missing or wrong type.
fn required_string(
    config: &HashMap<String, toml::Value>,
    field: &str,
    instance_name: &str,
) -> Result<String> {
    let value = config.get(field).ok_or_else(|| {
        anyhow!(
            "aws-secrets instance '{instance_name}': missing required field '{field}' \
             (set {field} = \"...\" under [backends.{instance_name}])"
        )
    })?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        anyhow!(
            "aws-secrets instance '{instance_name}': field '{field}' must be a string, got {}",
            value.type_str()
        )
    })
}

/// Optional string field. Ok(None) when absent; error when present with
/// wrong type.
fn optional_string(
    config: &HashMap<String, toml::Value>,
    field: &str,
    instance_name: &str,
) -> Result<Option<String>> {
    config.get(field).map_or(Ok(None), |value| {
        value.as_str().map(|s| Some(s.to_owned())).ok_or_else(|| {
            anyhow!(
                "aws-secrets instance '{instance_name}': field '{field}' must be a string, got {}",
                value.type_str()
            )
        })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    fn install_mock_aws(dir: &TempDir, body: &str) -> std::path::PathBuf {
        secretenv_testing::install_mock_aws(dir.path(), body)
    }

    fn backend(mock_path: &Path, profile: Option<&str>) -> AwsSecretsBackend {
        AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: "aws-secrets-prod".to_owned(),
            aws_region: "us-east-1".to_owned(),
            aws_profile: profile.map(ToOwned::to_owned),
            aws_bin: mock_path.to_str().unwrap().to_owned(),
        }
    }

    fn backend_with_nonexistent_aws() -> AwsSecretsBackend {
        AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: "aws-secrets-prod".to_owned(),
            aws_region: "us-east-1".to_owned(),
            aws_profile: None,
            aws_bin: "/definitely/not/a/real/path/to/aws-binary-XYZ".to_owned(),
        }
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_aws_secrets() {
        assert_eq!(AwsSecretsFactory::new().backend_type(), "aws-secrets");
    }

    #[test]
    fn factory_errors_when_aws_region_missing() {
        let factory = AwsSecretsFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("aws-secrets-prod", &cfg) else {
            panic!("expected error when aws_region is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("aws_region"), "names missing field: {msg}");
        assert!(msg.contains("aws-secrets-prod"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_region_and_no_profile() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        let b = factory.create("aws-secrets-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "aws-secrets");
        assert_eq!(b.instance_name(), "aws-secrets-prod");
    }

    #[test]
    fn factory_rejects_non_string_aws_region() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::Integer(1));
        let Err(err) = factory.create("aws-secrets-prod", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    // ---- check Level 1 ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_aws();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "aws");
                assert!(install_hint.contains("brew install awscli"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level1_parses_v2_version_from_stdout() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "aws-cli/2.15.0 Python/3.11.8 Darwin/23.0"
  exit 0
fi
if [ "$1 $2" = "sts get-caller-identity" ]; then
  echo '{"Account":"123456789","Arn":"arn:aws:iam::123456789:user/dev","UserId":"AIDAI"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("aws-cli/2.15.0"));
                assert!(identity.contains("account=123456789"));
                assert!(identity.contains("region=us-east-1"));
                assert!(identity.contains("profile=default"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level1_parses_v1_version_from_stderr() {
        // AWS CLI v1 prints --version to stderr.
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "aws-cli/1.33.0 Python/3.10.12 Linux/5.15" >&2
  exit 0
fi
if [ "$1 $2" = "sts get-caller-identity" ]; then
  echo '{"Account":"1","Arn":"arn:aws:iam::1:user/x","UserId":"u"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, .. } => {
                assert!(cli_version.contains("aws-cli/1.33.0"), "got: {cli_version}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_not_authenticated_on_expired_sso() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "aws-cli/2.15.0"
  exit 0
fi
if [ "$1 $2" = "sts get-caller-identity" ]; then
  echo "Error loading SSO Token: Token for dev has expired" >&2
  exit 253
fi
exit 1
"#,
        );
        let b = backend(&mock, Some("dev"));
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("aws configure --profile dev"), "hint: {hint}");
                assert!(hint.contains("aws sso login"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get — plain value ----

    #[tokio::test]
    async fn get_returns_plain_string_value() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "sk_live_abc"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/stripe").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_returns_raw_json_when_no_fragment() {
        // JSON body + no #fragment → return the blob as-is, unparsed.
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo '{"password":"hunter2","host":"db"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg").unwrap();
        let out = b.get(&uri).await.unwrap();
        assert!(out.contains("\"password\":\"hunter2\""));
        assert!(out.contains("\"host\":\"db\""));
    }

    // ---- get — #fragment dispatch ----

    #[tokio::test]
    async fn get_extracts_json_field_via_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo '{"password":"hunter2","host":"db.internal"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#password").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "hunter2");
    }

    #[tokio::test]
    async fn get_fragment_coerces_number_and_boolean_to_string() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo '{"port":5432,"tls":true}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let port_uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#port").unwrap();
        assert_eq!(b.get(&port_uri).await.unwrap(), "5432");
        let tls_uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#tls").unwrap();
        assert_eq!(b.get(&tls_uri).await.unwrap(), "true");
    }

    #[tokio::test]
    async fn get_errors_when_fragment_on_plain_string() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "plain-not-json"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/plain#field").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("#field"), "names the fragment: {msg}");
        assert!(msg.contains("not a JSON object"), "specific error: {msg}");
    }

    #[tokio::test]
    async fn get_errors_when_fragment_key_missing_lists_available_fields() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo '{"user":"alice","host":"db"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("password"), "names missing field: {msg}");
        // Both available fields listed in the error.
        assert!(msg.contains("user"), "lists available fields: {msg}");
        assert!(msg.contains("host"), "lists available fields: {msg}");
    }

    #[tokio::test]
    async fn get_fragment_errors_on_nested_object_value() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo '{"meta":{"nested":1}}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#meta").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("meta"), "names the field: {msg}");
        assert!(msg.contains("object"), "names the type: {msg}");
    }

    // ---- get error paths ----

    #[tokio::test]
    async fn get_resource_not_found_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret." >&2
  exit 254
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-secrets-prod"), "names instance: {msg}");
        assert!(msg.contains("ResourceNotFoundException"), "passes through: {msg}");
    }

    #[tokio::test]
    async fn get_access_denied_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "An error occurred (AccessDeniedException) when calling GetSecretValue" >&2
  exit 254
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/locked").unwrap();
        assert!(format!("{:#}", b.get(&uri).await.unwrap_err()).contains("AccessDeniedException"));
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager put-secret-value" ]; then
  echo '{"ARN":"arn:...","VersionId":"v1"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/rotate").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("argv_and_stdin.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
{{
  echo "--- ARGV ---"
  for a in "$@"; do echo "arg=$a"; done
  echo "--- STDIN ---"
  cat
}} > "$LOG" 2>&1
if [ "$1 $2" = "secretsmanager put-secret-value" ]; then
  echo '{{"ARN":"arn:..."}}'
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_aws(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/stripe").unwrap();
        let very_sensitive = "sk_live_TOP_SECRET_aws_secrets_never_argv_XYZ";
        b.set(&uri, very_sensitive).await.unwrap();

        let log = std::fs::read_to_string(&log_path).expect("mock wrote log");
        let (argv_section, stdin_section) =
            log.split_once("--- STDIN ---").expect("log has STDIN section");
        assert!(
            !argv_section.contains(very_sensitive),
            "secret value must NOT appear in argv; argv was:\n{argv_section}"
        );
        assert!(
            stdin_section.contains(very_sensitive),
            "secret should have arrived via stdin; stdin was:\n{stdin_section}"
        );
        assert!(
            argv_section.contains("arg=file:///dev/stdin"),
            "argv should carry the stdin sentinel:\n{argv_section}"
        );
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager put-secret-value" ]; then
  echo "An error occurred (ResourceNotFoundException) ..." >&2
  exit 254
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/nonexistent").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("ResourceNotFoundException"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_uses_force_delete_without_recovery() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("argv.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
for a in "$@"; do echo "arg=$a" >> "$LOG"; done
if [ "$1 $2" = "secretsmanager delete-secret" ]; then
  echo '{{"Name":"/myapp/gone"}}'
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_aws(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/gone").unwrap();
        b.delete(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            log.contains("arg=--force-delete-without-recovery"),
            "delete must skip the 30-day recovery window:\n{log}"
        );
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_json_registry_document() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  cat <<'JSON'
{"alpha":"aws-secrets-prod:///myapp/a","beta":"aws-secrets-prod:///myapp/b"}
JSON
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("alpha".to_owned(), "aws-secrets-prod:///myapp/a".to_owned()),
                ("beta".to_owned(), "aws-secrets-prod:///myapp/b".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_body_is_not_json_map() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_aws(
            &dir,
            r#"
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "not-json-at-all"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///bad-registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-secrets-prod"), "names instance: {msg}");
        assert!(msg.contains("alias→URI map"), "specific error: {msg}");
    }

    // ---- argv-shape assertions ----

    #[tokio::test]
    async fn command_always_passes_region() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("argv.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
for a in "$@"; do echo "arg=$a" >> "$LOG"; done
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "v"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_aws(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///x").unwrap();
        b.get(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("arg=--region"), "expected --region in argv:\n{log}");
        assert!(log.contains("arg=us-east-1"), "expected region value:\n{log}");
    }

    #[tokio::test]
    async fn command_omits_profile_when_not_configured() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("argv.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
for a in "$@"; do echo "arg=$a" >> "$LOG"; done
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "v"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_aws(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///x").unwrap();
        b.get(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(!log.contains("arg=--profile"), "profile not set → flag absent:\n{log}");
    }

    #[tokio::test]
    async fn command_includes_profile_when_configured() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("argv.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
for a in "$@"; do echo "arg=$a" >> "$LOG"; done
if [ "$1 $2" = "secretsmanager get-secret-value" ]; then
  echo "v"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_aws(&dir, &script);
        let b = backend(&mock, Some("prod"));
        let uri = BackendUri::parse("aws-secrets-prod:///x").unwrap();
        b.get(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("arg=--profile"), "expected --profile:\n{log}");
        assert!(log.contains("arg=prod"), "expected profile value:\n{log}");
    }
}
