// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! AWS Secrets Manager backend for SecretEnv.
//!
//! Wraps the `aws` CLI (v2 recommended) — **never** the AWS SDK.
//! Same auth story as `secretenv-backend-aws-ssm`: every credential
//! chain the user's `aws` CLI supports (SSO, MFA, profiles, instance
//! roles, `aws-vault`, cross-account assumption) works transparently.
//!
//! # URI shape
//!
//! `<instance>:///<secret-id>[#json-key=<field>]` — scheme is the
//! instance name (e.g. `aws-secrets-prod`); path is the Secret ARN or
//! friendly name passed verbatim to `--secret-id`. The optional
//! `#json-key=<field>` fragment directive selects a top-level field of
//! a JSON-shaped secret. Per the canonical fragment grammar introduced
//! in v0.2.1, legacy plain-string shorthand (`#password`) is rejected
//! at URI-parse time with a migration hint. `json-key` is the sole
//! directive aws-secrets recognizes.
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
//!   - No fragment → returns the value verbatim (plain string OR whole
//!     JSON blob — user's choice).
//!   - `#json-key=<field>` fragment → parses the value as a JSON object
//!     and extracts the top-level `<field>`. Any other directive key is
//!     rejected; plain-string shorthand (`#password`) is rejected at
//!     URI-parse time by [`secretenv_core::BackendUri::fragment_directives`].
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
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, optional_string, required_string, Backend, BackendFactory,
    BackendStatus, BackendUri, DEFAULT_GET_TIMEOUT,
};
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
    /// Per-instance deadline for fetch-class operations. From
    /// `timeout_secs` config field; defaults to [`DEFAULT_GET_TIMEOUT`].
    timeout: Duration,
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

    fn timeout(&self) -> Duration {
        self.timeout
    }

    #[allow(clippy::similar_names)]
    async fn check(&self) -> BackendStatus {
        // v0.3: Level 1 + Level 2 via `tokio::join!` — see aws-ssm
        // counterpart for rationale. `doctor` latency halved per
        // backend; both probes are independent.
        let version_fut = Command::new(&self.aws_bin).arg("--version").output();
        let mut sts_cmd = Command::new(&self.aws_bin);
        sts_cmd.args(["sts", "get-caller-identity", "--output", "json"]);
        self.append_region_and_profile(&mut sts_cmd);
        let sts_fut = sts_cmd.output();
        let (version_res, sts_res) = tokio::join!(version_fut, sts_fut);

        // --- Level 1 ---
        let version_out = match version_res {
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
        let cli_version = {
            let stdout = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();
            if stdout.is_empty() {
                String::from_utf8_lossy(&version_out.stderr).trim().to_owned()
            } else {
                stdout
            }
        };

        // --- Level 2 ---
        let sts_out = match sts_res {
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

    // `check_extensive` uses the `Backend` trait default (list().len()).

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        // Validate the fragment directive BEFORE any AWS API call. An
        // invalid fragment (legacy shorthand like `#password`, or an
        // unsupported directive like `#version=5`) is a local
        // grammar error — shelling out to AWS first would leak access
        // patterns, waste IAM permissions + latency + cost, and then
        // surface an error the caller could have learned about
        // instantly. Caught by the v0.2.6 strict-mode retrofit (the
        // v0.2 permissive-mock tests silently masked the extra call).
        let json_key: Option<String> = match uri.fragment_directives()? {
            None => None,
            Some(mut directives) => {
                if !directives.contains_key("json-key") {
                    let mut unsupported: Vec<&str> =
                        directives.keys().map(String::as_str).collect();
                    unsupported.sort_unstable();
                    bail!(
                        "aws-secrets backend '{}': URI '{}' has unsupported fragment \
                         directive(s) [{}]; aws-secrets recognizes only 'json-key' \
                         (example: '#json-key=password')",
                        self.instance_name,
                        uri.raw,
                        unsupported.join(", ")
                    );
                }
                if directives.len() > 1 {
                    let mut extra: Vec<&str> = directives
                        .keys()
                        .filter(|k| k.as_str() != "json-key")
                        .map(String::as_str)
                        .collect();
                    extra.sort_unstable();
                    bail!(
                        "aws-secrets backend '{}': URI '{}' has unsupported directive(s) \
                         [{}] alongside 'json-key'; aws-secrets recognizes only 'json-key'",
                        self.instance_name,
                        uri.raw,
                        extra.join(", ")
                    );
                }
                // Safe: we already verified presence above.
                let Some(key) = directives.shift_remove("json-key") else {
                    unreachable!("json-key presence was checked above")
                };
                Some(key)
            }
        };
        let raw = self.get_raw(uri).await?;
        match json_key {
            None => Ok(raw),
            Some(key) => extract_json_field(&self.instance_name, uri, &raw, &key),
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
            "aws-secrets backend '{instance_name}': URI '{}' selects JSON key '{key}' \
             but secret value at '{}' is not a JSON object",
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
        let aws_region = required_string(config, "aws_region", "aws-secrets", instance_name)?;
        let aws_profile = optional_string(config, "aws_profile", "aws-secrets", instance_name)?;
        let aws_bin = optional_string(config, "aws_bin", "aws-secrets", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "aws-secrets", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(Box::new(AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: instance_name.to_owned(),
            aws_region,
            aws_profile,
            aws_bin,
            timeout,
        }))
    }
}

// v0.3 Phase 0: `required_string` / `optional_string` moved to
// `secretenv_core::factory_helpers`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    const REGION: &str = "us-east-1";

    fn backend(mock_path: &Path, profile: Option<&str>) -> AwsSecretsBackend {
        AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: "aws-secrets-prod".to_owned(),
            aws_region: REGION.to_owned(),
            aws_profile: profile.map(ToOwned::to_owned),
            aws_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_aws() -> AwsSecretsBackend {
        AwsSecretsBackend {
            backend_type: "aws-secrets",
            instance_name: "aws-secrets-prod".to_owned(),
            aws_region: REGION.to_owned(),
            aws_profile: None,
            aws_bin: "/definitely/not/a/real/path/to/aws-binary-XYZ".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    /// Argv for `get-secret-value --secret-id <ID> --query SecretString
    /// --output text --region us-east-1`. Secret ID is the PR #33 BUG-2
    /// canonical form: NO leading slash. Any test whose URI carries a
    /// `:///<path>` (triple-slash) form implicitly exercises the slash
    /// stripping — if a regression reintroduced the slash on argv, the
    /// strict argv match would fail with a clear diagnostic.
    fn get_argv(secret_id: &str) -> [&str; 10] {
        [
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
            "--region",
            REGION,
        ]
    }

    /// Argv for `put-secret-value --secret-id <ID> --secret-string
    /// file:///dev/stdin --region us-east-1`. The secret value goes via
    /// stdin (CV-1 discipline), NOT this argv.
    fn put_argv(secret_id: &str) -> [&str; 8] {
        [
            "secretsmanager",
            "put-secret-value",
            "--secret-id",
            secret_id,
            "--secret-string",
            "file:///dev/stdin",
            "--region",
            REGION,
        ]
    }

    fn delete_argv(secret_id: &str) -> [&str; 7] {
        [
            "secretsmanager",
            "delete-secret",
            "--secret-id",
            secret_id,
            "--force-delete-without-recovery",
            "--region",
            REGION,
        ]
    }

    const STS_ARGV_NO_PROFILE: &[&str] =
        &["sts", "get-caller-identity", "--output", "json", "--region", REGION];

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

    #[test]
    fn factory_rejects_non_string_aws_profile() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        cfg.insert("aws_profile".to_owned(), toml::Value::Boolean(false));
        let Err(err) = factory.create("aws-secrets-prod", &cfg) else {
            panic!("expected type error for non-string aws_profile");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("aws_profile"), "names the field: {msg}");
        assert!(msg.contains("must be a string"), "describes type mismatch: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_aws_bin() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        cfg.insert("aws_bin".to_owned(), toml::Value::Integer(7));
        let Err(err) = factory.create("aws-secrets-prod", &cfg) else {
            panic!("expected type error for non-string aws_bin");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("aws_bin"), "names the field: {msg}");
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(22));
        let b = factory.create("aws-secrets-prod", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(22));
    }

    #[test]
    fn factory_uses_default_timeout_when_omitted() {
        let factory = AwsSecretsFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("aws_region".to_owned(), toml::Value::String("us-east-1".to_owned()));
        let b = factory.create("aws-secrets-prod", &cfg).unwrap();
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
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
        let mock = StrictMock::new("aws")
            .on(&["--version"], Response::success("aws-cli/2.15.0 Python/3.11.8 Darwin/23.0\n"))
            .on(
                STS_ARGV_NO_PROFILE,
                Response::success(
                    "{\"Account\":\"123456789\",\"Arn\":\"arn:aws:iam::123456789:user/dev\",\"UserId\":\"AIDAI\"}\n",
                ),
            )
            .install(dir.path());
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
        let mock = StrictMock::new("aws")
            .on(
                &["--version"],
                Response::success("").with_stderr("aws-cli/1.33.0 Python/3.10.12 Linux/5.15\n"),
            )
            .on(
                STS_ARGV_NO_PROFILE,
                Response::success(
                    "{\"Account\":\"1\",\"Arn\":\"arn:aws:iam::1:user/x\",\"UserId\":\"u\"}\n",
                ),
            )
            .install(dir.path());
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
        let sts_argv_dev: Vec<&str> =
            STS_ARGV_NO_PROFILE.iter().copied().chain(["--profile", "dev"]).collect();
        let mock = StrictMock::new("aws")
            .on(&["--version"], Response::success("aws-cli/2.15.0\n"))
            .on(
                &sts_argv_dev,
                Response::failure(253, "Error loading SSO Token: Token for dev has expired\n"),
            )
            .install(dir.path());
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
    //
    // PR #33 BUG-2 regression lock is implicit on every one of these
    // tests: the URI carries a `:///<path>` triple-slash form whose
    // `path` includes the leading slash; `secret_id()` strips it; the
    // declared argv carries the POST-STRIP form. Any regression that
    // re-introduced the slash would diverge from the declared argv →
    // `strict-mock-no-match` diagnostic.

    #[tokio::test]
    async fn get_returns_plain_string_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/stripe"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/stripe").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_returns_raw_json_when_no_fragment() {
        // JSON body + no #fragment → return the blob as-is, unparsed.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &get_argv("myapp/cfg"),
                Response::success("{\"password\":\"hunter2\",\"host\":\"db\"}\n"),
            )
            .install(dir.path());
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
        let mock = StrictMock::new("aws")
            .on(
                &get_argv("myapp/cfg"),
                Response::success("{\"password\":\"hunter2\",\"host\":\"db.internal\"}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=password").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "hunter2");
    }

    #[tokio::test]
    async fn get_fragment_coerces_number_and_boolean_to_string() {
        let dir = TempDir::new().unwrap();
        // Two separate URIs → two distinct get() calls → two identical
        // rules (same argv) → first-match-wins means both get the same
        // body. That's fine — both URIs share the same secret ID.
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/cfg"), Response::success("{\"port\":5432,\"tls\":true}\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let port_uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=port").unwrap();
        assert_eq!(b.get(&port_uri).await.unwrap(), "5432");
        let tls_uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=tls").unwrap();
        assert_eq!(b.get(&tls_uri).await.unwrap(), "true");
    }

    #[tokio::test]
    async fn get_errors_when_fragment_on_plain_string() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/plain"), Response::success("plain-not-json\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/plain#json-key=field").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("'field'"), "names the JSON key: {msg}");
        assert!(msg.contains("not a JSON object"), "specific error: {msg}");
    }

    #[tokio::test]
    async fn get_errors_when_fragment_key_missing_lists_available_fields() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/cfg"), Response::success("{\"user\":\"alice\",\"host\":\"db\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("password"), "names missing field: {msg}");
        // Both available fields listed in the error.
        assert!(msg.contains("user"), "lists available fields: {msg}");
        assert!(msg.contains("host"), "lists available fields: {msg}");
    }

    // v0.2.1 shorthand + unsupported-directive rejection. Under strict
    // mocks these tests get an EMPTY-RULE mock: any aws invocation
    // produces exit 97 with `strict-mock-no-match`. Tests assert the
    // error originates in core's fragment grammar (BEFORE any aws call)
    // — so the backend's own error message propagates, not the strict
    // harness's exit-97 diagnostic.

    #[tokio::test]
    async fn get_rejects_legacy_shorthand_fragment_with_migration_hint() {
        // `#password` was the v0.2.0 shorthand. v0.2.1 canonicalized the
        // grammar — this URI must fail at `fragment_directives()` before
        // any AWS call. Empty-rule mock makes the "no aws call" claim
        // a typed assertion: if the backend DID reach aws, the strict
        // harness would produce exit 97 with a `strict-mock-no-match`
        // stderr, not a silent success.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shorthand"), "error names the problem: {msg}");
        assert!(
            msg.contains("#json-key=password"),
            "error suggests the canonical form verbatim: {msg}"
        );
        assert!(msg.contains("fragment-vocabulary"), "error links to doc: {msg}");
        // Bonus: strict no-match diagnostic must NOT appear — the error
        // is supposed to come from the fragment parser, not the mock.
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from fragment parser, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_unsupported_directive_with_enumerated_list() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"), "error names the problem: {msg}");
        assert!(msg.contains("'version'") || msg.contains("[version]"), "lists offender: {msg}");
        assert!(msg.contains("json-key"), "names the supported directive: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from the backend, not the mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_extra_directives_alongside_json_key() {
        // Two-directive rejection happens AFTER the raw get_raw(), so
        // aws IS called. Give it a minimal happy rule so the directive-
        // check is the gating assertion.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/cfg"), Response::success("{\"password\":\"hunter2\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri =
            BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=password,version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"), "error names the problem: {msg}");
        assert!(msg.contains("version"), "lists extra directive: {msg}");
        assert!(msg.contains("json-key"), "references the recognized directive: {msg}");
    }

    #[tokio::test]
    async fn get_fragment_errors_on_nested_object_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&get_argv("myapp/cfg"), Response::success("{\"meta\":{\"nested\":1}}\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/cfg#json-key=meta").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("meta"), "names the field: {msg}");
        assert!(msg.contains("object"), "names the type: {msg}");
    }

    // ---- get error paths ----

    #[tokio::test]
    async fn get_resource_not_found_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &get_argv("myapp/missing"),
                Response::failure(
                    254,
                    "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret.\n",
                ),
            )
            .install(dir.path());
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
        let mock = StrictMock::new("aws")
            .on(
                &get_argv("myapp/locked"),
                Response::failure(
                    254,
                    "An error occurred (AccessDeniedException) when calling GetSecretValue\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/locked").unwrap();
        assert!(format!("{:#}", b.get(&uri).await.unwrap_err()).contains("AccessDeniedException"));
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &put_argv("myapp/rotate"),
                Response::success_with_stdin(
                    "{\"ARN\":\"arn:...\",\"VersionId\":\"v1\"}\n",
                    vec!["new-value".to_owned()],
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/rotate").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 discipline, declaratively: argv carries `file:///dev/stdin`
        // sentinel (NOT the secret); stdin-fragment check requires the
        // secret. Strict match on both simultaneously implies "secret
        // on stdin, NOT on argv" as a harness-level guarantee — no
        // file I/O, no grep.
        let very_sensitive = "sk_live_TOP_SECRET_aws_secrets_never_argv_XYZ";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &put_argv("myapp/stripe"),
                Response::success_with_stdin(
                    "{\"ARN\":\"arn:...\"}\n",
                    vec![very_sensitive.to_owned()],
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/stripe").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &put_argv("myapp/nonexistent"),
                Response::failure(254, "An error occurred (ResourceNotFoundException) ...\n")
                    .with_env_absent("NEVER_SET_SENTINEL"), // no-op env check — lets failure still pipe stderr correctly
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/nonexistent").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("ResourceNotFoundException"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_uses_force_delete_without_recovery() {
        // Under strict match, the declared argv explicitly lists
        // `--force-delete-without-recovery`. A regression that dropped
        // the flag would fail with `strict-mock-no-match` — no args-log
        // side-channel needed.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(&delete_argv("myapp/gone"), Response::success("{\"Name\":\"myapp/gone\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_json_registry_document() {
        let dir = TempDir::new().unwrap();
        let body = "{\"alpha\":\"aws-secrets-prod:///myapp/a\",\"beta\":\"aws-secrets-prod:///myapp/b\"}\n";
        let mock = StrictMock::new("aws")
            .on(&get_argv("registries/shared"), Response::success(body))
            .install(dir.path());
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
        let mock = StrictMock::new("aws")
            .on(&get_argv("bad-registry"), Response::success("not-json-at-all\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///bad-registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-secrets-prod"), "names instance: {msg}");
        assert!(msg.contains("alias→URI map"), "specific error: {msg}");
    }

    // ---- argv-shape assertions (absorbed into strict migration) ----
    //
    // The three v0.2 `command_always_passes_region` /
    // `command_omits_profile_when_not_configured` /
    // `command_includes_profile_when_configured` tests were log-file
    // side-channels asserting properties of the emitted argv. Under
    // strict match, EVERY migrated test above with `get_argv(...)`
    // implicitly asserts `--region us-east-1` is present (because the
    // const includes it). The profile-absent + profile-present
    // scenarios collapse to these two tests:

    #[tokio::test]
    async fn command_omits_profile_when_not_configured() {
        // Declared argv has NO `--profile` suffix. If the backend
        // emitted `--profile ...`, strict argv match would fail.
        let dir = TempDir::new().unwrap();
        let mock =
            StrictMock::new("aws").on(&get_argv("x"), Response::success("v\n")).install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_profile_when_configured() {
        // Declared argv MUST include `--profile prod` at the tail; any
        // regression dropping the flag produces exit 97.
        let dir = TempDir::new().unwrap();
        let get_argv_prod: Vec<&str> =
            get_argv("x").iter().copied().chain(["--profile", "prod"]).collect();
        let mock =
            StrictMock::new("aws").on(&get_argv_prod, Response::success("v\n")).install(dir.path());
        let b = backend(&mock, Some("prod"));
        let uri = BackendUri::parse("aws-secrets-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    // ---- drift-catch regression locks (new in v0.2.6) ----

    // PR #33 BUG-2 POSITIVE regression lock. The canonical `secret_id()`
    // strips the leading `/`; a regression that reintroduced it would
    // send `--secret-id /myapp/stripe` instead of `--secret-id
    // myapp/stripe`. This test declares the BUGGY form on argv: if the
    // backend regresses, it'd match this declared shape and succeed
    // (caller's .await.unwrap_err() would panic). Under the current
    // post-fix code, the backend sends `myapp/stripe` (no slash), which
    // does NOT match the declared `/myapp/stripe` shape, so strict
    // harness emits exit 97 and the get() surfaces a clear error.
    #[tokio::test]
    async fn get_drift_catch_rejects_leading_slash_on_secret_id() {
        let dir = TempDir::new().unwrap();
        // Declared argv with buggy leading-slash form.
        let buggy_argv = get_argv("/myapp/stripe");
        let mock = StrictMock::new("aws")
            .on(&buggy_argv, Response::success("never-matches-post-fix\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/stripe").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("strict-mock-no-match") || msg.contains("aws-secrets"),
            "expected strict no-match propagated as get() failure: {msg}"
        );
    }

    // CV-1 regression lock: secret on stdin, NOT on argv. Declared argv
    // has `file:///dev/stdin` sentinel + stdin-fragment check requires
    // the secret. Any CV-1 regression (secret leaking to argv) breaks
    // both simultaneously — strict argv match fails because argv now
    // has the secret in place of the sentinel, AND the stdin check
    // fails because the secret went elsewhere.
    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        let secret = "sk_live_CV1_aws_secrets_regression_lock";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("aws")
            .on(
                &put_argv("myapp/rotate"),
                Response::success_with_stdin("{\"ARN\":\"arn:...\"}\n", vec![secret.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("aws-secrets-prod:///myapp/rotate").unwrap();
        b.set(&uri, secret).await.unwrap();
    }
}
