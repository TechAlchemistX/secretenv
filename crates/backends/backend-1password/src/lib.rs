//! 1Password backend for SecretEnv.
//!
//! Wraps the `op` CLI — never 1Password's Connect Server SDK. The CLI
//! handles SSO, biometric unlock, service accounts, and multiple signed-
//! in accounts without us touching any of it.
//!
//! # URI shape
//!
//! `<instance>://<vault>/<item>/<field>` — exactly three non-empty path
//! segments. Example: `1password-personal://Engineering/Prod DB/url`
//! targets the `url` field of the `Prod DB` item in the `Engineering`
//! vault.
//!
//! Nested fields (items with sections, `op://vault/item/section/field`)
//! are out of scope for v0.1; the strict 3-segment rule is documented
//! in the error message when parsing fails.
//!
//! # Config fields
//!
//! - `op_account` (optional) — 1Password account shorthand or URL
//!   (e.g. `myteam.1password.com`). Needed only when multiple accounts
//!   are signed in simultaneously. Passed as `--account <value>` to
//!   every `op` invocation.
//!
//! # Semantics
//!
//! - [`get`](OnePasswordBackend) calls `op read op://<v>/<i>/<f>` and
//!   returns the field value verbatim.
//! - [`set`](OnePasswordBackend) calls `op item edit <item> <field>=<value> --vault <vault>`.
//!   Errors if the item does not exist — we never auto-create.
//! - [`delete`](OnePasswordBackend) calls `op item edit <item> <field>= --vault <vault>`
//!   (empty value). Full item deletion is out of scope for v0.1.
//! - [`list`](OnePasswordBackend) fetches the field value and parses it
//!   as flat TOML `HashMap<String, String>`. This is the registry-
//!   document shape: a 1Password note whose body is the alias → URI
//!   map in TOML form.
//! - [`check`](OnePasswordBackend) runs `op --version` (Level 1) and
//!   `op whoami --format=json` (Level 2).
//!
//! # Safety
//!
//! Every argv call goes through `tokio::process::Command::args(&[…])`
//! — never `sh -c`. URI-derived values never touch a shell interpreter.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{Backend, BackendFactory, BackendStatus, BackendUri};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "op";
const INSTALL_HINT: &str =
    "install via https://developer.1password.com/docs/cli/get-started/  (Homebrew: brew install 1password-cli)";

/// A live instance of the 1Password backend.
pub struct OnePasswordBackend {
    backend_type: &'static str,
    instance_name: String,
    op_account: Option<String>,
    /// Path or name of the `op` binary. Defaults to `"op"` (PATH
    /// lookup); tests override to a mock script path.
    op_bin: String,
}

#[derive(Deserialize)]
struct WhoAmI {
    url: String,
    #[serde(default)]
    email: String,
}

impl OnePasswordBackend {
    /// Parse `uri.path` into `(vault, item, field)`. Exactly 3 non-empty
    /// `/`-separated segments; a leading `/` is tolerated.
    fn parse_path(uri: &BackendUri) -> Result<(String, String, String)> {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|s| s.is_empty()) {
            bail!(
                "1password URI '{}' must have exactly three non-empty path segments \
                 (vault/item/field); got {} — v0.1 does not support nested sections",
                uri.raw,
                parts.len()
            );
        }
        Ok((parts[0].to_owned(), parts[1].to_owned(), parts[2].to_owned()))
    }

    fn append_account(&self, cmd: &mut Command) {
        if let Some(account) = &self.op_account {
            cmd.args(["--account", account]);
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
            "1password backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }
}

#[async_trait]
impl Backend for OnePasswordBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    async fn check(&self) -> BackendStatus {
        // Level 1: `op --version`
        let version_out = match Command::new(&self.op_bin).arg("--version").output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "1password backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.op_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "1password backend '{}': 'op --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let version_str = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();
        let cli_version = format!("op/{version_str}");

        // Level 2: `op whoami --format=json`
        let mut whoami_cmd = Command::new(&self.op_bin);
        whoami_cmd.args(["whoami", "--format=json"]);
        self.append_account(&mut whoami_cmd);
        let whoami_out = match whoami_cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "1password backend '{}': failed to invoke whoami: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !whoami_out.status.success() {
            let stderr = String::from_utf8_lossy(&whoami_out.stderr).trim().to_owned();
            let signin_hint = self
                .op_account
                .as_ref()
                .map_or_else(|| "op signin".to_owned(), |a| format!("op signin --account {a}"));
            return BackendStatus::NotAuthenticated {
                hint: format!("run: {signin_hint}  (stderr: {stderr})"),
            };
        }
        let who: WhoAmI = match serde_json::from_slice(&whoami_out.stdout) {
            Ok(w) => w,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "1password backend '{}': parsing whoami JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        let email_part =
            if who.email.is_empty() { String::new() } else { format!(" email={}", who.email) };
        BackendStatus::Ok { cli_version, identity: format!("account={}{email_part}", who.url) }
    }

    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        Ok(self.list(test_uri).await?.len())
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let (vault, item, field) = Self::parse_path(uri)?;
        let op_uri = format!("op://{vault}/{item}/{field}");
        let mut cmd = Command::new(&self.op_bin);
        cmd.args(["read", &op_uri]);
        self.append_account(&mut cmd);
        let output = cmd.output().await.with_context(|| {
            format!(
                "1password backend '{}': failed to invoke 'op read' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "1password backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        let (vault, item, field) = Self::parse_path(uri)?;
        let assignment = format!("{field}={value}");
        let mut cmd = Command::new(&self.op_bin);
        cmd.args(["item", "edit", &item, &assignment, "--vault", &vault]);
        self.append_account(&mut cmd);
        let output = cmd.output().await.with_context(|| {
            format!(
                "1password backend '{}': failed to invoke 'op item edit' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        let (vault, item, field) = Self::parse_path(uri)?;
        // 1Password's CLI has no "clear one field" — we set it to empty.
        // Full item deletion is out of scope for v0.1.
        let assignment = format!("{field}=");
        let mut cmd = Command::new(&self.op_bin);
        cmd.args(["item", "edit", &item, &assignment, "--vault", &vault]);
        self.append_account(&mut cmd);
        let output = cmd.output().await.with_context(|| {
            format!(
                "1password backend '{}': failed to invoke 'op item edit' for URI '{}'",
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
        let parsed: HashMap<String, String> = toml::from_str(&body).with_context(|| {
            format!(
                "1password backend '{}': field at '{}' is not a flat TOML key→string map \
                 (v0.1 only supports registry-document shape)",
                self.instance_name, uri.raw
            )
        })?;
        Ok(parsed.into_iter().collect())
    }
}

/// Factory for the 1Password backend. No required config fields;
/// `op_account` is optional.
pub struct OnePasswordFactory(&'static str);

impl OnePasswordFactory {
    /// Construct the factory. Equivalent to `OnePasswordFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("1password")
    }
}

impl Default for OnePasswordFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for OnePasswordFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        mut config: HashMap<String, String>,
    ) -> Result<Box<dyn Backend>> {
        let op_account = config.remove("op_account");
        Ok(Box::new(OnePasswordBackend {
            backend_type: "1password",
            instance_name: instance_name.to_owned(),
            op_account,
            op_bin: CLI_NAME.to_owned(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::*;

    /// Write a bash script to `dir/op`, chmod +x, return the path.
    /// Mirrors `install_mock_aws` in backend-aws-ssm (same ETXTBSY
    /// workaround for parallel-test flakiness on Linux).
    fn install_mock_op(dir: &TempDir, body: &str) -> PathBuf {
        use std::io::Write;

        let path = dir.path().join("op");
        let full = format!("#!/bin/sh\n{body}\n");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(full.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            match std::process::Command::new(&path).arg("--probe").output() {
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(_) | Err(_) => return path,
            }
        }
        path
    }

    fn backend(mock_path: &Path, account: Option<&str>) -> OnePasswordBackend {
        OnePasswordBackend {
            backend_type: "1password",
            instance_name: "1password-personal".to_owned(),
            op_account: account.map(ToOwned::to_owned),
            op_bin: mock_path.to_str().unwrap().to_owned(),
        }
    }

    fn backend_with_nonexistent_op() -> OnePasswordBackend {
        OnePasswordBackend {
            backend_type: "1password",
            instance_name: "1password-personal".to_owned(),
            op_account: None,
            op_bin: "/definitely/not/a/real/path/to/op-binary-98765".to_owned(),
        }
    }

    // ---- Factory ----

    #[test]
    fn factory_builds_backend_with_no_required_fields() {
        let factory = OnePasswordFactory::new();
        let b = factory.create("1password-personal", HashMap::new()).unwrap();
        assert_eq!(b.backend_type(), "1password");
        assert_eq!(b.instance_name(), "1password-personal");
    }

    #[test]
    fn factory_accepts_op_account() {
        let factory = OnePasswordFactory::new();
        let mut cfg = HashMap::new();
        cfg.insert("op_account".to_owned(), "myteam.1password.com".to_owned());
        assert!(factory.create("1password-team", cfg).is_ok());
    }

    #[test]
    fn factory_backend_type_is_1password() {
        assert_eq!(OnePasswordFactory::new().backend_type(), "1password");
    }

    // ---- URI parsing ----

    #[test]
    fn parse_path_three_segments_happy() {
        let uri = BackendUri::parse("1password-personal://Engineering/Prod DB/url").unwrap();
        let (v, i, f) = OnePasswordBackend::parse_path(&uri).unwrap();
        assert_eq!(v, "Engineering");
        assert_eq!(i, "Prod DB");
        assert_eq!(f, "url");
    }

    #[test]
    fn parse_path_tolerates_leading_slash() {
        let uri = BackendUri::parse("1password-personal:///Engineering/DB/url").unwrap();
        let (v, i, f) = OnePasswordBackend::parse_path(&uri).unwrap();
        assert_eq!(v, "Engineering");
        assert_eq!(i, "DB");
        assert_eq!(f, "url");
    }

    #[test]
    fn parse_path_rejects_two_segments() {
        let uri = BackendUri::parse("1password-personal://vault/item").unwrap();
        let err = OnePasswordBackend::parse_path(&uri).unwrap_err();
        assert!(format!("{err:#}").contains("vault/item/field"));
    }

    #[test]
    fn parse_path_rejects_four_segments() {
        let uri = BackendUri::parse("1password-personal://vault/item/section/field").unwrap();
        let err = OnePasswordBackend::parse_path(&uri).unwrap_err();
        assert!(format!("{err:#}").contains("three"));
    }

    #[test]
    fn parse_path_rejects_empty_segment() {
        let uri = BackendUri::parse("1password-personal://vault//field").unwrap();
        let err = OnePasswordBackend::parse_path(&uri).unwrap_err();
        assert!(format!("{err:#}").contains("non-empty"));
    }

    // ---- get happy path ----

    #[tokio::test]
    async fn get_returns_field_value_no_account() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  echo "super-secret-value"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://Eng/API/key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "super-secret-value");
    }

    #[tokio::test]
    async fn get_returns_field_value_with_account() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  echo "args: $*" >&2
  echo "value-from-team"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, Some("myteam.1password.com"));
        let uri = BackendUri::parse("1password-team://Eng/API/key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "value-from-team");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  printf 'raw-secret\n'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "raw-secret");
    }

    // ---- get errors ----

    #[tokio::test]
    async fn get_item_not_found_error_includes_stderr_and_uri() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  echo "[ERROR] 2026/04/17 14:00:00 item \"Prod DB\" not found in vault \"Engineering\"" >&2
  exit 1
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://Engineering/Prod DB/url").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "stderr propagates: {msg}");
        assert!(msg.contains("Prod DB"), "uri in context: {msg}");
        assert!(msg.contains("1password-personal"), "instance in context: {msg}");
    }

    #[tokio::test]
    async fn get_fails_fast_when_binary_missing() {
        let b = backend_with_nonexistent_op();
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1password-personal"), "instance in context: {msg}");
    }

    #[tokio::test]
    async fn get_non_utf8_response_errors_with_context() {
        let dir = TempDir::new().unwrap();
        // Octal escapes (POSIX), not \xFF (bash-specific).
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  printf '\377\376\375\374'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("non-UTF-8"), "specific error: {msg}");
        assert!(msg.contains("1password-personal"), "instance in context: {msg}");
    }

    // ---- set, delete, list ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1 $2" = "item edit" ]; then
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        b.set(&uri, "new-secret").await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_item_not_found_error() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1 $2" = "item edit" ]; then
  echo "[ERROR] item \"I\" not found in vault \"V\"" >&2
  exit 1
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("not found"));
    }

    #[tokio::test]
    async fn delete_runs_edit_with_empty_value() {
        let dir = TempDir::new().unwrap();
        // The mock writes its args to a side file so the test can
        // assert `F=` was passed (empty assignment).
        let args_log = dir.path().join("args.log");
        let log_str = args_log.to_str().unwrap().to_owned();
        let mock = install_mock_op(
            &dir,
            &format!(
                r#"
if [ "$1 $2" = "item edit" ]; then
  printf '%s\n' "$*" > "{log_str}"
  exit 0
fi
exit 1
"#
            ),
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        b.delete(&uri).await.unwrap();
        let logged = std::fs::read_to_string(&args_log).unwrap();
        assert!(logged.contains("F="), "delete sends F= (empty): {logged}");
        assert!(!logged.contains("F=foo"), "delete must not pass a value: {logged}");
    }

    #[tokio::test]
    async fn list_parses_toml_registry_document() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  cat <<'TOML'
stripe-key = "aws-ssm-prod:///prod/stripe"
db-url = "1password-personal://Engineering/Prod DB/url"
TOML
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://Shared/Registry/content").unwrap();
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
    async fn list_errors_when_body_is_not_flat_toml() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "read" ]; then
  printf '[sub]\nkey = "value"\n'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("1password-personal://V/I/F").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("flat TOML") || msg.contains("string"), "specific error: {msg}");
    }

    // ---- check ----

    #[tokio::test]
    async fn check_returns_cli_missing_when_binary_not_found() {
        let b = backend_with_nonexistent_op();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "op");
                assert!(
                    install_hint.contains("1password-cli") || install_hint.contains("developer")
                );
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_ok_when_version_and_whoami_succeed() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "2.30.0"
  exit 0
fi
if [ "$1" = "whoami" ]; then
  echo '{"url":"my.1password.com","email":"me@example.com"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, Some("my.1password.com"));
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("2.30.0"));
                assert!(identity.contains("account=my.1password.com"));
                assert!(identity.contains("email=me@example.com"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_not_authenticated_on_sign_in_error() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "2.30.0"
  exit 0
fi
if [ "$1" = "whoami" ]; then
  echo "[ERROR] You are not signed in. Run \"op signin\" to authenticate and try again." >&2
  exit 1
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("op signin"), "hint names signin: {hint}");
                assert!(hint.contains("not signed in"), "stderr in hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_signin_hint_includes_account_when_configured() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_op(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "2.30.0"
  exit 0
fi
if [ "$1" = "whoami" ]; then
  echo "[ERROR] You are not signed in." >&2
  exit 1
fi
exit 1
"#,
        );
        let b = backend(&mock, Some("myteam.1password.com"));
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(
                    hint.contains("--account myteam.1password.com"),
                    "hint tailored to configured account: {hint}"
                );
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }
}
