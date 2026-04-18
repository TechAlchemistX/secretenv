//! HashiCorp Vault backend for SecretEnv.
//!
//! Wraps the `vault` CLI — **never** a Vault HTTP SDK. This keeps
//! tokens, `AppRole` secret-ids, and Kubernetes service-account
//! credentials entirely in the user's CLI environment. It also means
//! every auth flow the `vault` CLI supports (`VAULT_TOKEN`, `AppRole`,
//! OIDC, Kubernetes, AWS IAM) works transparently — there is no
//! "secretenv auth" surface.
//!
//! # URI shape
//!
//! `<instance>://<mount>/<path-within-mount>` — scheme is the instance
//! name (e.g. `vault-eng`), the remainder of the path (after stripping
//! a leading `/`) is passed verbatim to `vault kv`. The unified
//! `vault kv` CLI injects the `data/` segment for KV v2 mounts
//! automatically — **secretenv does NOT rewrite `data/` itself**.
//!
//! # Config fields
//!
//! - `vault_address` (required) — full URL of the Vault instance
//! - `vault_namespace` (optional) — Vault Enterprise namespace.
//!   Omitted by the factory when unset so open-source Vault (which
//!   rejects the `-namespace` flag) stays happy.
//! - `vault_bin` (optional, test hook) — overrides the `vault`
//!   binary path. Defaults to `"vault"` (resolved via `$PATH`).
//!
//! # Semantics
//!
//! - [`get`](VaultBackend) runs `vault kv get -field=value <path>`
//!   and trims exactly one trailing newline.
//! - [`set`](VaultBackend) runs `vault kv put <path> value=-` and
//!   pipes the secret through child stdin. The value NEVER appears
//!   on argv.
//! - [`delete`](VaultBackend) runs `vault kv delete <path>`
//!   (KV v2 soft-delete — metadata + prior versions survive).
//! - [`list`](VaultBackend) reads one JSON-formatted secret and
//!   parses it as an alias→URI map (registry-document shape).
//! - [`check`](VaultBackend) runs `vault --version` (Level 1) and
//!   `vault token lookup -format=json` (Level 2 — requires a valid
//!   token, unlike `vault status` which succeeds anyway).
//!
//! # Safety
//!
//! Every argv call goes through `tokio::process::Command::args([…])`
//! with individual `&str`s — never `sh -c`, never `format!` into a
//! shell string. URI-derived values never touch a shell interpreter.
//!
//! See [[backends/vault]] in the kb for the full implementation
//! spec (identity table, mock-CLI test plan, open design questions).
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{Backend, BackendFactory, BackendStatus, BackendUri};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "vault";
// HashiCorp moved vault out of homebrew-core after the BSL license
// change (Aug 2023); the bare `brew install vault` formula no longer
// exists. Point at the tap form that actually works. The general
// install page still covers Linux, Windows, and manual downloads.
const INSTALL_HINT: &str = "brew tap hashicorp/tap && brew install hashicorp/tap/vault  OR  https://developer.hashicorp.com/vault/install";

/// A live instance of the HashiCorp Vault backend.
pub struct VaultBackend {
    backend_type: &'static str,
    instance_name: String,
    vault_address: String,
    vault_namespace: Option<String>,
    /// Path or name of the `vault` binary. Defaults to `"vault"` (PATH
    /// lookup); tests override to point at a mock script.
    vault_bin: String,
}

/// Level 2 identity response from `vault token lookup -format=json`.
/// We only need a couple of top-level fields to prove the token is
/// valid; policies + TTL are captured for a future
/// `doctor --extensive` enhancement but unused today.
#[derive(Deserialize)]
struct TokenLookup {
    #[allow(dead_code)]
    data: TokenLookupData,
}

#[derive(Deserialize)]
struct TokenLookupData {
    #[allow(dead_code)]
    #[serde(default)]
    display_name: String,
}

/// KV v2 response shape: `{"data": {"data": {...}, "metadata": {...}}}`.
/// KV v1 flattens to `{"data": {...}}`. We try v2 first, fall back to v1.
#[derive(Deserialize)]
struct KvResponse {
    data: KvData,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KvData {
    /// KV v2: an inner `data` object plus metadata we ignore.
    V2 { data: HashMap<String, String> },
    /// KV v1: the entries directly under `data`.
    V1(HashMap<String, String>),
}

impl VaultBackend {
    /// Strip a single leading `/` from `uri.path` to produce the path
    /// passed to `vault kv`. Mirrors the 1Password backend's
    /// path-splitting convention (see
    /// `secretenv-backend-1password/src/lib.rs`).
    fn vault_path(uri: &BackendUri) -> String {
        uri.path.strip_prefix('/').unwrap_or(&uri.path).to_owned()
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
            "vault backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `vault <subcommand> <extra_args...>` command with
    /// `-address` + conditional `-namespace` appended at the end.
    ///
    /// Argv shape mirrors `AwsSsmBackend::ssm_command`:
    /// `vault <subcommand> <extra_args...> -address <url> [-namespace <ns>]`
    /// — so mock scripts can assert `$1 $2 = kv get` without having to
    /// skip past leading flags.
    ///
    /// **Important:** the `-namespace` flag is ONLY appended when
    /// `vault_namespace` is `Some`. Open-source Vault rejects the
    /// flag outright; passing it unconditionally would break every
    /// OSS user. Test `command_omits_namespace_flag_when_not_configured`
    /// locks this.
    fn vault_command(&self, subcommand: &str, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.vault_bin);
        cmd.arg(subcommand);
        cmd.args(extra_args);
        // Route address + namespace via env rather than argv. The
        // earlier argv form (`vault kv get ... -address=<addr>`) was
        // rejected by the real vault binary ("Command flags must be
        // provided before positional arguments") — flags must precede
        // positional args and can't go where they previously landed.
        // Env-var config is the idiomatic vault CLI pattern anyway
        // and keeps argv stable so mock harnesses match `$1 $2 =
        // kv get/put/delete`. Set per-Command only so parent-process
        // env is untouched. Caught in integration validation 2026-04-18.
        cmd.env("VAULT_ADDR", &self.vault_address);
        if let Some(ns) = &self.vault_namespace {
            cmd.env("VAULT_NAMESPACE", ns);
        }
        cmd
    }
}

#[async_trait]
impl Backend for VaultBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    async fn check(&self) -> BackendStatus {
        // Level 1: `vault --version`
        let version_out = match Command::new(&self.vault_bin).arg("--version").output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "vault backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.vault_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "vault backend '{}': 'vault --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let cli_version = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();

        // Level 2: `vault token lookup -format=json`
        // `vault status` succeeds with no token (it reports cluster
        // state); `token lookup` requires an actual valid token and
        // is what confirms the user can `get` a secret.
        let token_out =
            match self.vault_command("token", &["lookup", "-format=json"]).output().await {
                Ok(o) => o,
                Err(e) => {
                    return BackendStatus::Error {
                        message: format!(
                            "vault backend '{}': failed to invoke 'vault token lookup': {e}",
                            self.instance_name
                        ),
                    };
                }
            };
        if !token_out.status.success() {
            let stderr = String::from_utf8_lossy(&token_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!("run: vault login  (or set VAULT_TOKEN) (stderr: {stderr})"),
            };
        }
        // The JSON is parsed for side-effect — validating shape is enough
        // to trust the token. Fields aren't surfaced in the one-line
        // identity (Phase 9's `doctor --extensive` will pick them up).
        if let Err(e) = serde_json::from_slice::<TokenLookup>(&token_out.stdout) {
            return BackendStatus::Error {
                message: format!(
                    "vault backend '{}': parsing 'vault token lookup' JSON: {e}",
                    self.instance_name
                ),
            };
        }
        let namespace_display = self.vault_namespace.as_deref().unwrap_or("(none)");
        BackendStatus::Ok {
            cli_version,
            identity: format!("addr={} namespace={namespace_display}", self.vault_address),
        }
    }

    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        Ok(self.list(test_uri).await?.len())
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let path = Self::vault_path(uri);
        let mut cmd = self.vault_command("kv", &["get", "-field=value", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "vault backend '{}': failed to invoke 'vault kv get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "vault backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `-field=value` output ends with exactly one '\n'. Strip
        // it but keep any other trailing whitespace (operators who
        // deliberately stored trailing spaces deserve them back).
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        // Secret value is piped via child stdin — NEVER on argv. The
        // `value=-` KV-pair tells `vault kv put` to read the value
        // from stdin. Same CV-1 discipline Phase 0.5 applied to
        // aws-ssm.
        let path = Self::vault_path(uri);
        let mut cmd = self.vault_command("kv", &["put", &path, "value=-"]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "vault backend '{}': failed to spawn 'vault kv put' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                // Linux produces EPIPE if the child exits before
                // reading stdin; trust the exit status instead (same
                // fix as aws-ssm Phase 3).
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "vault backend '{}': failed to write secret value to vault stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "vault backend '{}': 'vault kv put' exited abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        let path = Self::vault_path(uri);
        let mut cmd = self.vault_command("kv", &["delete", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "vault backend '{}': failed to invoke 'vault kv delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        let path = Self::vault_path(uri);
        let mut cmd = self.vault_command("kv", &["get", "-format=json", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "vault backend '{}': failed to invoke 'vault kv get -format=json' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }
        let parsed: KvResponse = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "vault backend '{}': 'vault kv get' response at '{}' is not the expected \
                 {{\"data\": ...}} shape",
                self.instance_name, uri.raw
            )
        })?;
        let map = match parsed.data {
            KvData::V2 { data } | KvData::V1(data) => data,
        };
        Ok(map.into_iter().collect())
    }
}

/// Factory for the Vault backend.
pub struct VaultFactory(&'static str);

impl VaultFactory {
    /// Construct the factory. Equivalent to `VaultFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("vault")
    }
}

impl Default for VaultFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for VaultFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let vault_address = required_string(config, "vault_address", instance_name)?;
        let vault_namespace = optional_string(config, "vault_namespace", instance_name)?;
        let vault_bin = optional_string(config, "vault_bin", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        Ok(Box::new(VaultBackend {
            backend_type: "vault",
            instance_name: instance_name.to_owned(),
            vault_address,
            vault_namespace,
            vault_bin,
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
            "vault instance '{instance_name}': missing required field '{field}' \
             (set {field} = \"...\" under [backends.{instance_name}])"
        )
    })?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        anyhow!(
            "vault instance '{instance_name}': field '{field}' must be a string, got {}",
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
                "vault instance '{instance_name}': field '{field}' must be a string, got {}",
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

    /// Thin wrapper over the shared `secretenv_testing` installer.
    fn install_mock_vault(dir: &TempDir, body: &str) -> std::path::PathBuf {
        secretenv_testing::install_mock(dir.path(), "vault", body)
    }

    fn backend(mock_path: &Path, namespace: Option<&str>) -> VaultBackend {
        VaultBackend {
            backend_type: "vault",
            instance_name: "vault-eng".to_owned(),
            vault_address: "https://vault.example.com".to_owned(),
            vault_namespace: namespace.map(ToOwned::to_owned),
            vault_bin: mock_path.to_str().unwrap().to_owned(),
        }
    }

    fn backend_with_nonexistent_vault() -> VaultBackend {
        VaultBackend {
            backend_type: "vault",
            instance_name: "vault-eng".to_owned(),
            vault_address: "https://vault.example.com".to_owned(),
            vault_namespace: None,
            vault_bin: "/definitely/not/a/real/path/to/vault-binary-12345".to_owned(),
        }
    }

    // ---- Factory tests ----

    #[test]
    fn factory_backend_type_is_vault() {
        assert_eq!(VaultFactory::new().backend_type(), "vault");
    }

    #[test]
    fn factory_errors_when_vault_address_missing() {
        let factory = VaultFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("vault-eng", &cfg) else {
            panic!("expected error when vault_address is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("vault_address"), "names missing field: {msg}");
        assert!(msg.contains("vault-eng"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_address_and_no_namespace() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        let b = factory.create("vault-eng", &cfg).unwrap();
        assert_eq!(b.backend_type(), "vault");
        assert_eq!(b.instance_name(), "vault-eng");
    }

    #[test]
    fn factory_accepts_address_and_namespace() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        cfg.insert("vault_namespace".to_owned(), toml::Value::String("engineering".to_owned()));
        let b = factory.create("vault-eng", &cfg).unwrap();
        assert_eq!(b.backend_type(), "vault");
    }

    #[test]
    fn factory_rejects_non_string_vault_address() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("vault_address".to_owned(), toml::Value::Integer(443));
        let Err(err) = factory.create("vault-eng", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    // ---- vault_path normalization ----

    #[test]
    fn vault_path_strips_leading_slash_triple_slash_form() {
        let uri = BackendUri::parse("vault-eng:///secret/myapp/db").unwrap();
        assert_eq!(VaultBackend::vault_path(&uri), "secret/myapp/db");
    }

    #[test]
    fn vault_path_preserves_no_leading_slash_double_slash_form() {
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        assert_eq!(VaultBackend::vault_path(&uri), "secret/myapp/db");
    }

    // ---- check Level 1 ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_vault();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "vault");
                // Loose check — survives future hint rewording but
                // fails if the tap-less `brew install vault` form
                // (broken post-BSL, see INSTALL_HINT comment) slips
                // back in.
                assert!(
                    install_hint.contains("hashicorp/tap/vault"),
                    "expected tap-form install hint, got: {install_hint}"
                );
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    // ---- check Level 2 ----

    #[tokio::test]
    async fn check_returns_ok_when_version_and_token_lookup_succeed() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "Vault v1.15.2 ('abc123')"
  exit 0
fi
if [ "$1" = "token" ] && [ "$2" = "lookup" ]; then
  cat <<'JSON'
{"data":{"display_name":"token-abc","policies":["default","engineering-read"],"ttl":3600}}
JSON
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("Vault v1.15.2"));
                assert!(identity.contains("addr=https://vault.example.com"));
                assert!(identity.contains("namespace=(none)"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_includes_namespace_in_identity_when_configured() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "Vault v1.15.2 ('abc123')"
  exit 0
fi
if [ "$1" = "token" ] && [ "$2" = "lookup" ]; then
  echo '{"data":{"display_name":"token-x"}}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, Some("engineering"));
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("namespace=engineering"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_not_authenticated_on_token_lookup_failure() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "--version" ]; then
  echo "Vault v1.15.2"
  exit 0
fi
if [ "$1" = "token" ] && [ "$2" = "lookup" ]; then
  echo "* permission denied" >&2
  exit 2
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("vault login"), "hint: {hint}");
                assert!(hint.contains("VAULT_TOKEN"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_trimmed_value() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo "supersekrit"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "supersekrit");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        // Vault prints "\n" when the value is empty; we strip the one
        // trailing '\n' → "".
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo ""
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/empty").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_preserves_internal_newlines() {
        // Multi-line secret body: we only strip a single trailing '\n'.
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  printf 'line1\nline2\n'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/ws").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_not_found_wraps_vault_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo "No value found at secret/myapp/missing" >&2
  exit 2
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("vault-eng"), "names instance: {msg}");
        assert!(msg.contains("secret/myapp/missing"), "names uri: {msg}");
        assert!(msg.contains("No value found"), "includes vault stderr: {msg}");
    }

    #[tokio::test]
    async fn get_permission_denied_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo "* permission denied" >&2
  exit 2
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/locked").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("permission denied"));
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "put" ]; then
  echo "Success! Data written to: secret/myapp/db"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // Mock records every argv element + stdin to a log file. We
        // assert the secret is in stdin AND absent from argv.
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
if [ "$1" = "kv" ] && [ "$2" = "put" ]; then
  echo "Success!"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_vault(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        let very_sensitive = "sk_live_TOP_SECRET_never_on_argv_555";
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
            "secret value should have arrived via stdin; stdin was:\n{stdin_section}"
        );
        assert!(
            argv_section.contains("arg=value=-"),
            "argv should name the stdin sentinel 'value=-':\n{argv_section}"
        );
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "put" ]; then
  echo "Error making API request. Code: 403" >&2
  exit 2
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        assert!(format!("{err:#}").contains("Error making API request"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "delete" ]; then
  echo "Success! Data deleted (if it existed) at: secret/myapp/gone"
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_kv_v2_json() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  cat <<'JSON'
{"data":{"data":{"stripe-key":"vault-eng://secret/prod/stripe","db-url":"vault-eng://secret/prod/db"},"metadata":{"version":3}}}
JSON
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("db-url".to_owned(), "vault-eng://secret/prod/db".to_owned()),
                ("stripe-key".to_owned(), "vault-eng://secret/prod/stripe".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_parses_kv_v1_json_fallback() {
        // KV v1 has a flat `data` map without the inner `data.data` wrap.
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  cat <<'JSON'
{"data":{"alpha":"vault-eng://secret/a","beta":"vault-eng://secret/b"}}
JSON
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://legacy/registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("alpha".to_owned(), "vault-eng://secret/a".to_owned()),
                ("beta".to_owned(), "vault-eng://secret/b".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_body_missing_data_field() {
        let dir = TempDir::new().unwrap();
        let mock = install_mock_vault(
            &dir,
            r#"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo '{"request_id":"abc"}'
  exit 0
fi
exit 1
"#,
        );
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/malformed").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("vault-eng"), "names instance: {msg}");
        assert!(msg.contains("\"data\""), "explains expected shape: {msg}");
    }

    // ---- Namespace flag omission / inclusion in argv ----

    #[tokio::test]
    async fn command_omits_namespace_env_when_not_configured() {
        // Record every VAULT_* env var. Backend is configured without a
        // namespace; the mock asserts `VAULT_NAMESPACE` never appears.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("env.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
env | grep "^VAULT_" | sort > "$LOG"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo "v"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_vault(&dir, &script);
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        b.get(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).expect("mock wrote log");
        assert!(
            !log.contains("VAULT_NAMESPACE"),
            "OSS vault would reject VAULT_NAMESPACE; env var must be absent:\n{log}"
        );
        // Sanity: VAULT_ADDR IS always set.
        assert!(log.contains("VAULT_ADDR="), "expected VAULT_ADDR in env:\n{log}");
    }

    #[tokio::test]
    async fn command_includes_namespace_env_when_configured() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("env.log");
        let log_path_str = log_path.to_string_lossy();
        let script = format!(
            r#"
LOG="{log_path_str}"
env | grep "^VAULT_" | sort > "$LOG"
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
  echo "v"
  exit 0
fi
exit 1
"#
        );
        let mock = install_mock_vault(&dir, &script);
        let b = backend(&mock, Some("engineering"));
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        b.get(&uri).await.unwrap();

        let log = std::fs::read_to_string(&log_path).expect("mock wrote log");
        assert!(
            log.contains("VAULT_NAMESPACE=engineering"),
            "expected VAULT_NAMESPACE=engineering in env:\n{log}"
        );
    }
}
