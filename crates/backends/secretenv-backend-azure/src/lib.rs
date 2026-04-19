//! Azure Key Vault backend for SecretEnv.
//!
//! Wraps the `az` CLI — **never** an Azure SDK. Every auth mode
//! `az` supports (interactive `az login`, service principal,
//! managed identity, federated credentials, Cloud Shell) works
//! transparently because the CLI resolves auth the way the user
//! already configured it.
//!
//! # URI shape
//!
//! `<instance>:///<secret-name>[#version=<id>]` — scheme is the
//! instance name (e.g. `azure-prod`); path is the Key Vault secret
//! name. The optional `#version=<id>` directive pins a specific
//! version ID; `<id>` is a 32-character lowercase hex string (Azure
//! generates these server-side) OR the literal `latest`. When absent
//! or `latest`, the `--version` flag is omitted and `az` defaults to
//! the newest enabled version.
//!
//! # Config fields
//!
//! - `azure_vault_url` (required) — fully-qualified Key Vault HTTPS
//!   URL. Validated at factory time against a regex covering all four
//!   sovereign clouds (Commercial, China, US Gov, Germany-legacy),
//!   rejecting path traversal + hyphen-edge vault names.
//! - `azure_tenant` (optional) — tenant ID or domain, passed via
//!   `--tenant`.
//! - `azure_subscription` (optional) — subscription ID, passed via
//!   `--subscription`.
//! - `az_bin` (test hook) — overrides the `az` binary path.
//!
//! # Safety
//!
//! Every CLI call goes through `Command::args([...])` with individual
//! `&str`s — never `sh -c`, never `format!` into a shell string. The
//! `set` path uses `--file /dev/stdin --encoding utf-8` — the secret
//! value is piped through child stdin, NEVER on argv. The
//! `--encoding utf-8` flag is REQUIRED when using `--file`; the
//! default `base64` would interpret the stdin bytes as base64-encoded
//! and corrupt the stored secret.
//!
//! See [[backends/azure]] in the kb for the full implementation spec.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use regex::Regex;
use secretenv_core::{
    optional_string, required_string, Backend, BackendFactory, BackendStatus, BackendUri,
};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "az";
const INSTALL_HINT: &str =
    "brew install azure-cli  OR  https://learn.microsoft.com/cli/azure/install-azure-cli";

/// Canonical vault-URL regex. Anchored; inner vault-name 3-24 chars
/// alphanumeric + hyphen with no hyphen-edge; covers all four
/// sovereign-cloud domains; lone trailing `/` accepted, anything
/// after it rejected (path-traversal block).
fn vault_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Statically-valid regex; `Regex::new` cannot fail here. If it
    // ever does, initialization aborts at first backend construction
    // — not an end-user-visible condition.
    //
    // Vault-name shape: 3-24 alphanumerics + hyphens, no hyphen-edge.
    // Structure: [first alphanumeric][middle 1-22 alphanumeric|hyphen]
    // [last alphanumeric] → total 3-24. Required middle+last (not
    // optional) so 2-char names are rejected. Matches Azure's own
    // naming rule.
    #[allow(clippy::expect_used)]
    RE.get_or_init(|| {
        Regex::new(
            r"^https://[a-zA-Z0-9][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]\.vault\.(azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)/?$",
        )
        .expect("vault URL regex is statically valid")
    })
}

/// Azure Key Vault version IDs: 32 lowercase hex chars. Opaque;
/// Azure generates these server-side.
fn version_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{32}$").expect("version ID regex is statically valid"))
}

/// Extract the short vault name from a validated vault URL.
/// `https://my-kv-prod.vault.azure.net/` → `my-kv-prod`.
fn vault_name_from_url(url: &str) -> &str {
    // Safe: the factory validates URL shape before constructing the
    // backend, so both slicing offsets are guaranteed present.
    let after_scheme = url.trim_start_matches("https://");
    after_scheme.split('.').next().unwrap_or(after_scheme)
}

/// A live instance of the Azure Key Vault backend.
pub struct AzureBackend {
    backend_type: &'static str,
    instance_name: String,
    #[allow(dead_code)] // Retained for diagnostics / future Level-3 probes.
    azure_vault_url: String,
    vault_name: String,
    azure_tenant: Option<String>,
    azure_subscription: Option<String>,
    az_bin: String,
}

#[derive(Deserialize)]
struct SecretShowResponse {
    /// Secret value. `None` when the secret is a certificate binding
    /// (`kid != null` in the response); surfaced as a distinct error.
    ///
    /// Deliberately NO `#[serde(default)]`: Azure's JSON response
    /// always includes `value` (as a string or `null`). Omission is
    /// unexpected — a missing key should surface as a deserialization
    /// error rather than silently become `None`.
    value: Option<String>,
    /// Key-identifier present on certificate-bound secrets. If set,
    /// we refuse to extract a scalar value — the caller asked for a
    /// secret but the storage slot is bound to a cert. Azure omits
    /// this field entirely for non-cert secrets, so `#[serde(default)]`
    /// is load-bearing.
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct AccountShowResponse {
    #[serde(default, rename = "tenantId")]
    tenant_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    user: Option<AccountUser>,
}

#[derive(Deserialize)]
struct AccountUser {
    #[serde(default)]
    name: String,
}

impl AzureBackend {
    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        format!(
            "azure backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build an `az <group_path...> <extra_args...> --vault-name <v>
    /// [--tenant <t>] [--subscription <s>] --output json` command.
    /// `group_path` is the leading subcommand tokens (e.g. `["keyvault",
    /// "secret", "show"]`); `extra_args` carries the per-op flags and
    /// positionals between the group and the scoping tail. Keeping
    /// the tail consistent across every op lets strict mocks lock
    /// argv shape.
    fn az_command(&self, group_path: &[&str], extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.az_bin);
        cmd.args(group_path);
        cmd.args(extra_args);
        cmd.args(["--vault-name", &self.vault_name]);
        if let Some(t) = &self.azure_tenant {
            cmd.args(["--tenant", t]);
        }
        if let Some(s) = &self.azure_subscription {
            cmd.args(["--subscription", s]);
        }
        cmd.args(["--output", "json"]);
        cmd
    }

    /// Strip exactly one leading `/` from `uri.path` to produce the
    /// post-strip secret name. Azure KV names cannot begin with `/`;
    /// triple-slash URIs (`azure-prod:///stripe-key`) yield
    /// `uri.path = "/stripe-key"` which we strip to `stripe-key`.
    fn secret_name(uri: &BackendUri) -> &str {
        uri.path.strip_prefix('/').unwrap_or(&uri.path)
    }

    /// Resolve the `#version=<id>` directive. Returns `Some(id)` when
    /// a specific version ID should be appended as `--version <id>`,
    /// or `None` when the fragment is absent OR the directive value
    /// is literally `latest` (both mean "omit `--version`").
    fn resolve_version(&self, uri: &BackendUri) -> Result<Option<String>> {
        let directives = uri.fragment_directives()?;
        let Some(mut directives) = directives else {
            return Ok(None);
        };
        if !directives.contains_key("version") {
            let mut unsupported: Vec<&str> = directives.keys().map(String::as_str).collect();
            unsupported.sort_unstable();
            bail!(
                "azure backend '{}': URI '{}' has unsupported fragment directive(s) [{}]; \
                 azure recognizes only 'version' (example: \
                 '#version=0123456789abcdef0123456789abcdef'). \
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
                "azure backend '{}': URI '{}' has unsupported directive(s) [{}] alongside \
                 'version'; azure recognizes only 'version'. \
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
            return Ok(None);
        }
        if !version_id_re().is_match(&value) {
            bail!(
                "azure backend '{}': URI '{}' has invalid version value '{}'; expected \
                 32-character lowercase hex (e.g. '0123456789abcdef0123456789abcdef') \
                 or 'latest'",
                self.instance_name,
                uri.raw,
                value
            );
        }
        Ok(Some(value))
    }

    /// Fetch a secret value with no fragment dispatch. Used by `list`
    /// (registry documents, which are always latest) and reused by
    /// `get` after fragment resolution.
    async fn get_raw(&self, uri: &BackendUri, version: Option<&str>) -> Result<String> {
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;
        let mut extra: Vec<&str> = vec!["--name", name];
        if let Some(v) = version {
            extra.extend(["--version", v]);
        }
        let mut cmd = self.az_command(&["keyvault", "secret", "show"], &extra);
        let output = cmd.output().await.with_context(|| {
            format!(
                "azure backend '{}': failed to invoke 'az keyvault secret show' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let parsed: SecretShowResponse =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "azure backend '{}': failed to parse JSON response from 'az keyvault \
                 secret show' for URI '{}'",
                    self.instance_name, uri.raw
                )
            })?;
        if let Some(kid) = parsed.kid {
            bail!(
                "azure backend '{}': URI '{}' resolves to a certificate-bound secret \
                 (kid='{}'); v0.3 supports text secrets only",
                self.instance_name,
                uri.raw,
                kid
            );
        }
        let value = parsed.value.ok_or_else(|| {
            anyhow!(
                "azure backend '{}': URI '{}' response missing 'value' field",
                self.instance_name,
                uri.raw
            )
        })?;
        Ok(value.strip_suffix('\n').unwrap_or(&value).to_owned())
    }
}

/// Validate that `name` matches Azure Key Vault's secret name charset
/// `[a-zA-Z0-9-]{1,127}`. Performed BEFORE any `az` invocation so
/// copy-paste mistakes fail locally instead of burning an Azure AD
/// token acquisition + subprocess.
fn validate_secret_name(instance_name: &str, uri: &BackendUri, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 127 {
        bail!(
            "azure backend '{instance_name}': URI '{}' has invalid secret name \
             (length {}); must be 1..=127 chars",
            uri.raw,
            name.len()
        );
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!(
            "azure backend '{instance_name}': URI '{}' has invalid secret name '{}'; \
             Azure Key Vault names allow only [a-zA-Z0-9-]",
            uri.raw,
            name
        );
    }
    Ok(())
}

#[async_trait]
impl Backend for AzureBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    #[allow(clippy::similar_names)]
    async fn check(&self) -> BackendStatus {
        // Level 1 (`az --version`) + Level 2 (`az account show`) run
        // concurrently via `tokio::join!`. The two probes are
        // independent; `doctor` latency ~halved per backend.
        let version_fut = Command::new(&self.az_bin).arg("--version").output();

        let mut account_cmd = Command::new(&self.az_bin);
        account_cmd.args(["account", "show", "--output", "json"]);
        if let Some(s) = &self.azure_subscription {
            account_cmd.args(["--subscription", s]);
        }
        let account_fut = account_cmd.output();

        let (version_res, account_res) = tokio::join!(version_fut, account_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "azure backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.az_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "azure backend '{}': 'az --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        // `az --version` output: first line "azure-cli  <x.y.z>\n..."
        // (variable whitespace). Extract the first token that looks
        // like a version after "azure-cli".
        let cli_version = {
            let stdout = String::from_utf8_lossy(&version_out.stdout);
            stdout
                .lines()
                .next()
                .and_then(|line| line.trim().strip_prefix("azure-cli"))
                .map_or_else(|| "unknown".to_owned(), |rest| format!("azure-cli {}", rest.trim()))
        };

        // --- Level 2 ---
        let account_out = match account_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "azure backend '{}': failed to invoke 'az account show': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !account_out.status.success() {
            let stderr = String::from_utf8_lossy(&account_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: az login  OR  az login --service-principal --tenant <t> \
                     --username <client-id> --password <secret> (stderr: {stderr})"
                ),
            };
        }
        let parsed: AccountShowResponse = match serde_json::from_slice(&account_out.stdout) {
            Ok(p) => p,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "azure backend '{}': parsing 'az account show' JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        let user = parsed.user.map_or_else(String::new, |u| u.name);

        BackendStatus::Ok {
            cli_version,
            identity: format!(
                "user={user} tenant={} subscription={} vault={}",
                parsed.tenant_id, parsed.name, self.vault_name
            ),
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        // Fragment + secret-name validation happen BEFORE any `az`
        // call (v0.2.6 pattern). Invalid URIs fail locally without
        // burning an Azure AD token, a network round-trip, or an
        // audit-log entry for a failed read.
        let version = self.resolve_version(uri)?;
        self.get_raw(uri, version.as_deref()).await
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        // A fragment (`#version=<id>`) on a `set` URI is nonsensical
        // — Azure assigns the version ID server-side; you can't ask
        // to write to a specific-numbered version. Reject before
        // shelling out.
        uri.reject_any_fragment("azure")?;
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;

        // Secret value is piped via child stdin — NEVER on argv. The
        // `--file /dev/stdin` + `--encoding utf-8` pair is the only
        // CV-1-compliant write path for `az keyvault secret set`.
        // `--encoding utf-8` is LOAD-BEARING: the default `base64`
        // would interpret stdin bytes as b64-encoded and corrupt the
        // stored secret.
        let mut cmd = self.az_command(
            &["keyvault", "secret", "set"],
            &["--name", name, "--file", "/dev/stdin", "--encoding", "utf-8"],
        );
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "azure backend '{}': failed to spawn 'az keyvault secret set' for \
                 URI '{}'",
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
                        "azure backend '{}': failed to write secret value to az stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "azure backend '{}': 'az keyvault secret set' exited abnormally for \
                 URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("azure")?;
        let name = Self::secret_name(uri);
        validate_secret_name(&self.instance_name, uri, name)?;
        // Azure Key Vault has soft-delete enabled by default —
        // `secret delete` marks the secret as deleted but preserves
        // it for the recovery window (90 days default). `purge` is
        // a separate permission most users don't have; we do NOT
        // chain it. This is asymmetric with aws-secrets
        // (--force-delete-without-recovery) and with gcp (full
        // delete) — platform reality, documented in docs/.
        let mut cmd = self.az_command(&["keyvault", "secret", "delete"], &["--name", name]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "azure backend '{}': failed to invoke 'az keyvault secret delete' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        // Registry documents are stored as a single Azure secret
        // whose value is a JSON alias→URI map — same shape as
        // aws-ssm / aws-secrets / vault / gcp.
        let body = self.get_raw(uri, None).await?;
        let map: HashMap<String, String> = serde_json::from_str(&body).with_context(|| {
            format!(
                "azure backend '{}': secret body at '{}' is not a JSON alias→URI map",
                self.instance_name, uri.raw
            )
        })?;
        Ok(map.into_iter().collect())
    }
}

/// Factory for the Azure Key Vault backend.
pub struct AzureFactory(&'static str);

impl AzureFactory {
    /// Construct the factory. Equivalent to `AzureFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("azure")
    }
}

impl Default for AzureFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for AzureFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let azure_vault_url = required_string(config, "azure_vault_url", "azure", instance_name)?;
        if !vault_url_re().is_match(&azure_vault_url) {
            bail!(
                "azure instance '{instance_name}': field 'azure_vault_url' value \
                 '{azure_vault_url}' is not a valid Azure Key Vault URL (expected \
                 '<https://<name>.vault.{{azure.net|azure.cn|usgovcloudapi.net|\
                 microsoftazure.de}}/>' — no path, no hyphen-edge name)"
            );
        }
        let vault_name = vault_name_from_url(&azure_vault_url).to_owned();
        let azure_tenant = optional_string(config, "azure_tenant", "azure", instance_name)?;
        let azure_subscription =
            optional_string(config, "azure_subscription", "azure", instance_name)?;
        let az_bin = optional_string(config, "az_bin", "azure", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        Ok(Box::new(AzureBackend {
            backend_type: "azure",
            instance_name: instance_name.to_owned(),
            azure_vault_url,
            vault_name,
            azure_tenant,
            azure_subscription,
            az_bin,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    const VAULT_URL: &str = "https://my-kv-prod.vault.azure.net/";
    const VAULT_NAME: &str = "my-kv-prod";
    const TENANT: &str = "contoso.onmicrosoft.com";
    const SUB: &str = "00000000-0000-0000-0000-000000000000";
    const VERSION_HEX: &str = "0123456789abcdef0123456789abcdef";

    fn backend(mock_path: &Path, tenant: Option<&str>, sub: Option<&str>) -> AzureBackend {
        AzureBackend {
            backend_type: "azure",
            instance_name: "azure-prod".to_owned(),
            azure_vault_url: VAULT_URL.to_owned(),
            vault_name: VAULT_NAME.to_owned(),
            azure_tenant: tenant.map(ToOwned::to_owned),
            azure_subscription: sub.map(ToOwned::to_owned),
            az_bin: mock_path.to_str().unwrap().to_owned(),
        }
    }

    fn backend_with_nonexistent_az() -> AzureBackend {
        AzureBackend {
            backend_type: "azure",
            instance_name: "azure-prod".to_owned(),
            azure_vault_url: VAULT_URL.to_owned(),
            vault_name: VAULT_NAME.to_owned(),
            azure_tenant: None,
            azure_subscription: None,
            az_bin: "/definitely/not/a/real/path/to/az-binary-XYZ".to_owned(),
        }
    }

    /// `keyvault secret show --name <n> --vault-name <v> --output json`.
    /// Shared scoping tail (`--vault-name ... --output json`) lives on
    /// every argv so strict mocks implicitly lock `--vault-name`
    /// presence — a regression dropping it diverges from the declared
    /// shape and produces exit 97.
    fn show_argv(name: &str) -> [&str; 9] {
        [
            "keyvault",
            "secret",
            "show",
            "--name",
            name,
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
    }

    fn set_argv(name: &str) -> [&str; 13] {
        [
            "keyvault",
            "secret",
            "set",
            "--name",
            name,
            "--file",
            "/dev/stdin",
            "--encoding",
            "utf-8",
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
    }

    fn delete_argv(name: &str) -> [&str; 9] {
        [
            "keyvault",
            "secret",
            "delete",
            "--name",
            name,
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const ACCOUNT_SHOW_ARGV: &[&str] = &["account", "show", "--output", "json"];

    const ACCOUNT_OK_JSON: &str = "{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Contoso Prod\",\"tenantId\":\"22222222-2222-2222-2222-222222222222\",\"user\":{\"name\":\"alice@contoso.com\",\"type\":\"user\"}}\n";

    fn check_mock_ok(_dir: &Path) -> StrictMock {
        StrictMock::new("az")
            .on(
                VERSION_ARGV,
                Response::success(
                    "azure-cli                         2.60.0\n\ncore                              2.60.0\n",
                ),
            )
            .on(ACCOUNT_SHOW_ARGV, Response::success(ACCOUNT_OK_JSON))
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_azure() {
        assert_eq!(AzureFactory::new().backend_type(), "azure");
    }

    #[test]
    fn factory_errors_when_vault_url_missing() {
        let factory = AzureFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("azure-prod", &cfg) else {
            panic!("expected error when azure_vault_url is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("azure_vault_url"), "names missing field: {msg}");
        assert!(msg.contains("azure-prod"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_canonical_url() {
        let factory = AzureFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("azure_vault_url".to_owned(), toml::Value::String(VAULT_URL.to_owned()));
        let b = factory.create("azure-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "azure");
        assert_eq!(b.instance_name(), "azure-prod");
    }

    #[test]
    fn factory_accepts_sovereign_cloud_urls() {
        // All four canonical sovereign-cloud domains must pass the regex.
        for url in [
            "https://my-kv.vault.azure.net/",
            "https://my-kv.vault.azure.cn/",
            "https://my-kv.vault.usgovcloudapi.net/",
            "https://my-kv.vault.microsoftazure.de/",
        ] {
            let factory = AzureFactory::new();
            let mut cfg: HashMap<String, toml::Value> = HashMap::new();
            cfg.insert("azure_vault_url".to_owned(), toml::Value::String(url.to_owned()));
            let r = factory.create("azure-prod", &cfg);
            assert!(
                r.is_ok(),
                "expected {url} to pass factory validation: {}",
                r.err().map_or_else(String::new, |e| format!("{e:#}"))
            );
        }
    }

    #[test]
    fn factory_rejects_one_char_vault_name() {
        // Azure vault naming rule is 3-24 chars. A 1-char leading
        // group matches the outer `[a-zA-Z0-9]` but then fails the
        // required middle+last inner pair. Lock the boundary.
        let factory = AzureFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "azure_vault_url".to_owned(),
            toml::Value::String("https://a.vault.azure.net/".to_owned()),
        );
        let Err(err) = factory.create("azure-prod", &cfg) else {
            panic!("expected rejection for 1-char vault name");
        };
        assert!(format!("{err:#}").contains("not a valid"));
    }

    #[test]
    fn factory_rejects_two_char_vault_name() {
        // 2-char also below the 3-char minimum.
        let factory = AzureFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "azure_vault_url".to_owned(),
            toml::Value::String("https://ab.vault.azure.net/".to_owned()),
        );
        let Err(err) = factory.create("azure-prod", &cfg) else {
            panic!("expected rejection for 2-char vault name");
        };
        assert!(format!("{err:#}").contains("not a valid"));
    }

    #[test]
    fn factory_accepts_three_char_vault_name() {
        // Minimum valid vault-name length.
        let factory = AzureFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "azure_vault_url".to_owned(),
            toml::Value::String("https://abc.vault.azure.net/".to_owned()),
        );
        factory.create("azure-prod", &cfg).expect("3-char vault name must be accepted");
    }

    #[test]
    fn factory_rejects_hyphen_edge_vault_names() {
        // Azure's own naming rules disallow leading/trailing hyphens.
        for bad in ["https://-foo.vault.azure.net/", "https://foo-.vault.azure.net/"] {
            let factory = AzureFactory::new();
            let mut cfg: HashMap<String, toml::Value> = HashMap::new();
            cfg.insert("azure_vault_url".to_owned(), toml::Value::String(bad.to_owned()));
            let Err(err) = factory.create("azure-prod", &cfg) else {
                panic!("expected rejection for {bad}");
            };
            assert!(format!("{err:#}").contains("not a valid"), "rejection for {bad}");
        }
    }

    #[test]
    fn factory_rejects_path_traversal_in_vault_url() {
        // Anchored regex must reject anything past the lone optional
        // trailing `/`. `url::Url::parse()` would accept this; regex
        // discipline is the gate.
        for bad in [
            "https://my-kv.vault.azure.net/evil/../etc",
            "https://my-kv.vault.azure.net/secrets/../x",
            "http://my-kv.vault.azure.net/", // must be https
            "https://my-kv.evil.azure.net/", // must be .vault.
        ] {
            let factory = AzureFactory::new();
            let mut cfg: HashMap<String, toml::Value> = HashMap::new();
            cfg.insert("azure_vault_url".to_owned(), toml::Value::String(bad.to_owned()));
            let Err(err) = factory.create("azure-prod", &cfg) else {
                panic!("expected rejection for {bad}");
            };
            assert!(format!("{err:#}").contains("not a valid"), "rejection for {bad}");
        }
    }

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_az();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "az");
                assert!(install_hint.contains("azure-cli"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level1_parses_multiline_version() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, .. } => {
                assert!(cli_version.contains("azure-cli"), "got: {cli_version}");
                assert!(cli_version.contains("2.60.0"), "parses version: {cli_version}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_auth_ok() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None, None);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("user=alice@contoso.com"), "identity: {identity}");
                assert!(identity.contains("tenant=22222222"), "identity: {identity}");
                assert!(identity.contains("subscription=Contoso Prod"), "identity: {identity}");
                assert!(identity.contains("vault=my-kv-prod"), "identity: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_not_authenticated() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(VERSION_ARGV, Response::success("azure-cli  2.60.0\n"))
            .on(
                ACCOUNT_SHOW_ARGV,
                Response::failure(1, "ERROR: Please run 'az login' to setup account.\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("az login"), "hint: {hint}");
                assert!(hint.contains("service-principal"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_value_from_json_response() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &show_argv("stripe-key"),
                Response::success("{\"id\":\"https://my-kv-prod.vault.azure.net/secrets/stripe-key/abc\",\"value\":\"sk_live_abc\",\"attributes\":{\"enabled\":true}}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_at_specific_version() {
        // `--version <id>` lives inside `extra_args` (between the
        // group tokens and the scoping tail), so it lands BEFORE
        // `--vault-name` + `--output json`. Mirror the real argv
        // layout here.
        let dir = TempDir::new().unwrap();
        let argv: Vec<&str> = [
            "keyvault",
            "secret",
            "show",
            "--name",
            "stripe-key",
            "--version",
            VERSION_HEX,
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
        .to_vec();
        let mock = StrictMock::new("az")
            .on(&argv, Response::success("{\"value\":\"older-value\",\"attributes\":{}}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri =
            BackendUri::parse(&format!("azure-prod:///stripe-key#version={VERSION_HEX}")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "older-value");
    }

    #[tokio::test]
    async fn get_latest_literal_omits_version_flag() {
        // `#version=latest` must normalize to NO --version flag. If
        // the backend emitted `--version latest`, this declared argv
        // (without --version) would NOT match → exit 97.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&show_argv("stripe-key"), Response::success("{\"value\":\"v\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key#version=latest").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "v");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&show_argv("multi-line"), Response::success("{\"value\":\"line1\\nline2\\n\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///multi-line").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_empty_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&show_argv("empty"), Response::success("{\"value\":\"\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///empty").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_secret_not_found_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &show_argv("missing"),
                Response::failure(
                    1,
                    "ERROR: (SecretNotFound) A secret with (name/id) missing was not found in this key vault\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("azure-prod"), "names instance: {msg}");
        assert!(msg.contains("SecretNotFound"), "passes through: {msg}");
    }

    #[tokio::test]
    async fn get_forbidden_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &show_argv("locked"),
                Response::failure(
                    1,
                    "ERROR: (Forbidden) The user, group or application does not have secrets get permission\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///locked").unwrap();
        assert!(format!("{:#}", b.get(&uri).await.unwrap_err()).contains("Forbidden"));
    }

    #[tokio::test]
    async fn get_rejects_shorthand_fragment() {
        // Empty-rule mock: any `az` invocation produces exit 97. The
        // error MUST come from the fragment parser BEFORE any `az` call.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key#password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("shorthand"), "error names problem: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error from fragment parser, not mock: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_unsupported_directive() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key#json-key=password").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"), "names problem: {msg}");
        assert!(msg.contains("json-key"), "lists offender: {msg}");
        assert!(msg.contains("version"), "names supported directive: {msg}");
        assert!(msg.contains("fragment-vocabulary"), "error links to canonical doc: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "error from backend, not mock: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_invalid_version_format() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key#version=not-hex").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid version value"), "names problem: {msg}");
        assert!(msg.contains("'not-hex'"), "quotes offender: {msg}");
        assert!(msg.contains("32-character"), "names expected shape: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "error from backend, not mock: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_invalid_secret_name() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az").install(dir.path());
        let b = backend(&mock, None, None);
        // Underscore is not in [a-zA-Z0-9-].
        let uri = BackendUri::parse("azure-prod:///bad_name").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid secret name"), "names problem: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "error from backend, not mock: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_certificate_bound_secret() {
        // `kid` field present → secret is bound to a cert; v0.3 only
        // supports plain text secrets.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &show_argv("cert-bound"),
                Response::success(
                    "{\"value\":null,\"kid\":\"https://my-kv-prod.vault.azure.net/keys/x/abc\"}\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///cert-bound").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("certificate-bound"), "names problem: {msg}");
        assert!(msg.contains("kid="), "shows kid value: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_with_encoding_utf8() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &set_argv("rotate-me"),
                Response::success_with_stdin(
                    "{\"value\":\"new-val\",\"id\":\"https://...\"}\n",
                    vec!["new-val".to_owned()],
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///rotate-me").unwrap();
        b.set(&uri, "new-val").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 discipline: argv carries `--file /dev/stdin` sentinel
        // (NOT the secret), stdin-fragment check requires the secret
        // in stdin. Strict match on both implies "secret on stdin,
        // NOT on argv".
        let very_sensitive = "sk_live_TOP_SECRET_azure_never_argv_XYZ";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &set_argv("stripe-key"),
                Response::success_with_stdin("{}\n", vec![very_sensitive.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///stripe-key").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_rejects_fragment_on_uri() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az").install(dir.path());
        let b = backend(&mock, None, None);
        let uri =
            BackendUri::parse(&format!("azure-prod:///stripe-key#version={VERSION_HEX}")).unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("azure"), "names backend: {msg}");
        assert!(msg.contains("version"), "names offending directive: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error from fragment-reject, not mock: {msg}"
        );
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_succeeds() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &delete_argv("retired"),
                Response::success("{\"deletedDate\":\"...\",\"recoveryId\":\"...\"}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///retired").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_surfaces_secret_not_found() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&delete_argv("retired"), Response::failure(1, "ERROR: (SecretNotFound) ...\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///retired").unwrap();
        assert!(format!("{:#}", b.delete(&uri).await.unwrap_err()).contains("SecretNotFound"));
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_json_registry_document() {
        let dir = TempDir::new().unwrap();
        let body =
            "{\"alpha\":\"azure-prod:///alpha-secret\",\"beta\":\"azure-prod:///beta-secret\"}";
        let response_body = format!("{{\"value\":{}}}\n", serde_json::to_string(body).unwrap());
        let mock = StrictMock::new("az")
            .on(&show_argv("registry-doc"), Response::success(&response_body))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///registry-doc").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("alpha".to_owned(), "azure-prod:///alpha-secret".to_owned()),
                ("beta".to_owned(), "azure-prod:///beta-secret".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_body_is_not_json_map() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&show_argv("bad-registry"), Response::success("{\"value\":\"not-json\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///bad-registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("azure-prod"), "names instance: {msg}");
        assert!(msg.contains("alias→URI map"), "specific error: {msg}");
    }

    // ---- tenant / subscription argv variants ----

    #[tokio::test]
    async fn command_omits_tenant_when_not_configured() {
        // Declared argv has NO `--tenant` flag. A regression emitting
        // it would diverge from this shape.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&show_argv("x"), Response::success("{\"value\":\"v\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_tenant_when_configured() {
        let dir = TempDir::new().unwrap();
        // `az_command` emits `--tenant T` AFTER `--vault-name V` and
        // BEFORE `--output json`. Mirror that ordering in the declared
        // argv.
        let argv: Vec<&str> = [
            "keyvault",
            "secret",
            "show",
            "--name",
            "x",
            "--vault-name",
            VAULT_NAME,
            "--tenant",
            TENANT,
            "--output",
            "json",
        ]
        .to_vec();
        let mock = StrictMock::new("az")
            .on(&argv, Response::success("{\"value\":\"v\"}\n"))
            .install(dir.path());
        let b = backend(&mock, Some(TENANT), None);
        let uri = BackendUri::parse("azure-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_subscription_when_configured() {
        let dir = TempDir::new().unwrap();
        let argv: Vec<&str> = [
            "keyvault",
            "secret",
            "show",
            "--name",
            "x",
            "--vault-name",
            VAULT_NAME,
            "--subscription",
            SUB,
            "--output",
            "json",
        ]
        .to_vec();
        let mock = StrictMock::new("az")
            .on(&argv, Response::success("{\"value\":\"v\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, Some(SUB));
        let uri = BackendUri::parse("azure-prod:///x").unwrap();
        b.get(&uri).await.unwrap();
    }

    // ---- drift-catch regression locks ----

    #[tokio::test]
    async fn get_drift_catch_rejects_missing_vault_name() {
        // Declared argv INTENTIONALLY omits `--vault-name <v>`. The
        // real backend emits it, so the declared shape won't match
        // and exit 97 surfaces as a backend error.
        let buggy_argv: [&str; 6] = ["keyvault", "secret", "show", "--name", "x", "--output"];
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(&buggy_argv, Response::success("{\"value\":\"never-matches-post-fix\"}\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///x").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        // Must be mock-level divergence — `unwrap_err` alone catches
        // the regression; this content check additionally confirms the
        // failure came from strict argv-mismatch, not from some other
        // azure-named error that could mask a different regression.
        assert!(msg.contains("strict-mock-no-match"), "must be mock-level divergence, got: {msg}");
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        let secret = "sk_live_CV1_azure_regression_lock";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("az")
            .on(
                &set_argv("rotate-me"),
                Response::success_with_stdin("{}\n", vec![secret.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///rotate-me").unwrap();
        b.set(&uri, secret).await.unwrap();
    }

    #[tokio::test]
    async fn check_extensive_counts_registry_entries() {
        // Locks the Backend-trait-default `check_extensive` behavior
        // (list().len()) for azure. A regression that overrode the
        // method with a broken impl would be caught here.
        let dir = TempDir::new().unwrap();
        let body = "{\"alpha\":\"azure-prod:///a\",\"beta\":\"azure-prod:///b\",\"gamma\":\"azure-prod:///c\"}";
        let response_body = format!("{{\"value\":{}}}\n", serde_json::to_string(body).unwrap());
        let mock = StrictMock::new("az")
            .on(&show_argv("reg-doc"), Response::success(&response_body))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///reg-doc").unwrap();
        assert_eq!(b.check_extensive(&uri).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_value_flag_on_argv() {
        // POSITIVE lock: declared argv carries the BUGGY `--value
        // <secret>` form. Post-fix code emits `--file /dev/stdin +
        // --encoding utf-8` instead — diverges, exit 97. Guards
        // against a future refactor "optimizing" small values onto
        // argv (which would break CV-1).
        let secret = "sk_live_would_leak_via_value_flag";
        let dir = TempDir::new().unwrap();
        let buggy_argv: Vec<&str> = [
            "keyvault",
            "secret",
            "set",
            "--name",
            "rotate-me",
            "--value",
            secret,
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
        .to_vec();
        let mock =
            StrictMock::new("az").on(&buggy_argv, Response::success("{}\n")).install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///rotate-me").unwrap();
        // Post-fix backend emits the CV-1 argv, NOT the buggy one, so
        // this must FAIL (strict no-match exit 97 surfaces as error).
        let err = b.set(&uri, secret).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("strict-mock-no-match"),
            "must be mock-level divergence — regression emitting --value would match buggy rule: {msg}"
        );
    }

    #[tokio::test]
    async fn set_drift_catch_rejects_missing_encoding_utf8() {
        // POSITIVE lock: declared argv omits `--encoding utf-8`. The
        // real backend always emits it (because the default `base64`
        // would corrupt the stored secret). A regression dropping the
        // flag would silently poison every subsequent set; this test
        // prevents that.
        let dir = TempDir::new().unwrap();
        let buggy_argv: Vec<&str> = [
            "keyvault",
            "secret",
            "set",
            "--name",
            "rotate-me",
            "--file",
            "/dev/stdin",
            "--vault-name",
            VAULT_NAME,
            "--output",
            "json",
        ]
        .to_vec();
        let mock = StrictMock::new("az")
            .on(&buggy_argv, Response::success_with_stdin("{}\n", vec!["v".to_owned()]))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("azure-prod:///rotate-me").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("strict-mock-no-match"),
            "must be mock-level divergence — regression dropping --encoding utf-8 would match buggy rule: {msg}"
        );
    }
}
