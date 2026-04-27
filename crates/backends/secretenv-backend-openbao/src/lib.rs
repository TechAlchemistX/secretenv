// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `OpenBao` backend for SecretEnv.
//!
//! Wraps the `bao` CLI — never an HTTP SDK. `OpenBao` is the Linux
//! Foundation MPL-2.0 fork of HashiCorp Vault that diverged after the
//! 2023 BSL relicense; the wire protocol, auth methods, and KV
//! semantics are unchanged from Vault, so this backend is a near-clone
//! of [`secretenv_backend_vault`] with three concrete differences:
//!
//! 1. Binary name: `bao` instead of `vault`.
//! 2. Env-var prefix: `BAO_ADDR` / `BAO_NAMESPACE` (the CLI also reads
//!    `VAULT_*` for transition compat, but this backend sets the
//!    canonical `BAO_*` form per child invocation).
//! 3. Install path: `brew install openbao` (no tap dance — `OpenBao` is
//!    in homebrew-core, unlike post-BSL Vault).
//!
//! # URI shape
//!
//! `<instance>://<mount>/<path-within-mount>[#json-key=<field>]` —
//! identical to Vault. The hash fragment is optional and selects a
//! top-level field of a JSON-encoded `value` (see `get` below).
//!
//! # Storage model
//!
//! `OpenBao` secrets in this backend are written and read through the
//! single `value` field of a KV v2 entry (`bao kv put <path> value=-`
//! / `bao kv get -field=value <path>`). Multi-field secrets are not
//! produced by this backend; if the operator wrote a multi-field
//! secret out-of-band, only `value` is read.
//!
//! Registry documents are stored as a JSON alias→URI map serialized
//! to a string in the `value` field (matching `aws-secrets` and
//! `aws-ssm`). [`OpenBaoBackend::list`] fetches `value` and parses
//! it as JSON.
//!
//! # `#json-key` fragment
//!
//! When `#json-key=<field>` is present in the URI fragment, [`get`]
//! parses the `value` field as a JSON object and returns the named
//! top-level scalar field. This is the canonical multi-field-in-one-
//! secret pattern carried over from `aws-secrets`. Other operations
//! (`set`, `delete`, `list`, `history`) reject any fragment.
//!
//! # `bao_unsafe_set` defense-in-depth flag
//!
//! [`set`] always passes the secret value through child stdin via the
//! `value=-` form — the value never appears on argv. The
//! `bao_unsafe_set` config field is reserved as a defense-in-depth
//! opt-in for any future code path that would route the secret
//! through argv (analogous to `op_unsafe_set` for the 1Password
//! backend). v0.10 has no such path; the flag defaults to `false` and
//! is effectively unused at runtime, but a regression that introduces
//! an argv-set branch must consult it.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_bool, optional_duration_secs, optional_string, required_string, Backend,
    BackendFactory, BackendStatus, BackendUri, DEFAULT_GET_TIMEOUT,
};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "bao";
// OpenBao is in homebrew-core (no tap dance, no BSL gymnastics) — the
// bare formula works and is the canonical macOS install. Linux/Windows
// + manual binaries live behind the docs URL. Note this is the explicit
// contrast with Vault's `brew tap hashicorp/tap && brew install
// hashicorp/tap/vault` post-BSL form.
const INSTALL_HINT: &str = "brew install openbao  OR  https://openbao.org/docs/install/";

/// A live instance of the `OpenBao` backend.
pub struct OpenBaoBackend {
    backend_type: &'static str,
    instance_name: String,
    bao_address: String,
    bao_namespace: Option<String>,
    /// Path or name of the `bao` binary. Defaults to `"bao"` (PATH
    /// lookup); tests override to point at a mock script.
    bao_bin: String,
    /// Defense-in-depth opt-in — currently unused at runtime because
    /// `set()` always uses the `value=-` stdin form. Reserved for a
    /// future regression check (see crate-level docs). Read by
    /// `bao_unsafe_set()` accessor under `#[cfg(test)]` so the
    /// default-off invariant is machine-checked.
    #[cfg_attr(not(test), allow(dead_code))]
    bao_unsafe_set: bool,
    /// Per-instance deadline for fetch-class operations.
    timeout: Duration,
}

/// Level 2 identity response from `bao token lookup -format=json`.
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

/// `bao kv get -format=json` envelope. Used by [`OpenBaoBackend::list`]
/// to extract the `value` field carrying the JSON-encoded alias map.
#[derive(Deserialize)]
struct KvJsonResponse {
    data: KvJsonData,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KvJsonData {
    /// KV v2 envelope: an inner `data` object (plus metadata we ignore).
    V2 { data: KvJsonInner },
    /// KV v1: the inner map directly.
    V1(KvJsonInner),
}

#[derive(Deserialize)]
struct KvJsonInner {
    /// The single canonical field this backend writes to. Optional so
    /// a pre-existing multi-field secret without `value` surfaces as a
    /// readable error rather than a deserialization panic.
    #[serde(default)]
    value: Option<String>,
}

impl OpenBaoBackend {
    /// Strip a single leading `/` from `uri.path` to produce the path
    /// passed to `bao kv`. Mirrors the Vault backend's
    /// path-splitting convention.
    fn bao_path(uri: &BackendUri) -> String {
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
            "openbao backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `bao <subcommand> <extra_args...>` command. Address +
    /// namespace are routed via `BAO_ADDR` / `BAO_NAMESPACE` env vars
    /// (set on the child only, parent process untouched). The argv
    /// form `-address <url>` works against `bao status` but breaks
    /// against subcommands that take a positional path when the flag
    /// arrives after positional args (same trap caught in the Vault
    /// backend); env routing is the safe canonical form.
    ///
    /// The CLI also reads `VAULT_*` as a transition fallback per
    /// `OpenBao` maintainer policy, but this wrapper sets the canonical
    /// `BAO_*` names.
    fn bao_command(&self, subcommand: &str, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bao_bin);
        cmd.arg(subcommand);
        cmd.args(extra_args);
        cmd.env("BAO_ADDR", &self.bao_address);
        if let Some(ns) = &self.bao_namespace {
            cmd.env("BAO_NAMESPACE", ns);
        }
        cmd
    }

    /// Validate the URI's fragment for `get` and return the requested
    /// JSON key, if any. `openbao` recognizes only the `json-key`
    /// directive (same vocabulary as `aws-secrets`).
    fn parse_json_key_fragment(&self, uri: &BackendUri) -> Result<Option<String>> {
        let Some(mut directives) = uri.fragment_directives()? else {
            return Ok(None);
        };
        if !directives.contains_key("json-key") {
            let mut unsupported: Vec<&str> = directives.keys().map(String::as_str).collect();
            unsupported.sort_unstable();
            bail!(
                "openbao backend '{}': URI '{}' has unsupported fragment directive(s) [{}]; \
                 openbao recognizes only 'json-key' (example: '#json-key=password')",
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
                "openbao backend '{}': URI '{}' has unsupported directive(s) [{}] alongside \
                 'json-key'; openbao recognizes only 'json-key'",
                self.instance_name,
                uri.raw,
                extra.join(", ")
            );
        }
        let Some(key) = directives.shift_remove("json-key") else {
            unreachable!("json-key presence was checked above")
        };
        Ok(Some(key))
    }

    /// Invoke `bao kv get -field=value <path>` and return the trimmed
    /// stdout. Used by both the user-facing `get` (without fragment)
    /// and as the raw fetch underlying fragment extraction + `list`.
    async fn get_raw_value(&self, uri: &BackendUri) -> Result<String> {
        let path = Self::bao_path(uri);
        let mut cmd = self.bao_command("kv", &["get", "-field=value", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "openbao backend '{}': failed to invoke 'bao kv get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "openbao backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `-field=value` output ends with exactly one '\n'; strip it
        // but keep any other trailing whitespace.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }
}

#[async_trait]
impl Backend for OpenBaoBackend {
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
        let version_fut = Command::new(&self.bao_bin).arg("--version").output();
        let token_fut = self.bao_command("token", &["lookup", "-format=json"]).output();
        let (version_res, token_res) = tokio::join!(version_fut, token_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "openbao backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.bao_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "openbao backend '{}': 'bao --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let cli_version = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();

        // --- Level 2: `bao token lookup -format=json` ---
        let token_out = match token_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "openbao backend '{}': failed to invoke 'bao token lookup': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !token_out.status.success() {
            let stderr = String::from_utf8_lossy(&token_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: bao login  (or set BAO_TOKEN, or place a token in ~/.vault-token) \
                     (stderr: {stderr})"
                ),
            };
        }
        if let Err(e) = serde_json::from_slice::<TokenLookup>(&token_out.stdout) {
            return BackendStatus::Error {
                message: format!(
                    "openbao backend '{}': parsing 'bao token lookup' JSON: {e}",
                    self.instance_name
                ),
            };
        }
        let namespace_display = self.bao_namespace.as_deref().unwrap_or("(none)");
        BackendStatus::Ok {
            cli_version,
            identity: format!("addr={} namespace={namespace_display}", self.bao_address),
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        // Fragment validation BEFORE any network call — a bad fragment
        // is a local grammar error and shelling out to OpenBao would
        // waste latency + leak access patterns.
        let json_key = self.parse_json_key_fragment(uri)?;
        let raw = self.get_raw_value(uri).await?;
        match json_key {
            None => Ok(raw),
            Some(key) => extract_json_field(&self.instance_name, uri, &raw, &key),
        }
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("openbao")?;
        // CV-1 discipline: the `value=-` token tells `bao kv put` to
        // read the value from stdin. The secret is piped via child
        // stdin and never appears on argv. Future regressions that
        // route the value through argv must consult `bao_unsafe_set`
        // (see crate docs).
        let path = Self::bao_path(uri);
        let mut cmd = self.bao_command("kv", &["put", &path, "value=-"]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "openbao backend '{}': failed to spawn 'bao kv put' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                // Linux EPIPE if the child exits before reading stdin —
                // trust the exit status (same fix as aws-ssm/vault).
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "openbao backend '{}': failed to write secret value to bao stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "openbao backend '{}': 'bao kv put' exited abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("openbao")?;
        let path = Self::bao_path(uri);
        let mut cmd = self.bao_command("kv", &["delete", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "openbao backend '{}': failed to invoke 'bao kv delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("openbao")?;
        let path = Self::bao_path(uri);
        let mut cmd = self.bao_command("kv", &["get", "-format=json", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "openbao backend '{}': failed to invoke 'bao kv get -format=json' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }
        let parsed: KvJsonResponse = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "openbao backend '{}': 'bao kv get' response at '{}' is not the expected \
                 {{\"data\": ...}} shape",
                self.instance_name, uri.raw
            )
        })?;
        let inner = match parsed.data {
            KvJsonData::V2 { data } | KvJsonData::V1(data) => data,
        };
        let value = inner.value.ok_or_else(|| {
            anyhow!(
                "openbao backend '{}': registry document at '{}' has no 'value' field — \
                 openbao registries store the alias map as a JSON string in the canonical \
                 'value' KV field",
                self.instance_name,
                uri.raw
            )
        })?;
        let map: HashMap<String, String> = serde_json::from_str(&value).with_context(|| {
            format!(
                "openbao backend '{}': registry value at '{}' is not a JSON alias→URI map",
                self.instance_name, uri.raw
            )
        })?;
        Ok(map.into_iter().collect())
    }

    // `history` falls back to the trait default ("unsupported"). KV v2
    // metadata is reachable via `bao kv metadata get` but exposing it
    // cleanly (KV v1 vs v2 mount detection, soft-delete + destroy
    // markers) is v0.10.x carry-forward, not the launch cycle.
}

/// Parse `raw` as a JSON object and extract the top-level `key` field
/// as a string. Mirrors `secretenv-backend-aws-secrets`'s extractor.
fn extract_json_field(
    instance_name: &str,
    uri: &BackendUri,
    raw: &str,
    key: &str,
) -> Result<String> {
    let mut map: HashMap<String, serde_json::Value> =
        serde_json::from_str(raw).with_context(|| {
            format!(
                "openbao backend '{instance_name}': URI '{}' selects JSON key '{key}' \
             but secret value at '{}' is not a JSON object",
                uri.raw, uri.path
            )
        })?;
    if !map.contains_key(key) {
        let mut fields: Vec<&str> = map.keys().map(String::as_str).collect();
        fields.sort_unstable();
        bail!(
            "openbao backend '{instance_name}': URI '{}' field '{key}' not found; \
             secret at '{}' has fields: [{}]",
            uri.raw,
            uri.path,
            fields.join(", ")
        );
    }
    // `remove` so the String arm can move rather than clone (rust-audit MEDIUM).
    let Some(value) = map.remove(key) else { unreachable!("presence checked above") };
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok("null".to_owned()),
        ref v @ (serde_json::Value::Array(_) | serde_json::Value::Object(_)) => bail!(
            "openbao backend '{instance_name}': URI '{}' field '{key}' is a JSON {} — only \
             scalar fields (string/number/boolean/null) can be extracted",
            uri.raw,
            if v.is_array() { "array" } else { "object" }
        ),
    }
}

/// Factory for the `OpenBao` backend.
pub struct OpenBaoFactory(&'static str);

impl OpenBaoFactory {
    /// Construct the factory. Equivalent to `OpenBaoFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("openbao")
    }
}

impl Default for OpenBaoFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenBaoFactory {
    /// Concrete-typed factory path. The trait `create()` boxes the
    /// result; tests use this directly so they can inspect private
    /// fields like `bao_unsafe_set` without downcast gymnastics.
    fn create_concrete(
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<OpenBaoBackend> {
        let bao_address = required_string(config, "bao_address", "openbao", instance_name)?;
        let bao_namespace = optional_string(config, "bao_namespace", "openbao", instance_name)?;
        let bao_bin = optional_string(config, "bao_bin", "openbao", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let bao_unsafe_set =
            optional_bool(config, "bao_unsafe_set", "openbao", instance_name)?.unwrap_or(false);
        let timeout = optional_duration_secs(config, "timeout_secs", "openbao", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(OpenBaoBackend {
            backend_type: "openbao",
            instance_name: instance_name.to_owned(),
            bao_address,
            bao_namespace,
            bao_bin,
            bao_unsafe_set,
            timeout,
        })
    }
}

impl BackendFactory for OpenBaoFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        Ok(Box::new(Self::create_concrete(instance_name, config)?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    const BAO_ADDR: &str = "http://127.0.0.1:8300";
    const BAO_NS: &str = "team-engineering";

    fn backend(mock_path: &Path, namespace: Option<&str>) -> OpenBaoBackend {
        OpenBaoBackend {
            backend_type: "openbao",
            instance_name: "openbao-dev".to_owned(),
            bao_address: BAO_ADDR.to_owned(),
            bao_namespace: namespace.map(ToOwned::to_owned),
            bao_bin: mock_path.to_str().unwrap().to_owned(),
            bao_unsafe_set: false,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_bao() -> OpenBaoBackend {
        OpenBaoBackend {
            backend_type: "openbao",
            instance_name: "openbao-dev".to_owned(),
            bao_address: BAO_ADDR.to_owned(),
            bao_namespace: None,
            bao_bin: "/definitely/not/a/real/path/to/bao-binary-12345".to_owned(),
            bao_unsafe_set: false,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn ok_no_ns(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var("BAO_ADDR", BAO_ADDR)
            .with_env_absent("BAO_NAMESPACE")
    }

    fn ok_with_ns(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var("BAO_ADDR", BAO_ADDR)
            .with_env_var("BAO_NAMESPACE", BAO_NS)
    }

    fn fail_no_ns(exit_code: i32, stderr: &str) -> Response {
        Response::failure(exit_code, stderr)
            .with_env_var("BAO_ADDR", BAO_ADDR)
            .with_env_absent("BAO_NAMESPACE")
    }

    // ---- factory ----

    #[test]
    fn factory_backend_type_is_openbao() {
        assert_eq!(OpenBaoFactory::new().backend_type(), "openbao");
    }

    #[test]
    fn factory_errors_when_bao_address_missing() {
        let factory = OpenBaoFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("openbao-dev", &cfg) else {
            panic!("expected error when bao_address is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("bao_address"), "names missing field: {msg}");
        assert!(msg.contains("openbao-dev"), "names instance: {msg}");
    }

    #[test]
    fn factory_accepts_address_and_no_namespace() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        let b = factory.create("openbao-dev", &cfg).unwrap();
        assert_eq!(b.backend_type(), "openbao");
        assert_eq!(b.instance_name(), "openbao-dev");
    }

    #[test]
    fn factory_accepts_address_and_namespace() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("bao_namespace".to_owned(), toml::Value::String("team-engineering".to_owned()));
        let b = factory.create("openbao-dev", &cfg).unwrap();
        assert_eq!(b.backend_type(), "openbao");
    }

    #[test]
    fn factory_rejects_non_string_bao_address() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("bao_address".to_owned(), toml::Value::Integer(8300));
        let Err(err) = factory.create("openbao-dev", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    #[test]
    fn factory_rejects_non_string_bao_namespace() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("bao_namespace".to_owned(), toml::Value::Boolean(true));
        let Err(err) = factory.create("openbao-dev", &cfg) else {
            panic!("expected type error for non-string bao_namespace");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("bao_namespace"), "names the field: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_bao_bin() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("bao_bin".to_owned(), toml::Value::Integer(0));
        let Err(err) = factory.create("openbao-dev", &cfg) else {
            panic!("expected type error for non-string bao_bin");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("bao_bin"), "names the field: {msg}");
    }

    #[test]
    fn factory_rejects_non_bool_bao_unsafe_set() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("bao_unsafe_set".to_owned(), toml::Value::String("yes".to_owned()));
        let Err(err) = factory.create("openbao-dev", &cfg) else {
            panic!("expected error for non-bool bao_unsafe_set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("bao_unsafe_set"), "names the field: {msg}");
    }

    #[test]
    fn factory_bao_unsafe_set_defaults_false() {
        // Defense-in-depth: the safe stdin path is always used in
        // v0.10. This test pins the default-off invariant via
        // `create_concrete` (the test-accessible factory path) so a
        // future regression that wires `bao_unsafe_set` into a
        // runtime branch starts from a closed door.
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        let b = OpenBaoFactory::create_concrete("openbao-dev", &cfg).unwrap();
        assert!(!b.bao_unsafe_set, "default must be false (defense-in-depth)");
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
    }

    #[test]
    fn factory_bao_unsafe_set_accepts_true() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("bao_unsafe_set".to_owned(), toml::Value::Boolean(true));
        let b = OpenBaoFactory::create_concrete("openbao-dev", &cfg).unwrap();
        assert!(b.bao_unsafe_set, "explicit true must round-trip");
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = OpenBaoFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bao_address".to_owned(),
            toml::Value::String("http://127.0.0.1:8300".to_owned()),
        );
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(11));
        let b = factory.create("openbao-dev", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(11));
    }

    // ---- bao_path ----

    #[test]
    fn bao_path_strips_leading_slash_triple_slash_form() {
        let uri = BackendUri::parse("openbao-dev:///secret/myapp/db").unwrap();
        assert_eq!(OpenBaoBackend::bao_path(&uri), "secret/myapp/db");
    }

    #[test]
    fn bao_path_preserves_no_leading_slash_double_slash_form() {
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db").unwrap();
        assert_eq!(OpenBaoBackend::bao_path(&uri), "secret/myapp/db");
    }

    // ---- check Level 1 ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_bao();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "bao");
                // OpenBao is in homebrew-core (no tap). The hint must
                // NOT contain "tap" — that would mean we accidentally
                // copied Vault's post-BSL hint form.
                assert!(
                    install_hint.contains("brew install openbao"),
                    "expected tap-less brew install hint, got: {install_hint}"
                );
                assert!(
                    !install_hint.contains("hashicorp/tap"),
                    "must not use Vault's tap form: {install_hint}"
                );
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    // ---- check Level 2 ----

    #[tokio::test]
    async fn check_returns_ok_when_version_and_token_lookup_succeed() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["--version"],
                Response::success(
                    "OpenBao v2.5.3 ('988c88d7'), built 2026-04-20T19:13:32Z (cgo)\n",
                ),
            )
            .on(
                &["token", "lookup", "-format=json"],
                ok_no_ns("{\"data\":{\"display_name\":\"token-abc\"}}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("OpenBao v2.5.3"));
                assert!(identity.contains("addr=http://127.0.0.1:8300"));
                assert!(identity.contains("namespace=(none)"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_includes_namespace_in_identity_when_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["--version"], Response::success("OpenBao v2.5.3\n"))
            .on(
                &["token", "lookup", "-format=json"],
                ok_with_ns("{\"data\":{\"display_name\":\"token-x\"}}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, Some(BAO_NS));
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("namespace=team-engineering"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_not_authenticated_on_token_lookup_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["--version"], Response::success("OpenBao v2.5.3\n"))
            .on(&["token", "lookup", "-format=json"], fail_no_ns(2, "* permission denied\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("bao login"), "hint: {hint}");
                assert!(hint.contains("BAO_TOKEN"), "hint: {hint}");
                // Transition compat — operators with VAULT_TOKEN still
                // get a pointer to the bao-native filename. Loose
                // assertion so the wording can flex.
                assert!(hint.contains("~/.vault-token"), "hint mentions token file: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_trimmed_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/db"], ok_no_ns("supersekrit\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "supersekrit");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/empty"], ok_no_ns("\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/empty").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_preserves_internal_newlines() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/ws"], ok_no_ns("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/ws").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_not_found_wraps_bao_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "get", "-field=value", "secret/myapp/missing"],
                fail_no_ns(2, "No value found at secret/myapp/missing\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("openbao-dev"), "names instance: {msg}");
        assert!(msg.contains("secret/myapp/missing"), "names uri: {msg}");
        assert!(msg.contains("No value found"), "includes bao stderr: {msg}");
    }

    #[tokio::test]
    async fn get_permission_denied_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "get", "-field=value", "secret/locked"],
                fail_no_ns(2, "* permission denied\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/locked").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("permission denied"));
    }

    #[tokio::test]
    async fn get_http_https_mismatch_surface() {
        // The CLI default address is https://127.0.0.1:8200; running
        // `bao server -dev` listens on HTTP, yielding the canonical
        // mismatch error. The backend must surface the bao stderr
        // verbatim so doctor / `secretenv get` users see the cause.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                fail_no_ns(
                    1,
                    "Error reading secret: http: server gave HTTP response to HTTPS client\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/x").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("HTTP response to HTTPS"), "surfaces the mismatch verbatim: {msg}");
    }

    // ---- get + #json-key fragment ----

    #[tokio::test]
    async fn get_with_json_key_fragment_extracts_field() {
        let dir = TempDir::new().unwrap();
        let body = "{\"username\":\"smoke-user\",\"password\":\"smoke-pw\"}";
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/db"], ok_no_ns(&format!("{body}\n")))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db#json-key=password").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "smoke-pw");
    }

    #[tokio::test]
    async fn get_with_unsupported_fragment_directive_errors_before_subprocess() {
        // No mock entry for `kv get` — if the backend shells out, the
        // strict mock fails with an unexpected-argv error. The
        // fragment validator must reject before that.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/x#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported fragment directive"), "msg: {msg}");
        assert!(msg.contains("json-key"), "names supported directive: {msg}");
    }

    #[tokio::test]
    async fn get_json_key_field_missing_lists_available_keys() {
        let dir = TempDir::new().unwrap();
        let body = "{\"username\":\"u\",\"password\":\"p\"}";
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/cfg"], ok_no_ns(&format!("{body}\n")))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/cfg#json-key=token").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("'token' not found"), "msg: {msg}");
        assert!(msg.contains("password"), "lists available keys: {msg}");
    }

    #[tokio::test]
    async fn get_json_key_on_non_json_value_errors() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/myapp/plain"], ok_no_ns("plain-string\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/plain#json-key=field").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a JSON object"), "msg: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::success_with_stdin(
                    "Success! Data written to: secret/myapp/db\n",
                    vec!["new-value".to_owned()],
                )
                .with_env_var("BAO_ADDR", BAO_ADDR)
                .with_env_absent("BAO_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 discipline: secret on stdin, `value=-` literal on argv.
        let very_sensitive = "sk_live_TOP_SECRET_never_on_argv_555";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::success_with_stdin("Success!\n", vec![very_sensitive.to_owned()])
                    .with_env_var("BAO_ADDR", BAO_ADDR)
                    .with_env_absent("BAO_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::failure(2, "Error making API request. Code: 403\n")
                    .with_env_var("BAO_ADDR", BAO_ADDR)
                    .with_env_absent("BAO_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        assert!(format!("{err:#}").contains("Error making API request"));
    }

    #[tokio::test]
    async fn set_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db#json-key=password").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("fragment"), "msg: {msg}");
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "delete", "secret/myapp/gone"],
                ok_no_ns("Success! Data deleted (if it existed) at: secret/myapp/gone\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/myapp/db#json-key=password").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("fragment"));
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_kv_v2_value_as_json_alias_map() {
        let dir = TempDir::new().unwrap();
        // KV v2 wraps `data.data.value` around the alias-map JSON
        // string. Inner JSON is the registry document.
        let body = r#"{
            "data": {
                "data": {
                    "value": "{\"stripe_key\":\"openbao-dev://secret/prod/stripe\",\"db_url\":\"openbao-dev://secret/prod/db\"}"
                },
                "metadata": {"version": 1}
            }
        }"#;
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-format=json", "secret/registries/shared"], ok_no_ns(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("db_url".to_owned(), "openbao-dev://secret/prod/db".to_owned()),
                ("stripe_key".to_owned(), "openbao-dev://secret/prod/stripe".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_parses_kv_v1_value_as_json_alias_map() {
        let dir = TempDir::new().unwrap();
        // KV v1 has a flat `data` map; `value` field carries the same
        // JSON-string registry doc.
        let body = r#"{
            "data": {
                "value": "{\"alpha\":\"openbao-dev://secret/a\",\"beta\":\"openbao-dev://secret/b\"}"
            }
        }"#;
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-format=json", "legacy/registries/shared"], ok_no_ns(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://legacy/registries/shared").unwrap();
        let mut entries = b.list(&uri).await.unwrap();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("alpha".to_owned(), "openbao-dev://secret/a".to_owned()),
                ("beta".to_owned(), "openbao-dev://secret/b".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_errors_when_value_field_absent() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"data": {"data": {"other_field": "x"}, "metadata": {}}}"#;
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-format=json", "secret/no-value"], ok_no_ns(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/no-value").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no 'value' field"), "msg: {msg}");
    }

    #[tokio::test]
    async fn list_errors_when_value_is_not_json_map() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"data": {"data": {"value": "not-a-json-object"}}}"#;
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-format=json", "secret/bad-registry"], ok_no_ns(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/bad-registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a JSON alias"), "msg: {msg}");
    }

    #[tokio::test]
    async fn list_errors_when_body_missing_data_field() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "get", "-format=json", "secret/malformed"],
                ok_no_ns("{\"request_id\":\"abc\"}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/malformed").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("openbao-dev"), "names instance: {msg}");
        assert!(msg.contains("\"data\""), "explains expected shape: {msg}");
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/registries/shared#json-key=foo").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("fragment"));
    }

    // ---- env-pathway regression locks (PR #33 lesson, ported from Vault) ----

    #[tokio::test]
    async fn command_omits_namespace_env_when_not_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/x"], ok_no_ns("v\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_namespace_env_when_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(&["kv", "get", "-field=value", "secret/x"], ok_with_ns("v\n"))
            .install(dir.path());
        let b = backend(&mock, Some(BAO_NS));
        let uri = BackendUri::parse("openbao-dev://secret/x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn get_drift_catch_env_check_rejects_wrong_bao_addr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("never-matches\n")
                    .with_env_var("BAO_ADDR", "http://DIFFERENT.example.com:8300")
                    .with_env_absent("BAO_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/x").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("env mismatch") || msg.contains("strict-mock"),
            "expected env mismatch diagnostic propagated as stderr, got: {msg}"
        );
    }

    // ---- CV-1 stdin lock ----

    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        let secret = "sk_live_CV1_regression_lock";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bao")
            .on(
                &["kv", "put", "secret/x", "value=-"],
                Response::success_with_stdin("Success!\n", vec![secret.to_owned()])
                    .with_env_var("BAO_ADDR", BAO_ADDR)
                    .with_env_absent("BAO_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("openbao-dev://secret/x").unwrap();
        b.set(&uri, secret).await.unwrap();
    }
}
