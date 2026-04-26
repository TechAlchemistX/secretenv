// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

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
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, optional_string, required_string, Backend, BackendFactory,
    BackendStatus, BackendUri, HistoryEntry, DEFAULT_GET_TIMEOUT,
};
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
    /// Per-instance deadline for fetch-class operations. From
    /// `timeout_secs` config field; defaults to [`DEFAULT_GET_TIMEOUT`].
    timeout: Duration,
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

/// `vault kv metadata get -format=json` envelope. Only the `data` arm
/// is captured; `request_id`, `lease_*`, `wrap_info`, etc. are ignored.
#[derive(Deserialize)]
struct KvMetadataResponse {
    data: KvMetadataData,
}

#[derive(Deserialize)]
struct KvMetadataData {
    /// Map keyed by version-as-string (`"1"`, `"2"`, ...). Vault's
    /// own JSON shape — we sort numerically descending so the unified
    /// `Vec<HistoryEntry>` contract (most-recent-first) holds.
    versions: HashMap<String, KvMetadataVersion>,
}

#[derive(Deserialize)]
struct KvMetadataVersion {
    /// RFC 3339 timestamp Vault stamps on the version when written.
    created_time: String,
    /// Empty string when the version is live; populated when soft-
    /// deleted (`vault kv delete`). We surface this as the
    /// `description` field so operators can spot deleted versions in
    /// the unified history table.
    #[serde(default)]
    deletion_time: String,
    /// `true` after `vault kv destroy` (versus the soft-delete above).
    /// We add a `[destroyed]` marker to the description for visibility.
    #[serde(default)]
    destroyed: bool,
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

    fn timeout(&self) -> Duration {
        self.timeout
    }

    #[allow(clippy::similar_names)]
    async fn check(&self) -> BackendStatus {
        // v0.3: Level 1 (`vault --version`) and Level 2 (`vault token
        // lookup -format=json`) run concurrently via `tokio::join!`.
        // Halves `doctor` latency.
        let version_fut = Command::new(&self.vault_bin).arg("--version").output();
        let token_fut = self.vault_command("token", &["lookup", "-format=json"]).output();
        let (version_res, token_res) = tokio::join!(version_fut, token_fut);

        // --- Level 1 ---
        let version_out = match version_res {
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

        // --- Level 2: `vault token lookup -format=json` ---
        // `vault status` succeeds with no token (it reports cluster
        // state); `token lookup` requires an actual valid token and
        // is what confirms the user can `get` a secret.
        let token_out = match token_res {
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

    // `check_extensive` uses the `Backend` trait default (list().len()).

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        uri.reject_any_fragment("vault")?;
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
        uri.reject_any_fragment("vault")?;
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
        uri.reject_any_fragment("vault")?;
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
        uri.reject_any_fragment("vault")?;
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

    /// `vault kv metadata get -format=json <path>` is the KV v2 surface
    /// that exposes per-version timestamps + soft-delete + destroy
    /// state. KV v1 has no version history; vault rejects this command
    /// against v1 mounts and we surface that error verbatim.
    ///
    /// Vault's metadata response doesn't carry an actor — that lives
    /// in the audit log, which secretenv is deliberately not reading
    /// (no privileged-credential requirement). Actor stays `None`.
    async fn history(&self, uri: &BackendUri) -> Result<Vec<HistoryEntry>> {
        uri.reject_any_fragment("vault")?;
        let path = Self::vault_path(uri);
        let mut cmd = self.vault_command("kv", &["metadata", "get", "-format=json", &path]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "vault backend '{}': failed to invoke 'vault kv metadata get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "history", &output.stderr));
        }
        let parsed: KvMetadataResponse =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "vault backend '{}': parsing 'vault kv metadata get' JSON for URI '{}'",
                    self.instance_name, uri.raw
                )
            })?;

        // Sort keys numerically descending so most-recent-first holds.
        // Vault emits version keys as decimal strings; bare lexical
        // sort gives wrong ordering past 9 (10 < 2 lexically).
        // `Reverse(n)` flips ascending → descending without a manual
        // closure (clippy::sort_by-then-reverse warns the other shape).
        let mut versions: Vec<(u64, KvMetadataVersion)> = parsed
            .data
            .versions
            .into_iter()
            .filter_map(|(k, v)| k.parse::<u64>().ok().map(|n| (n, v)))
            .collect();
        versions.sort_by_key(|(n, _)| std::cmp::Reverse(*n));

        Ok(versions
            .into_iter()
            .map(|(n, v)| {
                let mut markers: Vec<&str> = Vec::new();
                if v.destroyed {
                    markers.push("destroyed");
                }
                if !v.deletion_time.is_empty() && !v.destroyed {
                    markers.push("soft-deleted");
                }
                let description = if markers.is_empty() {
                    None
                } else {
                    Some(format!("[{}]", markers.join(", ")))
                };
                HistoryEntry {
                    version: n.to_string(),
                    timestamp: v.created_time,
                    actor: None,
                    description,
                }
            })
            .collect())
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
        let vault_address = required_string(config, "vault_address", "vault", instance_name)?;
        let vault_namespace = optional_string(config, "vault_namespace", "vault", instance_name)?;
        let vault_bin = optional_string(config, "vault_bin", "vault", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "vault", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(Box::new(VaultBackend {
            backend_type: "vault",
            instance_name: instance_name.to_owned(),
            vault_address,
            vault_namespace,
            vault_bin,
            timeout,
        }))
    }
}

// v0.3 Phase 0: `required_string` / `optional_string` moved to
// `secretenv_core::factory_helpers` (or via re-export as
// `secretenv_core::{required_string, optional_string}`). The backend-
// type label is passed as the second argument.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    const VAULT_ADDR: &str = "https://vault.example.com";
    const VAULT_NS: &str = "engineering";

    fn backend(mock_path: &Path, namespace: Option<&str>) -> VaultBackend {
        VaultBackend {
            backend_type: "vault",
            instance_name: "vault-eng".to_owned(),
            vault_address: VAULT_ADDR.to_owned(),
            vault_namespace: namespace.map(ToOwned::to_owned),
            vault_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_vault() -> VaultBackend {
        VaultBackend {
            backend_type: "vault",
            instance_name: "vault-eng".to_owned(),
            vault_address: VAULT_ADDR.to_owned(),
            vault_namespace: None,
            vault_bin: "/definitely/not/a/real/path/to/vault-binary-12345".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    /// Build a `Response::success` + `VAULT_ADDR` env check +
    /// `VAULT_NAMESPACE` absence check — the common response shape for
    /// no-namespace vault tests. Captures the PR #33 BUG-1 regression
    /// lock (no -address/-namespace argv flags; routing is env-only) as
    /// a typed assertion on every vault argv.
    fn ok_no_ns(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var("VAULT_ADDR", VAULT_ADDR)
            .with_env_absent("VAULT_NAMESPACE")
    }

    /// Same as `ok_no_ns` but requires `VAULT_NAMESPACE=engineering`.
    fn ok_with_ns(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var("VAULT_ADDR", VAULT_ADDR)
            .with_env_var("VAULT_NAMESPACE", VAULT_NS)
    }

    /// Failure-response variant with PR #33 env-pathway checks.
    fn fail_no_ns(exit_code: i32, stderr: &str) -> Response {
        Response::failure(exit_code, stderr)
            .with_env_var("VAULT_ADDR", VAULT_ADDR)
            .with_env_absent("VAULT_NAMESPACE")
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

    #[test]
    fn factory_rejects_non_string_vault_namespace() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        cfg.insert("vault_namespace".to_owned(), toml::Value::Boolean(true));
        let Err(err) = factory.create("vault-eng", &cfg) else {
            panic!("expected type error for non-string vault_namespace");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("vault_namespace"), "names the field: {msg}");
        assert!(msg.contains("must be a string"), "describes type mismatch: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_vault_bin() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        cfg.insert("vault_bin".to_owned(), toml::Value::Integer(0));
        let Err(err) = factory.create("vault-eng", &cfg) else {
            panic!("expected type error for non-string vault_bin");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("vault_bin"), "names the field: {msg}");
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(11));
        let b = factory.create("vault-eng", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(11));
    }

    #[test]
    fn factory_uses_default_timeout_when_omitted() {
        let factory = VaultFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "vault_address".to_owned(),
            toml::Value::String("https://vault.example.com".to_owned()),
        );
        let b = factory.create("vault-eng", &cfg).unwrap();
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
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
        let mock = StrictMock::new("vault")
            // --version is invoked WITHOUT env var setup — see
            // vault_command() call-site in check(): only token-lookup
            // goes through vault_command. So declare no env checks for
            // --version, but strict env checks for token lookup.
            .on(&["--version"], Response::success("Vault v1.15.2 ('abc123')\n"))
            .on(
                &["token", "lookup", "-format=json"],
                ok_no_ns(
                    "{\"data\":{\"display_name\":\"token-abc\",\"policies\":[\"default\",\"engineering-read\"],\"ttl\":3600}}\n",
                ),
            )
            .install(dir.path());
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
        let mock = StrictMock::new("vault")
            .on(&["--version"], Response::success("Vault v1.15.2 ('abc123')\n"))
            .on(
                &["token", "lookup", "-format=json"],
                ok_with_ns("{\"data\":{\"display_name\":\"token-x\"}}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, Some(VAULT_NS));
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
        let mock = StrictMock::new("vault")
            .on(&["--version"], Response::success("Vault v1.15.2\n"))
            .on(&["token", "lookup", "-format=json"], fail_no_ns(2, "* permission denied\n"))
            .install(dir.path());
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
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-field=value", "secret/myapp/db"], ok_no_ns("supersekrit\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "supersekrit");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        // Vault prints "\n" when the value is empty; we strip the one
        // trailing '\n' → "".
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-field=value", "secret/myapp/empty"], ok_no_ns("\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/empty").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_preserves_internal_newlines() {
        // Multi-line secret body: we only strip a single trailing '\n'.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-field=value", "secret/myapp/ws"], ok_no_ns("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/ws").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_not_found_wraps_vault_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/myapp/missing"],
                fail_no_ns(2, "No value found at secret/myapp/missing\n"),
            )
            .install(dir.path());
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
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/locked"],
                fail_no_ns(2, "* permission denied\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/locked").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("permission denied"));
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::success_with_stdin(
                    "Success! Data written to: secret/myapp/db\n",
                    vec!["new-value".to_owned()],
                )
                .with_env_var("VAULT_ADDR", VAULT_ADDR)
                .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_value_via_stdin_not_argv() {
        // CV-1 discipline: secret goes via stdin; argv contains only the
        // literal `value=-` sentinel. The combined argv-match +
        // stdin-fragment-check guarantees "secret on stdin, NOT on
        // argv" as a harness-level assertion — no file-I/O log grep.
        let very_sensitive = "sk_live_TOP_SECRET_never_on_argv_555";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::success_with_stdin("Success!\n", vec![very_sensitive.to_owned()])
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "put", "secret/myapp/db", "value=-"],
                Response::failure(2, "Error making API request. Code: 403\n")
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/db").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        assert!(format!("{err:#}").contains("Error making API request"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "delete", "secret/myapp/gone"],
                ok_no_ns("Success! Data deleted (if it existed) at: secret/myapp/gone\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/myapp/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_kv_v2_json() {
        let dir = TempDir::new().unwrap();
        let body = "{\"data\":{\"data\":{\"stripe-key\":\"vault-eng://secret/prod/stripe\",\"db-url\":\"vault-eng://secret/prod/db\"},\"metadata\":{\"version\":3}}}\n";
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-format=json", "secret/registries/shared"], ok_no_ns(body))
            .install(dir.path());
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
        let body =
            "{\"data\":{\"alpha\":\"vault-eng://secret/a\",\"beta\":\"vault-eng://secret/b\"}}\n";
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-format=json", "legacy/registries/shared"], ok_no_ns(body))
            .install(dir.path());
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
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "get", "-format=json", "secret/malformed"],
                ok_no_ns("{\"request_id\":\"abc\"}\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/malformed").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("vault-eng"), "names instance: {msg}");
        assert!(msg.contains("\"data\""), "explains expected shape: {msg}");
    }

    // ---- PR #33 BUG-1 regression locks: env-pathway for address + namespace ----
    //
    // These two tests codify the PR #33 fix — `-address` / `-namespace`
    // must NEVER appear on argv; routing goes through `VAULT_ADDR` /
    // `VAULT_NAMESPACE` env. In v0.2 they used file-log side-channels
    // (`env | grep ^VAULT_ > /tmp/...`); under v0.2.5 they become
    // declarative `with_env_var` + `with_env_absent` assertions, which
    // is both shorter and tighter than the file-based form.

    #[tokio::test]
    async fn command_omits_namespace_env_when_not_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-field=value", "secret/x"], ok_no_ns("v\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_includes_namespace_env_when_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(&["kv", "get", "-field=value", "secret/x"], ok_with_ns("v\n"))
            .install(dir.path());
        let b = backend(&mock, Some(VAULT_NS));
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        b.get(&uri).await.unwrap();
    }

    // ---- drift-catch regression locks (new in v0.2.5) ----

    // CV-1 regression lock: secret on stdin, NOT on argv. Declared argv
    // has the `value=-` sentinel (NOT the secret); success requires
    // stdin to contain the secret fragment. If a future change moves
    // the value to argv, either the declared argv shape diverges OR the
    // stdin fragment check fails — both fail loudly.
    #[tokio::test]
    async fn set_drift_catch_rejects_secret_leaking_to_argv() {
        let secret = "sk_live_CV1_regression_lock";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "put", "secret/x", "value=-"],
                Response::success_with_stdin("Success!\n", vec![secret.to_owned()])
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        // Secret ships via set(); mock only passes if stdin contained it.
        b.set(&uri, secret).await.unwrap();
    }

    // Env-pathway regression lock: with the backend configured with a
    // known VAULT_ADDR but a strict mock that requires a DIFFERENT
    // value, the env check fails → exit 97 surfaces as a runtime error.
    // Proves the env channel is what's being read by the child, not
    // some fallback argv path.
    #[tokio::test]
    async fn get_drift_catch_env_check_rejects_wrong_vault_addr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            // Declared VAULT_ADDR deliberately differs from the backend's.
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("never-matches\n")
                    .with_env_var("VAULT_ADDR", "https://DIFFERENT.example.com")
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("env mismatch") || msg.contains("strict-mock"),
            "expected env mismatch diagnostic propagated as stderr, got: {msg}"
        );
    }

    // ---- history (v0.4 Phase 2a) ----

    #[tokio::test]
    async fn history_returns_versions_most_recent_first_with_numeric_sort() {
        // Vault's metadata response keys versions as decimal strings.
        // A naive lexical sort would put "10" before "2"; this test
        // uses 12 versions to force the issue and asserts the parser
        // sorts numerically descending.
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "data": {
                "versions": {
                    "1":  {"created_time": "2026-04-01T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "2":  {"created_time": "2026-04-02T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "3":  {"created_time": "2026-04-03T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "10": {"created_time": "2026-04-10T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "11": {"created_time": "2026-04-11T00:00:00Z", "deletion_time": "", "destroyed": false},
                    "12": {"created_time": "2026-04-12T00:00:00Z", "deletion_time": "", "destroyed": false}
                }
            }
        }"#;
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "metadata", "get", "-format=json", "secret/registry"],
                Response::success(body)
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/registry").unwrap();
        let entries = b.history(&uri).await.unwrap();
        assert_eq!(entries.len(), 6);
        let versions: Vec<&str> = entries.iter().map(|e| e.version.as_str()).collect();
        assert_eq!(versions, vec!["12", "11", "10", "3", "2", "1"], "numeric desc");
    }

    #[tokio::test]
    async fn history_marks_destroyed_and_soft_deleted_versions_distinctly() {
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "data": {
                "versions": {
                    "1": {"created_time": "2026-04-01T00:00:00Z", "deletion_time": "2026-04-15T00:00:00Z", "destroyed": false},
                    "2": {"created_time": "2026-04-02T00:00:00Z", "deletion_time": "2026-04-16T00:00:00Z", "destroyed": true},
                    "3": {"created_time": "2026-04-03T00:00:00Z", "deletion_time": "", "destroyed": false}
                }
            }
        }"#;
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "metadata", "get", "-format=json", "secret/x"],
                Response::success(body)
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        let entries = b.history(&uri).await.unwrap();
        // Most-recent-first: 3 (live), 2 (destroyed), 1 (soft-deleted).
        assert_eq!(entries[0].version, "3");
        assert!(entries[0].description.is_none(), "live version → no marker");
        assert_eq!(entries[1].version, "2");
        assert_eq!(entries[1].description.as_deref(), Some("[destroyed]"), "destroyed only");
        assert_eq!(entries[2].version, "1");
        assert_eq!(
            entries[2].description.as_deref(),
            Some("[soft-deleted]"),
            "soft-deleted only when not destroyed"
        );
        // Vault doesn't expose actor in metadata — stays None.
        assert!(entries.iter().all(|e| e.actor.is_none()));
    }

    #[tokio::test]
    async fn history_propagates_kv_v1_unsupported_error() {
        // Vault rejects `kv metadata get` against KV v1 mounts. We
        // surface the native vault error verbatim so operators see why.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "metadata", "get", "-format=json", "kv1/legacy"],
                Response::failure(2, "Metadata not supported on KV Version 1\n")
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("vault-eng://kv1/legacy").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Metadata not supported"), "stderr surfaced: {msg}");
        assert!(msg.contains("history failed"), "operation labeled: {msg}");
    }

    #[tokio::test]
    async fn history_uses_namespace_env_when_configured() {
        // Same env-channel rigor as the other vault tests — assert
        // that namespace propagates through to the mock's env check.
        let dir = TempDir::new().unwrap();
        let body = r#"{"data":{"versions":{"1":{"created_time":"2026-04-19T00:00:00Z","deletion_time":"","destroyed":false}}}}"#;
        let mock = StrictMock::new("vault")
            .on(
                &["kv", "metadata", "get", "-format=json", "secret/x"],
                Response::success(body)
                    .with_env_var("VAULT_ADDR", VAULT_ADDR)
                    .with_env_var("VAULT_NAMESPACE", VAULT_NS),
            )
            .install(dir.path());
        let b = backend(&mock, Some(VAULT_NS));
        let uri = BackendUri::parse("vault-eng://secret/x").unwrap();
        let entries = b.history(&uri).await.unwrap();
        assert_eq!(entries.len(), 1);
    }
}
