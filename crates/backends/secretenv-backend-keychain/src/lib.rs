// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! macOS Keychain backend for SecretEnv.
//!
//! Wraps the `security` CLI that ships with every macOS. Supports both
//! generic-password and internet-password item kinds, selectable
//! per-instance via the `kind` config field. The backend is
//! macOS-only: the factory bails with a clear error on non-Darwin.
//! The crate itself compiles on every platform so the rest of the
//! workspace tests cleanly on Linux/Windows CI.
//!
//! # URI shape
//!
//! `keychain-<instance>:///<service>/<account>` — exactly two
//! non-empty path segments. `%2F` inside a segment is URL-decoded to a
//! literal `/`. Example:
//! `keychain-default:///com.acme.prod/stripe-key` targets the item
//! where `security add-generic-password` was invoked with
//! `-s com.acme.prod -a stripe-key`.
//!
//! # Config fields
//!
//! - `keychain_path` (optional) — absolute path to the keychain file.
//!   Default: user's login keychain. Passed as `-k <path>` to every
//!   `security` invocation.
//! - `kind` (optional) — `"generic-password"` (default) or
//!   `"internet-password"`. Selects which `security` subcommand
//!   family wraps `get` / `set` / `delete`.
//! - `timeout_secs` (optional) — per-instance fetch deadline.
//!   Default: [`DEFAULT_GET_TIMEOUT`].
//!
//! # List / history / extensive-check limitations
//!
//! The `security` CLI offers no safe list-by-prefix or
//! version-history operation. [`Backend::list`] and
//! [`Backend::check_extensive`] therefore bail with a clear message,
//! and [`Backend::history`] falls through to the trait default's
//! "unsupported" error. The keychain backend is a get/set/delete
//! target only — host your alias registry on a different backend
//! type.
//!
//! # Safety notes
//!
//! - **Stdin discipline.** Every `security` invocation sets
//!   `stdin: Stdio::null()` via [`KeychainBackend::security_command`].
//!   Without this, a locked keychain hangs on a TTY password prompt
//!   instead of failing fast with `errSecAuthFailed` (25).
//! - **`set` argv exposure.** `security add-*-password -w <value>`
//!   passes the value through child argv. On macOS's single-UID
//!   process model, `ps -ww` is only visible to the same UID — the
//!   risk is structurally lower than Linux's world-readable
//!   `/proc/<pid>/cmdline`, so we don't gate behind an opt-in flag
//!   (unlike 1password's `op_unsafe_set`). A `tracing::warn!`
//!   records each `set` for audit.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, optional_string, Backend, BackendFactory, BackendStatus, BackendUri,
    DEFAULT_GET_TIMEOUT,
};
use tokio::process::Command;

const CLI_NAME: &str = "security";
const INSTALL_HINT: &str =
    "the 'security' tool ships with macOS — if missing, your system is broken; \
     non-macOS users cannot use this backend";

/// Keychain item-kind selector, set from the `kind` config field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    GenericPassword,
    InternetPassword,
}

impl Kind {
    const fn find_subcommand(self) -> &'static str {
        match self {
            Self::GenericPassword => "find-generic-password",
            Self::InternetPassword => "find-internet-password",
        }
    }

    const fn add_subcommand(self) -> &'static str {
        match self {
            Self::GenericPassword => "add-generic-password",
            Self::InternetPassword => "add-internet-password",
        }
    }

    const fn delete_subcommand(self) -> &'static str {
        match self {
            Self::GenericPassword => "delete-generic-password",
            Self::InternetPassword => "delete-internet-password",
        }
    }
}

/// A live instance of the macOS Keychain backend.
pub struct KeychainBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Optional absolute path to the target keychain. `None` means
    /// "let `security` pick the default" (login.keychain-db).
    keychain_path: Option<String>,
    kind: Kind,
    /// Path or name of the `security` binary. Defaults to `"security"`
    /// (PATH lookup); tests override to a mock script path via
    /// [`secretenv_testing::StrictMock`].
    security_bin: String,
    /// Per-instance fetch deadline from `timeout_secs` config.
    timeout: Duration,
}

impl KeychainBackend {
    /// Parse `uri.path` into `(service, account)`. Exactly 2 non-empty
    /// `/`-separated segments; a leading `/` is tolerated. Occurrences
    /// of `%2F` (case-insensitive) inside a segment decode to a
    /// literal `/` — the spec-approved escape for service/account
    /// strings that themselves contain slashes.
    fn parse_path(uri: &BackendUri) -> Result<(String, String)> {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 2 || parts.iter().any(|s| s.is_empty()) {
            bail!(
                "keychain URI '{}' must have exactly two non-empty path segments \
                 (service/account); got {} — percent-encode literal slashes as %2F",
                uri.raw,
                parts.len()
            );
        }
        Ok((decode_percent_slash(parts[0]), decode_percent_slash(parts[1])))
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        format!(
            "keychain backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a base `security <subcommand>` invocation with
    /// `stdin: Stdio::null()` set. Every `security` call in this
    /// backend routes through here — the null-stdin discipline is the
    /// highest-priority habit to prevent a locked keychain from
    /// hanging on a TTY password prompt.
    fn security_command(&self, subcommand: &str) -> Command {
        let mut cmd = Command::new(&self.security_bin);
        cmd.arg(subcommand);
        // Without this, a locked keychain hangs waiting for the user's
        // password on the TTY. Null stdin converts the prompt case into
        // a fast non-zero exit (errSecAuthFailed / 25).
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Append `-k <keychain_path>` if one is configured. Call AFTER
    /// the subcommand-specific args so the flag lands at the tail of
    /// the argv — matching the strict-mock patterns and spec examples.
    fn append_keychain(&self, cmd: &mut Command) {
        if let Some(p) = &self.keychain_path {
            cmd.args(["-k", p]);
        }
    }

    fn keychain_basename(&self) -> &str {
        self.keychain_path.as_deref().map_or("login.keychain-db", |p| {
            p.rsplit('/').next().unwrap_or(p)
        })
    }

    fn unlock_hint_target(&self) -> &str {
        self.keychain_path.as_deref().unwrap_or("~/Library/Keychains/login.keychain-db")
    }
}

/// Decode `%2F` / `%2f` → `/`. Any other percent-escape passes
/// through verbatim — Keychain service/account fields accept raw
/// bytes, so we don't try to be a general percent-decoder.
fn decode_percent_slash(s: &str) -> String {
    s.replace("%2F", "/").replace("%2f", "/")
}

#[async_trait]
impl Backend for KeychainBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn check(&self) -> BackendStatus {
        // Single invocation does double duty:
        //   - Spawn-time ENOENT → CliMissing (the `security` binary is
        //     absent — only plausible on non-macOS or a broken system).
        //   - Non-zero exit → NotAuthenticated (typically
        //     errSecAuthFailed / 25 when the keychain is locked; also
        //     covers "no such keychain" if keychain_path is wrong).
        //   - Zero exit → Ok.
        let mut cmd = self.security_command("show-keychain-info");
        self.append_keychain(&mut cmd);

        let output = match cmd.output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return BackendStatus::CliMissing {
                    cli_name: CLI_NAME.to_owned(),
                    install_hint: INSTALL_HINT.to_owned(),
                };
            }
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "keychain backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.security_bin
                    ),
                };
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: security unlock-keychain {}  (stderr: {stderr})",
                    self.unlock_hint_target()
                ),
            };
        }

        BackendStatus::Ok {
            cli_version: "security (macOS system)".to_owned(),
            identity: format!("keychain={}", self.keychain_basename()),
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        uri.reject_any_fragment("keychain")?;
        let (service, account) = Self::parse_path(uri)?;

        let mut cmd = self.security_command(self.kind.find_subcommand());
        cmd.args(["-s", &service, "-a", &account, "-w"]);
        self.append_keychain(&mut cmd);

        let output = cmd.output().await.with_context(|| {
            format!(
                "keychain backend '{}': failed to invoke '{} {}' for URI '{}'",
                self.instance_name,
                self.security_bin,
                self.kind.find_subcommand(),
                uri.raw
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("could not be found") || output.status.code() == Some(44) {
                bail!(
                    "keychain backend '{}': item not found at URI '{}'",
                    self.instance_name,
                    uri.raw
                );
            }
            if stderr.contains("User interaction is not allowed")
                || output.status.code() == Some(25)
            {
                bail!(
                    "keychain backend '{}': keychain is locked for URI '{}' — \
                     run `security unlock-keychain {}` and retry",
                    self.instance_name,
                    uri.raw,
                    self.unlock_hint_target(),
                );
            }
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }

        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "keychain backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `security -w` always appends a single '\n'. Strip it.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("keychain")?;
        let (service, account) = Self::parse_path(uri)?;

        // Audit breadcrumb: on macOS argv is visible to same-UID
        // processes via `ps -ww`, which is the acceptable exposure
        // this backend accepts (no opt-in gate, unlike 1password's
        // `op_unsafe_set`). No value or its length in the log — just
        // the instance + URI so operators running in multi-user
        // contexts see the trail.
        tracing::warn!(
            instance = self.instance_name.as_str(),
            uri = uri.raw.as_str(),
            "macOS Keychain `set` passes the value through subprocess argv (same-UID \
             visibility via `ps -ww`; acceptable on single-user hosts — see \
             docs/backends/keychain.md)"
        );

        let mut cmd = self.security_command(self.kind.add_subcommand());
        // `-U` upserts: without it, `security` errors errSecDuplicateItem (45)
        // when the item already exists. set() has upsert semantics.
        cmd.args(["-s", &service, "-a", &account, "-w", value, "-U"]);
        self.append_keychain(&mut cmd);

        let output = cmd.output().await.with_context(|| {
            format!(
                "keychain backend '{}': failed to invoke '{} {}' for URI '{}'",
                self.instance_name,
                self.security_bin,
                self.kind.add_subcommand(),
                uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("keychain")?;
        let (service, account) = Self::parse_path(uri)?;

        let mut cmd = self.security_command(self.kind.delete_subcommand());
        cmd.args(["-s", &service, "-a", &account]);
        self.append_keychain(&mut cmd);

        let output = cmd.output().await.with_context(|| {
            format!(
                "keychain backend '{}': failed to invoke '{} {}' for URI '{}'",
                self.instance_name,
                self.security_bin,
                self.kind.delete_subcommand(),
                uri.raw
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("could not be found") || output.status.code() == Some(44) {
                // Match aws-secrets semantics: bail rather than silent-ok.
                bail!(
                    "keychain backend '{}': item not found at URI '{}' (delete is not \
                     idempotent for this backend — matches aws-secrets precedent)",
                    self.instance_name,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, _uri: &BackendUri) -> Result<Vec<(String, String)>> {
        bail!(
            "keychain backend '{}': list is not supported — the `security` CLI has no safe \
             list-by-prefix operation. Host your alias registry on a different backend type \
             (local, aws-ssm, aws-secrets, 1password, vault, gcp, or azure); keychain URIs \
             should appear only as alias TARGETS in the registry document.",
            self.instance_name
        )
    }

    async fn check_extensive(&self, _test_uri: &BackendUri) -> Result<usize> {
        bail!(
            "keychain backend '{}': extensive check is not supported — list operation is \
             unavailable (see docs/backends/keychain.md for the rationale)",
            self.instance_name
        )
    }

    // history() uses the trait default — keychain has no native
    // version-history API. The trait default's "unsupported for this
    // backend type" message already names `keychain`, so no override.
}

/// Factory for the macOS Keychain backend.
///
/// No required config fields; `keychain_path`, `kind`, and
/// `timeout_secs` are all optional. The factory compiles and
/// registers on every platform so the rest of the workspace tests
/// cleanly on Linux/Windows CI, but `create()` bails on non-macOS at
/// instance-build time with a clear error.
pub struct KeychainFactory(&'static str);

impl KeychainFactory {
    /// Construct the factory. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self("keychain")
    }
}

impl Default for KeychainFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for KeychainFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        if std::env::consts::OS != "macos" {
            bail!(
                "keychain instance '{instance_name}': the macOS Keychain backend is macOS-only \
                 (detected OS: {}). Pick a different backend type for this platform — e.g. \
                 'secret-service' on Linux (coming in v0.6).",
                std::env::consts::OS,
            );
        }

        let keychain_path = optional_string(config, "keychain_path", "keychain", instance_name)?;

        let kind = match optional_string(config, "kind", "keychain", instance_name)?.as_deref() {
            None | Some("generic-password") => Kind::GenericPassword,
            Some("internet-password") => Kind::InternetPassword,
            Some(other) => bail!(
                "keychain instance '{instance_name}': field 'kind' must be \
                 'generic-password' or 'internet-password', got '{other}'"
            ),
        };

        let timeout = optional_duration_secs(config, "timeout_secs", "keychain", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);

        Ok(Box::new(KeychainBackend {
            backend_type: "keychain",
            instance_name: instance_name.to_owned(),
            keychain_path,
            kind,
            security_bin: CLI_NAME.to_owned(),
            timeout,
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

    fn backend(
        mock_path: &Path,
        keychain_path: Option<&str>,
        kind: Kind,
    ) -> KeychainBackend {
        KeychainBackend {
            backend_type: "keychain",
            instance_name: "keychain-default".to_owned(),
            keychain_path: keychain_path.map(ToOwned::to_owned),
            kind,
            security_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_missing_binary() -> KeychainBackend {
        KeychainBackend {
            backend_type: "keychain",
            instance_name: "keychain-default".to_owned(),
            keychain_path: None,
            kind: Kind::GenericPassword,
            security_bin: "/definitely/not/a/real/path/to/security-98765".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_keychain() {
        assert_eq!(KeychainFactory::new().backend_type(), "keychain");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_builds_backend_with_no_required_fields() {
        let factory = KeychainFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("keychain-default", &cfg).unwrap();
        assert_eq!(b.backend_type(), "keychain");
        assert_eq!(b.instance_name(), "keychain-default");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn factory_bails_with_macos_only_message_on_non_macos() {
        let factory = KeychainFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("keychain-default", &cfg) else {
            panic!("expected error on non-macOS host");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("macOS-only"), "bail names the platform gate: {msg}");
        assert!(msg.contains("keychain-default"), "names the instance: {msg}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_accepts_internet_password_kind() {
        let factory = KeychainFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("kind".to_owned(), toml::Value::String("internet-password".to_owned()));
        assert!(factory.create("keychain-default", &cfg).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_rejects_unknown_kind_value() {
        let factory = KeychainFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("kind".to_owned(), toml::Value::String("certificate".to_owned()));
        let Err(err) = factory.create("keychain-default", &cfg) else {
            panic!("expected error for unknown kind value");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("generic-password"), "enumerates the valid values: {msg}");
        assert!(msg.contains("internet-password"), "enumerates the valid values: {msg}");
        assert!(msg.contains("certificate"), "quotes the offending value: {msg}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn factory_accepts_keychain_path_and_timeout() {
        let factory = KeychainFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "keychain_path".to_owned(),
            toml::Value::String("/Users/x/Library/Keychains/custom.keychain-db".to_owned()),
        );
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(5));
        assert!(factory.create("keychain-default", &cfg).is_ok());
    }

    // ---- URI parsing ----

    #[test]
    fn parse_path_two_segments_happy() {
        let uri = BackendUri::parse("keychain-default://myapp/stripe-key").unwrap();
        let (s, a) = KeychainBackend::parse_path(&uri).unwrap();
        assert_eq!(s, "myapp");
        assert_eq!(a, "stripe-key");
    }

    #[test]
    fn parse_path_tolerates_leading_slash() {
        let uri = BackendUri::parse("keychain-default:///myapp/stripe-key").unwrap();
        let (s, a) = KeychainBackend::parse_path(&uri).unwrap();
        assert_eq!(s, "myapp");
        assert_eq!(a, "stripe-key");
    }

    #[test]
    fn parse_path_rejects_one_segment() {
        let uri = BackendUri::parse("keychain-default://onlyservice").unwrap();
        let err = KeychainBackend::parse_path(&uri).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("service/account"), "names required shape: {msg}");
        assert!(msg.contains("%2F"), "hints the escape convention: {msg}");
    }

    #[test]
    fn parse_path_rejects_three_segments() {
        let uri = BackendUri::parse("keychain-default://a/b/c").unwrap();
        let err = KeychainBackend::parse_path(&uri).unwrap_err();
        assert!(format!("{err:#}").contains("two"));
    }

    #[test]
    fn parse_path_rejects_empty_segment() {
        let uri = BackendUri::parse("keychain-default://service/").unwrap();
        let err = KeychainBackend::parse_path(&uri).unwrap_err();
        assert!(format!("{err:#}").contains("non-empty"));
    }

    #[test]
    fn parse_path_decodes_percent_2f_case_insensitive() {
        let uri = BackendUri::parse("keychain-default://com.acme%2Fsubteam/key%2fname").unwrap();
        let (s, a) = KeychainBackend::parse_path(&uri).unwrap();
        assert_eq!(s, "com.acme/subteam");
        assert_eq!(a, "key/name");
    }

    // ---- get ----

    #[tokio::test]
    async fn get_happy_generic_password_strips_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "stripe", "-a", "prod", "-w"],
                Response::success("sk_live_secret_value\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_secret_value");
    }

    #[tokio::test]
    async fn get_uses_internet_password_subcommand_when_kind_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-internet-password", "-s", "api.example.com", "-a", "svc", "-w"],
                Response::success("basic-auth-token\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::InternetPassword);
        let uri = BackendUri::parse("keychain-default://api.example.com/svc").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "basic-auth-token");
    }

    #[tokio::test]
    async fn get_passes_k_flag_when_keychain_path_configured() {
        let dir = TempDir::new().unwrap();
        let path = "/tmp/custom.keychain-db";
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "stripe", "-a", "prod", "-w", "-k", path],
                Response::success("value\n"),
            )
            .install(dir.path());
        let b = backend(&mock, Some(path), Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "value");
    }

    #[tokio::test]
    async fn get_item_not_found_maps_to_clear_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "missing", "-a", "prod", "-w"],
                Response::failure(
                    44,
                    "security: SecKeychainSearchCopyNext: The specified item could not be \
                     found in the keychain.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://missing/prod").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("item not found"), "specific diagnostic: {msg}");
        assert!(msg.contains("keychain-default"), "names instance: {msg}");
        assert!(msg.contains("keychain-default://missing/prod"), "names URI: {msg}");
    }

    #[tokio::test]
    async fn get_locked_keychain_maps_to_unlock_hint() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "stripe", "-a", "prod", "-w"],
                Response::failure(
                    25,
                    "security: SecKeychainCopyDefault: User interaction is not allowed.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("locked"), "names the cause: {msg}");
        assert!(msg.contains("unlock-keychain"), "surfaces the fix: {msg}");
    }

    #[tokio::test]
    async fn get_fails_fast_when_binary_missing() {
        let b = backend_with_missing_binary();
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("keychain-default"));
    }

    #[tokio::test]
    async fn get_rejects_any_fragment() {
        // Keychain accepts no fragment directives. A `#version=2` form
        // is rejected by the shared `reject_any_fragment` helper.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "stripe", "-a", "prod", "-w"],
                Response::success("value\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod#version=2").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("keychain"), "names backend label: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &[
                    "add-generic-password",
                    "-s",
                    "stripe",
                    "-a",
                    "prod",
                    "-w",
                    "sk_live_new",
                    "-U",
                ],
                Response::success(""),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        b.set(&uri, "sk_live_new").await.unwrap();
    }

    #[tokio::test]
    async fn set_uses_add_internet_password_when_kind_configured() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &[
                    "add-internet-password",
                    "-s",
                    "api.example.com",
                    "-a",
                    "svc",
                    "-w",
                    "token",
                    "-U",
                ],
                Response::success(""),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::InternetPassword);
        let uri = BackendUri::parse("keychain-default://api.example.com/svc").unwrap();
        b.set(&uri, "token").await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_failure_with_instance_and_uri_context() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &[
                    "add-generic-password",
                    "-s",
                    "stripe",
                    "-a",
                    "prod",
                    "-w",
                    "v",
                    "-U",
                ],
                Response::failure(1, "security: some write failure\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("keychain-default"), "names instance: {msg}");
        assert!(msg.contains("keychain-default://stripe/prod"), "names URI: {msg}");
        assert!(msg.contains("write failure"), "propagates stderr: {msg}");
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_happy_path_zero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["delete-generic-password", "-s", "stripe", "-a", "prod"],
                Response::success(""),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_item_not_found_bails_with_clear_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["delete-generic-password", "-s", "gone", "-a", "prod"],
                Response::failure(
                    44,
                    "security: SecKeychainSearchCopyNext: The specified item could not be \
                     found in the keychain.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://gone/prod").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "names the cause: {msg}");
        assert!(msg.contains("not idempotent"), "documents the semantics: {msg}");
    }

    // ---- list, check_extensive, history (unsupported) ----

    #[tokio::test]
    async fn list_bails_with_clear_message_pointing_at_registry_alternatives() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security").install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://registry/content").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("list is not supported"), "specific wording: {msg}");
        assert!(msg.contains("local"), "points at registry alternatives: {msg}");
        assert!(msg.contains("keychain-default"), "names instance: {msg}");
    }

    #[tokio::test]
    async fn check_extensive_bails_with_clear_message() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security").install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://any/place").unwrap();
        let err = b.check_extensive(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("extensive check is not supported"), "specific wording: {msg}");
    }

    #[tokio::test]
    async fn history_uses_trait_default_unsupported_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security").install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://any/place").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not implemented"), "trait default wording: {msg}");
        assert!(msg.contains("keychain"), "names backend type: {msg}");
    }

    // ---- check ----

    #[tokio::test]
    async fn check_returns_cli_missing_when_binary_not_found() {
        let b = backend_with_missing_binary();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "security");
                assert!(install_hint.contains("ships with macOS"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_ok_when_show_keychain_info_succeeds() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["show-keychain-info"],
                Response::success("Keychain \"login.keychain-db\" no-timeout settings: unlocked\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("security"), "cli_version: {cli_version}");
                assert_eq!(identity, "keychain=login.keychain-db");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_identity_uses_basename_of_configured_keychain_path() {
        let dir = TempDir::new().unwrap();
        let path = "/Users/x/Library/Keychains/team.keychain-db";
        let mock = StrictMock::new("security")
            .on(&["show-keychain-info", "-k", path], Response::success(""))
            .install(dir.path());
        let b = backend(&mock, Some(path), Kind::GenericPassword);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert_eq!(identity, "keychain=team.keychain-db");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_locked_keychain_returns_not_authenticated() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["show-keychain-info"],
                Response::failure(
                    25,
                    "security: SecKeychainCopyDefault: User interaction is not allowed.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("unlock-keychain"), "surfaces unlock command: {hint}");
                assert!(
                    hint.contains("User interaction is not allowed"),
                    "propagates stderr: {hint}"
                );
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- drift-catch regression lock ----

    // Guard against a regression that drops the `-U` flag from set()'s
    // argv — without `-U`, `security` errors errSecDuplicateItem on an
    // existing item instead of upserting. Declared argv omits `-U`; the
    // real backend always appends it. Expect a no-match diagnostic.
    #[tokio::test]
    async fn set_drift_catch_rejects_missing_upsert_flag() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["add-generic-password", "-s", "stripe", "-a", "prod", "-w", "v"],
                Response::success(""),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("strict-mock-no-match"));
    }

    // Guard against a regression that drops `stdin: Stdio::null()` — on
    // a locked keychain, the real `security` binary would hang waiting
    // for a password prompt on the TTY. This test exercises the null-
    // stdin path by asserting that `get` returns FAST on a mock that
    // simulates the locked path; if null stdin were removed, the mock
    // would not hang (mocks don't read stdin), so this test is
    // DOCUMENTARY rather than behavioral. See docs/backends/keychain.md
    // for the real-world failure mode the null-stdin guard prevents.
    #[tokio::test]
    async fn get_on_locked_keychain_fails_fast_not_hangs() {
        use std::time::Instant;
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("security")
            .on(
                &["find-generic-password", "-s", "stripe", "-a", "prod", "-w"],
                Response::failure(
                    25,
                    "security: SecKeychainCopyDefault: User interaction is not allowed.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None, Kind::GenericPassword);
        let uri = BackendUri::parse("keychain-default://stripe/prod").unwrap();
        let start = Instant::now();
        let _ = b.get(&uri).await.unwrap_err();
        assert!(start.elapsed().as_secs() < 5, "locked-keychain path is fast, not a hang");
    }
}
