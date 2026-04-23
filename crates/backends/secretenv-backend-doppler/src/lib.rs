// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Doppler secrets-manager backend for SecretEnv.
//!
//! Wraps the `doppler` CLI (never the REST API or an SDK). Every auth
//! mode the CLI supports — `doppler login` keychain entry, `$DOPPLER_TOKEN`
//! env var, instance-scoped `doppler_token` config field — works
//! transparently because the CLI resolves auth the way the user already
//! configured it.
//!
//! # URI shape
//!
//! Two forms accepted:
//!
//! - **Full:** `<instance>:///<project>/<config>/<secret>` —
//!   `doppler-prod:///acme/prd/STRIPE_API_KEY`.
//! - **Short:** `<instance>:///<secret>` —
//!   `doppler-prod:///STRIPE_API_KEY`. Only valid when BOTH
//!   `doppler_project` and `doppler_config` are set in
//!   `[backends.<instance>]`. URI segments override config defaults
//!   (so the full form always wins if both are present).
//!
//! Fragments are reserved for v0.7+ and currently rejected.
//!
//! # Config fields
//!
//! - `doppler_project` (optional) — default project if the URI uses
//!   the short form.
//! - `doppler_config` (optional) — default Doppler config
//!   (environment) if the URI uses the short form.
//! - `doppler_token` (optional) — per-instance override for
//!   `$DOPPLER_TOKEN`. Passed via `Command::env("DOPPLER_TOKEN", …)`,
//!   **never** via the `--token` argv flag (argv is visible to
//!   same-UID processes via `ps -ww`).
//! - `timeout_secs` (optional) — per-instance deadline; default
//!   [`DEFAULT_GET_TIMEOUT`].
//! - `doppler_bin` (optional, test hook) — override the `doppler`
//!   binary path. Strict-mock tests use this.
//!
//! # `list()` semantics
//!
//! `doppler secrets download --format json --no-file` returns the
//! entire secret set for the scoped project+config as a single JSON
//! object. This backend uses that as the alias→URI map for registry
//! sources (each Doppler secret name becomes an alias, its value a
//! URI). Doppler auto-injects three synthetic entries —
//! `DOPPLER_PROJECT`, `DOPPLER_CONFIG`, `DOPPLER_ENVIRONMENT` — that
//! describe the config itself, not user-written data. [`Backend::list`]
//! filters every `DOPPLER_*`-prefixed key out of the map before
//! returning; a regression would pollute every registry-list caller
//! with three meaningless "aliases". A unit test locks this.
//!
//! # `history()` — unsupported via CLI
//!
//! Doppler has per-secret version history in the Dashboard and REST
//! API, but `doppler` CLI v3.76.0 exposes no `secrets versions`
//! subcommand. Since the backend-wraps-CLI pattern is load-bearing
//! ([[backends/template]] sec. "CLI-only"), [`Backend::history`]
//! overrides the trait default to surface a specific bail message
//! pointing users at the Dashboard for now. A future Doppler CLI
//! release that adds `secrets versions` can flip this to a native
//! implementation in a patch.
//!
//! # Security
//!
//! - Every `doppler` invocation goes through `Command::args([...])`
//!   with individual `&str` — never `sh -c`, never `format!` into a
//!   shell string.
//! - `set()` pipes the secret value via child stdin
//!   (`--no-interactive` flag), NEVER on argv. CV-1 discipline.
//! - `doppler_token` travels via `Command::env`, never via argv. A
//!   canary test locks this.
//! - `list()` response body is secret-bearing. Values are never
//!   logged; errors never interpolate the body.
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
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const CLI_NAME: &str = "doppler";
const INSTALL_HINT: &str =
    "brew install dopplerhq/cli/doppler  OR  https://docs.doppler.com/docs/install-cli";

/// Synthetic keys Doppler injects into `secrets download` output that
/// describe the config itself, not user-written data. Filtered out of
/// [`Backend::list`]. Doppler reserves the `DOPPLER_` prefix so any
/// user "secret" with this shape is system-generated.
const SYNTHETIC_KEY_PREFIX: &str = "DOPPLER_";

/// A live instance of the Doppler backend.
pub struct DopplerBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Default project if the URI uses the short form. `None` forces
    /// the URI to supply a project segment.
    doppler_project: Option<String>,
    /// Default config if the URI uses the short form. `None` forces
    /// the URI to supply a config segment.
    doppler_config: Option<String>,
    /// Instance-scoped token. When set, passed to every subprocess via
    /// `Command::env("DOPPLER_TOKEN", …)` — never argv. When absent,
    /// the CLI inherits from the user's environment or `doppler login`
    /// keychain entry.
    doppler_token: Option<String>,
    /// Path or name of the `doppler` binary. Defaults to `"doppler"`
    /// (PATH lookup); tests override to a mock script path via
    /// [`secretenv_testing::StrictMock`].
    doppler_bin: String,
    timeout: Duration,
}

/// Parsed identity of the token-holder, from `doppler me --json`.
/// Only the fields we render in the identity string are deserialized;
/// unknown fields (e.g. `slug`, `token_preview`, `created_at`) are
/// silently ignored so a future CLI minor release can add fields
/// without breaking our parse. `Option` handles missing keys —
/// `#[serde(default)]` would be redundant.
#[derive(Deserialize)]
struct DopplerMe {
    /// `personal` / `cli` / `service` / `service_account`. Rendered in identity.
    r#type: Option<String>,
    /// Display name for personal/cli tokens (device name), or the
    /// service-account slug. Rendered in identity when present.
    name: Option<String>,
    /// Containing workplace.
    workplace: Option<DopplerMeWorkplace>,
}

#[derive(Deserialize)]
struct DopplerMeWorkplace {
    name: Option<String>,
}

impl DopplerBackend {
    #[must_use]
    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        format!(
            "doppler backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `doppler` command with the shared scoping tail:
    /// `--project <p> --config <c>` appended after the caller's args,
    /// plus `DOPPLER_TOKEN` applied via env when the instance config
    /// supplied one. Strict-mock tests lock the full argv shape,
    /// implicitly locking that `--token` is NEVER passed.
    fn doppler_command(&self, args: &[&str], project: &str, config: &str) -> Command {
        let mut cmd = Command::new(&self.doppler_bin);
        cmd.args(args);
        cmd.args(["--project", project, "--config", config]);
        // Without null stdin, an interactive subcommand could hang
        // waiting for tty input. Every site that needs to feed stdin
        // overrides with `Stdio::piped()` AFTER this helper returns.
        cmd.stdin(Stdio::null());
        if let Some(token) = &self.doppler_token {
            // NEVER argv — ps -ww would leak it to same-UID processes.
            cmd.env("DOPPLER_TOKEN", token);
        }
        cmd
    }

    /// Resolve `(project, config, secret_name)` from the URI + instance
    /// config. Two shapes accepted:
    ///
    /// - 3 non-empty segments → `<project>/<config>/<secret>`.
    /// - 1 non-empty segment → `<secret>`; requires BOTH
    ///   `doppler_project` AND `doppler_config` in instance config.
    ///
    /// Any other segment count errors locally before shelling out.
    fn resolve_target<'a>(&'a self, uri: &'a BackendUri) -> Result<(&'a str, &'a str, &'a str)> {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let parts: Vec<&str> = path.split('/').collect();
        match parts.as_slice() {
            [secret] if !secret.is_empty() => {
                let project = self.doppler_project.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "doppler backend '{}': URI '{}' uses short form but \
                         config is missing 'doppler_project' — either set both \
                         'doppler_project' and 'doppler_config' under \
                         [backends.{}], or switch to the full form \
                         '<instance>:///<project>/<config>/<secret>'",
                        self.instance_name,
                        uri.raw,
                        self.instance_name
                    )
                })?;
                let config = self.doppler_config.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "doppler backend '{}': URI '{}' uses short form but \
                         config is missing 'doppler_config' — either set both \
                         'doppler_project' and 'doppler_config' under \
                         [backends.{}], or switch to the full form",
                        self.instance_name,
                        uri.raw,
                        self.instance_name
                    )
                })?;
                Ok((project, config, secret))
            }
            [project, config, secret]
                if !project.is_empty() && !config.is_empty() && !secret.is_empty() =>
            {
                Ok((project, config, secret))
            }
            _ => bail!(
                "doppler backend '{}': URI '{}' must have either 1 segment \
                 (short form, requires both 'doppler_project' and \
                 'doppler_config' in instance config) or 3 segments \
                 (full form: <project>/<config>/<secret>); got {} segment(s)",
                self.instance_name,
                uri.raw,
                parts.iter().filter(|s| !s.is_empty()).count()
            ),
        }
    }
}

#[async_trait]
impl Backend for DopplerBackend {
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
        // Two concurrent probes:
        //   Level 1: `doppler --version` → CliMissing on ENOENT, else
        //            cli_version string for identity.
        //   Level 2: `doppler me --json` → NotAuthenticated on non-zero
        //            or on an "unauthorized" stderr; otherwise parse
        //            account + token-type into the identity string.
        let version_fut = {
            let mut c = Command::new(&self.doppler_bin);
            c.arg("--version");
            c.stdin(Stdio::null());
            c.output()
        };

        let mut me_cmd = Command::new(&self.doppler_bin);
        me_cmd.args(["me", "--json"]);
        me_cmd.stdin(Stdio::null());
        if let Some(token) = &self.doppler_token {
            me_cmd.env("DOPPLER_TOKEN", token);
        }
        let me_fut = me_cmd.output();

        let (version_res, me_res) = tokio::join!(version_fut, me_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "doppler backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.doppler_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "doppler backend '{}': 'doppler --version' exited non-zero: {}",
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

        // --- Level 2 ---
        let me_out = match me_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "doppler backend '{}': failed to invoke 'doppler me --json': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !me_out.status.success() {
            let stderr = String::from_utf8_lossy(&me_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: doppler login  OR  export DOPPLER_TOKEN=<your-token>  \
                     (stderr: {stderr})"
                ),
            };
        }

        // Parse JSON identity. A malformed response surfaces as
        // Error — the token WAS accepted (non-zero would have been
        // caught above), so NotAuthenticated would mislead the user.
        let me: DopplerMe = match serde_json::from_slice(&me_out.stdout) {
            Ok(me) => me,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "doppler backend '{}': 'doppler me --json' returned \
                         unparseable JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        let token_type = me.r#type.as_deref().unwrap_or("unknown");
        let account = me.name.as_deref().unwrap_or("unknown");
        let workplace = me.workplace.as_ref().and_then(|w| w.name.as_deref()).unwrap_or("unknown");
        let identity = format!("account={account} token-type={token_type} workplace={workplace}");

        BackendStatus::Ok { cli_version, identity }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        uri.reject_any_fragment("doppler")?;
        let (project, config, secret) = self.resolve_target(uri)?;

        let mut cmd = self.doppler_command(&["secrets", "get", secret, "--plain"], project, config);
        let output = cmd.output().await.with_context(|| {
            format!(
                "doppler backend '{}': failed to invoke 'doppler secrets get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Could not find requested secret") || stderr.contains("not found") {
                bail!(
                    "doppler backend '{}': secret '{secret}' not found in \
                     project='{project}' config='{config}' (URI '{}')",
                    self.instance_name,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }

        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "doppler backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `secrets get --plain` appends exactly one '\n'. Strip it.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("doppler")?;
        let (project, config, secret) = self.resolve_target(uri)?;

        // `--no-interactive` tells Doppler to read the value from
        // stdin instead of prompting. Child stdin is piped; value is
        // written + stdin closed. argv carries ONLY the secret NAME,
        // NEVER the value.
        let mut cmd =
            self.doppler_command(&["secrets", "set", secret, "--no-interactive"], project, config);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "doppler backend '{}': failed to spawn 'doppler secrets set' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "doppler backend '{}': failed to write secret value to stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
            drop(stdin);
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "doppler backend '{}': 'doppler secrets set' exited abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("doppler")?;
        let (project, config, secret) = self.resolve_target(uri)?;

        let mut cmd =
            self.doppler_command(&["secrets", "delete", secret, "--yes"], project, config);
        let output = cmd.output().await.with_context(|| {
            format!(
                "doppler backend '{}': failed to invoke 'doppler secrets delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Could not find requested secret") || stderr.contains("not found") {
                bail!(
                    "doppler backend '{}': secret '{secret}' not found at URI '{}' \
                     (delete is not idempotent — matches aws-secrets precedent)",
                    self.instance_name,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("doppler")?;
        // list scopes to project+config, not to a single secret. We
        // still need the URI's project+config (or the instance
        // defaults via short-form), but the URI's secret segment is
        // ignored — a list URI addresses "the registry source" which
        // IS the whole Doppler config. A fully-scoped URI like
        // `doppler:///acme/prd/REGISTRY_MARKER` is valid: we use acme
        // + prd and ignore the marker.
        let (project, config, _secret_ignored) = self.resolve_target(uri)?;

        let mut cmd = self.doppler_command(
            &["secrets", "download", "--format", "json", "--no-file"],
            project,
            config,
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "doppler backend '{}': failed to invoke 'doppler secrets download' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }

        // Response body is secret-bearing — `download` is the ONLY
        // CLI path that returns every value in the config. Parse
        // directly from bytes so the body never flows through a
        // lossy conversion or a default-Debug print.
        let map: HashMap<String, String> =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "doppler backend '{}': 'doppler secrets download' returned \
                     JSON that is not a {{string: string}} map (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?;

        // Filter synthetic `DOPPLER_*` keys. Doppler reserves this
        // prefix so user secrets cannot collide with the three
        // always-injected ones (`DOPPLER_PROJECT`, `DOPPLER_CONFIG`,
        // `DOPPLER_ENVIRONMENT`). A regression would pollute every
        // registry caller with three meaningless aliases —
        // `synthetic_keys_are_filtered` locks this.
        Ok(map.into_iter().filter(|(k, _)| !k.starts_with(SYNTHETIC_KEY_PREFIX)).collect())
    }

    async fn history(&self, uri: &BackendUri) -> Result<Vec<secretenv_core::HistoryEntry>> {
        // Override the trait default so we can reject fragments and
        // surface a Doppler-specific explanation. Per-secret version
        // history exists in the Doppler Dashboard + REST API but the
        // CLI (v3.76.0) does not expose a `secrets versions`
        // subcommand. The wraps-CLI constraint means we can't
        // implement history until the CLI adds it.
        uri.reject_any_fragment("doppler")?;
        bail!(
            "doppler backend '{}': history is not supported — the `doppler` CLI \
             (v3.76.0) has no per-secret version-history subcommand; version \
             history IS available in the Doppler Dashboard and REST API. A \
             future CLI release adding `doppler secrets versions` can flip this \
             to a native implementation.",
            self.instance_name
        )
    }
}

/// Factory for the Doppler backend.
///
/// No required config fields — every field is optional because
/// Doppler inherits auth from the CLI's own login state. The factory
/// validates that `doppler_config` and `doppler_project` are either
/// both-set or both-unset: a half-configured short-form default is
/// a footgun (URIs relying on the short form would fail with half
/// the defaults, surfacing only at get-time).
pub struct DopplerFactory(&'static str);

impl DopplerFactory {
    /// Construct the factory. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self("doppler")
    }
}

impl Default for DopplerFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for DopplerFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let doppler_project = optional_string(config, "doppler_project", "doppler", instance_name)?;
        let doppler_config = optional_string(config, "doppler_config", "doppler", instance_name)?;

        // Both-or-neither rule. A user setting just one of the two
        // would get a confusing "missing doppler_config" error at
        // every short-form get() instead of at config-load time.
        match (&doppler_project, &doppler_config) {
            (Some(_), None) => bail!(
                "doppler instance '{instance_name}': field 'doppler_project' is set but \
                 'doppler_config' is not — short-form URIs require both or neither. \
                 Either add 'doppler_config' or remove 'doppler_project' and use full \
                 URIs ('<instance>:///<project>/<config>/<secret>')."
            ),
            (None, Some(_)) => bail!(
                "doppler instance '{instance_name}': field 'doppler_config' is set but \
                 'doppler_project' is not — short-form URIs require both or neither. \
                 Either add 'doppler_project' or remove 'doppler_config' and use full \
                 URIs ('<instance>:///<project>/<config>/<secret>')."
            ),
            _ => {}
        }

        let doppler_token = optional_string(config, "doppler_token", "doppler", instance_name)?;
        let doppler_bin = optional_string(config, "doppler_bin", "doppler", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "doppler", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);

        Ok(Box::new(DopplerBackend {
            backend_type: "doppler",
            instance_name: instance_name.to_owned(),
            doppler_project,
            doppler_config,
            doppler_token,
            doppler_bin,
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

    const PROJECT: &str = "acme";
    const CONFIG: &str = "prd";

    fn backend(mock_path: &Path, token: Option<&str>) -> DopplerBackend {
        DopplerBackend {
            backend_type: "doppler",
            instance_name: "doppler-prod".to_owned(),
            doppler_project: Some(PROJECT.to_owned()),
            doppler_config: Some(CONFIG.to_owned()),
            doppler_token: token.map(ToOwned::to_owned),
            doppler_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_no_defaults(mock_path: &Path) -> DopplerBackend {
        DopplerBackend {
            backend_type: "doppler",
            instance_name: "doppler-prod".to_owned(),
            doppler_project: None,
            doppler_config: None,
            doppler_token: None,
            doppler_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_missing_bin() -> DopplerBackend {
        DopplerBackend {
            backend_type: "doppler",
            instance_name: "doppler-prod".to_owned(),
            doppler_project: Some(PROJECT.to_owned()),
            doppler_config: Some(CONFIG.to_owned()),
            doppler_token: None,
            doppler_bin: "/definitely/not/a/real/path/to/doppler-XYZ987".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const ME_ARGV: &[&str] = &["me", "--json"];

    /// Argv shape every non-check subcommand uses. The trailing
    /// `--project <p> --config <c>` is appended by `doppler_command`;
    /// strict mocks lock the whole string so a regression that
    /// dropped the scoping flags would produce exit 97.
    fn get_argv(secret: &str) -> [&str; 8] {
        ["secrets", "get", secret, "--plain", "--project", PROJECT, "--config", CONFIG]
    }

    fn set_argv(secret: &str) -> [&str; 8] {
        ["secrets", "set", secret, "--no-interactive", "--project", PROJECT, "--config", CONFIG]
    }

    fn delete_argv(secret: &str) -> [&str; 8] {
        ["secrets", "delete", secret, "--yes", "--project", PROJECT, "--config", CONFIG]
    }

    const DOWNLOAD_ARGV: &[&str] = &[
        "secrets",
        "download",
        "--format",
        "json",
        "--no-file",
        "--project",
        PROJECT,
        "--config",
        CONFIG,
    ];

    /// `doppler me --json` happy body matching the real CLI's shape.
    const ME_OK_JSON: &str = r#"{
        "workplace": {"name": "TechAlchemist", "slug": "df890"},
        "type": "cli",
        "token_preview": "dp.ct…8kvKCl",
        "name": "alice-mbp"
    }"#;

    fn check_mock_ok(_dir: &Path) -> StrictMock {
        StrictMock::new("doppler")
            .on(VERSION_ARGV, Response::success("v3.76.0\n"))
            .on(ME_ARGV, Response::success(ME_OK_JSON))
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_doppler() {
        assert_eq!(DopplerFactory::new().backend_type(), "doppler");
    }

    #[test]
    fn factory_accepts_empty_config() {
        let factory = DopplerFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("doppler-default", &cfg).unwrap();
        assert_eq!(b.backend_type(), "doppler");
        assert_eq!(b.instance_name(), "doppler-default");
    }

    #[test]
    fn factory_accepts_both_defaults() {
        let factory = DopplerFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("doppler_project".to_owned(), toml::Value::String("acme".to_owned()));
        cfg.insert("doppler_config".to_owned(), toml::Value::String("prd".to_owned()));
        factory.create("doppler-prod", &cfg).unwrap();
    }

    #[test]
    fn factory_rejects_half_configured_defaults_project_only() {
        let factory = DopplerFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("doppler_project".to_owned(), toml::Value::String("acme".to_owned()));
        let Err(err) = factory.create("doppler-prod", &cfg) else {
            panic!("expected error when only doppler_project is set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("doppler_config"), "names missing field: {msg}");
        assert!(msg.contains("short-form"), "explains why: {msg}");
    }

    #[test]
    fn factory_rejects_half_configured_defaults_config_only() {
        let factory = DopplerFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("doppler_config".to_owned(), toml::Value::String("prd".to_owned()));
        let Err(err) = factory.create("doppler-prod", &cfg) else {
            panic!("expected error when only doppler_config is set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("doppler_project"), "names missing field: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_token() {
        let factory = DopplerFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("doppler_token".to_owned(), toml::Value::Integer(42));
        let Err(err) = factory.create("doppler-prod", &cfg) else {
            panic!("expected error on non-string token");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = DopplerFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(17));
        let b = factory.create("doppler-prod", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(17));
    }

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_missing_bin();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "doppler");
                assert!(install_hint.contains("dopplerhq/cli/doppler"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_parses_identity_from_me_json() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert_eq!(cli_version, "v3.76.0");
                assert!(
                    identity.contains("account=alice-mbp"),
                    "identity includes account: {identity}"
                );
                assert!(
                    identity.contains("token-type=cli"),
                    "identity includes token-type: {identity}"
                );
                assert!(
                    identity.contains("workplace=TechAlchemist"),
                    "identity includes workplace: {identity}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_not_authenticated_on_me_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(VERSION_ARGV, Response::success("v3.76.0\n"))
            .on(ME_ARGV, Response::failure(1, "Doppler Error: Unauthorized\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("doppler login"), "hint: {hint}");
                assert!(hint.contains("DOPPLER_TOKEN"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_error_on_unparseable_me_json() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(VERSION_ARGV, Response::success("v3.76.0\n"))
            .on(ME_ARGV, Response::success("not json {"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Error { message } => {
                assert!(message.contains("unparseable"), "explains: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_full_form_returns_secret() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_short_form_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        // Short form — project + config come from backend defaults.
        let uri = BackendUri::parse("doppler-prod:///STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_short_form_without_defaults_errors_locally() {
        // Empty-rule mock: ANY doppler invocation yields exit 97 with
        // "strict-mock-no-match". Error must come from `resolve_target`
        // BEFORE the subprocess runs.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend_no_defaults(&mock);
        let uri = BackendUri::parse("doppler-prod:///STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("short form"), "names the form: {msg}");
        assert!(msg.contains("doppler_project"), "names field: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from resolve, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_two_segment_uri() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1 segment") && msg.contains("3 segments"), "{msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from resolve, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("doppler"), "names backend: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from reject, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_not_found_stderr_shapes_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(
                &get_argv("MISSING"),
                Response::failure(1, "Doppler Error: Could not find requested secret: MISSING\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/MISSING").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "friendly text: {msg}");
        assert!(msg.contains("project='acme'"), "names project: {msg}");
        assert!(msg.contains("config='prd'"), "names config: {msg}");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&get_argv("MULTILINE"), Response::success("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/MULTILINE").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_passes_value_via_stdin_not_argv() {
        // CV-1 canary: argv carries the secret NAME but NOT the value;
        // stdin-fragment check requires the value on stdin. Strict
        // match implies "value on stdin, NOT on argv" declaratively.
        let canary = "sk_live_TOP_SECRET_doppler_never_in_argv_ABC";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(
                &set_argv("STRIPE_KEY"),
                Response::success_with_stdin("Updated secrets: 1\n", vec![canary.to_owned()]),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY").unwrap();
        b.set(&uri, canary).await.unwrap();
    }

    #[tokio::test]
    async fn set_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY#version=5").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess"
        );
    }

    #[tokio::test]
    async fn set_propagates_upstream_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&set_argv("STRIPE_KEY"), Response::failure(1, "Doppler Error: project not found\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(format!("{err:#}").contains("project not found"));
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_happy() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&delete_argv("OLD_KEY"), Response::success("Deleted secrets: 1\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/OLD_KEY").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_bails() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(
                &delete_argv("MISSING"),
                Response::failure(1, "Doppler Error: Could not find requested secret: MISSING\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/MISSING").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("not found"));
    }

    // ---- list ----

    #[tokio::test]
    async fn list_returns_filtered_map() {
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "DOPPLER_PROJECT": "acme",
            "DOPPLER_CONFIG": "prd",
            "DOPPLER_ENVIRONMENT": "prd",
            "STRIPE_KEY": "aws-ssm-prod:///stripe",
            "DB_URL": "vault-dev:///secret/db"
        }"#;
        let mock = StrictMock::new("doppler")
            .on(DOWNLOAD_ARGV, Response::success(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/REGISTRY").unwrap();
        let mut out = b.list(&uri).await.unwrap();
        out.sort();
        assert_eq!(
            out,
            vec![
                ("DB_URL".to_owned(), "vault-dev:///secret/db".to_owned()),
                ("STRIPE_KEY".to_owned(), "aws-ssm-prod:///stripe".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_filters_every_doppler_prefixed_key() {
        // Drift-catch: Doppler may add new `DOPPLER_*` synthetic keys
        // in the future (it already injects 3 today). Any NEW key
        // sharing the prefix MUST be filtered — if a regression
        // dropped the prefix filter and we only checked the 3
        // known names, new synthetic keys would silently pollute
        // every registry caller.
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "DOPPLER_PROJECT": "acme",
            "DOPPLER_CONFIG": "prd",
            "DOPPLER_ENVIRONMENT": "prd",
            "DOPPLER_FUTURE_SYNTHETIC": "whatever",
            "USER_SECRET": "target"
        }"#;
        let mock = StrictMock::new("doppler")
            .on(DOWNLOAD_ARGV, Response::success(body))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/REGISTRY").unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out.len(), 1, "only non-DOPPLER_ keys survive: {out:?}");
        assert_eq!(out[0].0, "USER_SECRET");
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/REG#version=5").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess"
        );
    }

    // ---- history ----

    #[tokio::test]
    async fn history_is_unsupported() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("history is not supported"), "{msg}");
        assert!(msg.contains("Dashboard"), "{msg}");
        assert!(!msg.contains("strict-mock-no-match"), "unsupported error must precede subprocess");
    }

    #[tokio::test]
    async fn history_rejects_fragment_before_unsupported_message() {
        // Mirrors keychain's pattern — reject fragment FIRST so the
        // user sees "fragment not allowed" instead of a misleading
        // "unsupported" response that obscures the URI mistake.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY#version=5").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        // Fragment-reject wins; "history is not supported" does NOT
        // appear.
        assert!(!msg.contains("history is not supported"), "{msg}");
    }

    // ---- token-via-env canary ----

    #[tokio::test]
    async fn token_travels_via_env_not_argv() {
        // StrictMock produces exit 97 if argv doesn't match the
        // declared shape. Our declared argv is `get_argv` which does
        // NOT include `--token`. If a regression passed the token as
        // `--token <value>`, argv length would diverge and the mock
        // would fail with strict-mock-no-match — locking the
        // env-only discipline.
        let canary_token = "dp.st.prd.TOKEN_NEVER_IN_ARGV_XYZ";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("doppler")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live\n"))
            .install(dir.path());
        let b = backend(&mock, Some(canary_token));
        let uri = BackendUri::parse("doppler-prod:///acme/prd/STRIPE_KEY").unwrap();
        b.get(&uri).await.unwrap();
    }
}
