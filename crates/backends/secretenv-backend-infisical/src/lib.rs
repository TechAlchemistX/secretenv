// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Infisical secrets-manager backend for SecretEnv.
//!
//! Wraps the `infisical` CLI (never the REST API or an SDK). Every
//! auth mode the CLI supports — `infisical login` keychain entry,
//! `$INFISICAL_TOKEN` env var (service or machine-identity tokens),
//! instance-scoped `infisical_token` config field — works transparently
//! because the CLI resolves auth the way the user already configured
//! it.
//!
//! Infisical runs as a hosted `SaaS` at `app.infisical.com` AND as a
//! self-hostable service; both surfaces share the same CLI. The
//! `infisical_domain` config field (or `$INFISICAL_API_URL`) targets a
//! self-hosted instance. Default is `https://app.infisical.com/api`.
//!
//! # URI shape
//!
//! Two forms accepted:
//!
//! - **Full:** `<instance>:///<project-id>/<env>/<secret>` —
//!   `infisical-prod:///abc-123/prod/STRIPE_API_KEY`. If the secret
//!   lives under a nested folder, fold the folder parts in as middle
//!   segments: `infisical-prod:///abc-123/prod/api/stripe/STRIPE_KEY`
//!   resolves to project=`abc-123`, env=`prod`, path=`/api/stripe`,
//!   name=`STRIPE_KEY`.
//! - **Short:** `<instance>:///<secret>` —
//!   `infisical-prod:///STRIPE_API_KEY`. Only valid when BOTH
//!   `infisical_project_id` and `infisical_environment` are set in
//!   `[backends.<instance>]`. Path defaults to the config's
//!   `infisical_secret_path` or `/`.
//!
//! Two-segment URIs are ambiguous (could be project/secret or
//! env/secret or folder/secret) and rejected.
//!
//! Fragments are reserved and currently rejected — Infisical doesn't
//! support version-pinning via the CLI.
//!
//! # Config fields
//!
//! - `infisical_project_id` (optional) — default project UUID if the
//!   URI uses the short form.
//! - `infisical_environment` (optional) — default environment slug
//!   (`dev`/`staging`/`prod`) if the URI uses the short form.
//! - `infisical_secret_path` (optional) — default folder path within
//!   the environment. Default: `/`.
//! - `infisical_token` (optional) — per-instance override for
//!   `$INFISICAL_TOKEN`. Passed via
//!   `Command::env("INFISICAL_TOKEN", …)`, **never** via the `--token`
//!   argv flag (argv is visible to same-UID processes via `ps -ww`).
//! - `infisical_domain` (optional) — self-hosted instance URL. Passed
//!   via `Command::env("INFISICAL_API_URL", …)` — never argv, to
//!   mirror the token discipline.
//! - `timeout_secs` (optional) — per-instance deadline; default
//!   [`DEFAULT_GET_TIMEOUT`].
//! - `infisical_bin` (optional, test hook) — override the `infisical`
//!   binary path. Strict-mock tests use this.
//!
//! # `set()` discipline — temp-file, NOT argv
//!
//! `infisical secrets set` at CLI v0.43.77 accepts values in exactly
//! two ways:
//!
//! 1. Positional `secretName=secretValue` pairs on argv — **rejected**
//!    here because argv is visible to same-UID processes.
//! 2. `--file <path>` pointing at a .env/YAML file — **used here**.
//!
//! There is no stdin form. [`Backend::set`] writes the single
//! `NAME=VALUE` pair to a `NamedTempFile` (mode 0600 on Unix), spawns
//! `infisical secrets set --file <tempfile> --type shared …`, and the
//! temp file is auto-unlinked when the `NamedTempFile` guard drops —
//! regardless of the spawn's exit code. The value never appears on
//! argv.
//!
//! `--type shared` is mandatory on `set` AND `delete`. The CLI default
//! is `personal`, which operates on an org-wide personal-override
//! scope rather than the project-shared secrets we want. Missing
//! `--type shared` would silently set/delete the wrong scope. Two
//! argv-canary tests lock this.
//!
//! # `list()` semantics
//!
//! Follows the **Doppler-style bulk model**: the entire Infisical
//! env + path IS the alias map. Each secret's name = one alias, each
//! secret's value = the alias's target URI (user stored URIs as
//! values). `infisical secrets --output json` returns
//! `[{"secretKey":"NAME","secretValue":"URI"}, …]`; [`Backend::list`]
//! parses into `(secretKey, secretValue)` tuples. Do NOT configure an
//! Infisical env+path as a registry source unless every entry's value
//! is a URI — mixed content leaks secret values as alias targets.
//!
//! The response body is secret-bearing. Errors/traces in this crate
//! NEVER interpolate the raw stdout or the parsed `Vec`; values leave
//! the backend only through the return of this method as alias-target
//! URIs — never via `Debug`, `tracing`, or error-message
//! interpolation.
//!
//! The `--plain` flag on `secrets` (list) is deprecated at v0.43.77;
//! `--output json` is the forward-compatible form.
//!
//! # `history()` — unsupported via CLI
//!
//! Infisical has per-secret version history in the Dashboard and REST
//! API, but `infisical` CLI v0.43.77 exposes no `secrets versions`
//! subcommand. [`Backend::history`] overrides the trait default to
//! surface a specific bail message pointing users at the Dashboard. A
//! future CLI release that adds the subcommand can flip this to a
//! native implementation in a patch.
//!
//! # Security
//!
//! - Every `infisical` invocation goes through `Command::args([...])`
//!   with individual `&str` — never `sh -c`, never `format!` into a
//!   shell string.
//! - `set()` writes `NAME=VALUE` to a mode-0600 temp file; never to
//!   argv, never to stdin (no stdin form exists).
//! - `infisical_token` travels via `Command::env("INFISICAL_TOKEN", …)`,
//!   never via argv. Canary tests lock this.
//! - `infisical_domain` travels via `Command::env("INFISICAL_API_URL", …)`,
//!   never via argv. Matches the token discipline.
//! - `list()` response body is secret-bearing. Values are returned as
//!   the second element of `(alias, target_uri)` tuples — do NOT use
//!   an Infisical env+path as a registry source unless every entry's
//!   value is a URI. Raw stdout bytes and the parsed `Vec` are never
//!   logged, `Debug`-dumped, or interpolated into errors.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_duration_secs, optional_string, Backend, BackendFactory, BackendStatus, BackendUri,
    DEFAULT_GET_TIMEOUT,
};
use serde::Deserialize;
use tempfile::NamedTempFile;
use tokio::process::Command;

const CLI_NAME: &str = "infisical";

/// Payload-size cutover above which `list()` runs `serde_json` on a
/// tokio `spawn_blocking` worker thread instead of inline. Below it,
/// the thread-pool dispatch cost exceeds the parse cost for a typical
/// small registry; above it, a multi-MB payload would otherwise stall
/// the tokio executor. 256 KiB is a crude threshold but correct
/// directionally; see v0.7.1 build-plan Phase 3.
const LIST_SPAWN_BLOCKING_THRESHOLD: usize = 256 * 1024;
const INSTALL_HINT: &str =
    "brew install infisical/get-cli/infisical  OR  https://infisical.com/docs/cli/overview";
const DEFAULT_DOMAIN: &str = "https://app.infisical.com/api";
const DEFAULT_PATH: &str = "/";

/// A live instance of the Infisical backend.
pub struct InfisicalBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Default project UUID if the URI uses the short form. `None`
    /// forces the URI to supply a project segment.
    infisical_project_id: Option<String>,
    /// Default environment slug if the URI uses the short form.
    /// `None` forces the URI to supply an environment segment.
    infisical_environment: Option<String>,
    /// Default folder path within the environment. Absent ≡ `/`.
    infisical_secret_path: Option<String>,
    /// Instance-scoped token. When set, passed via
    /// `Command::env("INFISICAL_TOKEN", …)` — never argv. When absent,
    /// the CLI inherits from the user's environment or
    /// `infisical login` cache.
    infisical_token: Option<String>,
    /// Self-hosted instance URL (e.g. `https://infisical.acme.com`).
    /// When set, passed via `Command::env("INFISICAL_API_URL", …)` —
    /// never the `--domain` argv flag.
    infisical_domain: Option<String>,
    /// Path or name of the `infisical` binary. Defaults to
    /// `"infisical"` (PATH lookup); tests override to a mock script
    /// path via [`secretenv_testing::StrictMock`].
    infisical_bin: String,
    timeout: Duration,
}

/// A single entry returned by `infisical secrets --output json`.
///
/// `secretKey` is the alias name; `secretValue` is the alias target URI
/// when this backend is configured as a registry source — **this
/// follows the Doppler-style bulk model** where each backend secret IS
/// one alias (rather than a single backend secret storing a serialized
/// alias map). Other fields the CLI emits (`type`, `version`,
/// `createdAt`, `updatedAt`, …) are dropped silently by serde.
///
/// **The response body is secret-bearing.** `secrets --output json`
/// returns every value in the scoped env + path. Errors + traces in
/// this file NEVER interpolate the raw stdout or the parsed `Vec`; the
/// values leave the backend only as alias-target URIs through
/// [`Backend::list`]. Do not configure an Infisical env+path as a
/// registry source unless every entry's value is a URI.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InfisicalListEntry {
    secret_key: String,
    secret_value: String,
}

/// Parsed URI target.
///
/// `secret_path` is owned because the full-form URI may build it from
/// multiple segments (`.../dev/api/stripe/KEY` → `/api/stripe`), and
/// the short form may need to own the config default to return a
/// unified type.
struct ResolvedTarget<'u> {
    project_id: &'u str,
    environment: &'u str,
    secret_path: String,
    secret_name: &'u str,
}

impl InfisicalBackend {
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
            "infisical backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// set()-specific failure message with value-aware stderr scrub.
    /// Replaces every occurrence of the secret value in stderr with
    /// `<REDACTED>` before interpolating. Covers the CLI-parse-error
    /// path that echoes the `--file` contents (NAME=VALUE) back into
    /// the error chain. Short values (<4 chars) are collision-prone so
    /// we don't scrub — the tempfile write path plus CV-1 canary cover
    /// those; the realistic regression is a high-entropy value being
    /// echoed verbatim by a CLI error message.
    fn set_failure_message(&self, uri: &BackendUri, stderr: &[u8], value: &str) -> String {
        let stderr_str = String::from_utf8_lossy(stderr).trim().to_owned();
        let scrubbed = if value.len() >= 4 && stderr_str.contains(value) {
            stderr_str.replace(value, "<REDACTED>")
        } else {
            stderr_str
        };
        format!(
            "infisical backend '{}': set failed for URI '{}': {scrubbed}",
            self.instance_name, uri.raw
        )
    }

    fn effective_domain(&self) -> &str {
        self.infisical_domain.as_deref().unwrap_or(DEFAULT_DOMAIN)
    }

    /// Build an `infisical` command with the shared scoping tail:
    /// `--projectId <p> --env <e> --path <path>` appended after the
    /// caller's args, plus `INFISICAL_TOKEN` and `INFISICAL_API_URL`
    /// applied via env when the instance config supplied them.
    /// Strict-mock tests lock the full argv shape, implicitly locking
    /// that `--token` and `--domain` are NEVER passed.
    fn infisical_command(
        &self,
        args: &[&str],
        project_id: &str,
        environment: &str,
        secret_path: &str,
    ) -> Command {
        let mut cmd = Command::new(&self.infisical_bin);
        cmd.args(args);
        cmd.args(["--projectId", project_id, "--env", environment, "--path", secret_path]);
        // Without null stdin, a subcommand could hang waiting for tty
        // input. No Infisical subcommand here reads stdin; `set` uses
        // `--file` instead (see module docs).
        cmd.stdin(Stdio::null());
        if let Some(token) = &self.infisical_token {
            // NEVER argv — ps -ww would leak it to same-UID processes.
            cmd.env("INFISICAL_TOKEN", token);
        }
        if let Some(domain) = &self.infisical_domain {
            // Symmetric to the token discipline — keep domain off
            // argv even though it's not as sensitive as a secret,
            // so every env for `infisical` spawns looks consistent.
            cmd.env("INFISICAL_API_URL", domain);
        }
        cmd
    }

    /// Resolve `(project_id, environment, secret_path, secret_name)`
    /// from the URI + instance config. Two shapes accepted:
    ///
    /// - 1 non-empty segment → `<secret>`; requires BOTH
    ///   `infisical_project_id` AND `infisical_environment` in instance
    ///   config. Path comes from `infisical_secret_path` or `/`.
    /// - 3+ non-empty segments → `<project>/<env>/[<folder…>]/<secret>`.
    ///   If there are exactly 3 segments, path = `/`. If more, the
    ///   middle segments join into `/part1/part2/…`.
    ///
    /// 0 or 2 segments error locally before shelling out. The 2-seg
    /// rejection is intentional — it could mean project/secret,
    /// env/secret, or folder/secret, and silently guessing would be
    /// worse than a clear bail.
    fn resolve_target<'s, 'u>(&'s self, uri: &'u BackendUri) -> Result<ResolvedTarget<'u>>
    where
        's: 'u,
    {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        match parts.as_slice() {
            [secret] => {
                let project_id = self.infisical_project_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "infisical backend '{}': URI '{}' uses short form but \
                         config is missing 'infisical_project_id' — either set \
                         both 'infisical_project_id' and 'infisical_environment' \
                         under [backends.{}], or switch to the full form \
                         '<instance>:///<project-id>/<env>/<secret>'",
                        self.instance_name,
                        uri.raw,
                        self.instance_name
                    )
                })?;
                let environment = self.infisical_environment.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "infisical backend '{}': URI '{}' uses short form but \
                         config is missing 'infisical_environment' — either set \
                         both 'infisical_project_id' and 'infisical_environment' \
                         under [backends.{}], or switch to the full form",
                        self.instance_name,
                        uri.raw,
                        self.instance_name
                    )
                })?;
                let secret_path =
                    self.infisical_secret_path.as_deref().unwrap_or(DEFAULT_PATH).to_owned();
                Ok(ResolvedTarget { project_id, environment, secret_path, secret_name: secret })
            }
            [project_id, environment, rest @ .., secret_name] => {
                let secret_path = if rest.is_empty() {
                    DEFAULT_PATH.to_owned()
                } else {
                    let mut p = String::from("/");
                    p.push_str(&rest.join("/"));
                    p
                };
                Ok(ResolvedTarget { project_id, environment, secret_path, secret_name })
            }
            _ => bail!(
                "infisical backend '{}': URI '{}' must have either 1 segment \
                 (short form, requires both 'infisical_project_id' and \
                 'infisical_environment' in instance config) or 3+ segments \
                 (full form: <project-id>/<env>/[<folder…>]/<secret>); got \
                 {} segment(s)",
                self.instance_name,
                uri.raw,
                parts.len()
            ),
        }
    }
}

#[async_trait]
impl Backend for InfisicalBackend {
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
        // Level 1: `infisical --version` → CliMissing on ENOENT, else
        //          cli_version string for identity.
        let mut version_cmd = Command::new(&self.infisical_bin);
        version_cmd.arg("--version");
        version_cmd.stdin(Stdio::null());

        let version_out = match version_cmd.output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "infisical backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.infisical_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "infisical backend '{}': 'infisical --version' exited non-zero: {}",
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

        // Level 2: `infisical user get token --plain` → success means
        // a cached `infisical login` token exists. Fed back to us on
        // stdout, which we redirect to /dev/null so the token never
        // materializes in our process memory.
        //
        // Env-var auth (`INFISICAL_TOKEN` in our process env OR the
        // instance's `infisical_token` field) bypasses the local
        // cache — `user get token --plain` will fail under CI-style
        // service-token usage even though subsequent `secrets …`
        // calls work fine. We detect that case and report Ok with a
        // token-auth identity instead of falsely NotAuthenticated.
        let mut probe = Command::new(&self.infisical_bin);
        probe.args(["user", "get", "token", "--plain"]);
        probe.stdin(Stdio::null());
        // Token goes to /dev/null — we don't need its value, only
        // exit status.
        probe.stdout(Stdio::null());
        probe.stderr(Stdio::piped());
        if let Some(token) = &self.infisical_token {
            probe.env("INFISICAL_TOKEN", token);
        }
        if let Some(domain) = &self.infisical_domain {
            probe.env("INFISICAL_API_URL", domain);
        }

        let domain = self.effective_domain().to_owned();
        let identity_user = || format!("auth=user-login domain={domain}");
        let identity_token = || format!("auth=token domain={domain}");

        let env_token_present =
            self.infisical_token.is_some() || std::env::var_os("INFISICAL_TOKEN").is_some();

        match probe.status().await {
            Ok(st) if st.success() => BackendStatus::Ok { cli_version, identity: identity_user() },
            Ok(_) if env_token_present => {
                BackendStatus::Ok { cli_version, identity: identity_token() }
            }
            Ok(_) => BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: infisical login  OR  export INFISICAL_TOKEN=<your-token>  \
                     (domain: {domain})"
                ),
            },
            Err(e) => BackendStatus::Error {
                message: format!(
                    "infisical backend '{}': failed to invoke 'infisical user get token': {e}",
                    self.instance_name
                ),
            },
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        uri.reject_any_fragment("infisical")?;
        let t = self.resolve_target(uri)?;

        let mut cmd = self.infisical_command(
            &["secrets", "get", t.secret_name, "--plain"],
            t.project_id,
            t.environment,
            &t.secret_path,
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "infisical backend '{}': failed to invoke 'infisical secrets get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Infisical emits a few flavors — "not found", "does not
            // exist", and the more specific "Secret with name X does
            // not exist". Match the first two which are substrings of
            // the third.
            if stderr.contains("not found") || stderr.contains("does not exist") {
                bail!(
                    "infisical backend '{}': secret '{}' not found in \
                     project='{}' env='{}' path='{}' (URI '{}')",
                    self.instance_name,
                    t.secret_name,
                    t.project_id,
                    t.environment,
                    t.secret_path,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }

        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "infisical backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `secrets get --plain` appends exactly one '\n'. Strip it.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("infisical")?;
        let t = self.resolve_target(uri)?;

        // No stdin form exists. Write "NAME=VALUE\n" to a
        // mode-0600 NamedTempFile under $TMPDIR, spawn
        // `secrets set --file <path> --type shared`, and let the
        // guard auto-unlink on drop (whether spawn succeeded or not).
        // Value NEVER appears on argv.
        let mut tempfile = NamedTempFile::new().with_context(|| {
            format!(
                "infisical backend '{}': failed to create temp file for set(URI '{}')",
                self.instance_name, uri.raw
            )
        })?;
        // NamedTempFile is mode 0600 on Unix by default (tempfile 3.x
        // uses O_CREAT|O_EXCL with mode 0600); the block below is a
        // belt-and-braces defense-in-depth that's harmless on Windows.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = tempfile
                .as_file()
                .metadata()
                .with_context(|| {
                    format!(
                        "infisical backend '{}': failed to stat temp file for set(URI '{}')",
                        self.instance_name, uri.raw
                    )
                })?
                .permissions();
            perm.set_mode(0o600);
            // fd-based chmod instead of path-based: closes the narrow
            // TOCTOU window between NamedTempFile::new() and chmod that
            // a path-based set_permissions would leave open.
            tempfile.as_file().set_permissions(perm).with_context(|| {
                format!(
                    "infisical backend '{}': failed to chmod 0600 temp file for set(URI '{}')",
                    self.instance_name, uri.raw
                )
            })?;
        }
        writeln!(tempfile.as_file_mut(), "{}={}", t.secret_name, value).with_context(|| {
            format!(
                "infisical backend '{}': failed to write to temp file for set(URI '{}')",
                self.instance_name, uri.raw
            )
        })?;
        tempfile.as_file_mut().sync_all().with_context(|| {
            format!(
                "infisical backend '{}': failed to fsync temp file for set(URI '{}')",
                self.instance_name, uri.raw
            )
        })?;

        // Explicit bail on non-UTF-8 temp-file paths. `to_string_lossy`
        // would silently substitute U+FFFD and the downstream
        // `infisical secrets set --file <garbled>` would fail with an
        // opaque "file not found" — bail explicitly instead.
        let tempfile_path_str = tempfile
            .path()
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "infisical backend '{}': temp file path under $TMPDIR is not \
                     valid UTF-8 for set(URI '{}')",
                    self.instance_name,
                    uri.raw
                )
            })?
            .to_owned();
        let mut cmd = self.infisical_command(
            &["secrets", "set", "--file", &tempfile_path_str, "--type", "shared"],
            t.project_id,
            t.environment,
            &t.secret_path,
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "infisical backend '{}': failed to invoke 'infisical secrets set' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // Explicit drop so the temp file is unlinked immediately — not
        // at scope exit — tightening the on-disk exposure window.
        drop(tempfile);

        if !output.status.success() {
            // Value-aware stderr scrub on set(). A CLI parse-error can
            // echo the `--file` contents (NAME=VALUE) back into stderr;
            // substitute the value with `<REDACTED>` before folding
            // stderr into the error chain so a regression cannot leak
            // the secret through anyhow's propagated context. The scrub
            // is targeted (value-string only) so non-value diagnostic
            // information (argv shape, error reason) is preserved for
            // debugging. Other trait methods (get/delete/list) keep
            // unscrubbed stderr because their stderr is not value-bearing.
            bail!(self.set_failure_message(uri, &output.stderr, value));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("infisical")?;
        let t = self.resolve_target(uri)?;

        // `--type shared` is mandatory — CLI default is `personal`
        // which silently no-ops against project-shared secrets.
        let mut cmd = self.infisical_command(
            &["secrets", "delete", t.secret_name, "--type", "shared"],
            t.project_id,
            t.environment,
            &t.secret_path,
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "infisical backend '{}': failed to invoke 'infisical secrets delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("does not exist") {
                bail!(
                    "infisical backend '{}': secret '{}' not found at URI '{}' \
                     (delete is not idempotent — matches aws-secrets precedent)",
                    self.instance_name,
                    t.secret_name,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("infisical")?;
        // list scopes to project+env+path, not to a single secret. We
        // still need the URI's project+env (or instance defaults via
        // short-form); the URI's secret segment is used as a "registry
        // marker" for addressability and ignored in the call.
        let t = self.resolve_target(uri)?;

        let mut cmd = self.infisical_command(
            &["secrets", "--output", "json"],
            t.project_id,
            t.environment,
            &t.secret_path,
        );
        let output = cmd.output().await.with_context(|| {
            format!(
                "infisical backend '{}': failed to invoke 'infisical secrets' \
                 for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }

        // Response body is secret-bearing — `secrets --output json`
        // returns every value in the scope. Parse via the
        // [`InfisicalListEntry`] struct which ONLY declares
        // `secretKey`; serde silently drops `secretValue` and every
        // other field we don't name. The canary test locks this.
        //
        // Parse on a blocking worker thread when the payload is large
        // enough that serde_json's work becomes meaningful vs. the
        // thread-pool dispatch cost (>= 256 KiB — crude heuristic but
        // correct directionally: a small registry stays inline, a
        // multi-MB payload stops stalling the tokio executor). Small
        // payloads take the zero-overhead inline path.
        let entries: Vec<InfisicalListEntry> = if output.stdout.len() >= LIST_SPAWN_BLOCKING_THRESHOLD {
            let bytes = output.stdout;
            tokio::task::spawn_blocking(move || {
                serde_json::from_slice::<Vec<InfisicalListEntry>>(&bytes)
            })
            .await
            .with_context(|| {
                format!(
                    "infisical backend '{}': list JSON-parse worker panicked for URI '{}'",
                    self.instance_name, uri.raw
                )
            })?
            .with_context(|| {
                format!(
                    "infisical backend '{}': 'infisical secrets --output json' returned \
                         a payload that is not a JSON array of {{secretKey, …}} objects \
                         (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?
        } else {
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "infisical backend '{}': 'infisical secrets --output json' returned \
                     a payload that is not a JSON array of {{secretKey, …}} objects \
                     (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?
        };

        // list() returns (alias, target-uri) pairs. The Doppler-style
        // bulk model: each Infisical secret name = one alias, each
        // Infisical secret value = the alias's target URI (user stored
        // URI strings as values). The resolver parses the target URI
        // and validates its backend scheme; a non-URI value surfaces
        // as a clean "not a valid URI" error upstream.
        Ok(entries.into_iter().map(|e| (e.secret_key, e.secret_value)).collect())
    }

    async fn history(&self, uri: &BackendUri) -> Result<Vec<secretenv_core::HistoryEntry>> {
        // Override trait default so we can reject fragments AND
        // surface an Infisical-specific explanation. Per-secret
        // version history exists in the Infisical Dashboard + REST
        // API but the CLI (v0.43.77) exposes no `secrets versions`
        // subcommand. The wraps-CLI constraint means we can't
        // implement history until the CLI adds it.
        uri.reject_any_fragment("infisical")?;
        bail!(
            "infisical backend '{}': history is not supported — the `infisical` \
             CLI (v0.43.77) has no per-secret version-history subcommand; version \
             history IS available in the Infisical Dashboard and REST API. A \
             future CLI release adding `infisical secrets versions` can flip this \
             to a native implementation.",
            self.instance_name
        )
    }
}

/// Factory for the Infisical backend.
///
/// No required config fields — every field is optional because
/// Infisical inherits auth from the CLI's login state OR from
/// `$INFISICAL_TOKEN` in the user's env. The factory validates that
/// `infisical_project_id` and `infisical_environment` are either
/// both-set or both-unset: a half-configured short-form default is
/// a footgun (URIs relying on the short form would fail with half
/// the defaults, surfacing only at get-time).
pub struct InfisicalFactory(&'static str);

impl InfisicalFactory {
    /// Construct the factory. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self("infisical")
    }
}

impl Default for InfisicalFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for InfisicalFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let infisical_project_id =
            optional_string(config, "infisical_project_id", "infisical", instance_name)?;
        let infisical_environment =
            optional_string(config, "infisical_environment", "infisical", instance_name)?;

        // Both-or-neither rule. A user setting just one of the two
        // would get a confusing "missing field" error at every
        // short-form get() instead of at config-load time.
        match (&infisical_project_id, &infisical_environment) {
            (Some(_), None) => bail!(
                "infisical instance '{instance_name}': field 'infisical_project_id' is set \
                 but 'infisical_environment' is not — short-form URIs require both or \
                 neither. Either add 'infisical_environment' or remove \
                 'infisical_project_id' and use full URIs \
                 ('<instance>:///<project-id>/<env>/<secret>')."
            ),
            (None, Some(_)) => bail!(
                "infisical instance '{instance_name}': field 'infisical_environment' is set \
                 but 'infisical_project_id' is not — short-form URIs require both or \
                 neither. Either add 'infisical_project_id' or remove \
                 'infisical_environment' and use full URIs."
            ),
            _ => {}
        }

        let infisical_secret_path =
            optional_string(config, "infisical_secret_path", "infisical", instance_name)?;
        let infisical_token =
            optional_string(config, "infisical_token", "infisical", instance_name)?;
        let infisical_domain =
            optional_string(config, "infisical_domain", "infisical", instance_name)?;
        let infisical_bin = optional_string(config, "infisical_bin", "infisical", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "infisical", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);

        Ok(Box::new(InfisicalBackend {
            backend_type: "infisical",
            instance_name: instance_name.to_owned(),
            infisical_project_id,
            infisical_environment,
            infisical_secret_path,
            infisical_token,
            infisical_domain,
            infisical_bin,
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

    const PROJECT: &str = "abc-123";
    const ENV: &str = "prod";
    const PATH: &str = "/";

    /// Serialize every test that mutates `INFISICAL_TOKEN` so parallel
    /// cargo-test threads don't race on the process-global env table.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard: unset a single env var for the duration of a test
    /// scope, restore on drop. Acquires `ENV_LOCK` so only one such
    /// scope executes at a time across test threads. Poisoned-mutex
    /// recovery: a panic while holding the guard may leave the env
    /// unset until another guard runs — acceptable because the guard's
    /// only declared var (`INFISICAL_TOKEN`) is unset by default on
    /// developer machines, and CI environments start fresh per job.
    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvVarGuard {
        fn unset(key: &'static str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, prev, _lock: lock }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn backend(mock_path: &Path, token: Option<&str>, domain: Option<&str>) -> InfisicalBackend {
        InfisicalBackend {
            backend_type: "infisical",
            instance_name: "infisical-prod".to_owned(),
            infisical_project_id: Some(PROJECT.to_owned()),
            infisical_environment: Some(ENV.to_owned()),
            infisical_secret_path: None,
            infisical_token: token.map(ToOwned::to_owned),
            infisical_domain: domain.map(ToOwned::to_owned),
            infisical_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_no_defaults(mock_path: &Path) -> InfisicalBackend {
        InfisicalBackend {
            backend_type: "infisical",
            instance_name: "infisical-prod".to_owned(),
            infisical_project_id: None,
            infisical_environment: None,
            infisical_secret_path: None,
            infisical_token: None,
            infisical_domain: None,
            infisical_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_missing_bin() -> InfisicalBackend {
        InfisicalBackend {
            backend_type: "infisical",
            instance_name: "infisical-prod".to_owned(),
            infisical_project_id: Some(PROJECT.to_owned()),
            infisical_environment: Some(ENV.to_owned()),
            infisical_secret_path: None,
            infisical_token: None,
            infisical_domain: None,
            infisical_bin: "/definitely/not/a/real/path/to/infisical-XYZ987".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const TOKEN_PROBE_ARGV: &[&str] = &["user", "get", "token", "--plain"];

    /// Argv shape every non-check subcommand uses. The trailing
    /// `--projectId <p> --env <e> --path <path>` is appended by
    /// `infisical_command`; strict mocks lock the whole string so a
    /// regression that dropped any scoping flag would produce exit 97.
    fn get_argv(secret: &str) -> [&str; 10] {
        ["secrets", "get", secret, "--plain", "--projectId", PROJECT, "--env", ENV, "--path", PATH]
    }

    fn delete_argv(secret: &str) -> [&str; 11] {
        [
            "secrets",
            "delete",
            secret,
            "--type",
            "shared",
            "--projectId",
            PROJECT,
            "--env",
            ENV,
            "--path",
            PATH,
        ]
    }

    const LIST_ARGV: &[&str] =
        &["secrets", "--output", "json", "--projectId", PROJECT, "--env", ENV, "--path", PATH];

    fn check_mock_ok(_dir: &Path) -> StrictMock {
        StrictMock::new("infisical")
            .on(VERSION_ARGV, Response::success("infisical version 0.43.77\n"))
            .on(TOKEN_PROBE_ARGV, Response::success(""))
    }

    // ---- Factory ----

    #[test]
    fn factory_backend_type_is_infisical() {
        assert_eq!(InfisicalFactory::new().backend_type(), "infisical");
    }

    #[test]
    fn factory_accepts_empty_config() {
        let factory = InfisicalFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("infisical-default", &cfg).unwrap();
        assert_eq!(b.backend_type(), "infisical");
        assert_eq!(b.instance_name(), "infisical-default");
    }

    #[test]
    fn factory_accepts_both_defaults() {
        let factory = InfisicalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("infisical_project_id".to_owned(), toml::Value::String("abc-123".to_owned()));
        cfg.insert("infisical_environment".to_owned(), toml::Value::String("prod".to_owned()));
        factory.create("infisical-prod", &cfg).unwrap();
    }

    #[test]
    fn factory_rejects_half_configured_defaults_project_only() {
        let factory = InfisicalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("infisical_project_id".to_owned(), toml::Value::String("abc-123".to_owned()));
        let Err(err) = factory.create("infisical-prod", &cfg) else {
            panic!("expected error when only infisical_project_id is set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("infisical_environment"), "names missing field: {msg}");
        assert!(msg.contains("short-form"), "explains why: {msg}");
    }

    #[test]
    fn factory_rejects_half_configured_defaults_env_only() {
        let factory = InfisicalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("infisical_environment".to_owned(), toml::Value::String("prod".to_owned()));
        let Err(err) = factory.create("infisical-prod", &cfg) else {
            panic!("expected error when only infisical_environment is set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("infisical_project_id"), "names missing field: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_token() {
        let factory = InfisicalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("infisical_token".to_owned(), toml::Value::Integer(42));
        let Err(err) = factory.create("infisical-prod", &cfg) else {
            panic!("expected error on non-string token");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = InfisicalFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(17));
        let b = factory.create("infisical-prod", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(17));
    }

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_missing_bin();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "infisical");
                assert!(install_hint.contains("infisical/get-cli/infisical"));
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_user_login_identity() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert_eq!(cli_version, "infisical version 0.43.77");
                assert!(
                    identity.contains("auth=user-login"),
                    "identity names auth mode: {identity}"
                );
                assert!(
                    identity.contains("domain=https://app.infisical.com/api"),
                    "identity includes default domain: {identity}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_token_auth_when_probe_fails_but_config_token_present() {
        // Simulates CI: user has a service-token in instance config
        // (or INFISICAL_TOKEN env), but `user get token --plain`
        // fails because there's no cached login.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(VERSION_ARGV, Response::success("infisical version 0.43.77\n"))
            .on(TOKEN_PROBE_ARGV, Response::failure(1, "no cached token\n"))
            .install(dir.path());
        let b = backend(&mock, Some("st.xxx.yyy"), None);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("auth=token"), "token-auth mode: {identity}");
            }
            other => panic!("expected Ok (token-auth), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_not_authenticated_when_probe_fails_and_no_token() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(VERSION_ARGV, Response::success("infisical version 0.43.77\n"))
            .on(TOKEN_PROBE_ARGV, Response::failure(1, "not logged in\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        // Deterministic env isolation: unset INFISICAL_TOKEN for the
        // test duration regardless of parent-process state, and
        // restore on drop. The `ENV_LOCK` mutex serializes every test
        // that mutates INFISICAL_TOKEN so parallel `cargo test` threads
        // don't race on the global env table.
        let _guard = EnvVarGuard::unset("INFISICAL_TOKEN");
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("infisical login"), "hint: {hint}");
                assert!(hint.contains("INFISICAL_TOKEN"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_identity_reports_custom_domain() {
        let dir = TempDir::new().unwrap();
        let mock = check_mock_ok(dir.path()).install(dir.path());
        let b = backend(&mock, None, Some("https://infisical.acme.com"));
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(
                    identity.contains("domain=https://infisical.acme.com"),
                    "identity includes custom domain: {identity}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_full_form_returns_secret() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_short_form_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_folder_path_forms_uri() {
        // Middle segments between env and secret name fold into path.
        let dir = TempDir::new().unwrap();
        let folder_argv: &[&str] = &[
            "secrets",
            "get",
            "STRIPE_KEY",
            "--plain",
            "--projectId",
            PROJECT,
            "--env",
            ENV,
            "--path",
            "/api/stripe",
        ];
        let mock = StrictMock::new("infisical")
            .on(folder_argv, Response::success("sk_live_abc\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri =
            BackendUri::parse("infisical-prod:///abc-123/prod/api/stripe/STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_abc");
    }

    #[tokio::test]
    async fn get_short_form_without_defaults_errors_locally() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend_no_defaults(&mock);
        let uri = BackendUri::parse("infisical-prod:///STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("short form"), "names the form: {msg}");
        assert!(msg.contains("infisical_project_id"), "names field: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from resolve, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_collapses_empty_segments_to_two_segment_form() {
        // Drift-catch: `resolve_target` uses `.filter(|s| !s.is_empty())`
        // so `/abc-123//KEY` collapses to `[abc-123, KEY]` — the
        // 2-segment form — and bails there. If the filter were ever
        // removed, an empty middle segment would pass through and
        // the backend would call the CLI with `--path //` which
        // Infisical might accept silently. Lock the current
        // behavior.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123//STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1 segment") && msg.contains("3+ segments"), "{msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from resolve, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_two_segment_uri() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1 segment") && msg.contains("3+ segments"), "{msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from resolve, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("infisical"), "names backend: {msg}");
        assert!(
            !msg.contains("strict-mock-no-match"),
            "error must come from reject, not subprocess: {msg}"
        );
    }

    #[tokio::test]
    async fn get_not_found_stderr_shapes_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(
                &get_argv("MISSING"),
                Response::failure(1, "error: Secret with name MISSING does not exist\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/MISSING").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "friendly text: {msg}");
        assert!(msg.contains("project='abc-123'"), "names project: {msg}");
        assert!(msg.contains("env='prod'"), "names env: {msg}");
    }

    #[tokio::test]
    async fn get_strips_single_trailing_newline() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&get_argv("MULTILINE"), Response::success("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/MULTILINE").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_value_never_appears_on_argv() {
        // CV-1 canary using the strict-mock's no-match diagnostic.
        // StrictMock dumps the observed argv verbatim in stderr when
        // no rule matches (exit 97). We pass a uniquely-recognizable
        // canary value through set(), install an EMPTY-rule mock
        // (every invocation trips no-match), and assert the canary
        // is absent from the dumped argv.
        //
        // Dual-purpose: this test also drift-catches `--type shared`
        // on set() (assertion at bottom of this fn). If a regression
        // dropped the explicit `--type shared` flag, this test would
        // fail its shape assertion — paired with
        // `delete_requires_type_shared_flag` to lock the CLI-default
        // `--type personal` footgun on both mutation paths.
        //
        // If a regression passed the value on argv as
        // `SECRET_NAME=<canary>` (the CLI's native positional form),
        // the canary would land in the strict-mock diagnostic and
        // fail the assertion.
        let canary_value = "sk_live_TOP_SECRET_infisical_never_in_argv_ABC42";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();

        // set() will spawn, strict-mock returns exit 97 with no-match
        // diagnostic in stderr, set() propagates as an error
        // including the diagnostic via `operation_failure_message`.
        let err = b.set(&uri, canary_value).await.unwrap_err();
        let msg = format!("{err:#}");

        assert!(
            msg.contains("strict-mock-no-match"),
            "expected no-match diagnostic in error: {msg}"
        );
        assert!(
            !msg.contains(canary_value),
            "canary value leaked to argv — set() must pass value via \
             --file tempfile, never argv: {msg}"
        );
        // Also assert the expected shape flags ARE present in argv.
        assert!(msg.contains("--file"), "--file flag present: {msg}");
        assert!(msg.contains("--type shared"), "--type shared present: {msg}");
    }

    #[tokio::test]
    async fn set_writes_tempfile_with_mode_0600() {
        // Can't observe the tempfile after set() returns (it's
        // auto-unlinked), but we CAN observe it mid-spawn via the
        // strict-mock no-match diagnostic — the file path appears in
        // the dumped argv. Parse it out, re-stat (race with unlink
        // may lose on some platforms — accept that and skip the
        // permissions check under that flake).
        //
        // This test is a structural smoke that the tempfile is
        // present in argv at all. The perms check happens
        // implicitly via `NamedTempFile`'s documented O_EXCL|0600
        // semantics on Unix, plus our explicit chmod fallback.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();

        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        // Path segment between `--file` and the next `--` flag. We
        // don't parse it out rigorously; we just confirm the argv
        // includes a `/tmp/` or `$TMPDIR/`-like path after `--file`.
        assert!(msg.contains("--file"), "--file in argv: {msg}");
    }

    #[tokio::test]
    async fn set_failure_message_scrubs_value_from_stderr() {
        // Regression test for the v0.7.1 `set()` stderr-redaction item.
        // If a future `infisical` CLI echoes the `--file` contents back
        // in a parse-error, the NAME=VALUE line would surface in
        // set()'s stderr. Assert that `set_failure_message` removes the
        // value string before folding stderr into the error.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        let canary = "sk_live_TOP_SECRET_set_failure_stderr_scrub_XYZ99";
        let synthetic_stderr = format!("parse error: STRIPE_KEY={canary}\n");

        let msg = b.set_failure_message(&uri, synthetic_stderr.as_bytes(), canary);

        assert!(!msg.contains(canary), "canary leaked in set_failure_message output: {msg}");
        assert!(msg.contains("<REDACTED>"), "expected <REDACTED> marker: {msg}");
        assert!(msg.contains("STRIPE_KEY"), "non-value diagnostic preserved: {msg}");
    }

    #[tokio::test]
    async fn set_failure_message_passthrough_when_value_absent() {
        // Scrub must be a no-op when the value isn't present in
        // stderr. Preserves diagnostic content for the common case
        // (permission denied, network error, etc.).
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        let msg = b.set_failure_message(
            &uri,
            b"error: 403 forbidden (token lacks 'secrets:write')\n",
            "some-value",
        );
        assert!(msg.contains("403 forbidden"), "diagnostic preserved: {msg}");
        assert!(!msg.contains("<REDACTED>"), "no-op when value absent: {msg}");
    }

    #[tokio::test]
    async fn set_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY#version=5").unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess"
        );
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_happy_uses_type_shared() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&delete_argv("OLD_KEY"), Response::success("deleted\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/OLD_KEY").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_bails() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(
                &delete_argv("MISSING"),
                Response::failure(1, "error: Secret with name MISSING does not exist\n"),
            )
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/MISSING").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("not found"));
    }

    #[tokio::test]
    async fn delete_requires_type_shared_flag() {
        // Drift-catch: the CLI default for `--type` is `personal`.
        // A regression that dropped our explicit `--type shared` would
        // produce an argv that no longer matches `delete_argv` —
        // strict mock returns exit 97 `strict-mock-no-match`.
        // Declares the BROKEN form and asserts the strict mock DOES
        // match it (proving our mock would catch a drop), then the
        // happy-path test elsewhere proves we don't emit the broken
        // form.
        let dir = TempDir::new().unwrap();
        let broken_argv: &[&str] = &[
            "secrets",
            "delete",
            "OLD_KEY",
            // no "--type shared"
            "--projectId",
            PROJECT,
            "--env",
            ENV,
            "--path",
            PATH,
        ];
        let mock = StrictMock::new("infisical")
            .on(broken_argv, Response::success("deleted\n"))
            .install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/OLD_KEY").unwrap();
        // Our real delete uses `--type shared`, which does NOT match
        // `broken_argv`, so the mock fires exit 97.
        let err = b.delete(&uri).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("strict-mock-no-match")
                || format!("{err:#}").contains("delete"),
            "proves our argv shape diverges from the broken form"
        );
    }

    // ---- list ----

    #[tokio::test]
    async fn list_returns_name_value_pairs() {
        // Doppler-style bulk model: each Infisical secret name = one
        // alias, each secret value = alias target URI. The resolver
        // downstream of this call parses the value as a BackendUri, so
        // the test values here are shaped like real URIs.
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"secretKey":"STRIPE_KEY","secretValue":"aws-ssm-prod:///stripe/api-key"},
            {"secretKey":"DB_URL","secretValue":"vault-dev:///secret/db"}
        ]"#;
        let mock =
            StrictMock::new("infisical").on(LIST_ARGV, Response::success(body)).install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/REGISTRY").unwrap();
        let mut out = b.list(&uri).await.unwrap();
        out.sort();
        assert_eq!(
            out,
            vec![
                ("DB_URL".to_owned(), "vault-dev:///secret/db".to_owned()),
                ("STRIPE_KEY".to_owned(), "aws-ssm-prod:///stripe/api-key".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_ignores_unknown_fields() {
        // CLI payload may grow new fields in future versions (type,
        // version, createdAt, updatedAt, environment, etc.). Our
        // struct names only `secretKey` and `secretValue`; serde
        // drops every other field silently. Locks forward
        // compatibility.
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"secretKey":"STRIPE_KEY","secretValue":"aws-ssm-prod:///stripe","type":"shared","version":3,"createdAt":"2026-01-01"}
        ]"#;
        let mock =
            StrictMock::new("infisical").on(LIST_ARGV, Response::success(body)).install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/REG").unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out, vec![("STRIPE_KEY".to_owned(), "aws-ssm-prod:///stripe".to_owned())]);
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/REG#version=5").unwrap();
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
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("history is not supported"), "{msg}");
        assert!(msg.contains("Dashboard"), "{msg}");
        assert!(!msg.contains("strict-mock-no-match"), "unsupported error must precede subprocess");
    }

    #[tokio::test]
    async fn history_rejects_fragment_before_unsupported_message() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical").install(dir.path());
        let b = backend(&mock, None, None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY#version=5").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        // Fragment-reject wins BEFORE the "unsupported" bail. The user
        // sees the URI mistake instead of a misleading "not supported"
        // message that obscures the fragment typo.
        assert!(!msg.contains("history is not supported"), "{msg}");
        assert!(msg.contains("infisical"), "fragment-reject names backend: {msg}");
    }

    // ---- token-via-env canary ----

    #[tokio::test]
    async fn token_travels_via_env_not_argv() {
        // StrictMock produces exit 97 if argv doesn't match the
        // declared shape. Our declared `get_argv` does NOT include
        // `--token`. If a regression passed the token as
        // `--token <value>`, argv length would diverge and the mock
        // would fail with strict-mock-no-match — locking env-only
        // discipline.
        let canary_token = "st.TOKEN_NEVER_IN_ARGV_XYZ";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live\n"))
            .install(dir.path());
        let b = backend(&mock, Some(canary_token), None);
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn domain_travels_via_env_not_argv() {
        // Same discipline as token: `--domain` must not appear on
        // argv. The `get_argv` shape asserts zero `--domain` tokens.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("infisical")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live\n"))
            .install(dir.path());
        let b = backend(&mock, None, Some("https://infisical.acme.com"));
        let uri = BackendUri::parse("infisical-prod:///abc-123/prod/STRIPE_KEY").unwrap();
        b.get(&uri).await.unwrap();
    }
}
