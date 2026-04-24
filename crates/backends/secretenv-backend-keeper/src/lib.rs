// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Keeper Security vault backend for SecretEnv.
//!
//! Wraps the `keeper` CLI (Keeper Commander v17+, installed via
//! `pip install keepercommander`). Unlike other backends whose CLIs
//! persist session state across one-shot invocations transparently,
//! Keeper Commander requires **persistent-login setup as a
//! prerequisite**: one-shot `keeper <cmd>` invocations prompt for the
//! master password unless a device token is persisted to
//! `~/.keeper/config.json` via:
//!
//! ```text
//! keeper shell
//! > this-device register
//! > this-device persistent-login on
//! > quit
//! ```
//!
//! Every backend invocation uses `--batch-mode` to prevent interactive
//! prompts. If persistent-login isn't set up, the backend surfaces a
//! clean "not authenticated" status rather than hanging on an
//! interactive prompt.
//!
//! # URI shape
//!
//! `<instance>:///<record-uid-or-title>` — one path segment. The
//! Keeper CLI accepts either a 22-char base64url UID or a record
//! title; this backend passes the segment through unchanged.
//!
//! Fragment `#field=<name>` selects a custom field by name. Default
//! (no fragment) returns the `password` field via `--format=password`.
//!
//! # Config fields
//!
//! - `keeper_folder` (optional) — reserved for future short-form
//!   scoping; currently unused.
//! - `keeper_config_path` (optional) — path to the Keeper Commander
//!   `config.json` holding the persisted device token. Defaults to
//!   `~/.keeper/config.json` (resolved by the CLI itself when
//!   `--config` is omitted).
//! - `keeper_unsafe_set` (optional) — default **`false`**. When
//!   `false`, `set()` bails. When `true`, opts into argv-based
//!   `set()` via `record-add`/`record-update` — the Keeper CLI has no
//!   stdin form for field values, so argv exposure via `ps -ww` is
//!   unavoidable. Matches the 1Password `op_unsafe_set` precedent.
//! - `timeout_secs` (optional) — per-instance deadline. Default
//!   [`DEFAULT_GET_TIMEOUT`].
//! - `keeper_bin` (optional, test hook) — override the `keeper`
//!   binary path.
//!
//! # `list()` — Pattern A bulk model
//!
//! `keeper list --format=json` returns an array of record-metadata
//! objects. This backend maps each record's `title` to a `(title,
//! password-field)` pair — mirroring Doppler + Infisical's bulk
//! model where each record IS one alias and the record's password
//! value serves as the alias target URI. Users seed URI-valued
//! records for the registry-source use case; the backend doesn't
//! pre-validate URI shape (the resolver does so downstream).
//!
//! # `history()` — unsupported via CLI
//!
//! Keeper Commander's `history` subcommand is COMMAND history
//! (interactive shell input lines), NOT per-record version history.
//! Record history is available in the Keeper Vault UI and via the
//! REST API but has no CLI surface at v17.2.13. [`Backend::history`]
//! overrides the trait default with a Keeper-specific bail pointing
//! users at the Vault UI.
//!
//! # Security
//!
//! - Every `keeper` invocation goes through `Command::args([...])`
//!   with individual `&str` — never `sh -c`, never `format!` into a
//!   shell string.
//! - Master password is NEVER read by this backend. Auth flows
//!   through the persistent-login device token stored in
//!   `~/.keeper/config.json`.
//! - `set()` exposes values via argv (CLI has no stdin form). Gated
//!   behind `keeper_unsafe_set = true` opt-in; emits
//!   `tracing::warn!` per invocation naming the instance + URI +
//!   exposure mechanism.
//! - Response bodies are secret-bearing. Errors never interpolate
//!   stdout; tracing fields never include the value.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_bool, optional_duration_secs, optional_string, Backend, BackendFactory, BackendStatus,
    BackendUri, DEFAULT_GET_TIMEOUT,
};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "keeper";
const INSTALL_HINT: &str =
    "pip install keepercommander  OR  https://docs.keeper.io/en/keeperpam/commander-cli";

/// A live instance of the Keeper backend.
pub struct KeeperBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Reserved for future short-form URI scoping. Currently unused;
    /// the v0.8 URI shape is a single segment (UID or title).
    #[allow(dead_code)]
    keeper_folder: Option<String>,
    /// Path to `~/.keeper/config.json` (or an equivalent config file)
    /// holding the persisted device token from `this-device
    /// persistent-login on`. `None` → the CLI's default resolution
    /// path (`~/.keeper/config.json`).
    keeper_config_path: Option<String>,
    /// Opt-in gate for argv-based `set()`. Default `false` → `set()`
    /// bails with a safer-path pointer. `true` → `record-add` /
    /// `record-update` with value on argv (visible via `ps -ww`).
    /// Mirrors 1Password's `op_unsafe_set` precedent.
    keeper_unsafe_set: bool,
    /// Path or name of the `keeper` binary. Defaults to `"keeper"`
    /// (PATH lookup); tests override to a mock script path via
    /// [`secretenv_testing::StrictMock`].
    keeper_bin: String,
    timeout: Duration,
}

/// Parsed identity from `keeper --batch-mode whoami`. The Commander
/// CLI at v17.2.13 has NO `--format json` flag on whoami — output is
/// plain text with `User: <email>` and `Server: <host>` lines. We
/// scan those two lines and ignore everything else; a CLI minor
/// release that adds lines or reorders them doesn't break this parse.
#[derive(Default)]
struct KeeperWhoami {
    user: Option<String>,
    server: Option<String>,
}

impl KeeperWhoami {
    /// Parse the plain-text `keeper whoami` stdout. Looks for lines
    /// containing `"User:"` and `"Server:"` (case-sensitive, with
    /// leading whitespace tolerated). Any other shape → `Default`
    /// (both `None`), which the caller renders as `user=unknown
    /// server=default`.
    fn parse(stdout: &str) -> Self {
        let mut out = Self::default();
        for line in stdout.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("User:") {
                out.user = Some(rest.trim().to_owned());
            } else if let Some(rest) = trimmed.strip_prefix("Server:") {
                out.server = Some(rest.trim().to_owned());
            }
        }
        out
    }
}

/// Parsed list entry. `keeper list --format=json` returns an array of
/// objects with `title`, `record_uid`, `type`, and (for legacy records)
/// a `password` field OR (for typed records) a `fields` array
/// containing typed field entries.
///
/// For v0.8 MVP we parse just `title` — the password value is fetched
/// per-record via `keeper get --format=password` inside the list flow.
/// This keeps the bulk response parse narrow and defensive (serde
/// silently drops every field we don't name).
#[derive(Deserialize)]
struct KeeperListEntry {
    title: String,
    // `uid` alias covers the abbreviated key shape some CLI list
    // payloads use; the canonical `record_uid` key matches the field
    // name so no alias is needed for it.
    #[serde(alias = "uid", default)]
    #[allow(dead_code)]
    record_uid: Option<String>,
}

/// Parsed `keeper get --format=json --unmask` output. Schema is
/// record-type-dependent. We extract ONLY what we need for field-by-
/// name resolution via the `#field=<name>` fragment:
///
/// - `fields`: typed-field array (login, password, url, etc.)
/// - `custom`: custom-field array (user-defined labels)
///
/// Secret values appear inside these arrays as `value: [<string>]` —
/// Keeper normalizes single-valued fields into a length-1 array.
#[derive(Deserialize, Default)]
struct KeeperRecordJson {
    #[serde(default)]
    fields: Vec<KeeperField>,
    #[serde(default)]
    custom: Vec<KeeperField>,
}

#[derive(Deserialize)]
struct KeeperField {
    #[serde(default)]
    label: Option<String>,
    #[serde(default, rename = "type")]
    field_type: Option<String>,
    #[serde(default)]
    value: Vec<serde_json::Value>,
}

impl KeeperBackend {
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
            "keeper backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `keeper` command with the shared preamble every
    /// operation uses: `--batch-mode` (mandatory, prevents interactive
    /// prompts that would hang the backend) + optional `--config
    /// <path>`. Caller's `args` are appended AFTER the preamble so the
    /// strict-mock argv shape locks the whole invocation.
    fn keeper_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.keeper_bin);
        // `--batch-mode` goes BEFORE the subcommand. If the persistent-
        // login token is stale or missing, the CLI exits non-zero
        // instead of prompting for a master password.
        cmd.arg("--batch-mode");
        if let Some(path) = &self.keeper_config_path {
            cmd.args(["--config", path]);
        }
        cmd.args(args);
        // Null stdin — Keeper Commander never reads stdin in batch
        // mode, but the null silences any edge case where a CLI bug
        // tries to open /dev/tty.
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Extract a named field from a [`KeeperRecordJson`]. Priority:
    /// custom-field label match → typed-field label match → typed-
    /// field type match. Case-insensitive matching throughout lets
    /// `#field=api_key` match a record whose label is `API_KEY`.
    /// Returns the first stringified value.
    ///
    /// The type-name fallback is deliberate — `#field=password`
    /// pulls the typed `password` field when no label of that name
    /// exists. This matches CLI semantics (`keeper get --format=json`
    /// typed-field shape) but can surprise: `#field=login` pulls the
    /// typed `login` field which is the USERNAME, not the password.
    /// Prefer label-driven selection when possible; type-name is the
    /// escape hatch for legacy records without labels.
    fn extract_field<'a>(record: &'a KeeperRecordJson, name: &str) -> Option<&'a str> {
        let find_by_label_ci = |list: &'a [KeeperField]| -> Option<&'a KeeperField> {
            list.iter().find(|f| f.label.as_deref().is_some_and(|l| l.eq_ignore_ascii_case(name)))
        };
        let find_by_type_ci = |list: &'a [KeeperField]| -> Option<&'a KeeperField> {
            list.iter()
                .find(|f| f.field_type.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(name)))
        };
        find_by_label_ci(&record.custom)
            .or_else(|| find_by_label_ci(&record.fields))
            .or_else(|| find_by_type_ci(&record.fields))
            .and_then(|f| f.value.first())
            .and_then(|v| v.as_str())
    }

    /// Parse an optional `field=<name>` directive from `uri.fragment`.
    /// `None` fragment OR an empty fragment → `None` (use default
    /// password-field). Any other shape is rejected with a specific
    /// error — ensures `#version=5` (v0.2.1 vocabulary) doesn't
    /// silently get treated as field selection.
    fn parse_field_fragment<'a>(&self, uri: &'a BackendUri) -> Result<Option<&'a str>> {
        let Some(frag) = &uri.fragment else {
            return Ok(None);
        };
        if frag.is_empty() {
            return Ok(None);
        }
        if let Some(name) = frag.strip_prefix("field=") {
            if name.is_empty() {
                bail!(
                    "keeper backend '{}': URI '{}' has empty #field= directive; \
                     either drop the fragment to read the password field or pass \
                     '#field=<name>'",
                    self.instance_name,
                    uri.raw
                );
            }
            return Ok(Some(name));
        }
        bail!(
            "keeper backend '{}': URI '{}' fragment '{frag}' is not recognized — \
             only '#field=<name>' is supported",
            self.instance_name,
            uri.raw
        )
    }

    /// Resolve the single URI segment (record UID or title). Empty
    /// path is rejected locally — there's nothing to look up.
    fn resolve_target<'u>(&self, uri: &'u BackendUri) -> Result<&'u str> {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            bail!(
                "keeper backend '{}': URI '{}' has no record UID or title — \
                 expected '<instance>:///<record-uid-or-title>'",
                self.instance_name,
                uri.raw
            );
        }
        if trimmed.contains('/') {
            bail!(
                "keeper backend '{}': URI '{}' has more than one path segment; \
                 Keeper URIs take exactly one segment (record UID or title), \
                 not folder-path-plus-title",
                self.instance_name,
                uri.raw
            );
        }
        Ok(trimmed)
    }
}

#[async_trait]
impl Backend for KeeperBackend {
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
        //   Level 1: `keeper --version` → CliMissing on ENOENT.
        //   Level 2: `keeper --batch-mode login-status` → Ok if stdout
        //            contains "Logged in". Any other shape (including
        //            missing persistent-login token prompting for a
        //            password — which exits non-zero under --batch-
        //            mode) → NotAuthenticated with setup hint.
        let version_fut = {
            let mut c = Command::new(&self.keeper_bin);
            c.arg("--version");
            c.stdin(Stdio::null());
            c.output()
        };

        let login_fut = self.keeper_command(&["login-status"]).output();

        let (version_res, login_res) = tokio::join!(version_fut, login_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "keeper backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.keeper_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "keeper backend '{}': 'keeper --version' exited non-zero: {}",
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
        let login_out = match login_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "keeper backend '{}': failed to invoke 'keeper login-status': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        let login_stdout = String::from_utf8_lossy(&login_out.stdout);
        if !login_out.status.success() || !login_stdout.contains("Logged in") {
            return BackendStatus::NotAuthenticated {
                hint: "set up persistent login: 'keeper shell' → 'this-device register' → \
                       'this-device persistent-login on' → 'quit'"
                    .to_owned(),
            };
        }

        // Try to enrich identity with whoami; failure is non-fatal —
        // we already know the device token is valid. whoami is
        // plain-text-only at CLI v17.2.13 (no `--format` option);
        // KeeperWhoami::parse scans two named lines.
        let whoami = self.keeper_command(&["whoami"]).output().await;
        let identity = match whoami {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let parsed = KeeperWhoami::parse(&stdout);
                let user = parsed.user.as_deref().unwrap_or("unknown");
                let server = parsed.server.as_deref().unwrap_or("default");
                format!("user={user} server={server} auth=persistent-login")
            }
            _ => "auth=persistent-login".to_owned(),
        };

        BackendStatus::Ok { cli_version, identity }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let target = self.resolve_target(uri)?;
        let field = self.parse_field_fragment(uri)?;

        // Default (no fragment) → --format=password returns the
        // password field as a raw string. With a field fragment we
        // use --format=json + our own field extraction.
        let format = if field.is_some() { "json" } else { "password" };
        let mut cmd = self.keeper_command(&["get", target, "--format", format, "--unmask"]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "keeper backend '{}': failed to invoke 'keeper get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("Cannot find") {
                bail!(
                    "keeper backend '{}': record '{target}' not found (URI '{}')",
                    self.instance_name,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }

        match field {
            None => {
                let stdout = String::from_utf8(output.stdout).with_context(|| {
                    format!(
                        "keeper backend '{}': non-UTF-8 response for URI '{}'",
                        self.instance_name, uri.raw
                    )
                })?;
                // `keeper get --format=password` writes the value
                // followed by a single newline. Strip exactly one.
                Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
            }
            Some(field_name) => {
                // Response body is secret-bearing — parse via a
                // narrow struct; serde drops every field we don't
                // name. The canary test locks this.
                let record: KeeperRecordJson = serde_json::from_slice(&output.stdout)
                    .with_context(|| {
                        format!(
                            "keeper backend '{}': 'keeper get --format=json' returned \
                             a payload that is not a JSON record object (URI '{}')",
                            self.instance_name, uri.raw
                        )
                    })?;
                let value = Self::extract_field(&record, field_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "keeper backend '{}': record '{target}' has no field \
                         named '{field_name}' (URI '{}')",
                        self.instance_name,
                        uri.raw
                    )
                })?;
                Ok(value.to_owned())
            }
        }
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        let target = self.resolve_target(uri)?;

        if !self.keeper_unsafe_set {
            bail!(
                "keeper backend '{}': set() is gated behind \
                 `keeper_unsafe_set = true` because the `keeper` CLI has no \
                 stdin form for field values — `record-add` and \
                 `record-update` pass the value on argv, which is visible to \
                 same-UID processes via `ps -ww`. Opt in explicitly in your \
                 config.toml, or set the value through the Keeper Vault UI \
                 (URI '{}').",
                self.instance_name,
                uri.raw
            );
        }

        tracing::warn!(
            instance = self.instance_name.as_str(),
            uri = uri.raw.as_str(),
            "keeper `set` passes the value through subprocess argv (same-UID \
             visibility via `ps -ww`; acceptable on single-user hosts — see \
             docs/backends/keeper.md)"
        );

        // Probe existence. `keeper get <target> --format=detail` exits
        // 0 on hit (record exists), non-zero on miss. Only the exit
        // code matters — null stdout so the probe's record-detail body
        // (which includes decrypted field values) never hits our heap.
        // Mirrors Infisical's probe discipline.
        //
        // TOCTOU note: between this probe and the record-add/update
        // call below, the record can be deleted or created by another
        // Keeper client — a concurrent write would race. Acceptable
        // for v0.8 because (a) Keeper's UI is single-user-per-device
        // and (b) CLI mutations from other processes are rare in the
        // SecretEnv use cases. If the concurrent-write case becomes
        // real, record-update's "record not found" error would surface
        // cleanly through operation_failure_message.
        let mut probe_cmd = self.keeper_command(&["get", target, "--format", "detail"]);
        probe_cmd.stdout(Stdio::null());
        let probe = probe_cmd.output().await;
        let exists = matches!(probe, Ok(o) if o.status.success());

        let field_arg = format!("password={value}");
        let mut cmd = if exists {
            self.keeper_command(&["record-update", "-r", target, &field_arg])
        } else {
            self.keeper_command(&["record-add", "-t", target, "-rt", "login", &field_arg])
        };
        let output = cmd.output().await.with_context(|| {
            format!(
                "keeper backend '{}': failed to invoke 'keeper {}' for URI '{}'",
                self.instance_name,
                if exists { "record-update" } else { "record-add" },
                uri.raw
            )
        })?;

        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("keeper")?;
        let target = self.resolve_target(uri)?;

        let mut cmd = self.keeper_command(&["rm", "-f", target]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "keeper backend '{}': failed to invoke 'keeper rm' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("Cannot find") {
                bail!(
                    "keeper backend '{}': record '{target}' not found at URI '{}' \
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
        uri.reject_any_fragment("keeper")?;
        // The URI's single segment is used as a "registry marker" for
        // addressability; the list call enumerates every record in
        // the vault. Matches Doppler/Infisical's bulk-model shape —
        // the URI-used-as-registry-source ignores its segment.
        let _marker = self.resolve_target(uri)?;

        let mut cmd = self.keeper_command(&["list", "--format", "json"]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "keeper backend '{}': failed to invoke 'keeper list' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }

        // Response contains record metadata for the whole vault.
        // Parse via a narrow struct that declares ONLY `title` +
        // optional `record_uid`; serde drops every other field. The
        // canary test locks this.
        let entries: Vec<KeeperListEntry> =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "keeper backend '{}': 'keeper list --format=json' returned a \
                     payload that is not a JSON array of record objects (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?;

        // Bulk model: each record becomes one alias. The alias NAME
        // is the record title. For the target URI, we fetch each
        // record's password field via a follow-up `keeper get
        // --format=password` call. Sequential to respect rate limits.
        //
        // SECURITY POSTURE (v0.8 — to tighten in v0.8.x+):
        // 1. N-wide secret fanout. Every vault record's decrypted
        //    password flows through a subprocess stdout into a
        //    Vec<u8> here. For a 1000-record vault, that's 1000 live
        //    secret values held in this process's heap at various
        //    points during the iteration. Values drop at each loop
        //    iteration boundary (Rust's String drops on scope exit)
        //    but under memory pressure could end up swapped. An
        //    opt-in record-count cap (`keeper_list_max_records`) is
        //    worth considering post-v0.8 if real deployments use
        //    large vaults.
        // 2. Silent per-record failure. The three `continue` arms
        //    below swallow: (a) spawn/IO errors, (b) non-zero exits
        //    (including rate-limit throttling, record-deleted-mid-
        //    iter, permission denied), (c) non-UTF-8 bodies. A
        //    registry-source caller will see a shorter alias map
        //    than the vault actually holds, with no indication of
        //    the truncation. Acceptable for v0.8 MVP because the
        //    downstream resolver filters on URI-parse anyway
        //    (most silent-skipped records would have been invalid-
        //    URI-values that the resolver would drop regardless),
        //    but a future enhancement should surface a count of
        //    skipped entries in `tracing::warn!` or equivalent.
        let mut out = Vec::with_capacity(entries.len());
        let mut skipped = 0u32;
        for entry in entries {
            let mut c =
                self.keeper_command(&["get", &entry.title, "--format", "password", "--unmask"]);
            let o = match c.output().await {
                Ok(o) => o,
                Err(e) => {
                    skipped += 1;
                    tracing::warn!(
                        instance = self.instance_name.as_str(),
                        title = entry.title.as_str(),
                        error = %e,
                        "keeper list(): failed to spawn per-record get; dropping entry"
                    );
                    continue;
                }
            };
            if !o.status.success() {
                skipped += 1;
                tracing::warn!(
                    instance = self.instance_name.as_str(),
                    title = entry.title.as_str(),
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "keeper list(): per-record get exited non-zero; dropping entry"
                );
                continue;
            }
            let Ok(val) = String::from_utf8(o.stdout) else {
                skipped += 1;
                tracing::warn!(
                    instance = self.instance_name.as_str(),
                    title = entry.title.as_str(),
                    "keeper list(): per-record get returned non-UTF-8 body; dropping entry"
                );
                continue;
            };
            let trimmed = val.strip_suffix('\n').unwrap_or(&val).to_owned();
            if !trimmed.is_empty() {
                out.push((entry.title, trimmed));
            }
        }
        if skipped > 0 {
            tracing::warn!(
                instance = self.instance_name.as_str(),
                skipped = skipped,
                returned = out.len(),
                "keeper list(): dropped entries due to per-record failures; \
                 downstream alias map is shorter than the vault"
            );
        }
        Ok(out)
    }

    async fn history(&self, uri: &BackendUri) -> Result<Vec<secretenv_core::HistoryEntry>> {
        // Override the trait default so we can reject fragments +
        // surface a Keeper-specific explanation. Keeper records HAVE
        // per-version history in the Vault UI and via the REST API,
        // but `keeper history` is COMMAND history (shell input lines)
        // — no CLI surface for record-version history at v17.2.13.
        uri.reject_any_fragment("keeper")?;
        bail!(
            "keeper backend '{}': history is not supported — the `keeper` CLI \
             (v17.2.13) has no per-record version-history subcommand; record \
             version history IS available in the Keeper Vault UI (Vault → \
             record → '...' → 'Record History'). URI '{}'",
            self.instance_name,
            uri.raw
        )
    }
}

/// Factory for the Keeper backend.
pub struct KeeperFactory(&'static str);

impl KeeperFactory {
    /// Construct a factory for the `keeper` backend type.
    #[must_use]
    pub const fn new() -> Self {
        Self("keeper")
    }
}

impl Default for KeeperFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for KeeperFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let keeper_folder = optional_string(config, "keeper_folder", "keeper", instance_name)?;
        let keeper_config_path =
            optional_string(config, "keeper_config_path", "keeper", instance_name)?;
        let keeper_unsafe_set =
            optional_bool(config, "keeper_unsafe_set", "keeper", instance_name)?.unwrap_or(false);
        let keeper_bin = optional_string(config, "keeper_bin", "keeper", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "keeper", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);

        Ok(Box::new(KeeperBackend {
            backend_type: "keeper",
            instance_name: instance_name.to_owned(),
            keeper_folder,
            keeper_config_path,
            keeper_unsafe_set,
            keeper_bin,
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

    fn backend(mock_path: &Path, unsafe_set: bool) -> KeeperBackend {
        KeeperBackend {
            backend_type: "keeper",
            instance_name: "keeper-prod".to_owned(),
            keeper_folder: None,
            keeper_config_path: None,
            keeper_unsafe_set: unsafe_set,
            keeper_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_missing_bin() -> KeeperBackend {
        KeeperBackend {
            backend_type: "keeper",
            instance_name: "keeper-prod".to_owned(),
            keeper_folder: None,
            keeper_config_path: None,
            keeper_unsafe_set: false,
            keeper_bin: "/definitely/not/a/real/path/to/keeper-XYZ987".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const LOGIN_STATUS_ARGV: &[&str] = &["--batch-mode", "login-status"];
    const WHOAMI_ARGV: &[&str] = &["--batch-mode", "whoami"];

    #[test]
    fn keeper_whoami_parses_text_format() {
        // Real `keeper whoami` output is indented text. Two named
        // lines matter: "User:" and "Server:". Everything else
        // (Account, Data Center, quota blocks, etc.) is ignored.
        let stdout = "
  User Info
  ──────────
                User: mandeep@techalchemist.io
              Server: keepersecurity.com
         Data Center: US
  Account
  Account Type: Keeper Free Trial
";
        let parsed = KeeperWhoami::parse(stdout);
        assert_eq!(parsed.user.as_deref(), Some("mandeep@techalchemist.io"));
        assert_eq!(parsed.server.as_deref(), Some("keepersecurity.com"));
    }

    #[test]
    fn keeper_whoami_parse_defaults_on_missing_lines() {
        let parsed = KeeperWhoami::parse("unrelated text\n");
        assert!(parsed.user.is_none());
        assert!(parsed.server.is_none());
    }

    fn get_pw_argv(target: &str) -> [&str; 6] {
        ["--batch-mode", "get", target, "--format", "password", "--unmask"]
    }

    fn get_json_argv(target: &str) -> [&str; 6] {
        ["--batch-mode", "get", target, "--format", "json", "--unmask"]
    }

    fn rm_argv(target: &str) -> [&str; 4] {
        ["--batch-mode", "rm", "-f", target]
    }

    const LIST_ARGV: &[&str] = &["--batch-mode", "list", "--format", "json"];

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_missing_bin();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "keeper");
                assert!(install_hint.contains("keepercommander"), "hint: {install_hint}");
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_when_logged_in_with_whoami_identity() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(VERSION_ARGV, Response::success("Keeper Commander, version 17.2.13\n"))
            .on(LOGIN_STATUS_ARGV, Response::success("Logged in\n"))
            .on(
                WHOAMI_ARGV,
                Response::success(
                    "\n  User Info\n  ─────────\n                User: alice@acme.com\n              Server: keepersecurity.com\n         Data Center: US\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, false);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("17.2.13"), "version: {cli_version}");
                assert!(identity.contains("alice@acme.com"), "identity: {identity}");
                assert!(identity.contains("server=keepersecurity.com"), "identity: {identity}");
                assert!(identity.contains("auth=persistent-login"), "identity: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_not_authenticated_when_login_status_fails() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(VERSION_ARGV, Response::success("Keeper Commander, version 17.2.13\n"))
            .on(LOGIN_STATUS_ARGV, Response::failure(1, "Not logged in\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("persistent-login"), "hint: {hint}");
                assert!(hint.contains("this-device register"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_not_authenticated_when_stdout_lacks_logged_in() {
        let dir = TempDir::new().unwrap();
        // Exit 0 but stdout doesn't contain "Logged in" — shape drift
        // or stale session without proper error exit. Treat as
        // NotAuthenticated rather than Ok to avoid false positives.
        let mock = StrictMock::new("keeper")
            .on(VERSION_ARGV, Response::success("Keeper Commander, version 17.2.13\n"))
            .on(LOGIN_STATUS_ARGV, Response::success("Session expired\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        match b.check().await {
            BackendStatus::NotAuthenticated { .. } => {}
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_default_returns_password_field() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(&get_pw_argv("MY_RECORD"), Response::success("sk_live_42\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_42");
    }

    #[tokio::test]
    async fn get_uid_shape_also_works() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(&get_pw_argv("kF3aBcDeFgHiJkLmNoPqRs"), Response::success("token_via_uid\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///kF3aBcDeFgHiJkLmNoPqRs").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "token_via_uid");
    }

    #[tokio::test]
    async fn get_field_fragment_extracts_custom_field() {
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "title":"MY_RECORD",
            "fields":[
                {"type":"password","value":["pw_value"]}
            ],
            "custom":[
                {"label":"api_key","type":"text","value":["ak_42"]}
            ]
        }"#;
        let mock = StrictMock::new("keeper")
            .on(&get_json_argv("MY_RECORD"), Response::success(body))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD#field=api_key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "ak_42");
    }

    #[tokio::test]
    async fn get_field_fragment_case_insensitive_label_match() {
        let dir = TempDir::new().unwrap();
        let body = r#"{
            "custom":[{"label":"API_KEY","type":"text","value":["ak_upper"]}]
        }"#;
        let mock = StrictMock::new("keeper")
            .on(&get_json_argv("MY_RECORD"), Response::success(body))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD#field=api_key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "ak_upper");
    }

    #[tokio::test]
    async fn get_field_fragment_missing_field_errors() {
        let dir = TempDir::new().unwrap();
        let body = r#"{"custom":[]}"#;
        let mock = StrictMock::new("keeper")
            .on(&get_json_argv("MY_RECORD"), Response::success(body))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD#field=missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("no field named 'missing'"), "err: {err:#}");
    }

    #[tokio::test]
    async fn get_rejects_unknown_fragment_before_subprocess() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not recognized"), "msg: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "reject must precede subprocess: {msg}");
    }

    #[tokio::test]
    async fn get_not_found_stderr_shapes_friendly_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(&get_pw_argv("MISSING"), Response::failure(1, "Record MISSING not found\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MISSING").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("record 'MISSING' not found"), "msg: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_empty_path() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no record UID or title"), "msg: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "local reject: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_multi_segment_path() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///folder/record").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("more than one path segment"), "msg: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_is_gated_by_keeper_unsafe_set() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false); // keeper_unsafe_set = false
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        let err = b.set(&uri, "secret_value").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("keeper_unsafe_set = true"), "gate hint: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "gate must precede subprocess: {msg}");
    }

    #[tokio::test]
    async fn set_opts_in_creates_new_record_on_miss() {
        let dir = TempDir::new().unwrap();
        // Probe: keeper get --format=detail → non-zero (miss)
        // Then: record-add -t MY_RECORD -rt login password=VALUE
        let probe_argv: &[&str] = &["--batch-mode", "get", "MY_RECORD", "--format", "detail"];
        let add_argv: &[&str] = &[
            "--batch-mode",
            "record-add",
            "-t",
            "MY_RECORD",
            "-rt",
            "login",
            "password=new_value",
        ];
        let mock = StrictMock::new("keeper")
            .on(probe_argv, Response::failure(1, "Record MY_RECORD not found\n"))
            .on(add_argv, Response::success("Record MY_RECORD added\n"))
            .install(dir.path());
        let b = backend(&mock, true);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        b.set(&uri, "new_value").await.unwrap();
    }

    #[tokio::test]
    async fn set_opts_in_updates_existing_record_on_hit() {
        let dir = TempDir::new().unwrap();
        let probe_argv: &[&str] = &["--batch-mode", "get", "MY_RECORD", "--format", "detail"];
        let update_argv: &[&str] =
            &["--batch-mode", "record-update", "-r", "MY_RECORD", "password=updated_value"];
        let mock = StrictMock::new("keeper")
            .on(probe_argv, Response::success("Record details...\n"))
            .on(update_argv, Response::success("Record updated\n"))
            .install(dir.path());
        let b = backend(&mock, true);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        b.set(&uri, "updated_value").await.unwrap();
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_happy_rm_force() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(&rm_argv("OLD"), Response::success("Record deleted\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///OLD").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_bails_not_idempotent() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper")
            .on(&rm_argv("MISSING"), Response::failure(1, "Record MISSING not found\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MISSING").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "msg: {msg}");
        assert!(
            msg.contains("not idempotent") || msg.contains("delete is not idempotent"),
            "msg: {msg}"
        );
    }

    #[tokio::test]
    async fn delete_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///OLD#field=foo").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess: {err:#}"
        );
    }

    // ---- list ----

    #[tokio::test]
    async fn list_returns_title_password_pairs() {
        let dir = TempDir::new().unwrap();
        let list_body = r#"[
            {"title":"STRIPE_KEY","record_uid":"abc123"},
            {"title":"DB_URL","record_uid":"def456"}
        ]"#;
        let mock = StrictMock::new("keeper")
            .on(LIST_ARGV, Response::success(list_body))
            .on(&get_pw_argv("STRIPE_KEY"), Response::success("aws-ssm-prod:///stripe\n"))
            .on(&get_pw_argv("DB_URL"), Response::success("vault-dev:///db\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///REGISTRY_MARKER").unwrap();
        let mut out = b.list(&uri).await.unwrap();
        out.sort();
        assert_eq!(
            out,
            vec![
                ("DB_URL".to_owned(), "vault-dev:///db".to_owned()),
                ("STRIPE_KEY".to_owned(), "aws-ssm-prod:///stripe".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn list_ignores_unknown_fields_in_response() {
        // Canary: serde must drop every field we don't name. If a
        // regression adds a #[serde(flatten)] or an untyped Value
        // capture to KeeperListEntry, a `secret_value`-shaped payload
        // would end up in an error string somewhere. Here we just
        // prove the bulk parse itself survives unknown fields.
        let dir = TempDir::new().unwrap();
        let list_body = r#"[
            {"title":"STRIPE_KEY","record_uid":"abc","type":"login","fields":[]}
        ]"#;
        let mock = StrictMock::new("keeper")
            .on(LIST_ARGV, Response::success(list_body))
            .on(&get_pw_argv("STRIPE_KEY"), Response::success("aws-ssm-prod:///stripe\n"))
            .install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///REG").unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///REG#field=foo").unwrap();
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
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("history is not supported"), "msg: {msg}");
        assert!(msg.contains("Vault UI"), "msg: {msg}");
    }

    #[tokio::test]
    async fn history_rejects_fragment_before_unsupported_message() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD#field=foo").unwrap();
        let err = b.history(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("history is not supported"),
            "fragment reject fires first: {err:#}"
        );
    }

    // ---- argv discipline canaries ----

    #[tokio::test]
    async fn set_value_never_appears_on_argv_for_default_gated_path() {
        // When keeper_unsafe_set=false, set() bails locally before
        // any subprocess. The value cannot reach argv because no
        // spawn happens. Declarative lock: empty-rule mock + bail
        // path + assert mock's no-match diagnostic is absent.
        let canary = "sk_live_TOP_SECRET_keeper_never_in_argv_DEFAULT_GATE";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("keeper").install(dir.path());
        let b = backend(&mock, false);
        let uri = BackendUri::parse("keeper-prod:///MY_RECORD").unwrap();
        let err = b.set(&uri, canary).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.contains(canary), "canary must not leak in gate bail: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "gate path must not spawn: {msg}");
    }

    #[tokio::test]
    async fn config_path_is_passed_via_flag_when_set() {
        // When keeper_config_path is set, the argv shape MUST include
        // `--config <path>` after `--batch-mode`. Strict-mock locking.
        let dir = TempDir::new().unwrap();
        let expected_argv: &[&str] = &[
            "--batch-mode",
            "--config",
            "/custom/path/config.json",
            "get",
            "R",
            "--format",
            "password",
            "--unmask",
        ];
        let mock = StrictMock::new("keeper")
            .on(expected_argv, Response::success("value\n"))
            .install(dir.path());
        let mut b = backend(&mock, false);
        b.keeper_config_path = Some("/custom/path/config.json".to_owned());
        let uri = BackendUri::parse("keeper-prod:///R").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "value");
    }

    // ---- factory ----

    #[test]
    fn factory_defaults_when_all_fields_omitted() {
        let factory = KeeperFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("keeper-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "keeper");
        assert_eq!(b.instance_name(), "keeper-prod");
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
    }

    #[test]
    fn factory_accepts_keeper_unsafe_set_true() {
        let factory = KeeperFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("keeper_unsafe_set".to_owned(), toml::Value::Boolean(true));
        factory.create("keeper-prod", &cfg).unwrap();
    }

    #[test]
    fn factory_rejects_non_bool_keeper_unsafe_set() {
        let factory = KeeperFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("keeper_unsafe_set".to_owned(), toml::Value::String("yes".into()));
        let Err(err) = factory.create("keeper-prod", &cfg) else {
            panic!("expected error on non-bool keeper_unsafe_set");
        };
        assert!(format!("{err:#}").contains("must be a boolean"), "err: {err:#}");
    }
}
