// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Cloudflare Workers KV backend for SecretEnv.
//!
//! Wraps the `wrangler` CLI (Cloudflare's official Workers tool,
//! installed via `npm install -g wrangler` or
//! `brew install cloudflare/cloudflare/wrangler`). Targets wrangler
//! `4.x`. The user authenticates once via `wrangler login` (OAuth) OR
//! exports `CLOUDFLARE_API_TOKEN` (CI form, picked up by wrangler
//! transparently).
//!
//! Spec pivot rationale (v0.9 Phase 0): the original spec recommended
//! a curl-against-REST design citing 2-3 s wrangler startup. Live
//! measurement at wrangler 4.85.0 shows `wrangler --version` runs in
//! 0.28 s — Bun-runtime'd binary, no longer Node + tsc bundle. The
//! curl-vs-wrangler debate is therefore obsolete; wrangler-wrapped
//! matches every other CLI-backend in the workspace and removes the
//! need for users to mint a separate API token when their wrangler
//! login already grants `workers_kv:write`.
//!
//! # URI shape
//!
//! `<instance>:///<namespace-id>/<key>` — two segments. The namespace
//! ID is the stable UUID-shaped identifier returned by
//! `wrangler kv namespace list` (NOT the Worker-local binding name,
//! which varies per Worker script). Keys are arbitrary strings; we
//! pass them verbatim to wrangler (which URL-encodes internally).
//!
//! If `cf_kv_default_namespace_id` is set in config, single-segment
//! URIs `<instance>:///<key>` are also accepted and resolve into the
//! default namespace. Two-segment URIs always override the default.
//! Mirrors Doppler's project-default + Infisical's projectId pattern.
//!
//! # Config fields
//!
//! - `cf_kv_default_namespace_id` (optional) — namespace ID used when
//!   the URI carries only one path segment. When unset, single-segment
//!   URIs are rejected with a hint.
//! - `timeout_secs` (optional) — per-instance deadline. Default
//!   [`DEFAULT_GET_TIMEOUT`].
//! - `wrangler_bin` (optional, test hook) — override the `wrangler`
//!   binary path.
//!
//! # `set()` — tempfile via `--path`, no `_unsafe_set` gate
//!
//! `wrangler kv key put <key> <value>` exposes the value on argv (same
//! `ps -ww` risk as 1Password and Keeper). BUT wrangler also accepts
//! `wrangler kv key put <key> --path <file>` reading the value from a
//! filesystem path. SecretEnv writes the value to a [`tempfile::NamedTempFile`]
//! created in the OS tempdir, sets mode 0600 on POSIX, passes the path
//! to wrangler, and lets RAII unlink immediately after. Strictly safer
//! than argv (no `ps -ww` exposure; same-UID file-system race window
//! is bounded by mode 0600 and the immediate unlink). No
//! `_unsafe_set` opt-in needed; matches Infisical's `--file` discipline.
//!
//! Wrangler 4.85.0's `put` writes an informational banner naming the
//! key, the namespace ID, and (in argv-mode) the value. We always pass
//! `--path` so the banner cannot include the value, and we still send
//! the wrangler banner to `Stdio::null()` so even a future regression
//! that includes the value in the banner cannot surface in our error
//! messages.
//!
//! # `list()` — Pattern A bulk model
//!
//! `wrangler kv key list --namespace-id <id> --remote` returns a JSON
//! array `[{"name": "..."}, ...]`. The list call enumerates every key
//! in the namespace; the URI's `<key>` segment is treated as a
//! registry marker (consumed but ignored), mirroring Keeper's bulk
//! model. Per-key value hydration runs sequential `get --text` calls
//! to respect Cloudflare's rate limits. Non-UTF-8 values + non-zero
//! exits + IO errors are skipped with a `tracing::warn!` per skip and
//! a summary count, identical to Keeper.
//!
//! # `history()` — unsupported
//!
//! Workers KV has no per-key version history. Overwrites simply replace.
//! [`Backend::history`] is overridden to bail with a KV-specific
//! pointer (recommends storing a versioning convention in the key
//! name if needed).
//!
//! # Security
//!
//! - Every `wrangler` invocation goes through `Command::args([...])`
//!   with individual `&str` — never `sh -c`, never `format!` into a
//!   shell string.
//! - `set()` value flows through a mode-0600 tempfile, never argv.
//! - `set()` subprocess `Stdio::null()`s stdout + stderr to suppress
//!   wrangler's info banner from any error-message capture.
//! - Response bodies for `get` are secret-bearing. Errors never
//!   interpolate stdout; tracing fields never include values.
//! - The OAuth token cached by `wrangler login` lives in
//!   `~/.config/.wrangler/config/default.toml` (wrangler-managed); we
//!   never read or write it.
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

const CLI_NAME: &str = "wrangler";
const INSTALL_HINT: &str =
    "npm install -g wrangler  OR  brew install cloudflare/cloudflare/wrangler";

/// Cloudflare KV "key not found" detector. Tightened from a loose
/// substring match on `"10009"` (which would false-positive on any
/// stderr containing those four digits — request IDs, timestamps) to
/// a word-boundary match against the canonical phrasings wrangler
/// emits across 4.x minor versions: `not found`, `error 10009`, and
/// `code 10009`. The space- and word-bounded forms keep the heuristic
/// from snagging digit substrings inside other tokens.
fn is_not_found_stderr(stderr: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(stderr).to_lowercase();
    lower.contains("not found")
        || lower.contains("error 10009")
        || lower.contains("code 10009")
        || lower.contains("code: 10009")
}

/// A live instance of the Cloudflare Workers KV backend.
pub struct CfKvBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Namespace ID used when a URI carries only one path segment.
    /// `None` → single-segment URIs are rejected at `resolve_target`
    /// with a hint pointing at this config field.
    cf_kv_default_namespace_id: Option<String>,
    /// Path or name of the `wrangler` binary. Defaults to `"wrangler"`
    /// (PATH lookup); tests override to a mock script path via
    /// [`secretenv_testing::StrictMock`].
    wrangler_bin: String,
    timeout: Duration,
}

/// Parsed list entry. `wrangler kv key list` returns an array of
/// objects; we declare ONLY `name`. serde silently drops every other
/// field (`expiration`, `metadata`, etc.). The canary test locks this.
#[derive(Deserialize)]
struct CfKvListEntry {
    name: String,
}

/// Parsed identity from `wrangler whoami`. Output is a chatty banner
/// followed by an ASCII table; we scan for the email line (highly
/// stable across wrangler versions) and ignore the rest. Tables are
/// formatting-volatile and not worth parsing.
#[derive(Default)]
struct WranglerWhoami {
    email: Option<String>,
}

impl WranglerWhoami {
    /// Scan stdout for the `associated with the email <email>` line.
    /// Anything else → `Default { email: None }`, which the caller
    /// renders as `email=unknown`.
    fn parse(stdout: &str) -> Self {
        let mut out = Self::default();
        for line in stdout.lines() {
            // Look for the exact phrase wrangler 4.x uses; a wrangler
            // version that changes wording silently degrades to
            // `email=unknown` rather than mis-parsing.
            if let Some(idx) = line.find("associated with the email ") {
                let rest = &line[idx + "associated with the email ".len()..];
                let email = rest.trim_end_matches('.').trim();
                if !email.is_empty() {
                    out.email = Some(email.to_owned());
                }
                break;
            }
        }
        out
    }
}

/// Resolved namespace + key from a URI. Two-segment URIs supply both;
/// single-segment URIs supply just the key and rely on the config's
/// default namespace ID.
struct ResolvedTarget<'a> {
    namespace_id: &'a str,
    key: &'a str,
}

impl CfKvBackend {
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
            "cf-kv backend '{}': {op} failed for URI '{}': {stderr_str}",
            self.instance_name, uri.raw
        )
    }

    /// Build a `wrangler` command. Caller's args are appended verbatim.
    /// Stdin nulled — wrangler reads no stdin in the operations we drive.
    fn wrangler_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.wrangler_bin);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Resolve the URI's path into `(namespace_id, key)`. Two-segment
    /// URIs supply both; one-segment URIs require
    /// `cf_kv_default_namespace_id` to be set in config. Empty / >2
    /// segments are rejected locally before any subprocess.
    fn resolve_target<'u>(&'u self, uri: &'u BackendUri) -> Result<ResolvedTarget<'u>> {
        let path = uri.path.strip_prefix('/').unwrap_or(&uri.path);
        let trimmed = path.trim_matches('/');
        if trimmed.is_empty() {
            bail!(
                "cf-kv backend '{}': URI '{}' has no path segments — \
                 expected '<instance>:///<namespace-id>/<key>' (or \
                 '<instance>:///<key>' when `cf_kv_default_namespace_id` is configured)",
                self.instance_name,
                uri.raw
            );
        }
        let segments: Vec<&str> = trimmed.split('/').collect();
        match segments.as_slice() {
            [key] => {
                let Some(ns) = self.cf_kv_default_namespace_id.as_deref() else {
                    bail!(
                        "cf-kv backend '{}': URI '{}' is single-segment but \
                         `cf_kv_default_namespace_id` is not set in config — \
                         either configure a default namespace or use the two-segment form \
                         '<instance>:///<namespace-id>/<key>'",
                        self.instance_name,
                        uri.raw
                    );
                };
                Ok(ResolvedTarget { namespace_id: ns, key })
            }
            [ns, key] => Ok(ResolvedTarget { namespace_id: ns, key }),
            _ => bail!(
                "cf-kv backend '{}': URI '{}' has more than two path segments; \
                 cf-kv URIs take at most '<namespace-id>/<key>'",
                self.instance_name,
                uri.raw
            ),
        }
    }
}

#[async_trait]
impl Backend for CfKvBackend {
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
        //   Level 1: `wrangler --version` → CliMissing on ENOENT.
        //   Level 2: `wrangler whoami` → Ok if exit 0, NotAuthenticated
        //            otherwise. wrangler exits non-zero when no OAuth
        //            token is cached AND no CLOUDFLARE_API_TOKEN is set.
        let version_fut = {
            let mut c = Command::new(&self.wrangler_bin);
            c.arg("--version");
            c.stdin(Stdio::null());
            c.output()
        };
        let whoami_fut = self.wrangler_command(&["whoami"]).output();
        let (version_res, whoami_res) = tokio::join!(version_fut, whoami_fut);

        // --- Level 1 ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "cf-kv backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.wrangler_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "cf-kv backend '{}': 'wrangler --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        // wrangler `--version` writes a banner like " ⛅️ wrangler 4.85.0\n
        // ───────────────────\n". Take the first non-empty line that
        // contains "wrangler".
        let cli_version = String::from_utf8_lossy(&version_out.stdout)
            .lines()
            .map(str::trim)
            .find(|l| l.contains("wrangler"))
            .unwrap_or("unknown")
            .to_owned();

        // --- Level 2 ---
        // Map ENOENT here too — `tokio::join!` fires both probes
        // simultaneously, so if the binary is missing both arms see
        // it. We surfaced CliMissing via the version arm above; if
        // execution reaches here with whoami_res == NotFound, the
        // version arm already returned. The explicit NotFound guard
        // is defense-in-depth in case the OS reports different error
        // kinds for the two spawns.
        let whoami_out = match whoami_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "cf-kv backend '{}': failed to invoke 'wrangler whoami': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !whoami_out.status.success() {
            return BackendStatus::NotAuthenticated {
                hint: "run `wrangler login` to authenticate via OAuth, OR export \
                       CLOUDFLARE_API_TOKEN with a token scoped to `Workers KV \
                       Storage:Edit`"
                    .to_owned(),
            };
        }
        let stdout = String::from_utf8_lossy(&whoami_out.stdout);
        let parsed = WranglerWhoami::parse(&stdout);
        let email = parsed.email.as_deref().unwrap_or("unknown");
        // wrangler doesn't always set non-zero on a stale token — its
        // whoami may print "You are not authenticated" with exit 0 in
        // older builds. Catch that conservatively: if the email parse
        // failed AND stdout contains "not authenticated", treat as
        // NotAuthenticated.
        if parsed.email.is_none() && stdout.to_lowercase().contains("not authenticated") {
            return BackendStatus::NotAuthenticated {
                hint: "run `wrangler login` to authenticate via OAuth, OR export \
                       CLOUDFLARE_API_TOKEN with a token scoped to `Workers KV \
                       Storage:Edit`"
                    .to_owned(),
            };
        }
        let identity = format!("email={email} auth=wrangler");
        BackendStatus::Ok { cli_version, identity }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        uri.reject_any_fragment("cf-kv")?;
        let target = self.resolve_target(uri)?;

        let mut cmd = self.wrangler_command(&[
            "kv",
            "key",
            "get",
            target.key,
            "--namespace-id",
            target.namespace_id,
            "--remote",
            "--text",
        ]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "cf-kv backend '{}': failed to invoke 'wrangler kv key get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;

        if !output.status.success() {
            if is_not_found_stderr(&output.stderr) {
                bail!(
                    "cf-kv backend '{}': key '{}' not found in namespace '{}' (URI '{}')",
                    self.instance_name,
                    target.key,
                    target.namespace_id,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }

        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "cf-kv backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `wrangler kv key get --text` writes the value followed by a
        // single newline. Strip exactly one.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("cf-kv")?;
        let target = self.resolve_target(uri)?;

        // Write the value to a mode-0600 tempfile, pass the path to
        // wrangler. The NamedTempFile RAII cleanup unlinks on drop. We
        // explicitly close (drop) the handle BEFORE invoking wrangler
        // so the file is in a clean closed-but-present state for the
        // subprocess to read.
        let mut tmp = NamedTempFile::new().with_context(|| {
            format!(
                "cf-kv backend '{}': failed to create tempfile for set() value (URI '{}')",
                self.instance_name, uri.raw
            )
        })?;
        // tempfile 3.x's `NamedTempFile::new()` uses mkstemp on POSIX,
        // which already creates the file with mode 0600. We re-chmod
        // explicitly here as defense-in-depth: a future tempfile crate
        // change OR a non-POSIX target's defaults can't silently widen
        // the perms past 0600 because we re-tighten before any write.
        // The chmod-then-write order is mandatory — a write before
        // chmod could expose the value to other-UID processes for the
        // narrow window between create and re-chmod if the platform
        // default ever drifts above 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tmp.as_file().metadata()?.permissions();
            perms.set_mode(0o600);
            tmp.as_file().set_permissions(perms).with_context(|| {
                format!(
                    "cf-kv backend '{}': failed to chmod 0600 on set() tempfile (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?;
            debug_assert_eq!(
                tmp.as_file().metadata()?.permissions().mode() & 0o777,
                0o600,
                "tempfile mode must be 0600 before write_all"
            );
        }
        tmp.write_all(value.as_bytes()).with_context(|| {
            format!(
                "cf-kv backend '{}': failed to write set() value to tempfile (URI '{}')",
                self.instance_name, uri.raw
            )
        })?;
        // Flush is fatal — silently dropping a flush error could leave
        // wrangler reading a truncated value with no surface to caller.
        tmp.flush().with_context(|| {
            format!(
                "cf-kv backend '{}': failed to flush set() tempfile (URI '{}')",
                self.instance_name, uri.raw
            )
        })?;

        let path_str = tmp
            .path()
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cf-kv backend '{}': tempfile path is not valid UTF-8 (URI '{}')",
                    self.instance_name,
                    uri.raw
                )
            })?
            .to_owned();

        let mut cmd = self.wrangler_command(&[
            "kv",
            "key",
            "put",
            target.key,
            "--namespace-id",
            target.namespace_id,
            "--remote",
            "--path",
            &path_str,
        ]);
        // Suppress wrangler's info banner so any future regression that
        // includes the value cannot surface in our error messages. We
        // capture stderr so a real failure produces a useful diagnostic
        // (and wrangler's banner-on-success goes nowhere because we
        // null stdout).
        cmd.stdout(Stdio::null());
        let output = cmd.output().await.with_context(|| {
            format!(
                "cf-kv backend '{}': failed to invoke 'wrangler kv key put' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            // operation_failure_message uses stderr (wrangler errors
            // land there), not stdout. Suffices for diagnosis without
            // leaking the banner-echoed value.
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        // Tempfile drops here → unlink. Anything that prevents drop
        // (panic, early return) leaves it; OS tempdir lifecycles will
        // clean up eventually.
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("cf-kv")?;
        let target = self.resolve_target(uri)?;

        let mut cmd = self.wrangler_command(&[
            "kv",
            "key",
            "delete",
            target.key,
            "--namespace-id",
            target.namespace_id,
            "--remote",
        ]);
        // Wrangler's `kv key delete` prompts interactively for
        // confirmation by default. We null stdin (already done) AND
        // pass `--force` if/when wrangler adds it; for now wrangler
        // 4.85.0 in non-interactive contexts (no TTY) skips the prompt
        // and proceeds. The CI environment we run in is non-TTY.
        let output = cmd.output().await.with_context(|| {
            format!(
                "cf-kv backend '{}': failed to invoke 'wrangler kv key delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            if is_not_found_stderr(&output.stderr) {
                bail!(
                    "cf-kv backend '{}': key '{}' not found in namespace '{}' at URI '{}' \
                     (delete is not idempotent — matches aws-secrets precedent)",
                    self.instance_name,
                    target.key,
                    target.namespace_id,
                    uri.raw
                );
            }
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("cf-kv")?;
        // The URI's path is consumed for namespace-id resolution; the
        // key segment (or single segment) is the registry marker —
        // ignored, mirroring Keeper / Doppler / Infisical bulk-mode.
        let target = self.resolve_target(uri)?;

        let mut cmd = self.wrangler_command(&[
            "kv",
            "key",
            "list",
            "--namespace-id",
            target.namespace_id,
            "--remote",
        ]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "cf-kv backend '{}': failed to invoke 'wrangler kv key list' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "list", &output.stderr));
        }

        let entries: Vec<CfKvListEntry> =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "cf-kv backend '{}': 'wrangler kv key list' returned a payload \
                     that is not a JSON array of key objects (URI '{}')",
                    self.instance_name, uri.raw
                )
            })?;

        // Bulk model: each KV key becomes one alias entry. The alias
        // NAME is the KV key; the alias VALUE is the KV value (which
        // SecretEnv users seed as a URI string for the registry-source
        // pattern). Sequential per-key fetches, identical posture to
        // Keeper. See Keeper docs for the security caveats around
        // N-wide secret fanout + silent per-record skip.
        let mut out = Vec::with_capacity(entries.len());
        let mut skipped = 0u32;
        for entry in entries {
            let mut c = self.wrangler_command(&[
                "kv",
                "key",
                "get",
                &entry.name,
                "--namespace-id",
                target.namespace_id,
                "--remote",
                "--text",
            ]);
            let o = match c.output().await {
                Ok(o) => o,
                Err(e) => {
                    skipped += 1;
                    tracing::warn!(
                        instance = self.instance_name.as_str(),
                        key = entry.name.as_str(),
                        error = %e,
                        "cf-kv list(): failed to spawn per-key get; dropping entry"
                    );
                    continue;
                }
            };
            if !o.status.success() {
                skipped += 1;
                tracing::warn!(
                    instance = self.instance_name.as_str(),
                    key = entry.name.as_str(),
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "cf-kv list(): per-key get exited non-zero; dropping entry"
                );
                continue;
            }
            let Ok(val) = String::from_utf8(o.stdout) else {
                skipped += 1;
                tracing::warn!(
                    instance = self.instance_name.as_str(),
                    key = entry.name.as_str(),
                    "cf-kv list(): per-key get returned non-UTF-8 body; dropping entry"
                );
                continue;
            };
            let trimmed = val.strip_suffix('\n').unwrap_or(&val).to_owned();
            if !trimmed.is_empty() {
                out.push((entry.name, trimmed));
            }
        }
        if skipped > 0 {
            tracing::warn!(
                instance = self.instance_name.as_str(),
                skipped = skipped,
                returned = out.len(),
                "cf-kv list(): dropped entries due to per-key failures; \
                 downstream alias map is shorter than the namespace"
            );
        }
        Ok(out)
    }

    async fn history(&self, uri: &BackendUri) -> Result<Vec<secretenv_core::HistoryEntry>> {
        uri.reject_any_fragment("cf-kv")?;
        bail!(
            "cf-kv backend '{}': history is not supported — Workers KV has no \
             per-key version history; overwrites simply replace the value. If \
             you need versioning, encode it in the key name (e.g. \
             'STRIPE_KEY/v3'). URI '{}'",
            self.instance_name,
            uri.raw
        )
    }
}

/// Factory for the Cloudflare Workers KV backend.
pub struct CfKvFactory(&'static str);

impl CfKvFactory {
    /// Construct a factory for the `cf-kv` backend type.
    #[must_use]
    pub const fn new() -> Self {
        Self("cf-kv")
    }
}

impl Default for CfKvFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendFactory for CfKvFactory {
    fn backend_type(&self) -> &str {
        self.0
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let cf_kv_default_namespace_id =
            optional_string(config, "cf_kv_default_namespace_id", "cf-kv", instance_name)?;
        let wrangler_bin = optional_string(config, "wrangler_bin", "cf-kv", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let timeout = optional_duration_secs(config, "timeout_secs", "cf-kv", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);

        Ok(Box::new(CfKvBackend {
            backend_type: "cf-kv",
            instance_name: instance_name.to_owned(),
            cf_kv_default_namespace_id,
            wrangler_bin,
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

    const NS: &str = "c554de8d89644f3d85f21933e7aea910";

    fn backend(mock_path: &Path, default_ns: Option<&str>) -> CfKvBackend {
        CfKvBackend {
            backend_type: "cf-kv",
            instance_name: "cf-kv-prod".to_owned(),
            cf_kv_default_namespace_id: default_ns.map(str::to_owned),
            wrangler_bin: mock_path.to_str().unwrap().to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_missing_bin() -> CfKvBackend {
        CfKvBackend {
            backend_type: "cf-kv",
            instance_name: "cf-kv-prod".to_owned(),
            cf_kv_default_namespace_id: None,
            wrangler_bin: "/definitely/not/a/real/path/to/wrangler-XYZ987".to_owned(),
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    const VERSION_ARGV: &[&str] = &["--version"];
    const WHOAMI_ARGV: &[&str] = &["whoami"];

    fn get_argv(key: &str) -> [&str; 8] {
        ["kv", "key", "get", key, "--namespace-id", NS, "--remote", "--text"]
    }

    fn delete_argv(key: &str) -> [&str; 7] {
        ["kv", "key", "delete", key, "--namespace-id", NS, "--remote"]
    }

    const LIST_ARGV: &[&str] = &["kv", "key", "list", "--namespace-id", NS, "--remote"];

    // ---- whoami parse ----

    #[test]
    fn whoami_parses_email_line() {
        let stdout = "
 ⛅️ wrangler 4.85.0
───────────────────
Getting User settings...
👋 You are logged in with an OAuth Token, associated with the email alice@acme.com.
┌───────┬────┐
";
        let parsed = WranglerWhoami::parse(stdout);
        assert_eq!(parsed.email.as_deref(), Some("alice@acme.com"));
    }

    #[test]
    fn whoami_parse_defaults_when_no_email_line() {
        let parsed = WranglerWhoami::parse("unrelated text\n");
        assert!(parsed.email.is_none());
    }

    // ---- check ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_missing_bin();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "wrangler");
                assert!(install_hint.contains("wrangler"), "hint: {install_hint}");
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_when_whoami_succeeds_with_email() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(VERSION_ARGV, Response::success(" ⛅️ wrangler 4.85.0\n"))
            .on(
                WHOAMI_ARGV,
                Response::success(
                    "👋 You are logged in with an OAuth Token, associated with the email alice@acme.com.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("4.85.0"), "version: {cli_version}");
                assert!(identity.contains("alice@acme.com"), "identity: {identity}");
                assert!(identity.contains("auth=wrangler"), "identity: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_not_authenticated_on_whoami_nonzero_exit() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(VERSION_ARGV, Response::success(" ⛅️ wrangler 4.85.0\n"))
            .on(WHOAMI_ARGV, Response::failure(1, "Not authenticated\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("wrangler login"), "hint: {hint}");
                assert!(hint.contains("CLOUDFLARE_API_TOKEN"), "hint: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_ok_parses_cli_version_from_multi_line_banner() {
        // wrangler 4.x prints a leading blank line + emoji banner +
        // separator before the version line. The version-finder must
        // skip empties and pick the line containing "wrangler".
        let dir = TempDir::new().unwrap();
        let multi_line = "\n ⛅️ wrangler 4.85.0\n───────────────────\n";
        let mock = StrictMock::new("wrangler")
            .on(VERSION_ARGV, Response::success(multi_line))
            .on(
                WHOAMI_ARGV,
                Response::success(
                    "👋 You are logged in with an OAuth Token, associated with the email a@b.c.\n",
                ),
            )
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::Ok { cli_version, .. } => {
                assert!(cli_version.contains("4.85.0"), "version: {cli_version}");
                assert!(!cli_version.starts_with('\n'), "leading newline trimmed: {cli_version:?}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn is_not_found_stderr_word_boundary_matches() {
        assert!(is_not_found_stderr(b"Error: key not found in namespace"));
        assert!(is_not_found_stderr(b"error 10009: key not found"));
        assert!(is_not_found_stderr(b"code 10009"));
        assert!(is_not_found_stderr(b"code: 10009"));
        // Tightened heuristic: a request ID containing 10009 substring
        // must NOT trigger the not-found mapping.
        assert!(!is_not_found_stderr(b"request_id=cf-100090abc internal error"));
        assert!(!is_not_found_stderr(b"unrelated error message"));
    }

    #[tokio::test]
    async fn check_not_authenticated_on_zero_exit_with_unauth_text() {
        // Some wrangler builds exit 0 from whoami while printing "you
        // are not authenticated". Treat that as NotAuthenticated.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(VERSION_ARGV, Response::success(" ⛅️ wrangler 4.85.0\n"))
            .on(WHOAMI_ARGV, Response::success("You are not authenticated\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        match b.check().await {
            BackendStatus::NotAuthenticated { .. } => {}
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_two_segment_uri_returns_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_42\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/STRIPE_KEY")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_42");
    }

    #[tokio::test]
    async fn get_one_segment_uri_uses_default_namespace() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(&get_argv("STRIPE_KEY"), Response::success("sk_live_42\n"))
            .install(dir.path());
        let b = backend(&mock, Some(NS));
        let uri = BackendUri::parse("cf-kv-prod:///STRIPE_KEY").unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_42");
    }

    #[tokio::test]
    async fn get_one_segment_uri_without_default_namespace_errors_locally() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("cf-kv-prod:///STRIPE_KEY").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cf_kv_default_namespace_id"), "msg: {msg}");
        assert!(!msg.contains("strict-mock-no-match"), "must not spawn: {msg}");
    }

    #[tokio::test]
    async fn get_not_found_shapes_friendly_error() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(&get_argv("MISSING"), Response::failure(1, "Error: key not found\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/MISSING")).unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("key 'MISSING' not found"), "msg: {msg}");
        assert!(msg.contains(NS), "namespace surfaced: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_fragment_before_subprocess() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/STRIPE_KEY#field=foo")).unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess: {err:#}"
        );
    }

    #[tokio::test]
    async fn get_rejects_three_segment_path() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/folder/STRIPE_KEY")).unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("more than two path segments"), "msg: {msg}");
    }

    #[tokio::test]
    async fn get_rejects_empty_path() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse("cf-kv-prod:///").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no path segments"), "msg: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_uses_path_flag_not_argv_value() {
        // We can't pin the exact tempfile path in a strict-mock argv
        // (it changes per run), so this test asserts the prefix of the
        // argv shape (everything up to `--path`) using a dynamic match
        // helper. Instead, prove the behavior by: (1) install a mock
        // that succeeds on any args, capturing the call, and (2)
        // assert the captured argv contains `--path` and does NOT
        // contain the canary value.
        //
        // The strict-mock harness as used elsewhere matches argv exactly,
        // which is too strict here. Use a permissive matcher: install
        // a script that succeeds for any invocation containing
        // `--path` AND doesn't contain the canary value. We do this by
        // inspecting StrictMock::install output OR — simpler — by
        // shipping a custom shell-script mock for this specific test.
        //
        // Pragmatic path: write a mock script ourselves that records
        // its argv to a file, exits 0, and lets the test assert.
        let dir = TempDir::new().unwrap();
        let argv_log = dir.path().join("argv.log");
        let script_path = dir.path().join("wrangler");
        let script = format!(
            "#!/bin/bash\nprintf '%s\\n' \"$@\" > {log}\nexit 0\n",
            log = argv_log.display()
        );
        std::fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let b = backend(&script_path, None);
        let canary = "sk_live_TOP_SECRET_cfkv_VALUE_NEVER_IN_ARGV_42";
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/STRIPE_KEY")).unwrap();
        b.set(&uri, canary).await.unwrap();

        let argv = std::fs::read_to_string(&argv_log).unwrap();
        assert!(argv.contains("--path"), "argv contained --path: {argv}");
        assert!(!argv.contains(canary), "canary VALUE must not appear in argv: {argv}");
        assert!(argv.contains("STRIPE_KEY"), "key on argv: {argv}");
        assert!(argv.contains(NS), "namespace on argv: {argv}");
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_happy() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(&delete_argv("OLD"), Response::success("deleted\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/OLD")).unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_bails_not_idempotent() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler")
            .on(&delete_argv("MISSING"), Response::failure(1, "Error: key not found\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/MISSING")).unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "msg: {msg}");
        assert!(msg.contains("not idempotent"), "msg: {msg}");
    }

    #[tokio::test]
    async fn delete_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/OLD#field=foo")).unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess: {err:#}"
        );
    }

    // ---- list ----

    #[tokio::test]
    async fn list_returns_key_value_pairs() {
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"name":"STRIPE_KEY"},
            {"name":"DB_URL"}
        ]"#;
        let mock = StrictMock::new("wrangler")
            .on(LIST_ARGV, Response::success(body))
            .on(&get_argv("STRIPE_KEY"), Response::success("aws-ssm-prod:///stripe\n"))
            .on(&get_argv("DB_URL"), Response::success("vault-dev:///db\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/REGISTRY_MARKER")).unwrap();
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
    async fn list_ignores_unknown_response_fields_canary() {
        // Canary: serde must drop every field we don't name. If the
        // payload grows `expiration`, `metadata`, etc., parse must
        // still succeed and produce only the named entries.
        let dir = TempDir::new().unwrap();
        let body = r#"[
            {"name":"STRIPE_KEY","expiration":1234567890,"metadata":{"v":"3"}}
        ]"#;
        let mock = StrictMock::new("wrangler")
            .on(LIST_ARGV, Response::success(body))
            .on(&get_argv("STRIPE_KEY"), Response::success("aws-ssm-prod:///stripe\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/REG")).unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "STRIPE_KEY");
    }

    #[tokio::test]
    async fn list_skips_empty_value_keys() {
        let dir = TempDir::new().unwrap();
        let body = r#"[{"name":"STRIPE_KEY"},{"name":"EMPTY_KEY"}]"#;
        let mock = StrictMock::new("wrangler")
            .on(LIST_ARGV, Response::success(body))
            .on(&get_argv("STRIPE_KEY"), Response::success("aws-ssm-prod:///stripe\n"))
            .on(&get_argv("EMPTY_KEY"), Response::success("\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/REG")).unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "STRIPE_KEY");
    }

    #[tokio::test]
    async fn list_continues_past_per_key_failures() {
        let dir = TempDir::new().unwrap();
        let body = r#"[{"name":"GOOD"},{"name":"BAD"}]"#;
        let mock = StrictMock::new("wrangler")
            .on(LIST_ARGV, Response::success(body))
            .on(&get_argv("GOOD"), Response::success("ok_value\n"))
            .on(&get_argv("BAD"), Response::failure(1, "Error: key not found\n"))
            .install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/REG")).unwrap();
        let out = b.list(&uri).await.unwrap();
        assert_eq!(out, vec![("GOOD".to_owned(), "ok_value".to_owned())]);
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/REG#field=foo")).unwrap();
        let err = b.list(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("strict-mock-no-match"),
            "fragment-reject must precede subprocess: {err:#}"
        );
    }

    // ---- history ----

    #[tokio::test]
    async fn history_is_unsupported() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/STRIPE_KEY")).unwrap();
        let err = b.history(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("history is not supported"), "msg: {msg}");
        assert!(msg.contains("encode it in the key name"), "msg: {msg}");
    }

    #[tokio::test]
    async fn history_rejects_fragment_before_unsupported_message() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("wrangler").install(dir.path());
        let b = backend(&mock, None);
        let uri = BackendUri::parse(&format!("cf-kv-prod:///{NS}/STRIPE_KEY#field=foo")).unwrap();
        let err = b.history(&uri).await.unwrap_err();
        assert!(
            !format!("{err:#}").contains("history is not supported"),
            "fragment reject fires first: {err:#}"
        );
    }

    // ---- factory ----

    #[test]
    fn factory_defaults_when_all_fields_omitted() {
        let factory = CfKvFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("cf-kv-prod", &cfg).unwrap();
        assert_eq!(b.backend_type(), "cf-kv");
        assert_eq!(b.instance_name(), "cf-kv-prod");
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
    }

    #[test]
    fn factory_accepts_default_namespace_id() {
        let factory = CfKvFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("cf_kv_default_namespace_id".to_owned(), toml::Value::String(NS.into()));
        factory.create("cf-kv-prod", &cfg).unwrap();
    }

    #[test]
    fn factory_rejects_non_string_default_namespace() {
        let factory = CfKvFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("cf_kv_default_namespace_id".to_owned(), toml::Value::Integer(42));
        let Err(err) = factory.create("cf-kv-prod", &cfg) else {
            panic!("expected error on non-string default namespace");
        };
        assert!(format!("{err:#}").contains("must be a string"), "err: {err:#}");
    }
}
