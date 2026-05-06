// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `Bitwarden Secrets Manager` backend for SecretEnv.
//!
//! Wraps the `bws` CLI v2.x — never an HTTP SDK. This backend
//! integrates the developer/CI **Bitwarden Secrets Manager** product
//! (machine-account access tokens, project-scoped secrets keyed by
//! UUID), which is a **distinct product from Bitwarden Password
//! Manager** (`bw` CLI, master-password vault items). The backend
//! `type` string is intentionally `bitwarden-sm` so the bare
//! `bitwarden` namespace stays open for a future Password Manager
//! wrapper without rename pain — same precedent as `aws-secrets` vs
//! a hypothetical `aws-ssm`.
//!
//! # URI shape
//!
//! `<instance>://<32-char-hex-uuid>[#json-key=<field>]`. Bitwarden
//! Secrets Manager addresses every secret by a server-generated
//! "simple" UUID (32 hex chars, no hyphens — verified live-probe
//! against `bws 2.0.0`: a path of length 0 yields
//! `invalid length: expected length 32 for simple format, found 0`).
//! `bws secret get` accepts ONLY UUIDs — there is no `--key` lookup
//! mode, and the server allows duplicate keys within a project, so
//! key-name addressing would be ambiguous as well as costlier
//! (extra `secret list` round-trip per fetch). Human-readable
//! aliases live in the SecretEnv registry layer above this backend.
//!
//! # Storage model
//!
//! Each secret is a JSON object: `{id, key, value, note, projectId,
//! creationDate, revisionDate, organizationId, object}`. [`get`]
//! parses the response and returns the `value` field. The fragment
//! `#json-key=<field>` then optionally extracts a top-level scalar
//! out of `value` when the secret stores a JSON object.
//!
//! Registry documents are stored as a JSON alias→URI map serialized
//! to the secret's `value` field (matching `aws-secrets`,
//! `openbao`, `conjur`). [`list`] fetches the secret and parses
//! `value` as a JSON object.
//!
//! # `bitwarden_unsafe_set` defense-in-depth flag
//!
//! Phase 0 (2026-05-05) live-probe confirmed `bws 2.0.0` has **no
//! stdin path** for `secret create` or `secret edit` — the value is
//! a positional `<VALUE>` argv (or `--value <VALUE>` for edit), so
//! the secret would be visible in `/proc/<pid>/cmdline` to any
//! process running as the same UID. There is no `-`/`/dev/stdin`
//! sentinel; there is no `--value-file` flag.
//!
//! Default posture: [`set`] and [`delete`] **refuse** with a clear
//! error pointing the operator at the Bitwarden web UI. Setting
//! `bitwarden_unsafe_set = true` opens the argv path explicitly —
//! same precedent as `1Password` (`op_unsafe_set`), `OpenBao`
//! (`bao_unsafe_set`), and `Conjur` (`conjur_unsafe_set`). `delete` is
//! gated alongside `set` by the same flag because the threat model
//! is "destructive write operations from a wrapped CLI", not
//! "argv-leak risk" specifically — splitting the gate would be
//! inconsistent with the precedent and would proliferate flags
//! without changing the operator's mental model.
//!
//! # `set` updates only — never creates
//!
//! The URI is a UUID. A UUID can only refer to a secret that
//! already exists. So [`set`] always invokes `bws secret edit
//! --value <value> <uuid>`, never `bws secret create`. Secret
//! creation is an out-of-band operator workflow (web UI or scripted
//! provisioning) that returns a UUID; the operator then writes that
//! UUID into the registry.
//!
//! # Identity line
//!
//! `bws project list` returns a JSON array of accessible projects.
//! There is no user identity (machine accounts aren't users), so
//! the doctor identity line shape is
//! `server=<url> token=<env-var-name> projects=<count>`. The token
//! VALUE is never echoed; only the env-var NAME and project COUNT
//! appear. An empty array is a valid response (token authenticated
//! but scoped to zero projects) — surfaced as a soft warning via
//! `projects=0` rather than a hard `NotAuthenticated`.
//!
//! # Token routing
//!
//! `BWS_ACCESS_TOKEN` is the standard env var `bws` reads. Operators
//! with multiple instances rename via `bitwarden_access_token_env`
//! (e.g. `BWS_ACCESS_TOKEN_PROD`). The wrapper sources the token
//! from the operator's shell at command time, then sets
//! `BWS_ACCESS_TOKEN` on the child process env only — it is never
//! written to argv, never written to the registry doc, never
//! logged. The renaming flag lives in config so a multi-instance
//! registry can route different instances at different machine
//! accounts without env-var collision.
//!
//! # Server URL
//!
//! Most operators use the US cloud (`https://vault.bitwarden.com`),
//! which is `bws`'s default — so the wrapper omits `BWS_SERVER_URL`
//! entirely when no override is configured (mirrors the vault
//! backend's omit-`VAULT_NAMESPACE` discipline). EU and self-hosted
//! operators set `bitwarden_server_url` explicitly.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_bool, optional_duration_secs, optional_string, Backend, BackendFactory, BackendStatus,
    BackendUri, DEFAULT_GET_TIMEOUT,
};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "bws";
const INSTALL_HINT: &str = "brew install bitwarden-secrets-manager (macOS) — \
     see https://bitwarden.com/help/secrets-manager-cli/ for Linux/Windows binaries";
const DEFAULT_TOKEN_ENV: &str = "BWS_ACCESS_TOKEN";
/// Server-URL env var read by the `bws` CLI itself. The wrapper sets
/// this only when `bitwarden_server_url` is configured (mirrors the
/// vault backend's omit-`VAULT_NAMESPACE` discipline) so the CLI's
/// US-cloud default applies on the most common path.
const SERVER_URL_ENV: &str = "BWS_SERVER_URL";
/// Minimum acceptable `bws` major version. v0.x had different argv
/// shapes; v1+ stabilized the surface this backend depends on.
const MIN_MAJOR_VERSION: u32 = 1;

/// A live instance of the `Bitwarden Secrets Manager` backend.
pub struct BitwardenSmBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Optional server-URL override. `None` → `bws` uses its built-in
    /// US-cloud default and the wrapper omits `BWS_SERVER_URL`. EU /
    /// self-hosted set this; the value is passed verbatim through
    /// `BWS_SERVER_URL`.
    bitwarden_server_url: Option<String>,
    /// Name of the env var holding the machine-account access token.
    /// Defaults to `BWS_ACCESS_TOKEN`. Renamed per-instance for
    /// multi-machine-account setups (e.g. `BWS_ACCESS_TOKEN_PROD`).
    /// The token VALUE is sourced from the operator's shell at
    /// command time; never persisted, never logged.
    bitwarden_access_token_env: String,
    /// Path or name of the `bws` binary. Defaults to `"bws"` (PATH
    /// lookup); tests override to a mock script.
    bitwarden_bin: String,
    /// Defense-in-depth opt-in (default `false`). When `false`,
    /// [`set`] and [`delete`] refuse with a clear error. When
    /// `true`, both proceed via the argv path (no stdin alternative
    /// exists in `bws 2.0.0`). Gates BOTH writes and deletes — see
    /// crate-level docs for rationale.
    bitwarden_unsafe_set: bool,
    /// Per-instance deadline for fetch-class operations.
    timeout: Duration,
}

/// `bws secret get` JSON envelope. Only the `value` field is read at
/// runtime; the rest are deserialized to validate shape and ignored.
/// `#[serde(default)]` so a server-side schema addition that omits a
/// field doesn't break existing clients.
#[derive(Deserialize)]
struct SecretGetResponse {
    #[serde(default)]
    value: String,
}

/// `bws project list` element. We only need the project count for
/// the identity line; `id` is named just to anchor the shape (so a
/// non-`id`-shaped element fails parse cleanly rather than silently
/// counting). We deliberately do NOT use `deny_unknown_fields`
/// because real `bws project list` returns the full envelope
/// (`organizationId`, `name`, `creationDate`, `revisionDate`, ...).
/// Phase 8 smoke caught this when strict-mock tests, which returned
/// only `{"id":"..."}`, missed the field-set drift.
#[derive(Deserialize)]
struct ProjectListElement {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
}

impl BitwardenSmBackend {
    /// Strip a single leading `/` from `uri.path` to produce the
    /// secret UUID passed to `bws secret get/edit/delete`. Bitwarden
    /// "simple" UUIDs are 32 hex chars, no hyphens. Validation is
    /// performed once per operation in [`Self::secret_uuid`] which
    /// returns a typed error on bad shape.
    fn raw_secret_id(uri: &BackendUri) -> &str {
        uri.path.strip_prefix('/').unwrap_or(&uri.path)
    }

    /// Validate the URI path is a Bitwarden simple-format UUID
    /// (`[0-9a-f]{32}`) and return the canonical lowercase form.
    /// `bws` v2.0.0 accepts BOTH the 36-char hyphenated canonical
    /// form (`8-4-4-4-12`) AND the 32-char "simple" form (no
    /// hyphens), and emits the hyphenated form on output — so
    /// users copying from the web UI or `bws secret list` get
    /// hyphenated by default. The wrapper accepts either; passes
    /// through verbatim since `bws` decodes both. Mixed case
    /// normalized to lowercase so registry documents written
    /// either way round-trip.
    fn secret_uuid(&self, uri: &BackendUri) -> Result<String> {
        let raw = Self::raw_secret_id(uri);
        let lower = raw.to_ascii_lowercase();
        match lower.len() {
            32 if lower.chars().all(|c| c.is_ascii_hexdigit()) => Ok(lower),
            36 if is_hyphenated_uuid(&lower) => Ok(lower),
            _ => bail!(
                "bitwarden-sm backend '{}': URI '{}' path must be a Bitwarden UUID — either the \
                 36-char hyphenated form (`8-4-4-4-12` lowercase hex, what `bws` emits) or the \
                 32-char simple form (no hyphens); got length {}",
                self.instance_name,
                uri.raw,
                raw.len()
            ),
        }
    }

    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        format!(
            "bitwarden-sm backend '{}': {op} failed for URI '{}': {}",
            self.instance_name,
            uri.raw,
            String::from_utf8_lossy(stderr).trim()
        )
    }

    /// Apply env routing common to every `bws` invocation:
    ///
    /// - `BWS_ACCESS_TOKEN` set from the configured env var (sourced
    ///   from the operator shell at call time). Missing → typed error
    ///   with the configured env-var name in the message.
    /// - `BWS_SERVER_URL` set when configured, ABSENT otherwise (so
    ///   the CLI's US-cloud default applies on the common path).
    fn apply_env(&self, cmd: &mut Command) -> Result<()> {
        let token = std::env::var(&self.bitwarden_access_token_env).map_err(|_| {
            anyhow::anyhow!(
                "bitwarden-sm backend '{}': env var ${} is not set; \
                 export the machine-account access token from the Bitwarden web UI \
                 (Secrets Manager → Machine Accounts → Access Tokens)",
                self.instance_name,
                self.bitwarden_access_token_env
            )
        })?;
        cmd.env(DEFAULT_TOKEN_ENV, token);
        if let Some(url) = &self.bitwarden_server_url {
            cmd.env(SERVER_URL_ENV, url);
        } else {
            // Active scrub: even if the parent has BWS_SERVER_URL
            // set globally, the wrapper's contract is "no override
            // configured ⇒ CLI default" — pinning the absence keeps
            // doctor output and smoke runs reproducible across hosts
            // with stale operator env.
            cmd.env_remove(SERVER_URL_ENV);
        }
        Ok(())
    }

    /// Build a `bws --output json <subcommand> <extra_args...>`
    /// command. `--output json` is pinned at the call site so a
    /// future change to the CLI's default output format doesn't
    /// silently break our parsers.
    fn bws_command(&self, subcommand: &str, extra_args: &[&str]) -> Result<Command> {
        let mut cmd = Command::new(&self.bitwarden_bin);
        cmd.arg("--output").arg("json").arg(subcommand);
        cmd.args(extra_args);
        self.apply_env(&mut cmd)?;
        Ok(cmd)
    }

    /// Build a `bws secret <verb> <args>` command (two positional
    /// args after the global `--output json`).
    fn bws_secret_command(&self, verb: &str, extra_args: &[&str]) -> Result<Command> {
        let mut cmd = Command::new(&self.bitwarden_bin);
        cmd.arg("--output").arg("json").arg("secret").arg(verb);
        cmd.args(extra_args);
        self.apply_env(&mut cmd)?;
        Ok(cmd)
    }

    /// `bws --version` — pure local, no env required, no server hit.
    /// Build directly without `apply_env` so a missing
    /// `BWS_ACCESS_TOKEN` doesn't mask a CLI-missing diagnosis at
    /// Level 1.
    fn version_command(&self) -> Command {
        let mut cmd = Command::new(&self.bitwarden_bin);
        cmd.arg("--version");
        cmd
    }

    /// Validate the URI's fragment for `get` and return the requested
    /// JSON key, if any. `bitwarden-sm` recognizes only the
    /// `json-key` directive (same vocabulary as `aws-secrets`,
    /// `openbao`, `conjur`).
    fn parse_json_key_fragment(&self, uri: &BackendUri) -> Result<Option<String>> {
        let Some(mut directives) = uri.fragment_directives()? else {
            return Ok(None);
        };
        let Some(key) = directives.shift_remove("json-key") else {
            let mut unsupported: Vec<&str> = directives.keys().map(String::as_str).collect();
            unsupported.sort_unstable();
            bail!(
                "bitwarden-sm backend '{}': URI '{}' has unsupported fragment directive(s) [{}]; \
                 bitwarden-sm recognizes only 'json-key' (example: '#json-key=password')",
                self.instance_name,
                uri.raw,
                unsupported.join(", ")
            );
        };
        if !directives.is_empty() {
            let mut extra: Vec<&str> = directives.keys().map(String::as_str).collect();
            extra.sort_unstable();
            bail!(
                "bitwarden-sm backend '{}': URI '{}' has unsupported directive(s) [{}] alongside \
                 'json-key'; bitwarden-sm recognizes only 'json-key'",
                self.instance_name,
                uri.raw,
                extra.join(", ")
            );
        }
        Ok(Some(key))
    }

    /// Invoke `bws secret get <uuid>` and return the parsed `value`
    /// field from the JSON envelope. Used by both the user-facing
    /// `get` (without fragment) and as the raw fetch underlying
    /// fragment extraction + `list`.
    async fn get_raw_value(&self, uri: &BackendUri) -> Result<String> {
        let uuid = self.secret_uuid(uri)?;
        let mut cmd = self.bws_secret_command("get", &[&uuid])?;
        let output = cmd.output().await.with_context(|| {
            format!(
                "bitwarden-sm backend '{}': failed to invoke 'bws secret get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let parsed: SecretGetResponse =
            serde_json::from_slice(&output.stdout).with_context(|| {
                format!(
                    "bitwarden-sm backend '{}': could not parse 'bws secret get' JSON for URI '{}'",
                    self.instance_name, uri.raw
                )
            })?;
        Ok(parsed.value)
    }

    /// Reject a write-class operation when the unsafe-set gate is
    /// closed (default). Wording is the verbatim error that ships in
    /// the spec; smoke section 28 asserts the exact string.
    fn unsafe_set_refused(&self, op: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "bitwarden-sm backend '{}': {op} is disabled by default because `bws` exposes the \
             secret value on argv (visible via /proc/<pid>/cmdline). To enable, set:\n  \
             [backends.{}]\n  bitwarden_unsafe_set = true\n\
             Recommended alternative: provision the secret via the Bitwarden web UI, then \
             reference its UUID from this registry. See docs/backends/bitwarden-sm.md.",
            self.instance_name,
            self.instance_name,
            op = op,
        )
    }

    /// Read-only accessor for the unsafe-set flag (test-only).
    /// Default-off invariant is machine-checked via
    /// `factory_bitwarden_unsafe_set_defaults_false`.
    #[cfg(test)]
    const fn unsafe_set(&self) -> bool {
        self.bitwarden_unsafe_set
    }

    /// Read-only accessor for the configured token env-var name
    /// (test-only). Used by the rename-roundtrip test.
    #[cfg(test)]
    fn token_env(&self) -> &str {
        &self.bitwarden_access_token_env
    }

    /// Read-only accessor for the configured server URL (test-only).
    /// Used by the omit-when-default test.
    #[cfg(test)]
    fn server_url(&self) -> Option<&str> {
        self.bitwarden_server_url.as_deref()
    }
}

#[async_trait]
impl Backend for BitwardenSmBackend {
    fn backend_type(&self) -> &str {
        self.backend_type
    }

    fn instance_name(&self) -> &str {
        &self.instance_name
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    #[allow(clippy::too_many_lines)]
    async fn check(&self) -> BackendStatus {
        // Level 1 — `bws --version` (no env required).
        let version_out = match self.version_command().output().await {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "bitwarden-sm backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.bitwarden_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "bitwarden-sm backend '{}': 'bws --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let version_line = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();
        let Some(version_token) = parse_version_token(&version_line) else {
            return BackendStatus::Error {
                message: format!(
                    "bitwarden-sm backend '{}': could not parse bws version line ({version_line}); \
                     expected `bws <X.Y.Z>` (v{MIN_MAJOR_VERSION}+)",
                    self.instance_name
                ),
            };
        };
        let Some(major) = version_token.split('.').next().and_then(|s| s.parse::<u32>().ok())
        else {
            return BackendStatus::Error {
                message: format!(
                    "bitwarden-sm backend '{}': bws version token '{version_token}' has no \
                     numeric major component (expected `<X.Y.Z>`)",
                    self.instance_name
                ),
            };
        };
        if major < MIN_MAJOR_VERSION {
            return BackendStatus::Error {
                message: format!(
                    "bitwarden-sm backend '{}': bws v{version_token} is below minimum \
                     supported v{MIN_MAJOR_VERSION}.x — upgrade via `brew upgrade \
                     bitwarden-secrets-manager` (or the Linux/Windows package)",
                    self.instance_name
                ),
            };
        }

        // Level 2 — `bws --output json project list` (token required).
        let mut list_cmd = match self.bws_command("project", &["list"]) {
            Ok(c) => c,
            Err(e) => {
                return BackendStatus::NotAuthenticated { hint: format!("{e:#}") };
            }
        };
        let list_out = match list_cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "bitwarden-sm backend '{}': failed to invoke 'bws project list': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !list_out.status.success() {
            let stderr = String::from_utf8_lossy(&list_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "set ${} to a machine-account access token from the Bitwarden web UI \
                     (Secrets Manager → Machine Accounts → Access Tokens) (stderr: {stderr})",
                    self.bitwarden_access_token_env
                ),
            };
        }
        let projects: Vec<ProjectListElement> = match serde_json::from_slice(&list_out.stdout) {
            Ok(p) => p,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "bitwarden-sm backend '{}': parsing 'bws project list' JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        let server = self.bitwarden_server_url.as_deref().unwrap_or("https://vault.bitwarden.com");
        BackendStatus::Ok {
            cli_version: version_line,
            identity: format!(
                "server={server} token=${} projects={}",
                self.bitwarden_access_token_env,
                projects.len()
            ),
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        let json_key = self.parse_json_key_fragment(uri)?;
        let raw = self.get_raw_value(uri).await?;
        match json_key {
            None => Ok(raw),
            Some(key) => extract_json_field(&self.instance_name, uri, &raw, &key),
        }
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("bitwarden-sm")?;
        if !self.bitwarden_unsafe_set {
            return Err(self.unsafe_set_refused("set"));
        }
        let uuid = self.secret_uuid(uri)?;
        // Per-invocation tracing breadcrumb so `secretenv --verbose`
        // surfaces the choice (mirrors 1Password / Conjur precedent).
        // Value never echoed.
        tracing::warn!(
            instance = self.instance_name.as_str(),
            uri = uri.raw.as_str(),
            "`bws secret edit --value <value>` passes the secret through subprocess argv \
             (bitwarden_unsafe_set = true was set; CV-1 exposure acknowledged) — \
             do not run on multi-user hosts unless audited"
        );
        // Argv ordering matches the Phase 0 live-probe of `bws 2.0.0`:
        //   bws --output json secret edit --value <value> <uuid>
        // The wrapper always uses `secret edit` (never `secret create`)
        // because the URI is a UUID — only an existing secret can be
        // referenced by UUID. Provisioning is an out-of-band op.
        let mut cmd = self.bws_secret_command("edit", &["--value", value, &uuid])?;
        let output = cmd.output().await.with_context(|| {
            format!(
                "bitwarden-sm backend '{}': failed to invoke 'bws secret edit' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "set", &output.stderr));
        }
        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("bitwarden-sm")?;
        if !self.bitwarden_unsafe_set {
            return Err(self.unsafe_set_refused("delete"));
        }
        let uuid = self.secret_uuid(uri)?;
        let mut cmd = self.bws_secret_command("delete", &[&uuid])?;
        let output = cmd.output().await.with_context(|| {
            format!(
                "bitwarden-sm backend '{}': failed to invoke 'bws secret delete' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "delete", &output.stderr));
        }
        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("bitwarden-sm")?;
        let raw = self.get_raw_value(uri).await?;
        let map: HashMap<String, String> = serde_json::from_str(&raw).with_context(|| {
            format!(
                "bitwarden-sm backend '{}': registry value at '{}' is not a JSON alias→URI map",
                self.instance_name, uri.raw
            )
        })?;
        // Stable, alphabetical ordering — `HashMap::into_iter()` is
        // randomized per-process and would give callers (and the
        // smoke harness's `assert_contains` checks) non-deterministic
        // output across runs.
        let mut pairs: Vec<(String, String)> = map.into_iter().collect();
        pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(pairs)
    }

    // `history` falls back to the trait default ("not implemented").
    // Bitwarden Secrets Manager surfaces revisions in the web UI
    // (every `secret edit` bumps `revisionDate`) but the CLI has no
    // `secret history` subcommand. Out of scope until vendor exposes
    // versioning.
}

/// Parse the version token (e.g. `2.0.0`) out of a `bws <X.Y.Z>`
/// line. Returns the `<X.Y.Z>` portion when matched.
fn parse_version_token(line: &str) -> Option<&str> {
    let after = line.strip_prefix("bws ")?;
    after.split_whitespace().next()
}

/// Parse `raw` as a JSON object and extract the top-level `key`
/// field as a string. Mirrors the `aws-secrets` / `openbao` /
/// `conjur` extractors so behavior is identical across backends.
fn extract_json_field(
    instance_name: &str,
    uri: &BackendUri,
    raw: &str,
    key: &str,
) -> Result<String> {
    let mut map: HashMap<String, serde_json::Value> =
        serde_json::from_str(raw).with_context(|| {
            format!(
                "bitwarden-sm backend '{instance_name}': URI '{}' selects JSON key '{key}' \
                 but secret value at '{}' is not a JSON object",
                uri.raw, uri.path
            )
        })?;
    if !map.contains_key(key) {
        let mut fields: Vec<&str> = map.keys().map(String::as_str).collect();
        fields.sort_unstable();
        bail!(
            "bitwarden-sm backend '{instance_name}': URI '{}' field '{key}' not found; \
             secret at '{}' has fields: [{}]",
            uri.raw,
            uri.path,
            fields.join(", ")
        );
    }
    let Some(value) = map.remove(key) else { unreachable!("presence checked above") };
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok("null".to_owned()),
        ref v @ (serde_json::Value::Array(_) | serde_json::Value::Object(_)) => bail!(
            "bitwarden-sm backend '{instance_name}': URI '{}' field '{key}' is a JSON {} — only \
             scalar fields (string/number/boolean/null) can be extracted",
            uri.raw,
            if v.is_array() { "array" } else { "object" }
        ),
    }
}

/// Reject control characters in operator-supplied config fields.
/// Mirrors the URI parser's check — null/control bytes can corrupt
/// `ps` output, smuggle terminal-control sequences into error
/// messages, and break `execvp` arg marshalling.
fn has_forbidden_control_char(s: &str) -> bool {
    s.bytes().any(|b| b == 0 || (b < 0x20 && b != b'\t'))
}

/// Factory for the `Bitwarden Secrets Manager` backend.
pub struct BitwardenSmFactory(&'static str);

impl BitwardenSmFactory {
    /// Construct the factory. Equivalent to
    /// `BitwardenSmFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("bitwarden-sm")
    }
}

impl Default for BitwardenSmFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BitwardenSmFactory {
    /// Concrete-typed factory path. The trait `create()` boxes the
    /// result; tests use this directly so they can inspect private
    /// fields like `bitwarden_unsafe_set` without downcast
    /// gymnastics.
    fn create_concrete(
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<BitwardenSmBackend> {
        let bitwarden_server_url =
            optional_string(config, "bitwarden_server_url", "bitwarden-sm", instance_name)?;
        if let Some(url) = &bitwarden_server_url {
            if has_forbidden_control_char(url) {
                bail!(
                    "bitwarden-sm backend '{instance_name}': field 'bitwarden_server_url' \
                     contains a forbidden control character (NUL or sub-0x20 byte other than tab)"
                );
            }
        }
        let bitwarden_access_token_env =
            optional_string(config, "bitwarden_access_token_env", "bitwarden-sm", instance_name)?
                .unwrap_or_else(|| DEFAULT_TOKEN_ENV.to_owned());
        if has_forbidden_control_char(&bitwarden_access_token_env) {
            bail!(
                "bitwarden-sm backend '{instance_name}': field 'bitwarden_access_token_env' \
                 contains a forbidden control character (NUL or sub-0x20 byte other than tab)"
            );
        }
        if !is_valid_env_var_name(&bitwarden_access_token_env) {
            bail!(
                "bitwarden-sm backend '{instance_name}': field 'bitwarden_access_token_env' \
                 ('{bitwarden_access_token_env}') is not a valid POSIX env var name (must match \
                 [A-Za-z_][A-Za-z0-9_]*)"
            );
        }
        let bitwarden_bin =
            optional_string(config, "bitwarden_bin", "bitwarden-sm", instance_name)?
                .unwrap_or_else(|| CLI_NAME.to_owned());
        let bitwarden_unsafe_set =
            optional_bool(config, "bitwarden_unsafe_set", "bitwarden-sm", instance_name)?
                .unwrap_or(false);
        let timeout =
            optional_duration_secs(config, "timeout_secs", "bitwarden-sm", instance_name)?
                .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(BitwardenSmBackend {
            backend_type: "bitwarden-sm",
            instance_name: instance_name.to_owned(),
            bitwarden_server_url,
            bitwarden_access_token_env,
            bitwarden_bin,
            bitwarden_unsafe_set,
            timeout,
        })
    }
}

/// True when `s` matches the canonical hyphenated UUID pattern
/// `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
/// Caller is responsible for already lowercasing.
fn is_hyphenated_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    bytes.iter().enumerate().all(|(i, &b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit())
}

/// POSIX env var name shape. The factory rejects custom token-env
/// names that wouldn't survive a shell `export NAME=...` round-trip
/// — without this check, a config field of `"BWS TOKEN"` (with
/// space) or `"1ST_TOKEN"` (digit-leading) would pass through and
/// `std::env::var` would just always fail to find it, producing a
/// confusing error far from the config site.
fn is_valid_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else { return false };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl BackendFactory for BitwardenSmFactory {
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    // Tests serialize via a `std::sync::Mutex` to coordinate
    // process-global env mutation. Holding the guard across
    // `.await` is the whole point — releasing it mid-await would
    // let a concurrent test's env-var poke race the mock's
    // env-var assertion. Same pattern as openbao/vault tests.
    clippy::await_holding_lock,
)]
mod tests {
    use std::path::Path;
    use std::sync::Mutex;

    use secretenv_testing::{Response, StrictMock};
    use tempfile::TempDir;

    use super::*;

    // Test fixtures live in this serializing mutex because every
    // test mutates process-global env (`BWS_ACCESS_TOKEN`,
    // `BWS_SERVER_URL`). Cargo runs tests in parallel by default;
    // without serialization, one test's `set_var` races another's
    // env-var assertion in the StrictMock. Same pattern openbao /
    // vault use.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// 32-char Bitwarden simple-format UUIDs for use in tests.
    const TEST_UUID: &str = "abcdef0123456789abcdef0123456789";
    const REGISTRY_UUID: &str = "1111111122222222333333334444aaaa";
    const TEST_TOKEN: &str = "0.fakeaccount.fakekey:fakemac";
    const CUSTOM_URL: &str = "https://vault.bitwarden.eu";

    fn backend(mock_path: &Path) -> BitwardenSmBackend {
        backend_full(mock_path, None, DEFAULT_TOKEN_ENV, false)
    }

    fn backend_with_unsafe_set(mock_path: &Path) -> BitwardenSmBackend {
        backend_full(mock_path, None, DEFAULT_TOKEN_ENV, true)
    }

    fn backend_full(
        mock_path: &Path,
        server_url: Option<&str>,
        token_env: &str,
        unsafe_set: bool,
    ) -> BitwardenSmBackend {
        BitwardenSmBackend {
            backend_type: "bitwarden-sm",
            instance_name: "bws-dev".to_owned(),
            bitwarden_server_url: server_url.map(str::to_owned),
            bitwarden_access_token_env: token_env.to_owned(),
            bitwarden_bin: mock_path.to_str().unwrap().to_owned(),
            bitwarden_unsafe_set: unsafe_set,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_bws() -> BitwardenSmBackend {
        BitwardenSmBackend {
            backend_type: "bitwarden-sm",
            instance_name: "bws-dev".to_owned(),
            bitwarden_server_url: None,
            bitwarden_access_token_env: DEFAULT_TOKEN_ENV.to_owned(),
            bitwarden_bin: "/definitely/not/a/real/path/to/bws-binary-12345".to_owned(),
            bitwarden_unsafe_set: false,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    /// Apply token env (and optionally URL) for a test, returning a
    /// guard that strips them on drop. Acquires `ENV_LOCK` so other
    /// tests don't observe partial state.
    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        keys: Vec<String>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for k in &self.keys {
                std::env::remove_var(k);
            }
        }
    }

    fn env_with(token_env: &str, token: &str, url_env: Option<(&str, &str)>) -> EnvGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut keys = Vec::new();
        std::env::set_var(token_env, token);
        keys.push(token_env.to_owned());
        // Always pre-clear BWS_SERVER_URL so a stale parent env
        // doesn't poison the env-absent assertions.
        std::env::remove_var(SERVER_URL_ENV);
        if let Some((k, v)) = url_env {
            std::env::set_var(k, v);
            keys.push(k.to_owned());
        }
        EnvGuard { _lock: lock, keys }
    }

    fn ok(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var(DEFAULT_TOKEN_ENV, TEST_TOKEN)
            .with_env_absent(SERVER_URL_ENV)
    }

    fn ok_with_url(stdout: &str, url: &str) -> Response {
        Response::success(stdout)
            .with_env_var(DEFAULT_TOKEN_ENV, TEST_TOKEN)
            .with_env_var(SERVER_URL_ENV, url)
    }

    fn fail(exit_code: i32, stderr: &str) -> Response {
        Response::failure(exit_code, stderr)
            .with_env_var(DEFAULT_TOKEN_ENV, TEST_TOKEN)
            .with_env_absent(SERVER_URL_ENV)
    }

    // ---- factory ----

    #[test]
    fn factory_backend_type_is_bitwarden_sm() {
        assert_eq!(BitwardenSmFactory::new().backend_type(), "bitwarden-sm");
    }

    #[test]
    fn factory_accepts_empty_config_with_defaults() {
        // Server URL, token env, bin, unsafe_set all have sensible
        // defaults — an instance with `type = "bitwarden-sm"` and no
        // other fields is a valid US-cloud machine-account setup.
        let factory = BitwardenSmFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = factory.create("bws-dev", &cfg).unwrap();
        assert_eq!(b.backend_type(), "bitwarden-sm");
        assert_eq!(b.instance_name(), "bws-dev");
    }

    #[test]
    fn factory_bitwarden_unsafe_set_defaults_false() {
        // Defense-in-depth: refuse-by-default for both `set` and
        // `delete` is the safe posture. Pin the default so a future
        // regression that flips the runtime branch starts from a
        // closed door.
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert!(!b.unsafe_set(), "default must be false (defense-in-depth)");
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
    }

    #[test]
    fn factory_bitwarden_unsafe_set_accepts_true() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("bitwarden_unsafe_set".to_owned(), toml::Value::Boolean(true));
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert!(b.unsafe_set(), "explicit true must round-trip");
    }

    #[test]
    fn factory_rejects_non_bool_bitwarden_unsafe_set() {
        let factory = BitwardenSmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("bitwarden_unsafe_set".to_owned(), toml::Value::String("yes".to_owned()));
        let Err(err) = factory.create("bws-dev", &cfg) else {
            panic!("expected error for non-bool bitwarden_unsafe_set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("bitwarden_unsafe_set"), "names the field: {msg}");
    }

    #[test]
    fn factory_rejects_non_string_bitwarden_server_url() {
        let factory = BitwardenSmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("bitwarden_server_url".to_owned(), toml::Value::Integer(8080));
        let Err(err) = factory.create("bws-dev", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("bitwarden_server_url"));
    }

    #[test]
    fn factory_rejects_control_char_in_server_url() {
        let factory = BitwardenSmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bitwarden_server_url".to_owned(),
            toml::Value::String("https://vault\nhostile.example.com".to_owned()),
        );
        let Err(err) = factory.create("bws-dev", &cfg) else {
            panic!("expected error for control char in server url");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("control character"), "names the issue: {msg}");
    }

    #[test]
    fn factory_token_env_defaults_to_bws_access_token() {
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert_eq!(b.token_env(), DEFAULT_TOKEN_ENV);
    }

    #[test]
    fn factory_token_env_round_trips_custom_name() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bitwarden_access_token_env".to_owned(),
            toml::Value::String("BWS_ACCESS_TOKEN_PROD".to_owned()),
        );
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert_eq!(b.token_env(), "BWS_ACCESS_TOKEN_PROD");
    }

    #[test]
    fn factory_rejects_invalid_env_var_name() {
        let factory = BitwardenSmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bitwarden_access_token_env".to_owned(),
            toml::Value::String("1ST_TOKEN".to_owned()),
        );
        let Err(err) = factory.create("bws-dev", &cfg) else {
            panic!("expected error for invalid env var name");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("POSIX env var name"), "names the issue: {msg}");
    }

    #[test]
    fn factory_server_url_round_trips_eu() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "bitwarden_server_url".to_owned(),
            toml::Value::String("https://vault.bitwarden.eu".to_owned()),
        );
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert_eq!(b.server_url(), Some("https://vault.bitwarden.eu"));
    }

    #[test]
    fn factory_server_url_defaults_to_none() {
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let b = BitwardenSmFactory::create_concrete("bws-dev", &cfg).unwrap();
        assert_eq!(b.server_url(), None);
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = BitwardenSmFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(11));
        let b = factory.create("bws-dev", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(11));
    }

    // ---- secret_uuid validation ----

    #[test]
    fn secret_uuid_accepts_simple_form() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        assert_eq!(b.secret_uuid(&uri).unwrap(), TEST_UUID);
    }

    #[test]
    fn secret_uuid_normalizes_uppercase_hex() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let uppercase = TEST_UUID.to_ascii_uppercase();
        let uri = BackendUri::parse(&format!("bws-dev://{uppercase}")).unwrap();
        assert_eq!(b.secret_uuid(&uri).unwrap(), TEST_UUID);
    }

    #[test]
    fn secret_uuid_accepts_hyphenated_form() {
        // `bws` v2.0.0 accepts both forms and EMITS the hyphenated
        // 36-char canonical form on every output (`secret list`,
        // `secret get`, `project list`). Live-probed 2026-05-05.
        // Users copying UUIDs from the web UI / `bws` output get
        // hyphenated by default.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let hyphenated = "abcdef01-2345-6789-abcd-ef0123456789";
        let uri = BackendUri::parse(&format!("bws-dev://{hyphenated}")).unwrap();
        assert_eq!(b.secret_uuid(&uri).unwrap(), hyphenated);
    }

    #[test]
    fn secret_uuid_normalizes_uppercase_hyphenated() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let upper = "ABCDEF01-2345-6789-ABCD-EF0123456789";
        let uri = BackendUri::parse(&format!("bws-dev://{upper}")).unwrap();
        assert_eq!(b.secret_uuid(&uri).unwrap(), upper.to_ascii_lowercase());
    }

    #[test]
    fn secret_uuid_rejects_hyphenated_with_misplaced_dashes() {
        // Right length (36) and right char set, wrong dash positions.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let bogus = "abcdef0-12345-6789-abcd-ef0123456789a"; // dashes at 7/13/18/23
        let uri = BackendUri::parse(&format!("bws-dev://{bogus}")).unwrap();
        let Err(err) = b.secret_uuid(&uri) else {
            panic!("expected error for misplaced-dash UUID");
        };
        assert!(format!("{err:#}").contains("Bitwarden UUID"));
    }

    #[test]
    fn secret_uuid_rejects_non_hex_chars() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        // 32 chars but `g` and `z` are non-hex.
        let uri = BackendUri::parse("bws-dev://gggggggggggggggggggggggggggggggz").unwrap();
        let Err(err) = b.secret_uuid(&uri) else {
            panic!("expected error for non-hex UUID");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("Bitwarden UUID"), "names the constraint: {msg}");
    }

    #[test]
    fn secret_uuid_rejects_short_path() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("bws-dev://abc").unwrap();
        let Err(err) = b.secret_uuid(&uri) else {
            panic!("expected length error");
        };
        assert!(format!("{err:#}").contains("length 3"));
    }

    // ---- check Level 1 ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_bws();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "bws");
                assert!(
                    install_hint.contains("brew install bitwarden-secrets-manager"),
                    "expected brew install hint, got: {install_hint}"
                );
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_rejects_unparseable_version_line() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("totally-not-a-version-line\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Error { message } => {
                assert!(message.contains("could not parse"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_rejects_too_old_major_version() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("bws 0.5.0\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Error { message } => {
                assert!(message.contains("below minimum"), "got: {message}");
                assert!(message.contains("0.5.0"), "names version: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level1_version_parses_v2() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        // Use the FULL `bws project list` envelope shape (Phase 8
        // smoke caught a `deny_unknown_fields` regression where
        // minimal `{"id":"x"}` mocks passed but real `bws` output
        // failed to parse). This shape mirrors what `bws 2.0.0`
        // actually returns.
        let real_envelope = r#"[{"id":"7c6991ce-1beb-40a4-85de-b4410182bfbf","organizationId":"fb710ff6-1692-4d75-99dc-b435003384b7","name":"SecretEnv","creationDate":"2026-05-05T23:28:06.581277600Z","revisionDate":"2026-05-05T23:28:14.912241300Z"}]"#;
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("bws 2.0.0\n"))
            .on(&["--output", "json", "project", "list"], ok(real_envelope))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert_eq!(cli_version, "bws 2.0.0");
                assert!(identity.contains("server=https://vault.bitwarden.com"));
                assert!(identity.contains("token=$BWS_ACCESS_TOKEN"));
                assert!(identity.contains("projects=1"), "got: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_empty_project_list_is_zero_not_failure() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("bws 2.0.0\n"))
            .on(&["--output", "json", "project", "list"], ok("[]"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(identity.contains("projects=0"), "got: {identity}");
            }
            other => panic!("expected Ok with projects=0, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_level2_not_authenticated_when_token_unset() {
        // Hold the lock without setting the token — ensure the
        // configured env var is unset before check runs.
        let lock = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var(DEFAULT_TOKEN_ENV);
        std::env::remove_var(SERVER_URL_ENV);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("bws 2.0.0\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("BWS_ACCESS_TOKEN"), "names env var: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
        drop(lock);
    }

    #[tokio::test]
    async fn check_level2_not_authenticated_on_bws_error() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--version"], Response::success("bws 2.0.0\n"))
            .on(&["--output", "json", "project", "list"], fail(1, "401 Unauthorized\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("BWS_ACCESS_TOKEN"), "names env var: {hint}");
                assert!(hint.contains("401"), "includes stderr fragment: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_value_field_from_json() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "get", TEST_UUID],
                ok(&format!(
                    r#"{{"object":"secret","id":"{TEST_UUID}","key":"K","value":"sk_live_xyz","note":"","projectId":"p","creationDate":"2026-05-05T00:00:00Z","revisionDate":"2026-05-05T00:00:00Z"}}"#
                )),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "sk_live_xyz");
    }

    #[tokio::test]
    async fn get_with_json_key_fragment_extracts_field() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "get", TEST_UUID],
                ok(r#"{"value":"{\"username\":\"alice\",\"password\":\"pw\"}"}"#),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}#json-key=password")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "pw");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", TEST_UUID], ok(r#"{"value":""}"#))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "");
    }

    #[tokio::test]
    async fn get_preserves_internal_whitespace() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "get", TEST_UUID],
                ok(r#"{"value":"line1\nline2"}"#),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        assert_eq!(b.get(&uri).await.unwrap(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_404_wraps_stderr() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", TEST_UUID], fail(1, "404 Not Found"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("404 Not Found"), "wraps stderr: {msg}");
        assert!(msg.contains("bws-dev"), "names instance: {msg}");
    }

    #[tokio::test]
    async fn get_unsupported_fragment_directive_rejected() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        // `unknown-directive` is not in the bitwarden-sm vocabulary.
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}#unknown-directive=x")).unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported fragment directive"), "got: {msg}");
        assert!(msg.contains("unknown-directive"), "names directive: {msg}");
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_value_as_json_alias_map() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        // The secret's `value` is a JSON-string containing the
        // alias→URI map. Outer object wraps the map as a string.
        let body = format!(
            r#"{{"value":"{{\"a\":\"bws-dev://{TEST_UUID}\",\"b\":\"vault-dev://secret/x\"}}"}}"#
        );
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", REGISTRY_UUID], ok(&body))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{REGISTRY_UUID}")).unwrap();
        let pairs = b.list(&uri).await.unwrap();
        assert_eq!(pairs.len(), 2);
        // Alphabetically sorted: a, b.
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[1].0, "b");
    }

    #[tokio::test]
    async fn list_errors_when_value_is_not_json_map() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "get", REGISTRY_UUID],
                ok(r#"{"value":"this-is-not-json"}"#),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{REGISTRY_UUID}")).unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a JSON alias→URI map"), "got: {msg}");
    }

    // ---- set ----

    #[tokio::test]
    async fn set_blocked_when_unsafe_set_false() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        // Mock has zero rules — any invocation is a no-match (exit
        // 97). The default-refuse path must NOT shell out, so this
        // mock should never be called. If it is, the test fails
        // loudly at exit 97.
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        let err = b.set(&uri, "secret-value").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("disabled by default"), "got: {msg}");
        assert!(msg.contains("bitwarden_unsafe_set"), "names the flag: {msg}");
        assert!(msg.contains("bws-dev"), "names instance: {msg}");
    }

    #[tokio::test]
    async fn set_argv_path_allowed_when_unsafe_set_true() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "edit", "--value", "sk_new", TEST_UUID],
                ok(r#"{"id":"x","value":"sk_new"}"#),
            )
            .install(dir.path());
        let b = backend_with_unsafe_set(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.set(&uri, "sk_new").await.unwrap();
    }

    #[tokio::test]
    async fn set_uses_secret_edit_not_create() {
        // Regression lock: the URI is a UUID, so set MUST update an
        // existing secret (`secret edit`) and never attempt
        // `secret create` (which would need a project ID we don't
        // have). The mock declares ONLY `secret edit ...` — a
        // `secret create ...` invocation lands in no-match (97).
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "edit", "--value", "v", TEST_UUID], ok("{}"))
            .install(dir.path());
        let b = backend_with_unsafe_set(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.set(&uri, "v").await.unwrap();
    }

    #[tokio::test]
    async fn set_rejects_fragment() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend_with_unsafe_set(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}#json-key=x")).unwrap();
        let err = b.set(&uri, "v").await.unwrap_err();
        let msg = format!("{err:#}");
        // `reject_any_fragment` returns its own error wording —
        // check it ran (didn't fall through to the unsafe-set gate).
        assert!(!msg.contains("disabled by default"), "fragment check ran first: {msg}");
    }

    // ---- delete ----

    #[tokio::test]
    async fn delete_blocked_when_unsafe_set_false() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("disabled by default"), "got: {msg}");
        assert!(msg.contains("bitwarden_unsafe_set"), "names the flag: {msg}");
    }

    #[tokio::test]
    async fn delete_argv_when_unsafe_set_true() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "delete", TEST_UUID], ok(r#"[{"id":"x"}]"#))
            .install(dir.path());
        let b = backend_with_unsafe_set(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.delete(&uri).await.unwrap();
    }

    // ---- env routing regression locks ----

    #[tokio::test]
    async fn command_passes_token_via_env_not_argv() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        // Rule asserts BWS_ACCESS_TOKEN=<TEST_TOKEN> in env. If the
        // wrapper passed it via `-t <token>` argv, the mock would
        // receive an extra arg and the rule's argv-match would fail
        // (no-match → exit 97).
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", TEST_UUID], ok(r#"{"value":"v"}"#))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_respects_custom_access_token_env() {
        let _env = env_with("BWS_ACCESS_TOKEN_PROD", TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        // Assertion: even with a renamed source env var, the wrapper
        // sets `BWS_ACCESS_TOKEN` (the canonical name `bws` reads)
        // on the child env. Renaming is operator-side ergonomics —
        // the CLI contract is fixed.
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", TEST_UUID], ok(r#"{"value":"v"}"#))
            .install(dir.path());
        let b = backend_full(&mock, None, "BWS_ACCESS_TOKEN_PROD", false);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_passes_server_url_via_env_when_configured() {
        let _env = env_with(DEFAULT_TOKEN_ENV, TEST_TOKEN, None);
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(
                &["--output", "json", "secret", "get", TEST_UUID],
                ok_with_url(r#"{"value":"v"}"#, CUSTOM_URL),
            )
            .install(dir.path());
        let b = backend_full(&mock, Some(CUSTOM_URL), DEFAULT_TOKEN_ENV, false);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn command_omits_server_url_env_for_default_us_cloud() {
        // With `bitwarden_server_url = None`, the wrapper actively
        // removes `BWS_SERVER_URL` from the child env (so the CLI's
        // built-in US-cloud default applies, even on a host where
        // the operator's parent shell has BWS_SERVER_URL set
        // globally to something else).
        let _env = env_with(
            DEFAULT_TOKEN_ENV,
            TEST_TOKEN,
            Some((SERVER_URL_ENV, "https://stale.example")),
        );
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("bws")
            .on(&["--output", "json", "secret", "get", TEST_UUID], ok(r#"{"value":"v"}"#))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse(&format!("bws-dev://{TEST_UUID}")).unwrap();
        b.get(&uri).await.unwrap();
    }
}
