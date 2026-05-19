// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `Conjur` backend for SecretEnv (`CyberArk` Conjur OSS / Enterprise).
//!
//! Wraps the **Go-based** `conjur` v8 CLI — never an HTTP SDK. Conjur OSS
//! (Apache-2.0) and Conjur Enterprise share the same wire protocol, so
//! this backend works against both deployments. The canonical macOS
//! install at v0.11 ship time is the `cyberark/conjur-cli:8` Docker
//! image (`PyPI` `conjur` is the EOL Ruby v7 line; `CyberArk` has not
//! published a Homebrew tap or native macOS binary).
//!
//! # URI shape
//!
//! `<instance>://<variable-id-with-slashes>[#json-key=<field>]`. Conjur
//! has **no KV-mount concept**: the entire URI path IS the variable ID.
//! Variable IDs reflect policy hierarchy (e.g. `prod/db/password`).
//! The hash fragment is optional and selects a top-level field of a
//! JSON-encoded variable value (see [`get`] below).
//!
//! # Storage model
//!
//! Conjur variables hold opaque string values. This backend writes the
//! value as raw bytes via the safe-stdin path (see below) and reads it
//! back via `conjur variable get -i <id>`, which returns the raw value
//! followed by exactly one trailing `\n` — the wrapper strips that
//! single newline.
//!
//! Registry documents are stored as a JSON alias→URI map serialized to
//! the variable value (matching `aws-secrets`, `aws-ssm`, and
//! `openbao`). [`ConjurBackend::list`] fetches the value verbatim and
//! parses it as a JSON object.
//!
//! # `#json-key` fragment
//!
//! When `#json-key=<field>` is present in the URI fragment, [`get`]
//! parses the variable value as a JSON object and returns the named
//! top-level scalar field. Other operations (`set`, `delete`, `list`,
//! `history`) reject any fragment.
//!
//! # `conjur_unsafe_set` defense-in-depth flag
//!
//! Phase 0 (2026-04-30) live-probed `Conjur CLI version 8.1.3` and
//! confirmed v8 has **no `--value-from-stdin` flag** (only `-v <value>`
//! argv and `-f <file>` file-path). [`set`] therefore uses
//! `-f /dev/stdin` with the value piped through child stdin — the
//! kernel pseudo-file lets the CLI read the bytes "as if from a file"
//! without touching disk and without ever appearing on argv. CV-1
//! discipline equivalent to `OpenBao`'s `value=-`.
//!
//! `conjur_unsafe_set = true` is the explicit operator opt-in that
//! switches `set` to the `-v <value>` argv path. The only legitimate
//! reason to flip it is a constrained execution environment without
//! `/dev/stdin` (chrooted CI runner with stripped `/dev`); default is
//! `false` and the default-off invariant is machine-checked via
//! [`ConjurFactory::create_concrete`] in tests.
//!
//! # Identity line
//!
//! `conjur whoami` returns JSON `{account, username, client_ip,
//! user_agent, token_issued_at}` — note that the **authenticator name
//! is NOT surfaced**. The doctor identity line constructs
//! `account=<from-whoami> identity=<username-from-whoami>
//! authn=<conjur_authn-from-config>` so the operator's configured
//! authenticator (`conjur_authn`, default `"authn"`) is always visible
//! even though the CLI doesn't echo it.
//!
//! # `delete` semantics
//!
//! Conjur has **no `conjur variable delete` command** — variables are
//! policy-defined and can only be removed by reloading policy with the
//! variable stripped, which requires policy-edit privileges far beyond
//! a typical SecretEnv operator's `read`/`update` scope. [`delete`]
//! therefore implements **clear** semantics: it sets the value to the
//! empty string via the safe stdin path. The variable itself remains
//! defined. This mirrors 1Password's `delete` precedent and is
//! documented as a deliberate semantic gap.
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use secretenv_core::{
    optional_bool, optional_duration_secs, optional_string, required_string, Backend,
    BackendFactory, BackendStatus, BackendUri, Secret, DEFAULT_GET_TIMEOUT,
};
use serde::Deserialize;
use tokio::process::Command;

const CLI_NAME: &str = "conjur";
// Phase 0 finding: there is no native macOS/Linux package for the v8
// CLI today. PyPI `conjur` is v7.1.0 (EOL Ruby line); no Homebrew tap;
// only RHEL+Windows native binaries on the GH releases page. The
// `cyberark/conjur-cli:8` Docker image is the canonical first-party
// install channel that runs cleanly on the supported SecretEnv host
// platforms. If this changes pre-GA (Homebrew tap or universal binary
// published), update this hint and bump CHANGELOG.
const INSTALL_HINT: &str =
    "docker pull cyberark/conjur-cli:8 (alias `conjur` to a docker-run wrapper) — \
     see https://github.com/cyberark/cyberark-conjur-cli for native builds";

/// A live instance of the `Conjur` backend.
pub struct ConjurBackend {
    backend_type: &'static str,
    instance_name: String,
    /// Full URL of the Conjur server (OSS or Enterprise). HTTP/HTTPS
    /// is the operator's choice; the wrapper passes it through.
    conjur_url: String,
    /// Top-level account namespace. Required, no env fallback — the
    /// registry document must deterministically point at the same
    /// Conjur cluster regardless of operator shell state.
    conjur_account: String,
    /// Authenticator name. Default `"authn"` (API-key). Other valid
    /// values map to `authn-jwt`, `authn-oidc`, `authn-iam`,
    /// `authn-k8s`, `authn-azure`, `authn-gcp`. Surfaced in the
    /// identity line; the wrapper does NOT pass it to the CLI (the
    /// operator's pre-established `conjur login` session controls
    /// actual auth).
    conjur_authn: String,
    /// Identity for non-default authenticators (`host/<id>` or
    /// `<user>`). Reserved for future use — currently surfaced in the
    /// identity line only when set. Unused at runtime today; the
    /// factory still validates it (control-character rejection) so a
    /// future `check()` enhancement can surface the configured login
    /// without re-plumbing config through.
    #[cfg_attr(not(test), allow(dead_code))]
    conjur_login: Option<String>,
    /// Path or name of the `conjur` binary. Defaults to `"conjur"`
    /// (PATH lookup); tests override to point at a mock script.
    conjur_bin: String,
    /// Defense-in-depth opt-in (default `false`). When `false`, [`set`]
    /// uses `-f /dev/stdin` with stdin-piped value (CV-1 safe). When
    /// `true`, [`set`] uses `-v <value>` argv path. The flag exists for
    /// environments where `/dev/stdin` is unavailable (chrooted CI
    /// runner with stripped `/dev`).
    conjur_unsafe_set: bool,
    /// Per-instance deadline for fetch-class operations.
    timeout: Duration,
}

/// Level 2 identity response from `conjur whoami`. Phase 0-confirmed
/// shape against `Conjur CLI version 8.1.3-879b90b`. `authn` is NOT
/// included in the response — derive from configured `conjur_authn`.
#[derive(Deserialize)]
struct WhoamiResponse {
    #[serde(default)]
    account: String,
    #[serde(default)]
    username: String,
}

impl ConjurBackend {
    /// Strip a single leading `/` from `uri.path` to produce the
    /// variable ID passed to `conjur variable get/set -i <id>`.
    /// Conjur policy hierarchies use `/` separators (`prod/db/pw`)
    /// which are part of the ID, not URL path delimiters.
    fn variable_id(uri: &BackendUri) -> String {
        uri.path.strip_prefix('/').unwrap_or(&uri.path).to_owned()
    }

    fn cli_missing() -> BackendStatus {
        BackendStatus::CliMissing {
            cli_name: CLI_NAME.to_owned(),
            install_hint: INSTALL_HINT.to_owned(),
        }
    }

    fn operation_failure_message(&self, uri: &BackendUri, op: &str, stderr: &[u8]) -> String {
        format!(
            "conjur backend '{}': {op} failed for URI '{}': {}",
            self.instance_name,
            uri.raw,
            String::from_utf8_lossy(stderr).trim()
        )
    }

    /// Build a `conjur --version` command with env-routing applied.
    /// The CLI does NOT consult `CONJUR_APPLIANCE_URL` / `CONJUR_ACCOUNT`
    /// for `--version` (it's a local-only print), but routing them
    /// through `Command::env` here keeps the env-only configuration
    /// invariant (and the strict-mock harness's env-var assertions)
    /// uniform across every child the backend spawns.
    fn version_command(&self) -> Command {
        let mut cmd = Command::new(&self.conjur_bin);
        cmd.arg("--version");
        cmd.env("CONJUR_APPLIANCE_URL", &self.conjur_url);
        cmd.env("CONJUR_ACCOUNT", &self.conjur_account);
        cmd
    }

    /// Build a `conjur <subcommand> <extra_args...>` command. The CLI
    /// does NOT take `--url` / `--account` flags (it reads
    /// `~/.conjurrc`); Phase 0 confirmed `CONJUR_APPLIANCE_URL` +
    /// `CONJUR_ACCOUNT` env routing works without a `~/.conjurrc`
    /// present, so the wrapper uses env-only configuration.
    fn conjur_command(&self, subcommand: &str, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.conjur_bin);
        cmd.arg(subcommand);
        cmd.args(extra_args);
        cmd.env("CONJUR_APPLIANCE_URL", &self.conjur_url);
        cmd.env("CONJUR_ACCOUNT", &self.conjur_account);
        cmd
    }

    /// Validate the URI's fragment for `get` and return the requested
    /// JSON key, if any. Conjur recognizes only the `json-key`
    /// directive (same vocabulary as `aws-secrets` and `openbao`).
    fn parse_json_key_fragment(&self, uri: &BackendUri) -> Result<Option<String>> {
        let Some(mut directives) = uri.fragment_directives()? else {
            return Ok(None);
        };
        // Single pass: `shift_remove("json-key")` either extracts the
        // key (success path) or returns None (key absent). Whatever
        // sits in `directives` after the remove is by definition the
        // "unsupported" set — no second filter pass needed.
        let Some(key) = directives.shift_remove("json-key") else {
            let mut unsupported: Vec<&str> = directives.keys().map(String::as_str).collect();
            unsupported.sort_unstable();
            bail!(
                "conjur backend '{}': URI '{}' has unsupported fragment directive(s) [{}]; \
                 conjur recognizes only 'json-key' (example: '#json-key=password')",
                self.instance_name,
                uri.raw,
                unsupported.join(", ")
            );
        };
        if !directives.is_empty() {
            let mut extra: Vec<&str> = directives.keys().map(String::as_str).collect();
            extra.sort_unstable();
            bail!(
                "conjur backend '{}': URI '{}' has unsupported directive(s) [{}] alongside \
                 'json-key'; conjur recognizes only 'json-key'",
                self.instance_name,
                uri.raw,
                extra.join(", ")
            );
        }
        Ok(Some(key))
    }

    /// Invoke `conjur variable get -i <id>` and return the value with
    /// exactly one trailing `\n` stripped. Used by both the user-facing
    /// `get` (without fragment) and as the raw fetch underlying
    /// fragment extraction + `list`.
    async fn get_raw_value(&self, uri: &BackendUri) -> Result<String> {
        let var_id = Self::variable_id(uri);
        let mut cmd = self.conjur_command("variable", &["get", "-i", &var_id]);
        let output = cmd.output().await.with_context(|| {
            format!(
                "conjur backend '{}': failed to invoke 'conjur variable get' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, "get", &output.stderr));
        }
        let stdout = String::from_utf8(output.stdout).with_context(|| {
            format!(
                "conjur backend '{}': non-UTF-8 response for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `conjur variable get` emits the value followed by exactly one
        // '\n' (verified Phase 0 via xxd). Strip exactly one.
        Ok(stdout.strip_suffix('\n').unwrap_or(&stdout).to_owned())
    }

    /// Write `value` to the variable at `uri` via the configured
    /// safe-stdin or unsafe-argv path. Shared by `set()` and
    /// `delete()` (which writes empty-string for clear semantics).
    async fn write_value(&self, uri: &BackendUri, value: &str, op: &str) -> Result<()> {
        let var_id = Self::variable_id(uri);
        if self.conjur_unsafe_set {
            // Unsafe argv path — explicit operator opt-in. Secret
            // appears in /proc/<pid>/cmdline and `ps` output.
            // Per-invocation tracing breadcrumb so `secretenv --verbose`
            // surfaces the choice (mirrors 1Password / Keeper precedent).
            tracing::warn!(
                instance = self.instance_name.as_str(),
                uri = uri.raw.as_str(),
                op = op,
                "`conjur variable set -v <value>` passes the secret through subprocess argv \
                 (conjur_unsafe_set = true was set; CV-1 exposure acknowledged) — \
                 do not run on multi-user hosts unless audited"
            );
            let mut cmd = self.conjur_command("variable", &["set", "-i", &var_id, "-v", value]);
            let output = cmd.output().await.with_context(|| {
                format!(
                    "conjur backend '{}': failed to invoke 'conjur variable set' for URI '{}'",
                    self.instance_name, uri.raw
                )
            })?;
            if !output.status.success() {
                bail!(self.operation_failure_message(uri, op, &output.stderr));
            }
            return Ok(());
        }
        // Safe path: -f /dev/stdin reads value bytes from child stdin.
        // Never on argv, never on disk. CV-1 discipline equivalent to
        // OpenBao's `value=-`.
        let mut cmd = self.conjur_command("variable", &["set", "-i", &var_id, "-f", "/dev/stdin"]);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "conjur backend '{}': failed to spawn 'conjur variable set' for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        // `child.stdin` should always be Some after `Stdio::piped()` +
        // a successful spawn. If it's None (resource-exhausted host,
        // OS pipe-creation failure post-spawn) the value would never
        // reach the CLI and the variable would silently land empty —
        // surface as an error rather than swallow.
        {
            use tokio::io::AsyncWriteExt;
            // Scope `stdin` so it's dropped at the closing brace,
            // closing the child's stdin pipe before `wait_with_output`.
            // Without this drop the child blocks reading from a still-
            // open stdin and `wait_with_output` deadlocks.
            let mut stdin = child.stdin.take().ok_or_else(|| {
                anyhow::anyhow!(
                    "conjur backend '{}': child stdin pipe was not created for 'conjur variable set'",
                    self.instance_name
                )
            })?;
            match stdin.write_all(value.as_bytes()).await {
                Ok(()) => {}
                // Linux EPIPE if the child exits before reading stdin —
                // trust the exit status (same fix as aws-ssm/vault/openbao).
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "conjur backend '{}': failed to write secret value to conjur stdin",
                        self.instance_name
                    )));
                }
            }
            stdin.shutdown().await.ok();
        }
        let output = child.wait_with_output().await.with_context(|| {
            format!(
                "conjur backend '{}': 'conjur variable set' exited abnormally for URI '{}'",
                self.instance_name, uri.raw
            )
        })?;
        if !output.status.success() {
            bail!(self.operation_failure_message(uri, op, &output.stderr));
        }
        Ok(())
    }

    /// Read-only accessor for the unsafe-set flag (test-only). Default-
    /// off invariant is machine-checked via `factory_conjur_unsafe_set_defaults_false`.
    #[cfg(test)]
    const fn unsafe_set(&self) -> bool {
        self.conjur_unsafe_set
    }

    /// Read-only accessor for the configured login (test-only). The
    /// field is reserved for future identity-line surfacing; the
    /// factory validates control-character rejection on it. The test
    /// reads it so the dead-code lint stays accurate as a regression
    /// signal: if a future runtime branch references the field, this
    /// accessor stops being the only reader and a real "is this used?"
    /// check would fire.
    #[cfg(test)]
    fn login(&self) -> Option<&str> {
        self.conjur_login.as_deref()
    }
}

#[async_trait]
impl Backend for ConjurBackend {
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
        let version_fut = self.version_command().output();
        let whoami_fut = self.conjur_command("whoami", &[]).output();
        let (version_res, whoami_res) = tokio::join!(version_fut, whoami_fut);

        // --- Level 1: `conjur --version` ---
        let version_out = match version_res {
            Ok(o) => o,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::cli_missing(),
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "conjur backend '{}': failed to invoke '{}': {e}",
                        self.instance_name, self.conjur_bin
                    ),
                };
            }
        };
        if !version_out.status.success() {
            return BackendStatus::Error {
                message: format!(
                    "conjur backend '{}': 'conjur --version' exited non-zero: {}",
                    self.instance_name,
                    String::from_utf8_lossy(&version_out.stderr).trim()
                ),
            };
        }
        let version_line = String::from_utf8_lossy(&version_out.stdout).trim().to_owned();
        // Format: `Conjur CLI version <X.Y.Z>[-<build-sha>]`. Reject
        // v7 (Ruby) explicitly — it uses an entirely different argv
        // shape and would fail mysteriously rather than cleanly. A
        // version line that doesn't parse at all is also rejected
        // (defense-in-depth: a hostile or broken `conjur` shim that
        // emits "conjur version 7.x" without the "CLI" word would
        // otherwise parse to None and silently bypass the v7 branch).
        let Some(version_token) = parse_version_token(&version_line) else {
            return BackendStatus::Error {
                message: format!(
                    "conjur backend '{}': could not parse Conjur CLI version line ({version_line}); \
                     expected `Conjur CLI version <X.Y.Z>[-<build-sha>]` (v8+)",
                    self.instance_name
                ),
            };
        };
        if version_token.starts_with("7.") {
            return BackendStatus::Error {
                message: format!(
                    "conjur backend '{}': v7 (Ruby) CLI detected ({version_line}); v8+ \
                     required — install via the cyberark/conjur-cli:8 Docker image",
                    self.instance_name
                ),
            };
        }

        // --- Level 2: `conjur whoami` ---
        let whoami_out = match whoami_res {
            Ok(o) => o,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "conjur backend '{}': failed to invoke 'conjur whoami': {e}",
                        self.instance_name
                    ),
                };
            }
        };
        if !whoami_out.status.success() {
            let stderr = String::from_utf8_lossy(&whoami_out.stderr).trim().to_owned();
            return BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: conjur login  (or 'conjur init' then 'conjur login' if first-time) \
                     (stderr: {stderr})"
                ),
            };
        }
        let parsed: WhoamiResponse = match serde_json::from_slice(&whoami_out.stdout) {
            Ok(p) => p,
            Err(e) => {
                return BackendStatus::Error {
                    message: format!(
                        "conjur backend '{}': parsing 'conjur whoami' JSON: {e}",
                        self.instance_name
                    ),
                };
            }
        };
        // Identity line: account + username come from the live `whoami`
        // response; `authn` comes from configured `conjur_authn` since
        // the v8 CLI doesn't surface the authenticator name.
        let account = if parsed.account.is_empty() { "(unknown)" } else { &parsed.account };
        let username = if parsed.username.is_empty() { "(unknown)" } else { &parsed.username };
        BackendStatus::Ok {
            cli_version: version_line,
            identity: format!("account={account} identity={username} authn={}", self.conjur_authn),
        }
    }

    async fn get(&self, uri: &BackendUri) -> Result<Secret<String>> {
        // Fragment validation BEFORE any network call — a bad fragment
        // is a local grammar error and shelling out to Conjur would
        // waste latency + leak access patterns.
        let json_key = self.parse_json_key_fragment(uri)?;
        let raw = self.get_raw_value(uri).await?;
        match json_key {
            None => Ok(Secret::new(raw)),
            Some(key) => extract_json_field(&self.instance_name, uri, &raw, &key).map(Secret::new),
        }
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        uri.reject_any_fragment("conjur")?;
        self.write_value(uri, value, "set").await
    }

    /// v0.15 migrate destination path. `Native` per the v0.15 audit
    /// table — wraps `set()` taking the value by `&Secret<String>`
    /// reference (SEC-INV-10 borrow-not-clone; `expose_secret`
    /// returns a `&str` borrow with the same lifetime as `value`,
    /// no allocation).
    async fn write_secret(&self, uri: &BackendUri, value: &Secret<String>) -> Result<()> {
        self.set(uri, value.expose_secret()).await
    }

    /// v0.15 migrate `--delete-source` cleanup path. `Native` per
    /// the v0.15 audit table — passthrough to `delete()`. Not called
    /// unless the operator opts in via `--delete-source`.
    async fn delete_secret(&self, uri: &BackendUri) -> Result<()> {
        self.delete(uri).await
    }

    /// v0.15 migrate success-message cleanup hint. Conjur 8.x has no
    /// CLI `variable delete` — `delete()` semantics in this backend
    /// are "clear the value" (rewrite to empty string). The hint
    /// surfaces the same `variable set` form so the operator can
    /// re-clear or change the value, and documents that full removal
    /// requires policy-level changes.
    fn delete_hint(&self, uri: &BackendUri) -> String {
        let id = Self::variable_id(uri);
        format!(
            "# Conjur 8.x has no `variable delete` CLI; clear the value:\n\
             conjur variable set -i {id} -v ''\n\
             # To fully remove, update the policy that defines this variable."
        )
    }

    /// Conjur has no native delete. This implements **clear** semantics
    /// — the variable retains its policy definition but the value is
    /// emptied. Documented at the crate level + in `docs/backends/conjur.md`.
    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        uri.reject_any_fragment("conjur")?;
        self.write_value(uri, "", "delete").await
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        uri.reject_any_fragment("conjur")?;
        // Conjur's `variable get` returns the raw value — there's no
        // KV-envelope to unwrap (unlike openbao/vault). The variable
        // value is the alias→URI JSON map verbatim.
        let raw = self.get_raw_value(uri).await?;
        let map: HashMap<String, String> = serde_json::from_str(&raw).with_context(|| {
            format!(
                "conjur backend '{}': registry value at '{}' is not a JSON alias→URI map",
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
    // Conjur tracks variable versions but listing them requires the
    // REST API; the v8 CLI exposes only single-version fetch
    // (`-v <n>`). v0.11.x carry-forward considers shelling out to
    // `curl` against the REST API.
}

/// Parse the version token (e.g. `8.1.3` or `8.1.3-879b90b`) out of a
/// `Conjur CLI version <X.Y.Z>[-<build-sha>]` line. Returns the
/// `<X.Y.Z>` portion (without build-sha suffix) when matched.
fn parse_version_token(line: &str) -> Option<&str> {
    let after = line.split_once("version ")?.1;
    let token = after.split_whitespace().next()?;
    // `split_once('-')` returns Some when a `-<build-sha>` suffix is
    // present (the v8 build-info form `8.1.3-879b90b`), None when it's
    // a bare semver (`8.1.3`). Either way the first arm is the X.Y.Z
    // portion. Cleaner than the prior `split('-').next().unwrap_or(token)`
    // dead-fallback shape — `split` always yields at least one element
    // so the unwrap_or arm was unreachable.
    Some(token.split_once('-').map_or(token, |(prefix, _)| prefix))
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
                "conjur backend '{instance_name}': URI '{}' selects JSON key '{key}' \
                 but variable value at '{}' is not a JSON object",
                uri.raw, uri.path
            )
        })?;
    if !map.contains_key(key) {
        let mut fields: Vec<&str> = map.keys().map(String::as_str).collect();
        fields.sort_unstable();
        bail!(
            "conjur backend '{instance_name}': URI '{}' field '{key}' not found; \
             variable at '{}' has fields: [{}]",
            uri.raw,
            uri.path,
            fields.join(", ")
        );
    }
    // `remove` so the String arm can move rather than clone.
    let Some(value) = map.remove(key) else { unreachable!("presence checked above") };
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok("null".to_owned()),
        ref v @ (serde_json::Value::Array(_) | serde_json::Value::Object(_)) => bail!(
            "conjur backend '{instance_name}': URI '{}' field '{key}' is a JSON {} — only \
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

/// Factory for the `Conjur` backend.
pub struct ConjurFactory(&'static str);

impl ConjurFactory {
    /// Construct the factory. Equivalent to `ConjurFactory::default()`.
    #[must_use]
    pub const fn new() -> Self {
        Self("conjur")
    }
}

impl Default for ConjurFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl ConjurFactory {
    /// Concrete-typed factory path. The trait `create()` boxes the
    /// result; tests use this directly so they can inspect private
    /// fields like `conjur_unsafe_set` without downcast gymnastics.
    fn create_concrete(
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<ConjurBackend> {
        let conjur_url = required_string(config, "conjur_url", "conjur", instance_name)?;
        let conjur_account = required_string(config, "conjur_account", "conjur", instance_name)?;
        let conjur_authn = optional_string(config, "conjur_authn", "conjur", instance_name)?
            .unwrap_or_else(|| "authn".to_owned());
        let conjur_login = optional_string(config, "conjur_login", "conjur", instance_name)?;
        if let Some(login) = &conjur_login {
            if has_forbidden_control_char(login) {
                bail!(
                    "conjur backend '{instance_name}': field 'conjur_login' contains a \
                     forbidden control character (NUL or sub-0x20 byte other than tab)"
                );
            }
        }
        let conjur_bin = optional_string(config, "conjur_bin", "conjur", instance_name)?
            .unwrap_or_else(|| CLI_NAME.to_owned());
        let conjur_unsafe_set =
            optional_bool(config, "conjur_unsafe_set", "conjur", instance_name)?.unwrap_or(false);
        let timeout = optional_duration_secs(config, "timeout_secs", "conjur", instance_name)?
            .unwrap_or(DEFAULT_GET_TIMEOUT);
        Ok(ConjurBackend {
            backend_type: "conjur",
            instance_name: instance_name.to_owned(),
            conjur_url,
            conjur_account,
            conjur_authn,
            conjur_login,
            conjur_bin,
            conjur_unsafe_set,
            timeout,
        })
    }
}

impl BackendFactory for ConjurFactory {
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

    const CONJUR_URL: &str = "http://localhost:8083";
    const CONJUR_ACCOUNT: &str = "myorg";

    fn backend(mock_path: &Path) -> ConjurBackend {
        backend_with_authn(mock_path, "authn", false)
    }

    fn backend_with_authn(mock_path: &Path, authn: &str, unsafe_set: bool) -> ConjurBackend {
        ConjurBackend {
            backend_type: "conjur",
            instance_name: "conjur-dev".to_owned(),
            conjur_url: CONJUR_URL.to_owned(),
            conjur_account: CONJUR_ACCOUNT.to_owned(),
            conjur_authn: authn.to_owned(),
            conjur_login: None,
            conjur_bin: mock_path.to_str().unwrap().to_owned(),
            conjur_unsafe_set: unsafe_set,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn backend_with_nonexistent_conjur() -> ConjurBackend {
        ConjurBackend {
            backend_type: "conjur",
            instance_name: "conjur-dev".to_owned(),
            conjur_url: CONJUR_URL.to_owned(),
            conjur_account: CONJUR_ACCOUNT.to_owned(),
            conjur_authn: "authn".to_owned(),
            conjur_login: None,
            conjur_bin: "/definitely/not/a/real/path/to/conjur-binary-12345".to_owned(),
            conjur_unsafe_set: false,
            timeout: DEFAULT_GET_TIMEOUT,
        }
    }

    fn ok(stdout: &str) -> Response {
        Response::success(stdout)
            .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
            .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT)
    }

    fn fail(exit_code: i32, stderr: &str) -> Response {
        Response::failure(exit_code, stderr)
            .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
            .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT)
    }

    // ---- factory ----

    #[test]
    fn factory_backend_type_is_conjur() {
        assert_eq!(ConjurFactory::new().backend_type(), "conjur");
    }

    #[test]
    fn factory_errors_when_conjur_url_missing() {
        let factory = ConjurFactory::new();
        let cfg: HashMap<String, toml::Value> = HashMap::new();
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected error when conjur_url is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur_url"), "names missing field: {msg}");
        assert!(msg.contains("conjur-dev"), "names instance: {msg}");
    }

    #[test]
    fn factory_errors_when_conjur_account_missing() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected error when conjur_account is missing");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur_account"), "names missing field: {msg}");
    }

    #[test]
    fn factory_accepts_url_and_account() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        let b = factory.create("conjur-dev", &cfg).unwrap();
        assert_eq!(b.backend_type(), "conjur");
        assert_eq!(b.instance_name(), "conjur-dev");
    }

    #[test]
    fn factory_authn_defaults_to_authn() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert_eq!(b.conjur_authn, "authn");
    }

    #[test]
    fn factory_authn_accepts_explicit_value() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert("conjur_authn".to_owned(), toml::Value::String("authn-jwt".to_owned()));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert_eq!(b.conjur_authn, "authn-jwt");
    }

    #[test]
    fn factory_rejects_non_string_conjur_url() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert("conjur_url".to_owned(), toml::Value::Integer(8083));
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected type error");
        };
        assert!(format!("{err:#}").contains("must be a string"));
    }

    #[test]
    fn factory_rejects_non_string_conjur_account() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::Boolean(true));
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected type error for non-string conjur_account");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur_account"), "names the field: {msg}");
    }

    #[test]
    fn factory_rejects_non_bool_conjur_unsafe_set() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert("conjur_unsafe_set".to_owned(), toml::Value::String("yes".to_owned()));
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected error for non-bool conjur_unsafe_set");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur_unsafe_set"), "names the field: {msg}");
    }

    #[test]
    fn factory_round_trips_conjur_login() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert("conjur_login".to_owned(), toml::Value::String("host/ci/runner".to_owned()));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert_eq!(b.login(), Some("host/ci/runner"));
    }

    #[test]
    fn factory_login_defaults_to_none() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert_eq!(b.login(), None);
    }

    #[test]
    fn factory_rejects_control_char_in_conjur_login() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert(
            "conjur_login".to_owned(),
            toml::Value::String("host/ci/runner\nhostile".to_owned()),
        );
        let Err(err) = factory.create("conjur-dev", &cfg) else {
            panic!("expected error for control char in conjur_login");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur_login"), "names the field: {msg}");
        assert!(msg.contains("control character"), "names the issue: {msg}");
    }

    #[test]
    fn factory_conjur_unsafe_set_defaults_false() {
        // Defense-in-depth: the safe -f /dev/stdin path is the default.
        // This test pins the default-off invariant via `create_concrete`
        // (the test-accessible factory path) so a future regression that
        // accidentally flips the runtime branch starts from a closed door.
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert!(!b.unsafe_set(), "default must be false (defense-in-depth)");
        assert_eq!(b.timeout(), DEFAULT_GET_TIMEOUT);
    }

    #[test]
    fn factory_conjur_unsafe_set_accepts_true() {
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert("conjur_unsafe_set".to_owned(), toml::Value::Boolean(true));
        let b = ConjurFactory::create_concrete("conjur-dev", &cfg).unwrap();
        assert!(b.unsafe_set(), "explicit true must round-trip");
    }

    #[test]
    fn factory_honors_timeout_secs() {
        let factory = ConjurFactory::new();
        let mut cfg: HashMap<String, toml::Value> = HashMap::new();
        cfg.insert(
            "conjur_url".to_owned(),
            toml::Value::String("http://localhost:8083".to_owned()),
        );
        cfg.insert("conjur_account".to_owned(), toml::Value::String("myorg".to_owned()));
        cfg.insert("timeout_secs".to_owned(), toml::Value::Integer(11));
        let b = factory.create("conjur-dev", &cfg).unwrap();
        assert_eq!(b.timeout(), Duration::from_secs(11));
    }

    // ---- variable_id ----

    #[test]
    fn variable_id_strips_leading_slash_triple_slash_form() {
        let uri = BackendUri::parse("conjur-dev:///prod/db/password").unwrap();
        assert_eq!(ConjurBackend::variable_id(&uri), "prod/db/password");
    }

    #[test]
    fn variable_id_preserves_no_leading_slash_double_slash_form() {
        let uri = BackendUri::parse("conjur-dev://prod/db/password").unwrap();
        assert_eq!(ConjurBackend::variable_id(&uri), "prod/db/password");
    }

    #[test]
    fn uri_parser_rejects_control_chars_in_variable_id_path() {
        // Defense-in-depth backstop: the URI parser at
        // `secretenv-core::BackendUri::parse` rejects sub-0x20 bytes
        // (NUL / newline / ESC / etc.) in the path before they ever
        // reach `variable_id()` — so a hostile registry document can
        // never smuggle terminal-control sequences onto Conjur's argv
        // or back into our error messages. This test pins the
        // upstream invariant from the conjur side; if the URI parser
        // ever loosens, this test fails loud and we add inline
        // validation in `variable_id()`.
        let with_newline = BackendUri::parse("conjur-dev://prod/db\npassword");
        assert!(with_newline.is_err(), "URI parser must reject newline in path");
        let with_esc = BackendUri::parse("conjur-dev://prod/\x1b[2Jx");
        assert!(with_esc.is_err(), "URI parser must reject ESC in path");
        let with_nul = BackendUri::parse("conjur-dev://prod/db\x00x");
        assert!(with_nul.is_err(), "URI parser must reject NUL in path");
    }

    // ---- check Level 1 ----

    #[tokio::test]
    async fn check_cli_missing_on_enoent() {
        let b = backend_with_nonexistent_conjur();
        match b.check().await {
            BackendStatus::CliMissing { cli_name, install_hint } => {
                assert_eq!(cli_name, "conjur");
                assert!(
                    install_hint.contains("cyberark/conjur-cli:8"),
                    "expected Docker-image install hint, got: {install_hint}"
                );
            }
            other => panic!("expected CliMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_rejects_unparseable_version_line() {
        // Defense-in-depth: a `conjur` shim that emits a line without
        // the literal "version " token (so `parse_version_token`
        // returns None — note "conjur version 7.x" actually parses
        // to "7.x" and goes through the v7 branch, so we omit the
        // "version " word entirely here) surfaces as Error rather
        // than silently bypassing the version probe.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], Response::success("conjur 7.0.0\n"))
            .on(&["whoami"], ok("{\"account\":\"myorg\",\"username\":\"admin\"}\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Error { message } => {
                assert!(message.contains("could not parse"), "names parse failure: {message}");
                assert!(message.contains("v8+"), "names version requirement: {message}");
            }
            other => panic!("expected Error for unparseable version, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_rejects_v7_ruby_cli() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], Response::success("Conjur CLI version 7.1.0\n"))
            .on(&["whoami"], ok("{\"account\":\"myorg\",\"username\":\"admin\"}\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Error { message } => {
                assert!(message.contains("v7"), "names version: {message}");
                assert!(message.contains("v8+ required"), "names requirement: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ---- check Level 2 ----

    #[tokio::test]
    async fn check_returns_ok_when_version_and_whoami_succeed() {
        // Both the --version probe and the whoami probe must carry
        // CONJUR_APPLIANCE_URL + CONJUR_ACCOUNT in the child env. Using
        // `ok()` (which asserts both env vars are set) for the version
        // arm too locks the env-routing invariant uniformly across
        // every child the backend spawns.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], ok("Conjur CLI version 8.1.3-879b90b\n"))
            .on(
                &["whoami"],
                ok("{\"account\":\"myorg\",\"username\":\"admin\",\"client_ip\":\"172.21.0.4\"}\n"),
            )
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Ok { cli_version, identity } => {
                assert!(cli_version.contains("8.1.3"));
                assert!(identity.contains("account=myorg"), "identity: {identity}");
                assert!(identity.contains("identity=admin"), "identity: {identity}");
                assert!(identity.contains("authn=authn"), "default authn: {identity}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_version_string_without_build_sha_parses() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], Response::success("Conjur CLI version 8.1.3\n"))
            .on(&["whoami"], ok("{\"account\":\"myorg\",\"username\":\"admin\"}\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::Ok { .. } => {}
            other => panic!("expected Ok for sha-less version, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_identity_line_uses_configured_authn() {
        // whoami doesn't surface authenticator name — derived from
        // configured `conjur_authn`.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], Response::success("Conjur CLI version 8.1.3\n"))
            .on(&["whoami"], ok("{\"account\":\"myorg\",\"username\":\"host/ci/runner\"}\n"))
            .install(dir.path());
        let b = backend_with_authn(&mock, "authn-jwt", false);
        match b.check().await {
            BackendStatus::Ok { identity, .. } => {
                assert!(
                    identity.contains("authn=authn-jwt"),
                    "identity reflects configured authn: {identity}"
                );
                assert!(identity.contains("identity=host/ci/runner"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_returns_not_authenticated_on_whoami_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["--version"], Response::success("Conjur CLI version 8.1.3\n"))
            .on(&["whoami"], fail(1, "Error: Unauthorized\n"))
            .install(dir.path());
        let b = backend(&mock);
        match b.check().await {
            BackendStatus::NotAuthenticated { hint } => {
                assert!(hint.contains("conjur login"), "hint: {hint}");
                assert!(hint.contains("conjur init"), "hint mentions init: {hint}");
            }
            other => panic!("expected NotAuthenticated, got {other:?}"),
        }
    }

    // ---- get ----

    #[tokio::test]
    async fn get_returns_trimmed_value() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/stripe-key"], ok("sk_live_xyz\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/stripe-key").unwrap();
        assert_eq!(b.get(&uri).await.unwrap().expose_secret(), "sk_live_xyz");
    }

    #[tokio::test]
    async fn get_empty_value_returns_empty_string() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/empty"], ok("\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/empty").unwrap();
        assert_eq!(b.get(&uri).await.unwrap().expose_secret(), "");
    }

    #[tokio::test]
    async fn get_preserves_internal_newlines() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/multiline"], ok("line1\nline2\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/multiline").unwrap();
        assert_eq!(b.get(&uri).await.unwrap().expose_secret(), "line1\nline2");
    }

    #[tokio::test]
    async fn get_404_wraps_conjur_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/missing"], fail(1, "Error: 404 Not Found\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/missing").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("conjur-dev"), "names instance: {msg}");
        assert!(msg.contains("prod/missing"), "names uri: {msg}");
        assert!(msg.contains("404"), "includes conjur stderr: {msg}");
    }

    #[tokio::test]
    async fn get_403_permission_denied_wraps_stderr() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "locked/secret"], fail(1, "Error: 403 Forbidden\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://locked/secret").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("403"));
    }

    // ---- get + #json-key fragment ----

    #[tokio::test]
    async fn get_with_json_key_fragment_extracts_field() {
        let dir = TempDir::new().unwrap();
        let body = "{\"username\":\"smoke-user\",\"password\":\"smoke-pw\"}";
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/db-creds"], ok(&format!("{body}\n")))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/db-creds#json-key=password").unwrap();
        assert_eq!(b.get(&uri).await.unwrap().expose_secret(), "smoke-pw");
    }

    #[tokio::test]
    async fn get_with_unsupported_fragment_directive_errors_before_subprocess() {
        // No mock entry — if the backend shells out, the strict mock
        // fails. Fragment validator must reject before that.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/x#version=5").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported fragment directive"), "msg: {msg}");
        assert!(msg.contains("json-key"), "names supported directive: {msg}");
    }

    #[tokio::test]
    async fn get_json_key_field_missing_lists_available_keys() {
        let dir = TempDir::new().unwrap();
        let body = "{\"username\":\"u\",\"password\":\"p\"}";
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/cfg"], ok(&format!("{body}\n")))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/cfg#json-key=token").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("'token' not found"), "msg: {msg}");
        assert!(msg.contains("password"), "lists available keys: {msg}");
    }

    #[tokio::test]
    async fn get_json_key_on_non_json_value_errors() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/plain"], ok("plain-string\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/plain#json-key=field").unwrap();
        let err = b.get(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a JSON object"), "msg: {msg}");
    }

    // ---- set (safe -f /dev/stdin path) ----

    #[tokio::test]
    async fn set_succeeds_on_zero_exit_via_stdin() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "set", "-i", "prod/stripe-key", "-f", "/dev/stdin"],
                Response::success_with_stdin("Value added\n", vec!["new-value".to_owned()])
                    .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/stripe-key").unwrap();
        b.set(&uri, "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_passes_secret_via_stdin_not_argv() {
        // CV-1 discipline: secret on stdin, `-f /dev/stdin` literal on argv.
        let very_sensitive = "sk_live_TOP_SECRET_never_on_argv_555";
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "set", "-i", "prod/db", "-f", "/dev/stdin"],
                Response::success_with_stdin("Value added\n", vec![very_sensitive.to_owned()])
                    .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/db").unwrap();
        b.set(&uri, very_sensitive).await.unwrap();
    }

    #[tokio::test]
    async fn set_propagates_stderr_on_failure() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "set", "-i", "prod/db", "-f", "/dev/stdin"],
                Response::failure(1, "Error: 403 Forbidden\n")
                    .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/db").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        assert!(format!("{err:#}").contains("403"));
    }

    #[tokio::test]
    async fn set_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/db#json-key=password").unwrap();
        let err = b.set(&uri, "x").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("fragment"), "msg: {msg}");
    }

    // ---- set (unsafe argv path) ----

    #[tokio::test]
    async fn set_uses_argv_path_when_unsafe_set_true() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "set", "-i", "prod/db", "-v", "argv-value"], ok("Value added\n"))
            .install(dir.path());
        let b = backend_with_authn(&mock, "authn", true);
        let uri = BackendUri::parse("conjur-dev://prod/db").unwrap();
        b.set(&uri, "argv-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_argv_path_unreachable_when_unsafe_set_false() {
        // The strict mock has ONLY the argv-path entry registered. With
        // unsafe_set=false, the backend must take the stdin path
        // instead; the strict mock fails because no `-f /dev/stdin`
        // entry exists. The test passes when the unwrap_err fires on
        // the unexpected-argv error from the strict mock — proving the
        // safe branch was taken.
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "set", "-i", "prod/db", "-v", "would-be-leaked"], ok("Value added\n"))
            .install(dir.path());
        let b = backend_with_authn(&mock, "authn", false);
        let uri = BackendUri::parse("conjur-dev://prod/db").unwrap();
        let err = b.set(&uri, "would-be-leaked").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("/dev/stdin") || msg.contains("strict-mock"),
            "expected safe path attempted, got: {msg}"
        );
    }

    // ---- delete (clear via empty stdin) ----

    #[tokio::test]
    async fn delete_clears_value_via_empty_stdin() {
        // Conjur has no native delete — the wrapper implements clear
        // semantics by writing an empty value through the same safe
        // -f /dev/stdin path used by `set`. Asserts argv is the
        // identical shape (so the same execvp signature renders); the
        // empty-payload stdin lock is implicit (any non-empty fragment
        // would fail).
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "set", "-i", "prod/gone", "-f", "/dev/stdin"],
                Response::success("Value added\n")
                    .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/gone").unwrap();
        b.delete(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn delete_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/db#json-key=password").unwrap();
        let err = b.delete(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("fragment"));
    }

    // ---- list ----

    #[tokio::test]
    async fn list_parses_value_as_json_alias_map_in_sorted_order() {
        let dir = TempDir::new().unwrap();
        // Conjur returns the variable value verbatim — no KV envelope
        // (unlike openbao/vault). The value IS the alias-map JSON.
        // The body is intentionally written with `stripe_key` before
        // `db_url` to prove `list()` sorts (alphabetical) rather than
        // returning insertion or HashMap-randomized order.
        let body = r#"{"stripe_key":"conjur-dev://prod/stripe","db_url":"conjur-dev://prod/db"}"#;
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "registries/shared"], ok(&format!("{body}\n")))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://registries/shared").unwrap();
        let entries = b.list(&uri).await.unwrap();
        assert_eq!(
            entries,
            vec![
                ("db_url".to_owned(), "conjur-dev://prod/db".to_owned()),
                ("stripe_key".to_owned(), "conjur-dev://prod/stripe".to_owned()),
            ],
            "list() must return entries in sorted-by-key order, not HashMap-randomized order"
        );
    }

    #[tokio::test]
    async fn list_errors_when_value_is_not_json_map() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "bad/registry"], ok("not-a-json-object\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://bad/registry").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not a JSON alias"), "msg: {msg}");
    }

    #[tokio::test]
    async fn list_rejects_fragment() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur").install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://registries/shared#json-key=foo").unwrap();
        let err = b.list(&uri).await.unwrap_err();
        assert!(format!("{err:#}").contains("fragment"));
    }

    // ---- env-pathway regression locks ----

    #[tokio::test]
    async fn command_passes_url_and_account_via_env_not_argv() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(&["variable", "get", "-i", "prod/x"], ok("v\n"))
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/x").unwrap();
        b.get(&uri).await.unwrap();
    }

    #[tokio::test]
    async fn get_drift_catch_env_check_rejects_wrong_url() {
        let dir = TempDir::new().unwrap();
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "get", "-i", "prod/x"],
                Response::success("never-matches\n")
                    .with_env_var("CONJUR_APPLIANCE_URL", "http://DIFFERENT.example.com:8083")
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/x").unwrap();
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
        let mock = StrictMock::new("conjur")
            .on(
                &["variable", "set", "-i", "prod/x", "-f", "/dev/stdin"],
                Response::success_with_stdin("Value added\n", vec![secret.to_owned()])
                    .with_env_var("CONJUR_APPLIANCE_URL", CONJUR_URL)
                    .with_env_var("CONJUR_ACCOUNT", CONJUR_ACCOUNT),
            )
            .install(dir.path());
        let b = backend(&mock);
        let uri = BackendUri::parse("conjur-dev://prod/x").unwrap();
        b.set(&uri, secret).await.unwrap();
    }

    // ---- version-token parser ----

    #[test]
    fn parse_version_token_with_build_sha() {
        assert_eq!(parse_version_token("Conjur CLI version 8.1.3-879b90b"), Some("8.1.3"));
    }

    #[test]
    fn parse_version_token_without_build_sha() {
        assert_eq!(parse_version_token("Conjur CLI version 8.1.3"), Some("8.1.3"));
    }

    #[test]
    fn parse_version_token_v7() {
        assert_eq!(parse_version_token("Conjur CLI version 7.1.0"), Some("7.1.0"));
    }

    #[test]
    fn parse_version_token_garbage() {
        assert_eq!(parse_version_token("nope"), None);
    }
}
