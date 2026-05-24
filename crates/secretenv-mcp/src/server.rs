// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `MCP` server entry point — stdio transport.
//!
//! Phase 2a: bare scaffold. `serve()` instantiates a [`crate::tools::Server`]
//! with all 14 tool stubs registered, binds it to `rmcp::transport::stdio`,
//! and runs until the transport closes. Capability handshake + `tools/list`
//! work out of the box via the `#[tool_handler]` macro expansion in
//! [`crate::tools::Server`].
//!
//! Phase 2b: the disable-sentinel check fires before binding. A
//! sentinel at [`disable_sentinel_path`] short-circuits `serve()` with
//! a clear stderr message and a non-zero exit; the sentinel may
//! optionally carry an expiry timestamp (epoch seconds, one line) and
//! is auto-cleared on read when expired.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rmcp::transport::stdio;
use rmcp::ServiceExt;
use secretenv_core::Config;

use crate::audit_log::MutationLog;
use crate::config::McpConfig;
use crate::tools::Server;

/// `$XDG_CONFIG_HOME/secretenv/mcp-disabled` sentinel path. `secretenv mcp disable`
/// writes here; [`serve`] short-circuits if it exists (and the embedded
/// expiry, if any, is in the future).
///
/// # Errors
///
/// Returns an error if no home directory can be determined for XDG
/// lookup.
pub fn disable_sentinel_path() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("could not determine a home directory for XDG config lookup"))?;
    Ok(base.config_dir().join("secretenv").join("mcp-disabled"))
}

/// Write the disable sentinel.
///
/// With `duration = None` the sentinel is indefinite ([`enable`] is
/// the only way to clear it); with `duration = Some(d)` the sentinel
/// auto-expires at `now + d` — [`serve`] checks the expiry and
/// self-clears the sentinel on the next start when expired.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created or the
/// sentinel cannot be written.
pub fn disable(duration: Option<Duration>) -> Result<PathBuf> {
    let path = disable_sentinel_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    let body = match duration {
        None => String::new(),
        Some(d) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before UNIX epoch")?;
            let expires_at = now + d;
            format!("{}\n", expires_at.as_secs())
        }
    };

    let mut file =
        fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(body.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Remove the disable sentinel. No-op if absent.
///
/// # Errors
///
/// Returns an error if the sentinel exists but cannot be removed.
pub fn enable() -> Result<()> {
    let path = disable_sentinel_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!(e)).with_context(|| format!("removing {}", path.display())),
    }
}

/// Current state of the disable sentinel as observed by [`serve`].
enum DisableState {
    /// No sentinel present (or it had expired and was just cleared).
    NotPresent,
    /// Sentinel present with no expiry — `mcp enable` is the only
    /// way to clear it.
    Indefinite,
    /// Sentinel present with an expiry timestamp (UNIX seconds) that
    /// is still in the future.
    UntilEpochSecs(u64),
}

/// Inspect the disable sentinel.
///
/// As a side effect, this function CLEARS the sentinel if its expiry
/// has already passed — so subsequent calls to [`serve`] proceed
/// normally without operator intervention.
fn read_disable_state() -> Result<DisableState> {
    let path = disable_sentinel_path()?;
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DisableState::NotPresent),
        Err(e) => return Err(anyhow!(e)).with_context(|| format!("reading {}", path.display())),
    };

    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(DisableState::Indefinite);
    }

    let expires_at: u64 = trimmed
        .parse()
        .with_context(|| format!("invalid expiry timestamp in {}", path.display()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();

    if now >= expires_at {
        // Expired — self-clear, then report absent.
        fs::remove_file(&path).with_context(|| format!("clearing expired {}", path.display()))?;
        Ok(DisableState::NotPresent)
    } else {
        Ok(DisableState::UntilEpochSecs(expires_at))
    }
}

/// Load the machine-level [`Config`] for the MCP server.
///
/// With `Some(path)`, loads via [`Config::load_from`] — a missing or
/// malformed file is a hard error (mirrors the CLI's `--config <path>`
/// semantics). With `None`, loads the XDG default via [`Config::load`]
/// — a missing file silently yields [`Config::default`].
fn load_config(config_path: Option<&Path>) -> Result<Config> {
    config_path.map_or_else(
        || Config::load().context("loading MCP server config from XDG default"),
        |p| {
            Config::load_from(p)
                .with_context(|| format!("loading MCP server config from {}", p.display()))
        },
    )
}

/// Run the `SecretEnv` `MCP` server over stdio until the transport closes.
///
/// Checks the disable sentinel first; if present and unexpired, prints
/// a clear stderr message and returns an error (caller propagates as a
/// non-zero exit). Loads [`Config`] (via `config_path` or the XDG
/// default) and hands it to [`Server::new`] so tool handlers can read
/// registries + backend instances.
///
/// # Errors
///
/// Returns an error if the disable sentinel is present and unexpired,
/// if the config cannot be loaded, if the `rmcp` `serve` call fails to
/// perform the initialize handshake, or if the underlying transport
/// errors during the service lifetime.
/// Per-launch policy overrides applied AFTER the `[mcp]` section is
/// loaded from `config.toml`. Used by per-IDE setup blocks (e.g.
/// `secretenv mcp setup --ide gemini` emits `--allow-mutations always`
/// in its `args[]` because Gemini CLI 0.43.0 does not advertise the
/// MCP elicitation capability).
///
/// `None` means "use the config value (or default if absent)". `Some`
/// overrides it.
#[derive(Debug, Clone, Default)]
pub struct PolicyOverrides {
    /// Override for `[mcp].allow_mutations`.
    pub allow_mutations: Option<crate::config::AllowMutations>,
    /// Override for `[mcp].confirm_via`.
    pub confirm_via: Option<crate::config::ConfirmVia>,
}

/// Run the `MCP` server with no per-launch policy overrides. Thin
/// wrapper around [`serve_with_overrides`] for callers that don't
/// need to override `[mcp]` values from the CLI.
///
/// # Errors
///
/// Same as [`serve_with_overrides`].
pub async fn serve(config_path: Option<PathBuf>) -> Result<()> {
    serve_with_overrides(config_path, PolicyOverrides::default()).await
}

/// As [`serve`] but accepts per-launch [`PolicyOverrides`] from
/// command-line flags.
///
/// The overrides are applied after the `[mcp]` section is loaded
/// from `config.toml` and BEFORE the audit log is opened — so the
/// mutation-log file used by the lifetime of this server is the one
/// selected by the (possibly overridden) config.
///
/// # Errors
///
/// Same as [`serve`].
pub async fn serve_with_overrides(
    config_path: Option<PathBuf>,
    overrides: PolicyOverrides,
) -> Result<()> {
    match read_disable_state()? {
        DisableState::NotPresent => {}
        DisableState::Indefinite => {
            let path = disable_sentinel_path()?;
            bail!(
                "SecretEnv MCP server is disabled by a sentinel at {}. \
                 Run `secretenv mcp enable` to re-enable.",
                path.display()
            );
        }
        DisableState::UntilEpochSecs(expires_at) => {
            let path = disable_sentinel_path()?;
            bail!(
                "SecretEnv MCP server is disabled until UNIX timestamp {expires_at} \
                 (sentinel at {}). Run `secretenv mcp enable` to clear immediately.",
                path.display()
            );
        }
    }

    let config = Arc::new(load_config(config_path.as_deref())?);
    let mut mcp_config = McpConfig::from_core_value(config.mcp.as_ref())
        .context("parsing [mcp] section from loaded config")?;
    // Apply CLI-flag overrides (Phase 7f). `None` means "keep config
    // value"; `Some(value)` overrides. Logged via tracing so the
    // override is observable in the audit / debug trail.
    if let Some(am) = overrides.allow_mutations {
        tracing::info!(
            "policy override from CLI flag: allow_mutations = {am:?} (was {:?} in config)",
            mcp_config.allow_mutations,
        );
        mcp_config.allow_mutations = am;
    }
    if let Some(cv) = overrides.confirm_via {
        tracing::info!(
            "policy override from CLI flag: confirm_via = {cv:?} (was {:?} in config)",
            mcp_config.confirm_via,
        );
        mcp_config.confirm_via = cv;
    }
    let mcp_config = Arc::new(mcp_config);
    let mutation_log = Arc::new(
        MutationLog::open_with_default(mcp_config.mutation_log.as_deref())
            .context("opening MCP mutation audit log")?,
    );

    let service = Server::new(config, mcp_config, mutation_log)
        .serve(stdio())
        .await
        .map_err(|e| anyhow!("rmcp serve failed during initialize: {e}"))?;

    service.waiting().await.map_err(|e| anyhow!("rmcp service join error: {e}"))?;

    Ok(())
}
