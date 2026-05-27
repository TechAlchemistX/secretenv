// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Registry-document writers shared by `set_alias` + `delete_alias`.
//!
//! v0.16.2 D.2b: the list+edit+serialize+set transaction body
//! lives in [`secretenv_registry_mutate`]; this module owns the
//! MCP-specific selection helper (`pick_primary_source` — named
//! registries only, no URI-form selection; intentionally stricter
//! than the CLI's env-aware `pick_registry_source`).
//!
//! # SEC-INV-02 reminder
//!
//! These functions never touch a [`secretenv_core::Secret`]. The
//! `set(uri, &str)` call passes the SERIALIZED REGISTRY DOC bytes
//! (an alias→URI map) — not a secret value. Per SEC-INV-02 the
//! `Backend::set` trait method takes `&str` (not `&Secret`);
//! calling it from `secretenv-mcp` (now via
//! `secretenv-registry-mutate`) with a registry document is the
//! value-free path.

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::{Backend, BackendRegistry, BackendUri, Config, RegistrySelection};
use secretenv_registry_mutate::{apply_change, validate_target_uri, AliasChange};

/// Resolve the primary source URI of `registry` (the operator-
/// supplied name, or `default` when `None`) to the backing
/// `&dyn Backend` + `BackendUri`.
///
/// **Strict named-only selection** — refuses URI-form registry
/// selections that the CLI's `pick_registry_source` would accept.
/// The MCP boundary enforces "named registries only" so an agent
/// cannot smuggle an arbitrary backend URI as a "registry" target.
fn pick_primary_source<'a>(
    registry_name: Option<&str>,
    config: &Config,
    backends: &'a BackendRegistry,
) -> Result<(BackendUri, &'a dyn Backend)> {
    let name = registry_name.unwrap_or("default").to_owned();
    let selection = RegistrySelection::Name(name.clone());
    let registry_cfg = match &selection {
        RegistrySelection::Name(n) => config
            .registries
            .get(n)
            .ok_or_else(|| anyhow!("named registry `{n}` not found in config.toml"))?,
        RegistrySelection::Uri(_) => bail!("MCP mutation tools accept only named registries"),
    };

    let raw_primary = registry_cfg
        .sources
        .first()
        .ok_or_else(|| anyhow!("registry `{name}` has no source URIs"))?;
    let source_uri = BackendUri::parse(raw_primary)
        .with_context(|| format!("registry `{name}` primary source URI is not parseable"))?;
    let backend = backends.get(&source_uri.scheme).ok_or_else(|| {
        anyhow!(
            "registry `{name}` primary source references backend instance \
             `{}` which is not configured in [backends.*]",
            source_uri.scheme
        )
    })?;
    Ok((source_uri, backend))
}

/// Insert or update `alias → target_uri` in the registry document
/// backing `registry_name`.
///
/// # Errors
///
/// - Target URI fails to parse / is a `secretenv://` alias / target
///   backend is not configured (per
///   [`secretenv_registry_mutate::validate_target_uri`]).
/// - Registry source URI is invalid / backend not configured.
/// - Backend `list` or `set` call fails.
pub async fn set_alias_in_registry(
    alias: &str,
    target_uri: &str,
    registry_name: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    validate_target_uri(target_uri, backends)?;
    let registry_label = registry_name.unwrap_or("default").to_owned();
    let (source_uri, backend) = pick_primary_source(registry_name, config, backends)?;
    apply_change(
        backend,
        &source_uri,
        &registry_label,
        AliasChange::Insert { alias: alias.to_owned(), target_uri: target_uri.to_owned() },
    )
    .await
}

/// Remove `alias` from the registry document backing
/// `registry_name`.
///
/// Removing an absent alias is treated as success (idempotent —
/// matches the MCP boundary's `delete_alias` contract, which
/// intentionally diverges from the CLI's `registry unset`
/// strict-not-found semantics).
///
/// # Errors
///
/// - Registry source URI is invalid / backend not configured.
/// - Backend `list` or `set` call fails.
pub async fn delete_alias_in_registry(
    alias: &str,
    registry_name: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let registry_label = registry_name.unwrap_or("default").to_owned();
    let (source_uri, backend) = pick_primary_source(registry_name, config, backends)?;
    apply_change(
        backend,
        &source_uri,
        &registry_label,
        AliasChange::Remove { alias: alias.to_owned(), required: false },
    )
    .await
}
