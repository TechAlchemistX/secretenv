// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Registry-document writers shared by `set_alias` + `delete_alias`.
//!
//! Mirrors `secretenv-cli/src/cli.rs::{registry_set, registry_unset}`
//! at the seam: build the live `BackendRegistry`, pick the primary
//! source URI for the named registry, list the current alias→target
//! map, mutate it (insert/remove), serialize via
//! [`secretenv_core::serialize_registry_doc`], and write back via
//! [`secretenv_core::Backend::set`]. The CLI helper is private to
//! its binary crate so this duplication is the price of not adding
//! another shared library crate.
//!
//! These functions never touch a [`secretenv_core::Secret`]. The
//! `set(uri, &str)` call passes the SERIALIZED REGISTRY DOC bytes
//! (an alias→URI map) — not a secret value. Per SEC-INV-02 the
//! `Backend::set` trait method takes `&str` (not `&Secret`); calling
//! it from `secretenv-mcp` with a registry document is the
//! value-free path.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::{Backend, BackendRegistry, BackendUri, Config, RegistrySelection};

/// Resolve the primary source URI of `registry` (the operator-
/// supplied name, or `default` when `None`) to the backing
/// `&dyn Backend` + `BackendUri`. Mirrors `pick_registry_source` in
/// the CLI.
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
    let source_uri = BackendUri::parse(raw_primary).with_context(|| {
        format!("registry `{name}` primary source `{raw_primary}` is not a valid URI")
    })?;
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
/// - Target URI fails to parse.
/// - Target URI is itself a `secretenv://` alias (chains rejected).
/// - Target backend instance is not configured.
/// - Registry source URI is invalid / backend not configured.
/// - Backend `list` or `set` call fails.
pub async fn set_alias_in_registry(
    alias: &str,
    target_uri: &str,
    registry_name: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let target = BackendUri::parse(target_uri)
        .with_context(|| format!("target `{target_uri}` is not a valid URI"))?;
    if target.is_alias() {
        bail!("target must be a direct backend URI, not a secretenv:// alias");
    }
    if backends.get(&target.scheme).is_none() {
        bail!(
            "target `{target_uri}` references backend instance `{}` which is not configured",
            target.scheme
        );
    }

    let (source_uri, backend) = pick_primary_source(registry_name, config, backends)?;
    let current = backend
        .list(&source_uri)
        .await
        .with_context(|| format!("reading registry document at `{}`", source_uri.raw))?;
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
    map.insert(alias.to_owned(), target_uri.to_owned());
    let serialized = secretenv_core::serialize_registry_doc(backend.registry_format(), &map)?;
    backend
        .set(&source_uri, &serialized)
        .await
        .with_context(|| format!("writing updated registry document to `{}`", source_uri.raw))?;
    Ok(())
}

/// Remove `alias` from the registry document backing `registry_name`.
/// Removing an absent alias is treated as success (idempotent — matches
/// the CLI's `registry unset` shape).
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
    let (source_uri, backend) = pick_primary_source(registry_name, config, backends)?;
    let current = backend
        .list(&source_uri)
        .await
        .with_context(|| format!("reading registry document at `{}`", source_uri.raw))?;
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
    map.remove(alias);
    let serialized = secretenv_core::serialize_registry_doc(backend.registry_format(), &map)?;
    backend
        .set(&source_uri, &serialized)
        .await
        .with_context(|| format!("writing updated registry document to `{}`", source_uri.raw))?;
    Ok(())
}
