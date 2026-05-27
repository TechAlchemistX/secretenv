// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared registry-document mutation helpers.
//!
//! Centralizes the `list + edit + serialize + set` transaction that
//! `secretenv-cli` and `secretenv-mcp` previously duplicated when
//! applying alias insert / remove operations to a registry's
//! primary source. Per v0.16 Phase 7 architecture C-2 + code-review
//! Medium: extracted in v0.16.2 (Phase 1b D.2b) so both consumers
//! share the same writer.
//!
//! # What this crate is — and what it isn't
//!
//! This crate centralizes the **transaction body**: the
//! list-current-map → mutate-map → serialize → write-back chain
//! that's identical between CLI and MCP.
//!
//! It does NOT centralize:
//!
//! - **Registry-source selection** — CLI honors `SECRETENV_REGISTRY`
//!   env var + accepts URI-form selections; MCP intentionally rejects
//!   URI-form and only accepts named registries (`[registries.<name>]`).
//!   Each caller keeps its own `pick_*_source` helper.
//! - **Target-URI validation** — exposed here as
//!   [`validate_target_uri`] but called by each caller before
//!   committing to the transaction (the CLI's user-facing error
//!   text + the MCP's structured `WriteFailed` outcome want
//!   different framing).
//! - **Idempotency policy** — [`AliasChange::Remove`] carries a
//!   `required` flag: CLI's `registry unset` bails when the alias
//!   is absent (`required: true`); MCP's `delete_alias` treats an
//!   absent alias as success (`required: false`).
//!
//! # SEC-INV-02 compliance
//!
//! This crate depends on `secretenv-core` with the default-features
//! set (no opt-in to `value-access`) — the registry-document write
//! path takes a serialized `&str` (an alias→URI map, NOT a
//! `Secret<T>` value). `Backend::set(uri, &str)` is the
//! value-free trait method per SEC-INV-02; passing it a registry
//! document is the structurally-safe call.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::{Backend, BackendRegistry, BackendUri};

/// Describes the change to apply to one registry document.
///
/// Constructed by the caller (CLI or MCP) after it has resolved
/// the source URI + backend via its own selection helper. Passed
/// to [`apply_change`].
///
/// `#[non_exhaustive]` per v0.16.2 Phase 7 architecture review:
/// new variants (e.g. a future `Bulk { changes: Vec<...> }`) can
/// be added in a patch release without forcing every downstream
/// `match` site to update.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AliasChange {
    /// Insert (or update if already present) `alias → target_uri`.
    Insert {
        /// Alias name being added/updated (e.g. `"STRIPE_API_KEY"`).
        alias: String,
        /// Direct backend URI the alias should resolve to.
        target_uri: String,
    },
    /// Remove `alias` from the document. When `required = true`,
    /// an absent alias bails with an error (CLI behavior). When
    /// `required = false`, absent-alias is treated as success
    /// (MCP behavior).
    Remove {
        /// Alias name to remove.
        alias: String,
        /// CLI-mode `registry unset` semantics: bail if absent.
        /// MCP-mode `delete_alias` semantics: idempotent on absent.
        required: bool,
    },
}

/// Validate that `target_uri` is a legal alias destination:
///
/// 1. Parses as a [`BackendUri`].
/// 2. Is NOT a `secretenv://` alias (chains rejected — direct
///    backend URI only).
/// 3. References a backend instance configured in
///    `[backends.<name>]` (already present in `backends`).
///
/// Callers run this before [`apply_change`] so the failure mode is
/// "rejected before any read/write" rather than "wrote a value the
/// caller can't actually use later". The MCP boundary surfaces the
/// failure as a structured `WriteFailed` outcome; the CLI surfaces
/// it as a `bail!` from `registry_set`.
///
/// # Errors
///
/// - Target URI fails to parse.
/// - Target URI is a `secretenv://` alias.
/// - Target backend instance is not configured.
pub fn validate_target_uri(target_uri: &str, backends: &BackendRegistry) -> Result<()> {
    let target = BackendUri::parse(target_uri)
        .with_context(|| format!("target '{target_uri}' is not a valid URI"))?;
    if target.is_alias() {
        bail!("target must be a direct backend URI, not a secretenv:// alias");
    }
    if backends.get(&target.scheme).is_none() {
        bail!(
            "target '{target_uri}' references backend instance '{}' which is not configured",
            target.scheme
        );
    }
    Ok(())
}

/// Apply `change` to the registry document at `source_uri`.
///
/// Transaction body:
///
/// 1. `backend.list(source_uri).await` — read the current
///    alias→URI map from the backing storage.
/// 2. Mutate the map per `change` (insert / remove with the
///    documented `required` semantics).
/// 3. [`secretenv_core::serialize_registry_doc`] with the
///    backend's `registry_format()` — re-emit the canonical bytes.
/// 4. `backend.set(source_uri, &serialized).await` — write back.
///
/// `registry_label` is used only in error messages (it's the
/// operator-facing name, e.g. `"default"`); the actual storage
/// location is `source_uri`.
///
/// # Errors
///
/// - `backend.list` fails (storage unreachable, auth, etc.).
/// - `change` is [`AliasChange::Remove`] with `required: true` and
///   the alias is absent from the current document.
/// - Serialization fails (should not happen for valid maps).
/// - `backend.set` fails (storage write error).
pub async fn apply_change(
    backend: &dyn Backend,
    source_uri: &BackendUri,
    registry_label: &str,
    change: AliasChange,
) -> Result<()> {
    let current = backend
        .list(source_uri)
        .await
        .with_context(|| format!("reading registry document for registry `{registry_label}`"))?;
    let mut map: BTreeMap<String, String> = current.into_iter().collect();

    match change {
        AliasChange::Insert { alias, target_uri } => {
            map.insert(alias, target_uri);
        }
        AliasChange::Remove { alias, required } => {
            if map.remove(&alias).is_none() && required {
                return Err(anyhow!(
                    "alias '{alias}' not found in registry at '{}'",
                    source_uri.raw
                ));
            }
        }
    }

    let serialized = secretenv_core::serialize_registry_doc(backend.registry_format(), &map)?;
    backend.set(source_uri, &serialized).await.with_context(|| {
        format!("writing updated registry document for registry `{registry_label}`")
    })?;
    Ok(())
}
