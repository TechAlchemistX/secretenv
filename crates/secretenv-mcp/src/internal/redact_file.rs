// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Value-handling internals for `redact_file`.
//!
//! # SEC-INV-02 escape hatch
//!
//! This file is the second consumer of the documented
//! `disallowed-types` escape hatch (after `gen_engine.rs`). It MUST
//! name [`secretenv_core::Secret`] because `Backend::get` returns
//! one — there is no other way to obtain the bytes the file-scrubber
//! needs to redact. The `#[allow(clippy::disallowed_types)]`
//! pragma at the module level is the deliberate seam.
//!
//! Value-handling discipline observed here:
//!
//! - `Secret<String>` is consumed inline via `expose_secret()` at the
//!   single point where the value crosses into the `TaintedSet` (a
//!   v0.14-era struct that owns its bytes + zeroes them on drop).
//!   The exposed `&str` does NOT outlive that line.
//! - The `TaintedSet` is the only thing the caller (`tools/mod.rs`'s
//!   `redact_file` handler) ever sees from this module. Internally it
//!   holds the byte patterns, but the scrubber API only reports
//!   match COUNTS — no matched bytes ever leave this module.
//! - On error paths, the error context strings contain alias NAMES
//!   only (e.g. "fetching value for alias `stripe-key`"), never the
//!   value or any portion of it. Reviewers should flag any `format!`
//!   here that interpolates a `&Secret` or its `expose_secret()`.
//!
//! The MCP handler in `src/tools/mod.rs` consumes this module
//! through [`build_tainted_set`] + [`scrub_to_file`], never naming
//! `Secret` itself.

#![allow(clippy::disallowed_types)]

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::redact::{
    refuse_foreign_owner, refuse_special_paths, scrub_file_in_place, ScrubReport, Scrubber,
    SubstitutionToken, TaintedSet, TaintedValue,
};
use secretenv_core::{resolve_registry, BackendRegistry, Config, RegistryCache, RegistrySelection};

/// Resolve every alias in the named registry, fetch each one's value
/// via `Backend::get`, and stuff the resulting bytes into a
/// [`TaintedSet`].
///
/// `registry_name = None` defaults to `"default"` (mirrors the CLI's
/// `secretenv redact` selection logic).
///
/// # Errors
///
/// - Registry name not in `config.registries`.
/// - `resolve_registry` fails (backend unreachable, malformed
///   registry doc, etc.).
/// - Any single backend `get` call fails (network, auth, missing
///   secret).
pub async fn build_tainted_set(
    config: &Config,
    backends: &BackendRegistry,
    registry_name: Option<&str>,
) -> Result<TaintedSet> {
    let name = registry_name.unwrap_or("default").to_owned();
    let selection = RegistrySelection::Name(name.clone());
    if !config.registries.contains_key(&name) {
        bail!("named registry `{name}` not found in config.toml");
    }
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;

    let mut tainted = TaintedSet::new();
    for (alias_name, target, _source) in aliases.iter() {
        let backend = backends
            .get(&target.scheme)
            .ok_or_else(|| anyhow!("no backend instance `{}` configured", target.scheme))?;
        // The single `Secret`-naming line in the entire MCP crate
        // outside this file would be the `backend.get(...).await?`
        // call below. `expose_secret()` is invoked inline, immediately
        // handed to `TaintedValue::from_alias` (which owns the bytes
        // + zeroes them on drop), then the `Secret` itself is dropped
        // by going out of scope at the end of the loop body.
        let value = backend
            .get(target)
            .await
            .with_context(|| format!("fetching value for alias `{alias_name}`"))?;
        tainted.insert(TaintedValue::from_alias(alias_name.clone(), value.expose_secret()));
    }
    Ok(tainted)
}

/// Scrub `path` in-place using the supplied [`TaintedSet`]. Returns
/// the `ScrubReport` with match-count / byte-count statistics — never
/// any matched bytes.
///
/// Applies the same special-path + foreign-owner refusals as the
/// CLI's `secretenv redact`. `allow_foreign_owner = false` rejects
/// files owned by a UID other than the caller.
///
/// # Errors
///
/// - Path is a special device / symlink / pipe.
/// - Path is owned by a foreign UID and `allow_foreign_owner = false`.
/// - `Scrubber::new` fails (tainted set is empty / below the
///   `MIN_TAINTED_LEN` floor).
/// - Underlying read/write fails.
pub fn scrub_to_file(
    tainted: &TaintedSet,
    path: &Path,
    allow_foreign_owner: bool,
) -> Result<ScrubReport> {
    refuse_special_paths(path)?;
    refuse_foreign_owner(path, allow_foreign_owner)?;
    let scrubber = Scrubber::new(tainted, SubstitutionToken::AliasAware)?
        .ok_or_else(|| anyhow!("tainted set is empty or below the `MIN_TAINTED_LEN` floor"))?;
    scrub_file_in_place(path, &scrubber, None, allow_foreign_owner)
}

/// Dry-run counterpart: scan `path` but write nothing. Returns the
/// `ScrubReport` describing what WOULD change.
///
/// # Errors
///
/// Same as [`scrub_to_file`] minus the write-side failures, plus
/// the open + read errors that `O_NOFOLLOW` may surface.
pub fn scrub_dry_run(
    tainted: &TaintedSet,
    path: &Path,
    allow_foreign_owner: bool,
) -> Result<ScrubReport> {
    refuse_special_paths(path)?;
    refuse_foreign_owner(path, allow_foreign_owner)?;
    let scrubber = Scrubber::new(tainted, SubstitutionToken::AliasAware)?
        .ok_or_else(|| anyhow!("tainted set is empty or below the `MIN_TAINTED_LEN` floor"))?;
    let mut reader = secretenv_core::redact::open_no_follow(path)
        .with_context(|| format!("opening `{}` with O_NOFOLLOW", path.display()))?;
    let mut sink = std::io::sink();
    scrubber.scrub_reader(&mut reader, &mut sink)
}
