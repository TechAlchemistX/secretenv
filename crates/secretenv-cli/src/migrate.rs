// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

// Phase 6 lands this module; Phase 5 (next commit) wires the CLI to
// it. Until the wiring lands, every item here is technically
// "unused" from the binary's main code path. Suppress at the module
// boundary rather than per-item.
#![allow(dead_code)]

//! v0.15 `secretenv registry migrate` library entry.
//!
//! This module is the load-bearing core of the migrate cycle. The CLI
//! layer (`crate::cli`) parses args, handles confirmation prompts, and
//! formats the report; everything between the source read and the
//! pointer flip lives here.
//!
//! # Three-step transaction (plus optional fourth)
//!
//! 1. **read** — `source.get(&plan.source_uri)`.
//! 2. **write** — `dest.write_secret(&plan.dest_uri, &value)`.
//! 3. **pointer flip** — re-serialize the registry doc with the alias
//!    pointing at the destination URI. This is the commit point.
//! 4. **source delete** (opt-in `--delete-source`, double-confirmed by
//!    the CLI layer even under `--yes`) — `source.delete_secret(&plan.source_uri)`.
//!
//! # Borrow-not-clone (SEC-INV-10)
//!
//! The secret value rides as `Secret<String>` end-to-end. It is read
//! once, passed by reference to `write_secret`, then dropped — which
//! zeroes the wrapped buffer per the `Secret::Drop` impl.
//!
//! # No auto-rollback by deletion (SEC-INV-09)
//!
//! A failed pointer-flip after a successful destination write does
//! NOT trigger an automatic delete on the destination. The operator
//! is told the value exists in both backends and given the manual
//! recovery commands; the destination delete is their explicit call.
//!
//! # Resolve-once invariant
//!
//! [`MigrationPlan`] is built once at command start and bound through
//! the entire flow. Subsequent phases consume `&MigrationPlan` by
//! reference; no phase re-resolves the alias or re-parses URIs.
//!
//! # Telemetry seam
//!
//! Each discrete async phase opens a `tracing::info_span!()` so the
//! v0.17 `OTel` wiring can attach an exporter without restructuring.
//! The phase-level recorders on
//! [`secretenv_telemetry::SecretEnvSpan`] are no-ops in v0.15
//! (the structural fixture lives in v0.14); v0.17 fills them in.

use std::collections::BTreeMap;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::{
    resolve_registry, AliasMap, Backend, BackendRegistry, BackendUri, Config, RegistryCache,
    RegistrySelection, Secret,
};
use secretenv_telemetry::span::{MigrateOutcome, MigratePhase, SecretEnvSpan};

/// Arguments accepted by [`migrate`]. Built by the CLI layer from
/// clap parsing.
#[derive(Debug, Clone)]
pub struct MigrateArgs {
    /// Registry alias to migrate.
    pub alias: String,
    /// Destination backend URI (instance + path).
    pub dest_uri: String,
    /// Override the source URI (used for recovery flows where the
    /// registry already points at the destination but the value is
    /// still in the old backend). When `None`, the source is the
    /// current registry pointer.
    pub source_uri: Option<String>,
    /// Registry selection — name or direct URI. Mirrors
    /// `secretenv run --registry` / `secretenv registry --registry`.
    pub registry: Option<String>,
    /// Plan-only: probe destination + source liveness, render the
    /// plan, exit without mutation.
    pub dry_run: bool,
    /// Skip the top-level confirmation prompt. The `--delete-source`
    /// extra confirmation still fires even under this flag
    /// (SEC-INV-08).
    pub yes: bool,
    /// Opt-in cleanup: after successful migrate, delete source.
    pub delete_source: bool,
}

/// Resolved migration plan — built once at command start, bound
/// through every phase. No phase re-resolves the alias or re-parses
/// any URI.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub alias: String,
    pub source_uri: BackendUri,
    pub dest_uri: BackendUri,
    /// Registry source URI we'll re-write to flip the pointer.
    pub registry_source_uri: BackendUri,
    pub delete_source: bool,
    /// Stable per-invocation identifier. v0.15 uses nanoseconds since
    /// the UNIX epoch in hex form; v0.17 may upgrade to `UUIDv7`.
    pub transaction_id: String,
}

/// Recorded duration of every phase. Missing phases (e.g.
/// `source_delete_ms` when `--delete-source` was not set) are `None`.
#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct PhaseDurations {
    pub probe_ms: u64,
    pub read_ms: u64,
    pub write_ms: u64,
    pub pointer_flip_ms: u64,
    pub source_delete_ms: Option<u64>,
}

/// Final outcome — maps 1:1 to
/// [`secretenv_telemetry::span::MigrateOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateReportOutcome {
    Success,
    /// Pointer flip failed after a successful destination write.
    /// The value exists in BOTH backends; recovery is the operator's
    /// call (SEC-INV-09).
    PartialFailurePointerFlip,
    /// Migration succeeded but the source-delete leg (opt-in) failed.
    /// Migration is complete; cleanup is the operator's call.
    SourceDeleteFailedPostCommit,
    /// `--dry-run`; no read, write, or commit attempted.
    DryRun,
}

impl MigrateReportOutcome {
    const fn as_telemetry(self) -> MigrateOutcome {
        match self {
            // `Success` and `SourceDeleteFailedPostCommit` both map to
            // telemetry `Ok` — the latter is a post-commit warning, not
            // a transaction failure (SEC-INV-09: migration completed).
            // Identical-arm clippy lint suppressed because the mapping
            // is intentional and should stay independently maintained.
            Self::Success | Self::SourceDeleteFailedPostCommit => MigrateOutcome::Ok,
            Self::PartialFailurePointerFlip => MigrateOutcome::PartialFailure,
            Self::DryRun => MigrateOutcome::DryRun,
        }
    }
}

/// Returned by [`migrate`]. Stable surface for the CLI's text-mode
/// rendering + `--json` formatter; v0.16 MCP `migrate_alias` tool
/// re-exports this verbatim.
#[derive(Debug, Clone)]
pub struct MigrateReport {
    pub alias: String,
    pub source_backend_type: String,
    pub dest_backend_type: String,
    pub outcome: MigrateReportOutcome,
    pub phase_durations: PhaseDurations,
    pub delete_source: bool,
    /// Copy-paste cleanup command when `--delete-source` was not set
    /// (or was set but failed post-commit). `None` when the source
    /// was successfully deleted.
    pub delete_hint: Option<String>,
    pub transaction_id: String,
    /// Probe diagnostics surface raised in dry-run mode (and recorded
    /// regardless). Each entry is `(backend_instance, "ok" | "error: <msg>")`.
    pub probe_results: Vec<(String, String)>,
}

/// Build the [`MigrationPlan`] from CLI args + active registry state.
///
/// # Errors
/// - Alias not in the resolved registry cascade (and `--from` not set).
/// - Destination URI doesn't parse, or references a backend instance
///   not in `config.toml`.
/// - Source URI (whether inferred or `--from`-provided) references an
///   unconfigured backend.
pub async fn build_migration_plan(
    args: &MigrateArgs,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<MigrationPlan> {
    let dest_uri = BackendUri::parse(&args.dest_uri)
        .with_context(|| format!("destination '{}' is not a valid URI", args.dest_uri))?;
    if dest_uri.is_alias() {
        bail!("destination must be a direct backend URI, not a secretenv:// alias");
    }
    if backends.get(&dest_uri.scheme).is_none() {
        bail!(
            "destination '{}' references backend instance '{}' which is not configured",
            args.dest_uri,
            dest_uri.scheme
        );
    }

    // Resolve the registry cascade to either (a) find the alias's
    // current pointer or (b) pick the primary source for the
    // pointer-flip write.
    let selection = registry_selection(args.registry.as_deref(), config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;

    let source_uri = if let Some(explicit) = &args.source_uri {
        BackendUri::parse(explicit)
            .with_context(|| format!("--from '{explicit}' is not a valid URI"))?
    } else {
        let (target, _src) = aliases.get(&args.alias).ok_or_else(|| {
            anyhow!(
                "alias '{}' not found in registry cascade [{}]",
                args.alias,
                format_sources(&aliases)
            )
        })?;
        target.clone()
    };
    if source_uri.is_alias() {
        bail!(
            "alias '{}' resolved to another alias ('{}') — migrate operates on backend URIs only",
            args.alias,
            source_uri.raw
        );
    }
    if backends.get(&source_uri.scheme).is_none() {
        bail!(
            "source '{}' references backend instance '{}' which is not configured",
            source_uri.raw,
            source_uri.scheme
        );
    }

    let registry_source_uri = aliases.primary_source().clone();

    Ok(MigrationPlan {
        alias: args.alias.clone(),
        source_uri,
        dest_uri,
        registry_source_uri,
        delete_source: args.delete_source,
        transaction_id: new_transaction_id(),
    })
}

/// Drive the migration end-to-end. The CLI layer is responsible for
/// confirmation prompts (both top-level and the `--delete-source`
/// extra) BEFORE calling this function.
///
/// # Errors
/// - Plan build failure (alias resolution, URI parsing).
/// - Destination probe failure (returned [`Err`] only on definitive
///   capability deny — see [`Backend::probe_write`] contract).
/// - Source read failure.
/// - Destination write failure (pre-commit; nothing to recover).
/// - Pointer-flip failure (post-commit; value lives in BOTH backends;
///   surfaced as `MigrateReportOutcome::PartialFailurePointerFlip`).
///
/// Source-delete failure is non-fatal — it produces a
/// `SourceDeleteFailedPostCommit` outcome plus a populated
/// `delete_hint`.
pub async fn migrate(
    args: MigrateArgs,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<MigrateReport> {
    let (mut span, _guard) = SecretEnvSpan::start("secretenv.migrate");
    span.record_command("migrate");

    let plan = build_migration_plan(&args, config, backends).await?;
    span.record_alias_name(&plan.alias)
        .record_migrate_transaction_id(&plan.transaction_id);

    let source = backend_for(backends, &plan.source_uri)?;
    let dest = backend_for(backends, &plan.dest_uri)?;
    span.record_migrate_source_backend_type(source.backend_type())
        .record_migrate_dest_backend_type(dest.backend_type())
        .record_migrate_delete_source(args.delete_source);

    // ----- Probe phase -----
    let (probe_ms, probe_results) = probe_phase(&plan, source, dest).await?;
    if args.dry_run {
        span.record_migrate_outcome(MigrateOutcome::DryRun);
        return Ok(MigrateReport {
            alias: plan.alias.clone(),
            source_backend_type: source.backend_type().to_owned(),
            dest_backend_type: dest.backend_type().to_owned(),
            outcome: MigrateReportOutcome::DryRun,
            phase_durations: PhaseDurations { probe_ms, ..PhaseDurations::default() },
            delete_source: args.delete_source,
            delete_hint: Some(source.delete_hint(&plan.source_uri)),
            transaction_id: plan.transaction_id,
            probe_results,
        });
    }

    // ----- Read -----
    let (value, read_ms) = match migrate_read(&plan, source).await {
        Ok(v) => v,
        Err(e) => {
            span.record_migrate_outcome(MigrateOutcome::SourceReadFailed);
            return Err(e);
        }
    };

    // ----- Write -----
    let write_ms = match migrate_write(&plan, dest, &value).await {
        Ok(ms) => ms,
        Err(e) => {
            span.record_migrate_outcome(MigrateOutcome::DestWriteFailed);
            // Pre-commit: nothing to recover. value drops here → zeroized.
            return Err(e);
        }
    };

    // ----- Pointer flip (commit point) -----
    let (flip_ms, flip_err) = match migrate_registry_flip(&plan, backends, &args).await {
        Ok(ms) => (ms, None),
        Err(e) => (0, Some(e)),
    };
    // Value drops now — `Zeroizing<String>` clears the buffer (SEC-INV-10).
    drop(value);

    if let Some(err) = flip_err {
        span.record_migrate_phase(MigratePhase::PointerFlip)
            .record_migrate_outcome(MigrateOutcome::PartialFailure);
        // Partial-failure path: report and propagate so the CLI layer
        // can emit the manual recovery stderr.
        return Err(err.context(format!(
            "migrate {alias}: pointer flip failed after destination write succeeded — \
             value now exists in BOTH backends. Run `secretenv registry set {alias} \
             {dest}` to complete; or `{dest_hint}` to roll back the destination write.",
            alias = plan.alias,
            dest = plan.dest_uri.raw,
            dest_hint = dest.delete_hint(&plan.dest_uri),
        )));
    }

    // ----- Optional source-delete -----
    let mut source_delete_ms = None;
    let mut outcome = MigrateReportOutcome::Success;
    let mut delete_hint = Some(source.delete_hint(&plan.source_uri));
    if args.delete_source {
        match migrate_source_delete(&plan, source).await {
            Ok(ms) => {
                source_delete_ms = Some(ms);
                delete_hint = None;
            }
            Err(_e) => {
                outcome = MigrateReportOutcome::SourceDeleteFailedPostCommit;
                // Migration is committed; surface as a warning, not a hard error.
            }
        }
    }

    span.record_migrate_outcome(outcome.as_telemetry());

    Ok(MigrateReport {
        alias: plan.alias.clone(),
        source_backend_type: source.backend_type().to_owned(),
        dest_backend_type: dest.backend_type().to_owned(),
        outcome,
        phase_durations: PhaseDurations {
            probe_ms,
            read_ms,
            write_ms,
            pointer_flip_ms: flip_ms,
            source_delete_ms,
        },
        delete_source: args.delete_source,
        delete_hint,
        transaction_id: plan.transaction_id,
        probe_results,
    })
}

/// Source liveness + destination write-capability probe phase. Driven
/// by [`Backend::probe_write`] (default no-op; 4 backends override
/// per Phase 3).
///
/// Returns `(total_duration_ms, per-backend probe results)` where
/// each result is `(instance_name, "ok" | "error: <msg>")`. Errors
/// inside individual probes are propagated as overall failure ONLY
/// when the destination probe definitively says "deny" — see
/// `Backend::probe_write` contract.
async fn probe_phase(
    plan: &MigrationPlan,
    source: &dyn Backend,
    dest: &dyn Backend,
) -> Result<(u64, Vec<(String, String)>)> {
    let span = tracing::info_span!("secretenv.migrate.probe", alias = %plan.alias);
    let _enter = span.enter();
    let start = Instant::now();
    let mut results = Vec::with_capacity(2);

    // Source: a cheap-but-honest liveness signal is `check()`. We
    // don't probe-read the source value (that would materialize the
    // secret; SEC-INV-01).
    let source_status = source.check().await;
    results.push((source.instance_name().to_owned(), format!("{source_status:?}")));

    // Destination: the actual write-permission probe.
    match dest.probe_write(&plan.dest_uri).await {
        Ok(()) => results.push((dest.instance_name().to_owned(), "ok".to_owned())),
        Err(e) => {
            results.push((dest.instance_name().to_owned(), format!("error: {e}")));
            // Definitive deny — fail the migrate here, BEFORE any read.
            // SEC-INV-09: do not auto-rollback (nothing was written yet).
            return Err(e.context(format!(
                "destination probe rejected migrate {alias}: {dest_instance} cannot write at {dest_uri}",
                alias = plan.alias,
                dest_instance = dest.instance_name(),
                dest_uri = plan.dest_uri.raw,
            )));
        }
    }
    let dur = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok((dur, results))
}

/// Phase 1 — read the source value. Discrete async function wrapped
/// in its own `tracing::info_span!()` so the v0.17 `OTel` exporter can
/// attach without restructuring.
#[tracing::instrument(skip(plan, source), fields(alias = %plan.alias))]
async fn migrate_read(
    plan: &MigrationPlan,
    source: &dyn Backend,
) -> Result<(Secret<String>, u64)> {
    let span = tracing::info_span!("secretenv.migrate.read");
    let _enter = span.enter();
    let start = Instant::now();
    let value = source
        .get(&plan.source_uri)
        .await
        .with_context(|| format!("reading source value for alias '{}'", plan.alias))?;
    let dur = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok((value, dur))
}

/// Phase 2 — write to destination. Borrows the value as
/// `&Secret<String>` (SEC-INV-10).
#[tracing::instrument(skip(plan, dest, value), fields(alias = %plan.alias))]
async fn migrate_write(plan: &MigrationPlan, dest: &dyn Backend, value: &Secret<String>) -> Result<u64> {
    let span = tracing::info_span!("secretenv.migrate.write");
    let _enter = span.enter();
    let start = Instant::now();
    dest.write_secret(&plan.dest_uri, value)
        .await
        .with_context(|| format!("writing destination value for alias '{}'", plan.alias))?;
    let dur = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(dur)
}

/// Phase 3 — pointer flip (commit point). Re-reads the registry doc,
/// inserts the new pointer, serializes, and writes it back. Mirrors
/// `registry_set` in `cli.rs` for the registry-write side.
#[tracing::instrument(skip(plan, backends, args), fields(alias = %plan.alias))]
async fn migrate_registry_flip(
    plan: &MigrationPlan,
    backends: &BackendRegistry,
    args: &MigrateArgs,
) -> Result<u64> {
    let span = tracing::info_span!("secretenv.migrate.pointer_flip");
    let _enter = span.enter();
    let start = Instant::now();

    let backend = backend_for(backends, &plan.registry_source_uri)?;
    let current = backend
        .list(&plan.registry_source_uri)
        .await
        .with_context(|| {
            format!("reading registry document at '{}'", plan.registry_source_uri.raw)
        })?;
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
    map.insert(plan.alias.clone(), plan.dest_uri.raw.clone());
    let serialized = secretenv_core::serialize_registry_doc(backend.registry_format(), &map)?;
    backend
        .set(&plan.registry_source_uri, &serialized)
        .await
        .with_context(|| {
            format!("writing updated registry document to '{}'", plan.registry_source_uri.raw)
        })?;

    // `args.registry` reference used only to keep instrument fields
    // stable across the signature; suppress the unused-binding lint.
    let _ = args;

    let dur = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(dur)
}

/// Phase 4 (opt-in) — delete source after a successful commit.
#[tracing::instrument(skip(plan, source), fields(alias = %plan.alias))]
async fn migrate_source_delete(plan: &MigrationPlan, source: &dyn Backend) -> Result<u64> {
    let span = tracing::info_span!("secretenv.migrate.source_delete");
    let _enter = span.enter();
    let start = Instant::now();
    source
        .delete_secret(&plan.source_uri)
        .await
        .with_context(|| format!("deleting source value for alias '{}'", plan.alias))?;
    let dur = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(dur)
}

// --- helpers ---------------------------------------------------------

fn backend_for<'a>(backends: &'a BackendRegistry, uri: &BackendUri) -> Result<&'a dyn Backend> {
    backends
        .get(&uri.scheme)
        .ok_or_else(|| anyhow!("no backend instance '{}' is configured", uri.scheme))
}

fn registry_selection(registry: Option<&str>, config: &Config) -> Result<RegistrySelection> {
    if let Some(value) = registry {
        if value.starts_with("secretenv://") || value.contains("://") {
            return BackendUri::parse(value)
                .map(RegistrySelection::Uri)
                .with_context(|| format!("--registry '{value}' is not a valid URI"));
        }
        return Ok(RegistrySelection::Name(value.to_owned()));
    }
    if let Ok(env) = std::env::var("SECRETENV_REGISTRY") {
        if !env.is_empty() {
            if env.contains("://") {
                return BackendUri::parse(&env)
                    .map(RegistrySelection::Uri)
                    .with_context(|| format!("SECRETENV_REGISTRY '{env}' is not a valid URI"));
            }
            return Ok(RegistrySelection::Name(env));
        }
    }
    if config.registries.contains_key("default") {
        Ok(RegistrySelection::Name("default".to_owned()))
    } else {
        bail!(
            "no registry selected: pass --registry, set SECRETENV_REGISTRY, \
             or define [registries.default] in config.toml"
        )
    }
}

fn format_sources(aliases: &AliasMap) -> String {
    aliases.sources().map(|u| u.raw.as_str()).collect::<Vec<_>>().join(", ")
}

/// Stable per-invocation identifier — nanoseconds since the UNIX
/// epoch encoded as lowercase hex. Cheap and dependency-free; v0.17
/// may upgrade to `UUIDv7` once we have a use case for sortable IDs
/// that survive process boundaries.
fn new_transaction_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_id_is_32_hex_chars() {
        let id = new_transaction_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn report_outcome_maps_to_telemetry() {
        assert_eq!(MigrateReportOutcome::Success.as_telemetry(), MigrateOutcome::Ok);
        assert_eq!(
            MigrateReportOutcome::PartialFailurePointerFlip.as_telemetry(),
            MigrateOutcome::PartialFailure
        );
        assert_eq!(
            MigrateReportOutcome::SourceDeleteFailedPostCommit.as_telemetry(),
            MigrateOutcome::Ok
        );
        assert_eq!(MigrateReportOutcome::DryRun.as_telemetry(), MigrateOutcome::DryRun);
    }
}
