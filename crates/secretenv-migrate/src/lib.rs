// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `secretenv registry migrate` library entry — the alias-migration
//! engine.
//!
//! Shipped in v0.15 as a private module inside the `secretenv-cli`
//! binary crate; extracted into its own library crate at v0.16 Phase
//! 1a so the MCP server's `migrate_alias` tool can call the same
//! library entry the CLI uses (v0.15 architect-reviewer carry-forward
//! B1). The CLI layer (`secretenv-cli::cli`) parses args, handles
//! confirmation prompts, and formats the report; everything between
//! the source read and the pointer flip lives here.
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
//! The canonical entry is [`migrate_with_plan`] — it takes a
//! pre-built plan and is what both the CLI and the future v0.16 MCP
//! `migrate_alias` tool will call directly. [`migrate`] is the
//! convenience wrapper that builds the plan then dispatches, used
//! only when the caller hasn't already done the plan-preview render
//! (e.g. unit tests). The CLI builds the plan once for the
//! confirmation-prompt render and reuses the same plan instance for
//! the actual migration — the `transaction_id` the operator sees in
//! the prompt is the same one that lands in the report and any
//! captured telemetry. Phase 7 audit (code-rev B1) flagged the prior
//! two-call shape as a TOCTOU + `transaction_id`-drift hazard.
//!
//! The pointer-flip phase ([`migrate_registry_flip`]) deliberately
//! re-reads the registry document from the registry backend. This is
//! NOT a violation of resolve-once — the invariant binds the *alias
//! resolution and URI parsing*, not the registry-document snapshot.
//! Reading the latest doc immediately before mutation minimizes the
//! read-modify-write window (which is still racy in v0.15 — see
//! SEC-INV-21 in [[v0.14-plus-security-invariants]] for the v0.17
//! `cas_set` evolution plan).
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
use secretenv_telemetry::span::{
    BackendType, MigrateOutcome, MigratePhase, MutationSpanName, SecretEnvSpan,
};

pub mod mcp_safe;

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
    /// Opt-in cleanup: after successful migrate, delete source. The
    /// CLI layer also accepts a `--yes` flag for the top-level
    /// confirmation prompt; that flag is consumed by the CLI handler
    /// before [`migrate`] is called, so it does not appear here.
    pub delete_source: bool,
}

/// Resolved migration plan — built once at command start, bound
/// through every phase. No phase re-resolves the alias or re-parses
/// any URI.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    /// Registry alias being migrated.
    pub alias: String,
    /// Parsed source backend URI (where the value currently lives).
    pub source_uri: BackendUri,
    /// Parsed destination backend URI (where the value will be written).
    pub dest_uri: BackendUri,
    /// Registry source URI we'll re-write to flip the pointer.
    pub registry_source_uri: BackendUri,
    /// Stable per-invocation identifier. v0.15 uses nanoseconds since
    /// the UNIX epoch in hex form; v0.17 may upgrade to `UUIDv7`.
    ///
    /// v0.18 Code-M4 doc-hygiene note: this field is moved (not
    /// borrowed) into [`MigrateReport`] at the end of
    /// [`migrate_with_plan`]. The resolve-once invariant means the
    /// `MigrationPlan` must not be reused after the migrate; a fresh
    /// plan + fresh `transaction_id` is required for each migrate
    /// invocation. See [`migrate_with_plan`] line ~471 and ~606 for
    /// the move sites.
    pub transaction_id: String,
}

/// Recorded duration of every phase. Missing phases (e.g.
/// `source_delete_ms` when `--delete-source` was not set) are `None`.
#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct PhaseDurations {
    /// Time spent in the destination-probe phase (`--dry-run` or pre-write check).
    pub probe_ms: u64,
    /// Time spent reading the source value.
    pub read_ms: u64,
    /// Time spent writing to the destination backend.
    pub write_ms: u64,
    /// Time spent re-serializing and writing the registry document (commit phase).
    pub pointer_flip_ms: u64,
    /// Time spent deleting the source value (opt-in `--delete-source`); `None` when not requested.
    pub source_delete_ms: Option<u64>,
}

/// Final outcome — maps 1:1 to
/// [`secretenv_telemetry::span::MigrateOutcome`].
///
/// `#[non_exhaustive]` added in v0.16 Phase 7h release-prep per the
/// Phase 9 architecture audit's R-4 recommendation — keeps the
/// freedom to add variants in v0.16.x patches without breaking
/// downstream `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MigrateReportOutcome {
    /// Migration committed successfully.
    Success,
    /// Pointer flip failed after a successful destination write.
    /// The value exists in BOTH backends; recovery is the operator's
    /// call (SEC-INV-09).
    ///
    /// `migrate_with_plan` currently surfaces this via `Err` (the
    /// downcast lookup is [`PointerFlipFailed`]) so the CLI can
    /// render the manual-recovery block to stderr without embedding
    /// URI bodies in the bubbled error message (SEC-INV-22). The
    /// variant is retained as the wire-format anchor so a future MCP
    /// boundary or a `Result<MigrateReport, MigrateReport>` API can
    /// switch to Ok-with-partial-failure without an enum-variant
    /// break. Phase 7 audit (architect M2): the
    /// `report_outcome_json_round_trip` test exercises the variant
    /// via direct construction so the JSON wire-format stays locked.
    /// v0.16 Phase 1a: un-hidden (architect B2/P1 carry-forward) now
    /// that the MCP boundary will exercise it.
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
            Self::Success => MigrateOutcome::Ok,
            // Phase 7 audit (code-rev S8): distinct telemetry outcome
            // — migration committed but post-commit source delete
            // failed; operators querying OTel can see this without
            // scraping logs.
            Self::SourceDeleteFailedPostCommit => MigrateOutcome::OkWithCleanupFailure,
            Self::PartialFailurePointerFlip => MigrateOutcome::PartialFailure,
            Self::DryRun => MigrateOutcome::DryRun,
        }
    }
}

/// Returned by [`migrate`]. Stable surface for the CLI's text-mode
/// rendering + `--json` formatter.
///
/// # Do not serialize directly — go through [`mcp_safe::McpSafeReport`]
///
/// This type intentionally does NOT derive `serde::Serialize`. The
/// MCP boundary (and any future wire-format consumer) MUST go
/// through [`mcp_safe::McpSafeReport::from`] which projects out the
/// fields that may carry backend stderr (`probe_results`) or CLI
/// recovery commands embedding URI bodies (`delete_hint`). v0.16.1
/// D.4 lifted that projection out of `secretenv-mcp` so the "what's
/// safe to publish" decision lives next to the source type.
#[derive(Debug, Clone)]
pub struct MigrateReport {
    /// Registry alias that was migrated.
    pub alias: String,
    /// Source backend type label (e.g. `"vault"`, `"aws-ssm"`).
    pub source_backend_type: String,
    /// Destination backend type label.
    pub dest_backend_type: String,
    /// Final outcome — maps 1:1 to [`MigrateOutcome`].
    pub outcome: MigrateReportOutcome,
    /// Recorded per-phase durations.
    pub phase_durations: PhaseDurations,
    /// Whether `--delete-source` was requested.
    pub delete_source: bool,
    /// Copy-paste cleanup command when `--delete-source` was not set
    /// (or was set but failed post-commit). `None` when the source
    /// was successfully deleted.
    pub delete_hint: Option<String>,
    /// Stable per-invocation identifier (same value as `MigrationPlan::transaction_id`).
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
        transaction_id: new_transaction_id(),
    })
}

/// Structured context for the partial-failure stderr renderer.
///
/// Raised by `migrate_with_plan`. The CLI dispatcher downcasts the
/// returned `anyhow::Error` against this type to decide whether to
/// print the manual-recovery block to stderr (vs. bubble the chain
/// unmodified).
///
/// SEC-INV-20 / Phase 7 audit (security M2) — the recovery block
/// carries the destination URI body, which must stay on the
/// operator's terminal and not leak into a captured stderr→log
/// stream as the `anyhow::Error` Display.
#[derive(Debug)]
pub struct PointerFlipFailed {
    /// Alias whose pointer flip failed (the only safe-to-log field).
    pub alias: String,
    /// Raw destination URI string — for the CLI's terminal-only recovery render. NEVER include in logged error output.
    pub dest_uri_raw: String,
    /// Backend-specific cleanup command hint for the destination — for the CLI's terminal-only recovery render. NEVER include in logged error output.
    pub dest_delete_hint: String,
}

impl std::fmt::Display for PointerFlipFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Compact form for log capture — recovery details go through
        // the dedicated terminal-only renderer in the CLI dispatcher.
        write!(
            f,
            "pointer flip failed for alias '{}' after destination write succeeded; \
             value exists in both backends — operator action required (see stderr).",
            self.alias
        )
    }
}

impl std::error::Error for PointerFlipFailed {}

/// Convenience entry: build the [`MigrationPlan`] then dispatch to
/// [`migrate_with_plan`]. Used when the caller has no need to render
/// a confirmation preview against the resolved plan.
///
/// The CLI dispatcher does NOT use this entry — it builds the plan
/// itself for the top-level confirmation render and reuses the same
/// plan via [`migrate_with_plan`] (Phase 7 audit fix — code-rev B1
/// — eliminates the TOCTOU + `transaction_id`-drift between preview
/// and execution). v0.16 MCP `migrate_alias` and integration tests
/// are the expected consumers of this entry.
///
/// # Errors
/// See [`migrate_with_plan`].
pub async fn migrate<F>(
    args: MigrateArgs,
    config: &Config,
    backends: &BackendRegistry,
    post_commit_source_delete_consent: F,
) -> Result<MigrateReport>
where
    F: FnOnce(&MigrationPlan) -> bool,
{
    let plan = build_migration_plan(&args, config, backends).await?;
    migrate_with_plan(plan, &args, backends, post_commit_source_delete_consent).await
}

/// Drive the migration end-to-end against a pre-built plan.
///
/// The CLI layer is responsible for the top-level confirmation prompt
/// BEFORE calling this function. The `--delete-source` extra
/// confirmation fires AFTER the pointer-flip commit succeeds — per
/// SEC-INV-08 it must run even when `--yes` is set globally, and the
/// operator must have seen the commit succeed before deciding.
///
/// This is the canonical entry point. v0.16 MCP `migrate_alias` will
/// call this directly with a precomputed plan + a closure that
/// returns `false` (no destructive default) or `true` (explicit
/// MCP-side opt-in already confirmed at the MCP boundary).
///
/// The closure `post_commit_source_delete_consent` runs synchronously
/// between phase 3 and phase 4; it can read stdin, query a prompt,
/// or return a precomputed bool. The state machine is:
///
/// - `args.delete_source == false`: closure NEVER called; delete leg
///   skipped; report's `delete_hint` is populated.
/// - `args.delete_source == true` AND closure returns `true`:
///   delete-source leg runs; report's `delete_hint` is `None` on
///   success, populated on failure (with `SourceDeleteFailedPostCommit`
///   outcome).
/// - `args.delete_source == true` AND closure returns `false`:
///   delete leg skipped; report's `delete_hint` is populated;
///   outcome stays `Success` (operator declined but migration
///   committed).
///
/// # Errors
/// - Destination probe failure (returned [`Err`] only on definitive
///   capability deny — see [`Backend::probe_write`] contract).
/// - Source read failure (pre-commit; nothing to recover).
/// - Destination write failure (pre-commit; nothing to recover).
/// - Pointer-flip failure (post-commit; value lives in BOTH backends;
///   the returned [`anyhow::Error`] downcasts to [`PointerFlipFailed`]
///   so the CLI can render the manual-recovery block to stderr
///   without embedding URI bodies in the bubbled error message —
///   Phase 7 audit fix, SEC-INV-20).
///
/// Source-delete failure is non-fatal — it produces a
/// `SourceDeleteFailedPostCommit` outcome plus a populated
/// `delete_hint` in the report (not an `Err`).
// v0.17 Phase 8c added per-phase OTel child spans (probe / read /
// write / pointer_flip / delete) inline at each phase invocation,
// pushing this function over the 100-line clippy threshold.
// Splitting would mean dragging the span guards across helper
// boundaries; the function remains a single linear story (root span
// → 4 phase spans → optional delete span → report).
#[allow(clippy::too_many_lines)]
pub async fn migrate_with_plan<F>(
    plan: MigrationPlan,
    args: &MigrateArgs,
    backends: &BackendRegistry,
    post_commit_source_delete_consent: F,
) -> Result<MigrateReport>
where
    F: FnOnce(&MigrationPlan) -> bool,
{
    // v0.17 Phase 8c — root span uses the spec'd name
    // `secretenv.registry.migrate` (was `secretenv.migrate`); per-phase
    // child spans match the topology in
    // `docs/reference/opentelemetry.md` §4.2. The mutation
    // non-droppable sampler keeps every child + root in the trace
    // stream even under aggressive ratio sampling (SEC-INV-22).
    let (mut span, _guard) = SecretEnvSpan::start("secretenv.registry.migrate");
    span.record_command(secretenv_telemetry::SecretEnvCommand::Migrate)
        .record_alias_name(&plan.alias)
        .record_migrate_transaction_id(&plan.transaction_id);
    // v0.18 Phase 7b Arch-F-2: the unconditional
    // `record_migrate_collapsed(false)` emission removed. v0.18 has
    // no backend exposing atomic compare-and-set, so the value would
    // always be `false` — emitting that to the wire told operators
    // "we checked and the migrate did not collapse" when the code
    // does not yet actually check. The setter stays in span.rs as a
    // reserved attribute slot; once a backend exposes the surface
    // and collapse detection lands here, this call site flips the
    // bool from the real source/dest analysis. Matches the project's
    // D-3.1 "no setter without a real caller" pattern.

    let source = backend_for(backends, &plan.source_uri)?;
    let dest = backend_for(backends, &plan.dest_uri)?;
    span.record_migrate_source_backend_type(BackendType::from_runtime_str(source.backend_type()))
        .record_migrate_dest_backend_type(BackendType::from_runtime_str(dest.backend_type()))
        .record_migrate_delete_source(args.delete_source);

    // ----- Probe phase -----
    let (probe_ms, probe_results) = {
        let (mut probe_span, _probe_guard) = SecretEnvSpan::start("secretenv.migrate.probe");
        probe_span
            .record_migrate_phase(MigratePhase::Probe)
            .record_migrate_source_backend_type(BackendType::from_runtime_str(
                source.backend_type(),
            ))
            .record_migrate_dest_backend_type(BackendType::from_runtime_str(dest.backend_type()));
        let r = probe_phase(&plan, source, dest).await?;
        probe_span.record_migrate_outcome(MigrateOutcome::Ok);
        r
    };
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
    let (value, read_ms) = {
        let (mut read_span, _read_guard) =
            SecretEnvSpan::start_mutation(MutationSpanName::MigrateRead);
        read_span.record_migrate_phase(MigratePhase::Read).record_migrate_source_backend_type(
            BackendType::from_runtime_str(source.backend_type()),
        );
        match migrate_read(&plan, source).await {
            Ok(v) => {
                read_span.record_migrate_outcome(MigrateOutcome::Ok);
                v
            }
            Err(e) => {
                read_span.record_migrate_outcome(MigrateOutcome::SourceReadFailed);
                span.record_migrate_outcome(MigrateOutcome::SourceReadFailed);
                return Err(e);
            }
        }
    };

    // ----- Write -----
    let write_ms = {
        let (mut write_span, _write_guard) =
            SecretEnvSpan::start_mutation(MutationSpanName::MigrateWrite);
        write_span
            .record_migrate_phase(MigratePhase::Write)
            .record_migrate_dest_backend_type(BackendType::from_runtime_str(dest.backend_type()));
        match migrate_write(&plan, dest, &value).await {
            Ok(ms) => {
                write_span.record_migrate_outcome(MigrateOutcome::Ok);
                ms
            }
            Err(e) => {
                write_span.record_migrate_outcome(MigrateOutcome::DestWriteFailed);
                span.record_migrate_outcome(MigrateOutcome::DestWriteFailed);
                // Pre-commit: nothing to recover. value drops here → zeroized.
                return Err(e);
            }
        }
    };

    // Phase 7 audit (code-rev S7): drop the secret value immediately
    // after the destination write returns Ok. The registry-flip
    // round-trip can take 100s of ms (cloud backends); holding the
    // Secret<String> across that window for no reason widens the
    // SEC-INV-10 in-memory lifetime.
    drop(value);

    // ----- Pointer flip (commit point) -----
    let flip_start = Instant::now();
    let (mut flip_span, flip_guard) =
        SecretEnvSpan::start_mutation(MutationSpanName::MigratePointerFlip);
    flip_span.record_migrate_phase(MigratePhase::PointerFlip);
    let flip_result = migrate_registry_flip(&plan, backends).await;
    // Phase 7 audit (code-rev S5): capture elapsed even on Err so the
    // report carries the duration for triage.
    let flip_ms = u64::try_from(flip_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    if let Err(flip_err) = flip_result {
        flip_span.record_migrate_outcome(MigrateOutcome::PartialFailure);
        drop(flip_span);
        drop(flip_guard);
        span.record_migrate_phase(MigratePhase::PointerFlip)
            .record_migrate_outcome(MigrateOutcome::PartialFailure);
        // Phase 7 audit (security M2): bubble a structured
        // PointerFlipFailed error WITHOUT embedding dest_uri.raw or
        // delete_hint into its Display. The CLI dispatcher
        // downcasts and renders the manual-recovery block to stderr
        // (terminal-only per SEC-INV-22).
        return Err(flip_err.context(PointerFlipFailed {
            alias: plan.alias.clone(),
            dest_uri_raw: plan.dest_uri.raw.clone(),
            dest_delete_hint: dest.delete_hint(&plan.dest_uri),
        }));
    }

    // Successful flip closes its span here so the optional delete
    // span starts as a sibling, not a child.
    flip_span.record_migrate_outcome(MigrateOutcome::Ok);
    drop(flip_span);
    drop(flip_guard);

    // ----- Optional source-delete -----
    // Per SEC-INV-08: fire consent closure EVEN when --yes is set
    // globally, AND only AFTER the commit (steps 1-3) succeeded.
    let mut source_delete_ms = None;
    let mut outcome = MigrateReportOutcome::Success;
    let mut delete_hint = Some(source.delete_hint(&plan.source_uri));
    if args.delete_source && post_commit_source_delete_consent(&plan) {
        let (mut delete_span, _delete_guard) =
            SecretEnvSpan::start_mutation(MutationSpanName::MigrateDelete);
        delete_span
            .record_migrate_phase(MigratePhase::DeleteSource)
            .record_migrate_source_backend_type(BackendType::from_runtime_str(
                source.backend_type(),
            ));
        match migrate_source_delete(&plan, source).await {
            Ok(ms) => {
                source_delete_ms = Some(ms);
                delete_hint = None;
                delete_span.record_migrate_outcome(MigrateOutcome::Ok);
            }
            Err(_e) => {
                // Phase 7 audit (code-rev S8): distinct telemetry
                // outcome so OTel queries can see "migrated but
                // source cleanup failed" without scraping logs.
                // Phase 9b — Sec F-4: use the dedicated
                // `OkWithCleanupFailure` variant rather than the
                // misleading `DestWriteFailed` (which an operator
                // would read as a pre-commit write failure).
                outcome = MigrateReportOutcome::SourceDeleteFailedPostCommit;
                delete_span.record_migrate_outcome(MigrateOutcome::OkWithCleanupFailure);
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
    // v0.17 Phase 9b — Phase 8c added a typed `SecretEnvSpan` at the
    // caller site (`migrate_with_plan`); the bridged `info_span!` here
    // would emit a duplicate OTel span via the tracing-opentelemetry
    // layer (`cli/src/main.rs:53`). Dropped to keep one span per phase.
    let start = Instant::now();
    let mut results = Vec::with_capacity(2);

    // Source: a cheap-but-honest liveness signal is `check()`. We
    // don't probe-read the source value (that would materialize the
    // secret; SEC-INV-01). Phase 7 audit (code-rev B4): normalize to
    // the documented `"ok" | "error: <msg>"` shape rather than the
    // raw `{source_status:?}` Debug dump which leaked identity,
    // profile, region, and cli_version into the dry-run terminal +
    // JSON output.
    let source_status = source.check().await;
    let source_label = match source_status {
        secretenv_core::BackendStatus::Ok { .. } => "ok".to_owned(),
        secretenv_core::BackendStatus::NotAuthenticated { .. } => {
            "error: not authenticated".to_owned()
        }
        secretenv_core::BackendStatus::CliMissing { .. } => "error: cli missing".to_owned(),
        secretenv_core::BackendStatus::Error { .. } => "error: backend reported error".to_owned(),
    };
    results.push((source.instance_name().to_owned(), source_label));

    // Destination: the actual write-permission probe. Phase 7 audit
    // (architect M1): also report whether the backend has a real
    // probe vs. relies on the default `Ok(())` no-op, so the dry-run
    // can label "probed-and-ok" vs "no probe available".
    match dest.probe_write(&plan.dest_uri).await {
        Ok(()) => {
            let dest_label = if dest.has_probe_write() {
                "ok (probed)".to_owned()
            } else {
                "ok (no probe available for this backend)".to_owned()
            };
            results.push((dest.instance_name().to_owned(), dest_label));
        }
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
///
/// Phase 7 audit (code-rev S4): single explicit `info_span!` rather
/// than combining `#[tracing::instrument]` (which opens a span on
/// call) with a manual `info_span!` in the body (which would open a
/// duplicate nested child). The `OTel` contract uses the
/// `secretenv.migrate.*` names exactly.
async fn migrate_read(plan: &MigrationPlan, source: &dyn Backend) -> Result<(Secret<String>, u64)> {
    // v0.17 Phase 9b — typed span lives at the caller (migrate_with_plan).
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
async fn migrate_write(
    plan: &MigrationPlan,
    dest: &dyn Backend,
    value: &Secret<String>,
) -> Result<u64> {
    // v0.17 Phase 9b — typed span lives at the caller (migrate_with_plan).
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
///
/// Phase 7 audit (architect M4 / code-rev S6): the vestigial `args`
/// parameter was dropped — the elapsed measurement now lives in the
/// caller so it's captured even on `Err` (code-rev S5).
async fn migrate_registry_flip(plan: &MigrationPlan, backends: &BackendRegistry) -> Result<()> {
    // v0.17 Phase 9b — typed span lives at the caller (migrate_with_plan).
    let backend = backend_for(backends, &plan.registry_source_uri)?;
    let current = backend.list(&plan.registry_source_uri).await.with_context(|| {
        format!("reading registry document at '{}'", plan.registry_source_uri.raw)
    })?;
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
    map.insert(plan.alias.clone(), plan.dest_uri.raw.clone());
    let serialized = secretenv_core::serialize_registry_doc(backend.registry_format(), &map)?;
    backend.set(&plan.registry_source_uri, &serialized).await.with_context(|| {
        format!("writing updated registry document to '{}'", plan.registry_source_uri.raw)
    })?;

    Ok(())
}

/// Phase 4 (opt-in) — delete source after a successful commit.
async fn migrate_source_delete(plan: &MigrationPlan, source: &dyn Backend) -> Result<u64> {
    // v0.17 Phase 9b — typed span lives at the caller (migrate_with_plan).
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
        // Phase 7 audit (code-rev S8): distinct telemetry outcome,
        // not collapsed to `Ok`.
        assert_eq!(
            MigrateReportOutcome::SourceDeleteFailedPostCommit.as_telemetry(),
            MigrateOutcome::OkWithCleanupFailure
        );
        assert_eq!(MigrateReportOutcome::DryRun.as_telemetry(), MigrateOutcome::DryRun);
    }

    #[test]
    fn pointer_flip_failed_display_omits_uri_body() {
        // Phase 7 audit (security M2): the bubbled error's Display
        // must NOT carry the dest URI body or delete_hint — only the
        // alias. The CLI dispatcher downcasts and renders the
        // manual-recovery block to stderr (terminal-only per
        // SEC-INV-22).
        let e = PointerFlipFailed {
            alias: "stripe-key".to_owned(),
            dest_uri_raw: "vault-prod://secret/payments/stripe_key".to_owned(),
            dest_delete_hint: "VAULT_ADDR=… vault kv delete …".to_owned(),
        };
        let rendered = format!("{e}");
        assert!(rendered.contains("stripe-key"), "{rendered}");
        assert!(!rendered.contains("vault-prod://"), "leaked URI: {rendered}");
        assert!(!rendered.contains("vault kv delete"), "leaked hint: {rendered}");
    }
}
