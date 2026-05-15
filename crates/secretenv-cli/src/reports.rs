// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed per-handler reports.
//!
//! Every CLI handler returns one of these structs instead of `()`.
//! In v0.14 the structs are minimal data carriers — the dispatcher
//! discards them via `let _ = handler.await?;`. v0.17 will read
//! the populated fields and emit them as OTel span attributes (per
//! the synthesis §6 matrix).
//!
//! Naming: one type per top-level subcommand. Fields are restricted
//! to ALLOW attributes from the v0.14+ §6 matrix; DENY data
//! (values, URI paths, raw error messages) never lands here.
//!
//! See [[build-plan-v0.14-redact]] §Phase 6 and
//! [[v0.14-plus-synthesis]] §6 for the rationale.
//!
//! # Phase 7 code-review B1: `Drop` does not fire on `secretenv run`
//!
//! The Phase 6 commit message described v0.17 wiring as "the
//! report's `Drop` impl emits the root span." That works for handler
//! paths whose function bodies return normally (`cmd_get`, `cmd_redact`,
//! `cmd_resolve`, `cmd_registry`, `cmd_setup`, `cmd_profile`,
//! `cmd_completions`) but **does not work for `cmd_run`'s exec /
//! pipe-redact happy paths**: both end in `std::process::exit(...)`
//! or `cmd.exec()`, which replace the process / terminate without
//! running Rust destructors. As written, v0.17 would silently emit
//! zero spans for every successful `secretenv run`.
//!
//! **v0.17 must add a pre-exec emission hook** — synchronously
//! flush whatever the v0.17 OTel exporter requires before the
//! `exec()` / `exit()` call. Concretely: in `runner::run_with_options`
//! and `runner::run_with_pipe_redaction`, just before the terminal
//! `exec_with_env(...)` / `std::process::exit(...)`, emit a
//! [`RunReport`]-equivalent span via the v0.17 telemetry sink and
//! flush. The `RunReport` returned to the dispatcher then becomes a
//! no-op for those paths; the other handlers continue to rely on
//! `Drop` emission.
//!
//! v0.14 `#[allow(dead_code)]`: every report field exists for
//! v0.17 emission (whether via `Drop` or pre-exec hook).

#![allow(dead_code, clippy::doc_markdown)]

use secretenv_telemetry::SecretEnvErrorKind;

/// Outcome bucket on every report. v0.17 emits this as
/// `secretenv.command.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Handler returned `Ok(report)`.
    Ok,
    /// Handler returned `Err(_)`. The [`SecretEnvErrorKind`] is the
    /// classified bucket; the full `anyhow::Error` chain stays on
    /// the dispatcher's stderr path.
    Err(SecretEnvErrorKind),
    /// Handler short-circuited via a dry-run path.
    DryRun,
}

/// `secretenv run` outcome metadata.
#[derive(Debug)]
pub struct RunReport {
    /// Number of aliases the manifest resolved.
    pub alias_count: u64,
    /// Whether the run took the pipe-based redact path, the `exec()`
    /// path, or the dry-run path.
    pub dispatch: RunDispatch,
    /// Resolved outcome at handler exit.
    pub outcome: CommandOutcome,
}

/// Which post-resolution dispatch [`RunReport`] reflects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDispatch {
    /// `secretenv run --dry-run` — no fetch, no spawn.
    DryRun,
    /// Pipe-based stdout/stderr redaction (v0.14 default on
    /// non-TTY parent, or `--redact` opt-in).
    PipeRedact,
    /// Classic `exec()` — either `--no-redact --i-know` opt-out
    /// or `Auto` falling back on TTY.
    Exec,
}

/// `secretenv resolve` outcome metadata.
#[derive(Debug)]
pub struct ResolveReport {
    /// Cascade layer index the alias was found at.
    pub cascade_layer_index: u32,
    /// The backend type the alias resolves to.
    pub backend_type: String,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// `secretenv get` outcome metadata.
#[derive(Debug)]
pub struct GetReport {
    /// The backend type the alias resolved to.
    pub backend_type: String,
    /// Whether the operator confirmed at the y/N prompt.
    pub confirmed: bool,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// `secretenv redact` outcome metadata.
#[derive(Debug)]
pub struct RedactReport {
    /// Which mode B sub-path: dry-run / in-place / stdout.
    pub mode: RedactMode,
    /// Match count produced by the scrubber. ALLOW per
    /// `secretenv.redact.match_count`.
    pub match_count: u64,
    /// Byte count replaced. ALLOW per `secretenv.redact.byte_count`.
    pub byte_count: u64,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// Which redact-mode-B sub-dispatch the report reflects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// `--dry-run`.
    DryRun,
    /// `--in-place`.
    InPlace,
    /// Default — write to stdout.
    Stdout,
}

/// `secretenv registry <subcommand>` outcome metadata.
#[derive(Debug)]
pub struct RegistryReport {
    /// Which subcommand fired (e.g. `"set"`, `"unset"`, `"list"`).
    pub subcommand: &'static str,
    /// Number of aliases the operation touched.
    pub aliases_touched: u64,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// `secretenv setup` outcome metadata.
#[derive(Debug)]
pub struct SetupReport {
    /// Whether the operator forced overwrite of an existing config.
    pub force: bool,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// `secretenv profile <subcommand>` outcome metadata.
#[derive(Debug)]
pub struct ProfileReport {
    /// Which subcommand fired.
    pub subcommand: &'static str,
    /// Outcome.
    pub outcome: CommandOutcome,
}

/// `secretenv completions` outcome metadata.
#[derive(Debug)]
pub struct CompletionsReport {
    /// Outcome.
    pub outcome: CommandOutcome,
}
