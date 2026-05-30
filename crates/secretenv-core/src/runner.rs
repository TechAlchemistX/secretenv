// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The runner — Phase 8's final piece of the resolution flow.
//!
//! Given a slice of [`ResolvedSecret`]s from
//! [`resolve_manifest`](crate::resolve_manifest) and a loaded
//! [`BackendRegistry`], the runner:
//!
//! 1. Fetches the value for every `ResolvedSource::Uri` via
//!    [`Backend::get`](crate::Backend::get).
//! 2. Builds an env map containing every fetched value plus every
//!    `ResolvedSource::Default` literal.
//! 3. On Unix, `exec()`s the target command — **replacing** the
//!    current process. The child inherits the parent's TTY, stdio,
//!    signal dispositions, and process group. On non-Unix, the
//!    runner spawns and propagates the child's exit code via
//!    [`std::process::exit`] (v0.3+; today the runner is Unix-first).
//!
//! # Dry-run mode
//!
//! In dry-run mode the runner prints `KEY ← <uri>` to stdout for each
//! [`ResolvedSource::Uri`] (never the value) and does **not** invoke
//! `Backend::get`. `ResolvedSource::Default` entries are also printed
//! in the form `KEY = <value>` because defaults are non-secret by
//! contract ([[secretenv-toml]] explicitly documents defaults are for
//! non-sensitive config like log levels).
//!
//! # Zeroization
//!
//! Fetched values are wrapped in [`zeroize::Zeroizing`] so the
//! plaintext is zeroed on drop in the non-exec paths (dry-run,
//! error short-circuit). On the happy path, `exec()` replaces the
//! process entirely — the heap is discarded, which is strictly more
//! aggressive than zeroization.
//!
//! # Errors
//!
//! A single alias failure propagates its error as-is (env-var name +
//! URI + upstream error chain). **Multiple** alias failures are
//! aggregated into one error that lists every failed alias — operators
//! troubleshooting a misconfigured environment see every broken alias
//! in one pass. If `exec()` itself fails (e.g., the target command is
//! missing), the function returns with an error; it never silently
//! crashes.
#![allow(clippy::module_name_repetitions)]

use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

use crate::backend::Backend;
use crate::redact::{StreamingScrubber, SubstitutionToken, TaintedSet, TaintedValue};
use crate::registry::BackendRegistry;
use crate::resolver::{ResolvedSecret, ResolvedSource};
use crate::Secret;

/// How `secretenv run` should treat its child's stdout/stderr w.r.t.
/// the redact engine.
///
/// Default: [`RedactMode::Auto`] (pipe + redact when the child's
/// stdin is non-TTY; fall back to `exec()` otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactMode {
    /// Default: pipe-based redact when stdin is non-TTY; auto
    /// fall back to `exec()` on a TTY (preserves interactive
    /// programs like `psql`, `vim`, `ssh`).
    #[default]
    Auto,
    /// Force pipe-based redaction even when stdin is a TTY.
    /// Operator opts in via `--redact`; PTY-bound programs may
    /// misbehave.
    ForcePipe,
    /// Force `exec()` path — no redaction. Operator opts out via
    /// `--no-redact --i-know`.
    ForceExec,
}

/// Options for [`run`].
///
/// Constructed by the CLI from `--dry-run` / `--verbose` /
/// `--redact` / `--no-redact` flags. Defaults match v0.13
/// behavior except `redact` which is `Auto` (the v0.14 default).
// v0.17 Phase 9b — Code H3 / Arch L1. Mark non-exhaustive so adding a
// new option (a likely scenario for v0.17.x: telemetry-include-error-detail,
// signed-attribute opt-in, etc.) doesn't silently break downstream
// integrators constructing this struct via record-update syntax.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RunOptions {
    /// Print what would happen without fetching or executing.
    pub dry_run: bool,
    /// Emit fetch progress to stderr.
    pub verbose: bool,
    /// How to handle stdout/stderr redaction.
    pub redact: RedactMode,
    /// Override the substitution token. `None` → alias-aware default.
    pub redact_token: Option<String>,
    /// v0.17 Phase 8b — registry name to attach to the
    /// `secretenv.run` `OTel` span as `secretenv.registry.name`.
    /// `None` skips the attribute; operator-stated identifier per
    /// `docs/reference/opentelemetry.md` §2.5.
    pub registry_name: Option<String>,
    /// v0.18 D-5.1 — opt-in for the
    /// `secretenv.backend.error.message` `OTel` span attribute.
    /// Default `false`; the attribute is structurally absent.
    /// When `true`, backend stderr is passed through the SEC-INV-20
    /// shape-based scrubber before emission via
    /// `SecretEnvSpan::record_backend_error_message_scrubbed`.
    /// Driven by `--otel-include-error-detail` on `secretenv run`.
    pub otel_include_error_detail: bool,
}

/// A fully-resolved env-var pair, ready for injection into the child
/// process. The value is wrapped in [`Secret`]; the inner buffer is
/// zeroed on drop.
pub struct EnvEntry {
    /// The environment variable name.
    pub key: String,
    /// The registry alias name the value came from, when resolved
    /// via a `secretenv://<alias>` reference. `None` for manifest
    /// defaults (which have no registry alias). Carried so mode-A
    /// redact emits `[redacted:<alias>]` consistent with mode B
    /// per Phase 9 Code-H4.
    ///
    /// SEC-INV-19: alias names are **DENY** for `OTel` because they
    /// fingerprint resolved values. The field stays a plain `String`
    /// (not `Secret<String>`) per v0.14.x `DiD` chip L1 — the only
    /// consumer is the terminal substitution renderer, which needs
    /// the bare string; wrapping in `Secret<T>` would force an
    /// `expose_secret()` at every render site for cosmetic gain.
    /// Future leak vectors (a `tracing::Subscriber` → `OTel` adapter,
    /// any new `RedactionSink` impl that emits this field) MUST
    /// project the alias away — see
    /// [`secretenv_telemetry::event::RedactionEvent::for_otel`].
    pub alias_name: Option<String>,
    value: Secret<String>,
}

impl EnvEntry {
    /// Borrow the value as a `&str` for the duration of the borrow.
    /// The underlying buffer is zeroed on drop.
    ///
    /// Gated behind `cfg(not(feature = "mcp-safe"))` for the same
    /// reason as [`Secret::expose_secret`]: crates linking with
    /// `mcp-safe` (the v0.16 MCP server) must not be able to read
    /// resolved values through any safe public API. Per Phase 7
    /// security audit finding B1.
    #[cfg(feature = "value-access")]
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str_internal()
    }
}

/// Fetch every secret and run `command` with the resolved env merged
/// into the process environment.
///
/// On Unix this is a classic `exec()` — the current process is
/// replaced. On success, this function does not return. It only
/// returns to signal an error (fetch failure, missing backend, failed
/// exec, dry-run success).
///
/// # Errors
/// - `command` is empty.
/// - Any `ResolvedSource::Uri` targets a backend instance not
///   registered in `backends`.
/// - Any [`Backend::get`] call fails.
/// - `exec()` itself fails (non-existent command, permission denied,
///   etc.).
pub async fn run(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    command: &[String],
    dry_run: bool,
    verbose: bool,
) -> Result<()> {
    run_with_options(
        resolved,
        backends,
        command,
        &RunOptions { dry_run, verbose, ..RunOptions::default() },
    )
    .await
}

/// Like [`run`] but takes a full [`RunOptions`] including
/// redact-mode selection. The v0.14 CLI uses this entry point.
///
/// # Errors
/// Same set as [`run`], plus a redact-mode-A startup error if any
/// tainted value exceeds the 64 KiB tail-window cap.
// Phase 8b + 9b added inline span lifecycle, metric emission, and
// path-stripping for command_name, pushing this function over the
// 100-line clippy threshold. The function is still a single linear
// story (start root span → resolve → emit metrics → dispatch to
// exec / pipe-redact / dry-run paths). Splitting would mean dragging
// the run_span guard across helper boundaries.
#[allow(clippy::too_many_lines)]
pub async fn run_with_options(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    command: &[String],
    options: &RunOptions,
) -> Result<()> {
    use secretenv_telemetry::{ResolutionOutcome, SecretEnvCommand, SecretEnvSpan};

    if command.is_empty() {
        bail!("no command specified — 'secretenv run' needs a program to execute");
    }

    // v0.17 Phase 8b — root `secretenv.run` span. Wraps the entire
    // resolution + exec lifecycle. Held in a scoped block so the
    // exec() path can end it explicitly before handoff (Drop won't
    // fire across an execve()); the pipe-redact + dry-run paths
    // return normally and the span drops at end-of-function.
    let (mut run_span, run_guard) = SecretEnvSpan::start("secretenv.run");
    // v0.17 Phase 9b — Sec F-1. Strip any path prefix from argv[0]
    // before emission: operators routinely run
    // `secretenv run -- /usr/local/bin/deploy.sh` and the absolute
    // path leaks host filesystem layout (incl. `/home/<user>/...` on
    // dev workstations) to whatever OTel backend is configured.
    // Spec §2.5 contracts this as "argv[0] only" — basename only.
    let argv0_raw = command.first().map_or("<empty>", String::as_str);
    let argv0 =
        std::path::Path::new(argv0_raw).file_name().and_then(|s| s.to_str()).unwrap_or(argv0_raw);
    run_span
        .record_run_id(&secretenv_telemetry::fresh_run_id())
        .record_command(SecretEnvCommand::Run)
        .record_process_command_name(argv0)
        .record_process_env_var_count(resolved.len() as u64)
        .record_run_dry_run(options.dry_run)
        .record_run_verbose(options.verbose);
    if let Some(name) = options.registry_name.as_deref() {
        run_span.record_registry_name(name);
    }

    let resolution_started = std::time::Instant::now();
    let env = match build_env(resolved, backends, options.dry_run, options.verbose).await {
        Ok(env) => {
            run_span.record_run_failed_alias_count(0);
            env
        }
        Err(err) => {
            // build_env aggregates per-alias failures into one error; the
            // per-resolution spans already carry the precise count
            // (`outcome=failure`). Setting failed=alias_count at the
            // run level is the conservative aggregate.
            run_span
                .record_run_outcome(ResolutionOutcome::Failure)
                .record_run_failed_alias_count(resolved.len() as u64);
            // Emit the spec's run-level histogram point on the failure
            // branch too so the operator sees the latency distribution.
            let registry = options.registry_name.as_deref().unwrap_or("<direct-uri>");
            let resolution_ms =
                u64::try_from(resolution_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let bucket =
                secretenv_telemetry::metrics::AliasCountBucket::from_count(resolved.len() as u64);
            secretenv_telemetry::metrics::record_resolution_duration(
                resolution_ms,
                registry,
                ResolutionOutcome::Failure,
                bucket,
            );
            secretenv_telemetry::metrics::increment_resolution_count(
                registry,
                ResolutionOutcome::Failure,
            );
            return Err(err);
        }
    };

    let resolution_ms = u64::try_from(resolution_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let registry_for_metrics = options.registry_name.as_deref().unwrap_or("<direct-uri>");
    let alias_bucket =
        secretenv_telemetry::metrics::AliasCountBucket::from_count(resolved.len() as u64);
    let outcome_for_metric =
        if options.dry_run { ResolutionOutcome::DryRun } else { ResolutionOutcome::Success };
    secretenv_telemetry::metrics::record_resolution_duration(
        resolution_ms,
        registry_for_metrics,
        outcome_for_metric,
        alias_bucket,
    );
    secretenv_telemetry::metrics::increment_resolution_count(
        registry_for_metrics,
        outcome_for_metric,
    );

    if options.dry_run {
        run_span.record_run_outcome(ResolutionOutcome::DryRun);
        return Ok(());
    }

    // Decide redact dispatch.
    let mode = effective_redact_mode(options.redact);
    match mode {
        RedactMode::ForceExec => {
            // Set success + end the span explicitly — execve() bypasses
            // Drop, so without this the BatchProcessor's flush would
            // ship an unended span and Jaeger drops it.
            run_span.record_run_outcome(ResolutionOutcome::Success);
            drop(run_span);
            drop(run_guard);
            exec_with_env(command, &env)
        }
        RedactMode::ForcePipe | RedactMode::Auto => {
            // For Auto, we've already decided via effective_redact_mode
            // whether to fall back to exec. Build the tainted set here.
            let mut tainted = TaintedSet::new();
            for entry in &env {
                // Phase 9 Code-H4 fix: use the registry alias name
                // (lowercase, e.g. `stripe_key`) for the
                // substitution token when one is available, so mode
                // A's `[redacted:<alias>]` matches mode B's. Falls
                // back to the env-var name for manifest-default
                // entries (which have no registry alias).
                let alias_label = entry.alias_name.clone().unwrap_or_else(|| entry.key.clone());
                tainted
                    .insert(TaintedValue::from_alias(alias_label, entry.value.as_str_internal()));
            }
            let token = options
                .redact_token
                .as_ref()
                .map_or(SubstitutionToken::AliasAware, |s| SubstitutionToken::Fixed(s.clone()));
            let result = run_with_pipe_redaction(command, &env, &tainted, token).await;
            // Span ends normally via Drop here; record outcome first.
            match &result {
                Ok(()) => run_span.record_run_outcome(ResolutionOutcome::Success),
                Err(_) => run_span.record_run_outcome(ResolutionOutcome::Failure),
            };
            result
        }
    }
}

/// Resolve the effective dispatch given the operator-chosen
/// [`RedactMode`] and the current stdin TTY state.
#[cfg(unix)]
fn effective_redact_mode(requested: RedactMode) -> RedactMode {
    use std::io::IsTerminal;
    match requested {
        RedactMode::ForceExec => RedactMode::ForceExec,
        RedactMode::ForcePipe => RedactMode::ForcePipe,
        RedactMode::Auto => {
            if std::io::stdin().is_terminal() {
                eprintln!(
                    "secretenv: interactive TTY detected; runtime redaction disabled \
                     for this invocation. Run with --redact to force pipe-based \
                     redaction (may break PTY-bound prompts).",
                );
                RedactMode::ForceExec
            } else {
                RedactMode::ForcePipe
            }
        }
    }
}

#[cfg(not(unix))]
const fn effective_redact_mode(requested: RedactMode) -> RedactMode {
    // No `exec()` semantics off Unix anyway; pipe-based is the only
    // option. ForceExec falls back to spawn+wait inside
    // exec_with_env.
    match requested {
        RedactMode::ForceExec => RedactMode::ForceExec,
        _ => RedactMode::ForcePipe,
    }
}

/// Spawn `command` with `env`, pipe stdout + stderr through a
/// streaming redact scrubber, forward signals, and exit with the
/// child's exit code.
///
/// # Errors
/// Returns an error on spawn failure, redact-scrubber construction
/// failure (oversize pattern), or any I/O failure during the
/// streaming relay.
async fn run_with_pipe_redaction(
    command: &[String],
    env: &[EnvEntry],
    tainted: &TaintedSet,
    token: SubstitutionToken,
) -> Result<()> {
    use std::process::Stdio;

    use tokio::process::Command as TokioCommand;

    // Build two independent streaming scrubbers — one per stream.
    // Sharing one through a Mutex would serialize the relay and
    // negate the parallel-pipe model.
    let Some(scrubber_out) = StreamingScrubber::new(tainted, token.clone())? else {
        // No redactable values (set was empty after the min-length
        // filter). Fall back to the simple exec() path.
        return exec_with_env(command, env);
    };
    let scrubber_err = StreamingScrubber::new(tainted, token)?
        .ok_or_else(|| anyhow!("internal: streaming scrubber surprise-empty for stderr"))?;

    let program = &command[0];
    let args = &command[1..];
    let mut cmd = TokioCommand::new(program);
    cmd.args(args);
    scrub_secretenv_env(|k| {
        cmd.env_remove(k);
    });
    inject_env_entries(env, |k, v| {
        cmd.env(k, v);
    });
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| format!("failed to spawn '{program}'"))?;
    let child_id = child.id();

    let child_stdout = child.stdout.take().ok_or_else(|| anyhow!("child has no stdout"))?;
    let child_stderr = child.stderr.take().ok_or_else(|| anyhow!("child has no stderr"))?;

    // Wire signal forwarding so SIGINT/SIGTERM to the parent
    // propagate to the child. Without this, Ctrl-C in the parent
    // terminal would leave the child orphaned.
    #[cfg(unix)]
    let signal_task = tokio::spawn(forward_signals_to(child_id));
    #[cfg(not(unix))]
    let signal_task: tokio::task::JoinHandle<()> = tokio::spawn(async {
        let _ = child_id;
    });

    let stdout_task = tokio::spawn(relay_stream(scrubber_out, child_stdout, StreamKind::Stdout));
    let stderr_task = tokio::spawn(relay_stream(scrubber_err, child_stderr, StreamKind::Stderr));

    let exit_status = child.wait().await.context("waiting for child to exit")?;
    // Per Phase 7 code-review H2: previously the relay tasks were
    // `let _ = ... .await`-discarded, hiding mid-stream scrubber
    // errors and parent-stdout write failures. Now we collect them
    // and surface a single error if either relay reported one.
    // A `BrokenPipe` on the parent side (`secretenv run ... | head`)
    // is mapped to a clean exit inside `relay_stream`.
    let stdout_res = stdout_task.await.context("redact stdout relay panicked")?;
    let stderr_res = stderr_task.await.context("redact stderr relay panicked")?;
    signal_task.abort();
    let stdout_report = stdout_res.context("redact stdout relay failed")?;
    let stderr_report = stderr_res.context("redact stderr relay failed")?;

    // v0.17 Phase 8c — emit one `secretenv.redact.filter_event` span
    // per stream with the aggregated match/byte counts. Emission is
    // suppressed when match_count == 0 so quiet runs don't add empty
    // spans (the contract is "report what was scrubbed").
    emit_redact_event_span(secretenv_telemetry::RedactionStream::Stdout, &stdout_report);
    emit_redact_event_span(secretenv_telemetry::RedactionStream::Stderr, &stderr_report);
    secretenv_telemetry::flush_before_exec(std::time::Duration::from_secs(1));

    let code = exit_status.code().unwrap_or(128);
    std::process::exit(code);
}

/// v0.17 Phase 8c — emit one `secretenv.redact.filter_event` span
/// summarising a single stream's runtime-mode redact pass.
///
/// Quiet streams (`match_count == 0`) get no span. The recorded
/// attributes (`mode=runtime`, `stream`, aggregate counts) match
/// `docs/reference/opentelemetry.md` §2.6.
fn emit_redact_event_span(
    stream: secretenv_telemetry::RedactionStream,
    report: &crate::redact::ScrubReport,
) {
    if report.match_count == 0 {
        return;
    }
    let (mut span, _guard) =
        secretenv_telemetry::SecretEnvSpan::start("secretenv.redact.filter_event");
    span.record_redact_mode(secretenv_telemetry::RedactMode::Runtime)
        .record_redact_stream(stream)
        .record_redact_match_count(report.match_count)
        .record_redact_byte_count(report.byte_count);
}

#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

/// Relay a child stream through a streaming scrubber to the
/// parent's matching stream. Chunks of 8 KiB; flush on EOF.
async fn relay_stream<R>(
    mut scrubber: StreamingScrubber,
    mut reader: R,
    kind: StreamKind,
) -> Result<crate::redact::ScrubReport>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; 8 * 1024];
    let mut out_buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut total = crate::redact::ScrubReport::zero();
    loop {
        let n = reader.read(&mut buf).await.context("redact stream: reading from child pipe")?;
        if n == 0 {
            break;
        }
        out_buf.clear();
        let chunk_rep = scrubber.push(&buf[..n], &mut out_buf)?;
        total = total + chunk_rep;
        if let Err(err) = write_kind(kind, &out_buf) {
            if is_broken_pipe(&err) {
                // parent's stdout was closed early — clean exit; return
                // whatever scrub totals we accumulated so the caller's
                // span still carries truthful aggregates.
                return Ok(total);
            }
            return Err(err);
        }
    }
    out_buf.clear();
    let flush_rep = scrubber.flush(&mut out_buf)?;
    total = total + flush_rep;
    if !out_buf.is_empty() {
        if let Err(err) = write_kind(kind, &out_buf) {
            if is_broken_pipe(&err) {
                return Ok(total);
            }
            return Err(err);
        }
    }
    Ok(total)
}

/// Whether the error chain at `err` includes a `BrokenPipe` io error.
/// Used to convert "parent closed stdout early" (legitimate, e.g.
/// `secretenv run ... | head`) into a clean relay exit.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
    })
}

fn write_kind(kind: StreamKind, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    match kind {
        StreamKind::Stdout => {
            let mut out = std::io::stdout().lock();
            out.write_all(bytes).context("redact: writing to parent stdout")?;
            out.flush().context("redact: flush parent stdout")?;
        }
        StreamKind::Stderr => {
            let mut out = std::io::stderr().lock();
            out.write_all(bytes).context("redact: writing to parent stderr")?;
            out.flush().context("redact: flush parent stderr")?;
        }
    }
    Ok(())
}

/// Forward SIGINT / SIGTERM / SIGHUP / SIGQUIT / SIGUSR1 / SIGUSR2
/// from the parent to the child process so Ctrl-C / Ctrl-\ in the
/// parent terminal cleanly tear down `secretenv run`'s subprocess
/// instead of leaving it orphaned.
///
/// SIGQUIT (Ctrl-\) coverage — v0.14.x `DiD` chip L2. Default macOS /
/// Linux shells set `ulimit -c 0`, so a SIGQUIT-induced core dump
/// containing env-bytes is out-of-scope per `docs/security.md`; the
/// forwarder forwards SIGQUIT so the child's own quit handler runs,
/// not for core-dump protection. SIGUSR1/SIGUSR2 are forwarded so
/// children that use them for user-defined runtime control (logrotate,
/// nginx reload, etc.) receive them when the parent does.
///
/// Uses rustix's `kill_process` for the actual signal delivery —
/// avoids `unsafe extern "C" { fn kill }` and keeps the crate's
/// `forbid(unsafe_code)` intact.
#[cfg(unix)]
async fn forward_signals_to(child_pid: Option<u32>) {
    use tokio::signal::unix::{signal, SignalKind};
    let Some(pid_raw) = child_pid else { return };
    let Some(pid) = i32::try_from(pid_raw).ok().and_then(rustix::process::Pid::from_raw) else {
        return;
    };
    let Ok(mut sigint) = signal(SignalKind::interrupt()) else { return };
    let Ok(mut sigterm) = signal(SignalKind::terminate()) else { return };
    let Ok(mut sighup) = signal(SignalKind::hangup()) else { return };
    let Ok(mut sigquit) = signal(SignalKind::quit()) else { return };
    let Ok(mut sigusr1) = signal(SignalKind::user_defined1()) else { return };
    let Ok(mut sigusr2) = signal(SignalKind::user_defined2()) else { return };

    loop {
        let sig = tokio::select! {
            _ = sigint.recv() => rustix::process::Signal::INT,
            _ = sigterm.recv() => rustix::process::Signal::TERM,
            _ = sighup.recv() => rustix::process::Signal::HUP,
            _ = sigquit.recv() => rustix::process::Signal::QUIT,
            _ = sigusr1.recv() => rustix::process::Signal::USR1,
            _ = sigusr2.recv() => rustix::process::Signal::USR2,
        };
        let _ = rustix::process::kill_process(pid, sig);
    }
}

/// Fetch every secret and build the env map. Visible to tests and
/// callers that want the env map without executing (e.g., `doctor`
/// pre-flight validation).
///
/// `Default`-sourced entries resolve inline with zero I/O.
/// `Uri`-sourced entries are fetched concurrently via
/// [`futures::future::join_all`]. On dry-run, no backend is invoked.
///
/// # Errors
///
/// If a single alias fetch fails, its error is returned as-is (with
/// the backend error chain plus an alias/URI context line).
///
/// If **multiple** alias fetches fail, the returned error aggregates
/// every failure — one per line, each naming the env-var, the target
/// URI, and the upstream error. This is intentional: operators
/// troubleshooting a misconfigured environment see every broken alias
/// in one pass rather than fixing one, re-running, fixing the next,
/// and so on.
pub async fn build_env(
    resolved: &[ResolvedSecret],
    backends: &BackendRegistry,
    dry_run: bool,
    verbose: bool,
) -> Result<Vec<EnvEntry>> {
    // Output preserves `resolved`'s declaration order. We collect into
    // a `Vec<Option<EnvEntry>>` of the same length and then drop the
    // dry-run `None`s at the end.
    let mut slots: Vec<Option<EnvEntry>> = (0..resolved.len()).map(|_| None).collect();

    // First pass: handle `Default` inline (no I/O) and collect indices
    // for the `Uri` branch.
    let mut uri_indices: Vec<usize> = Vec::new();
    for (idx, secret) in resolved.iter().enumerate() {
        match &secret.source {
            ResolvedSource::Default(value) => {
                if dry_run {
                    println!("{} = {value}  (default)", secret.env_var);
                }
                slots[idx] = Some(EnvEntry {
                    key: secret.env_var.clone(),
                    alias_name: None, // manifest defaults have no registry alias
                    value: Secret::new(value.clone()),
                });
            }
            ResolvedSource::Uri { .. } => uri_indices.push(idx),
        }
    }

    // v0.17 Phase 6.1: pre-fetch header for --verbose. Counts only
    // the uri-backed aliases — manifest defaults don't run an
    // observable fetch.
    if verbose && !dry_run && !uri_indices.is_empty() {
        eprintln!("[secretenv] resolving {} aliases...", uri_indices.len());
    }

    // Second pass: dispatch all URI fetches concurrently. `fetch_one`
    // returns `Ok(None)` in dry-run mode (printed the placeholder,
    // nothing to inject), `Ok(Some(entry, timing))` on success. The
    // `AliasTiming` lets us print a per-alias summary table after all
    // fetches return.
    let fetches = uri_indices.iter().map(|&idx| fetch_one(&resolved[idx], backends, dry_run));
    let results = futures::future::join_all(fetches).await;

    // Collect successes into their original slots; aggregate every
    // failure's error message. Multi-failure returns a single joined
    // anyhow error so one CLI run surfaces every broken alias.
    let mut errors: Vec<anyhow::Error> = Vec::new();
    let mut timings: Vec<AliasTiming> = Vec::new();
    for (idx, result) in uri_indices.iter().zip(results) {
        match result {
            Ok((Some(entry), timing)) => {
                timings.push(timing);
                slots[*idx] = Some(entry);
            }
            Ok((None, timing)) => {
                // dry-run path; still capture timing so the table
                // sees the alias even though no fetch ran.
                timings.push(timing);
            }
            Err((err, timing)) => {
                timings.push(timing);
                errors.push(err);
            }
        }
    }

    // v0.17 Phase 6.1: per-alias summary table on stderr. Sorted by
    // declaration order via uri_indices; the table NEVER includes a
    // backend URI (only the alias name + the backend instance
    // scheme) so --verbose can stay on in CI builds without leaking
    // registry topology.
    if verbose && !dry_run && !timings.is_empty() {
        render_alias_timing_table(&timings);
    }

    if !errors.is_empty() {
        return Err(aggregate_errors(errors));
    }

    Ok(slots.into_iter().flatten().collect())
}

/// Per-alias timing captured during the parallel fetch pass, used to
/// render the `--verbose` summary table (v0.17 Phase 6.1).
#[derive(Debug, Clone)]
struct AliasTiming {
    alias_name: String,
    backend_instance: String,
    duration_ms: u64,
    outcome: AliasFetchOutcome,
}

#[derive(Debug, Clone, Copy)]
enum AliasFetchOutcome {
    Ok,
    Failed,
    DryRun,
}

impl AliasFetchOutcome {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::DryRun => "dry-run",
        }
    }
}

fn render_alias_timing_table(timings: &[AliasTiming]) {
    let alias_w = timings.iter().map(|t| t.alias_name.len()).max().unwrap_or(0).max(5);
    let backend_w = timings.iter().map(|t| t.backend_instance.len()).max().unwrap_or(0).max(7);
    for t in timings {
        eprintln!(
            "  {:<alias_w$} {:<backend_w$} {:>5}ms   {}",
            t.alias_name,
            t.backend_instance,
            t.duration_ms,
            t.outcome.as_label(),
            alias_w = alias_w,
            backend_w = backend_w,
        );
    }
}

/// Fetch a single `Uri`-sourced secret. Returns `Ok((None, _))` in
/// dry-run (placeholder printed, caller should not inject anything).
/// Returns `Ok((Some(entry), timing))` on a successful fetch.
///
/// The tuple's second element is the per-alias timing captured for
/// the v0.17 Phase 6.1 `--verbose` summary table. Errors carry the
/// timing too so a failed fetch still shows up as a row with `failed`
/// outcome, not silently absent from the table.
///
/// Runs under the global `DEFAULT_GET_TIMEOUT` via
/// [`crate::with_timeout`].
type FetchOk = (Option<EnvEntry>, AliasTiming);

// v0.17 Phase 8b adds span + metric emission, pushing this function
// over the 100-line clippy threshold. Splitting would mean dragging
// the AliasTiming + span/metric pair through tuple-passing across an
// arbitrary helper; the function is still a single linear story
// (start span → dispatch dry-run / no-backend / fetch → record
// outcome + timing). Allow it locally rather than fragment the flow.
#[allow(clippy::too_many_lines)]
async fn fetch_one(
    secret: &ResolvedSecret,
    backends: &BackendRegistry,
    dry_run: bool,
) -> Result<FetchOk, (anyhow::Error, AliasTiming)> {
    use secretenv_telemetry::{
        BackendProbeLevel, BackendProbeOutcome, BackendType, FetchOutcome, ResolutionOutcome,
        SecretEnvSpan,
    };

    let started = std::time::Instant::now();
    let (target, alias_name) = match &secret.source {
        ResolvedSource::Uri { target, alias_name, .. } => (target, alias_name.clone()),
        ResolvedSource::Default(_) => {
            // Unreachable: `build_env` only calls `fetch_one` for
            // `Uri` entries. Kept as defensive no-op rather than a
            // panic because one-shot helper misuse should not abort.
            return Ok((
                None,
                AliasTiming {
                    alias_name: secret.env_var.clone(),
                    backend_instance: String::new(),
                    duration_ms: 0,
                    outcome: AliasFetchOutcome::DryRun,
                },
            ));
        }
    };

    // v0.17 Phase 8b — per-alias `secretenv.resolution` span. Carries
    // alias.name + backend.type/instance + outcome + latency. Wrapping
    // happens after the Default short-circuit so synthetic dry-run
    // rows for malformed-source defaults stay span-free.
    let (mut span, _guard) = SecretEnvSpan::start("secretenv.resolution");
    span.record_alias_name(&alias_name)
        .record_alias_env_var(&secret.env_var)
        .record_backend_instance(&target.scheme);

    if dry_run {
        println!("{} ← {}", secret.env_var, target.raw);
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        span.record_resolution_outcome(ResolutionOutcome::DryRun).record_resolution_latency_ms(ms);
        return Ok((
            None,
            AliasTiming {
                alias_name,
                backend_instance: target.scheme.clone(),
                duration_ms: ms,
                outcome: AliasFetchOutcome::DryRun,
            },
        ));
    }

    let Some(backend) = backends.get(&target.scheme) else {
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        span.record_resolution_outcome(ResolutionOutcome::Failure).record_resolution_latency_ms(ms);
        let timing = AliasTiming {
            alias_name,
            backend_instance: target.scheme.clone(),
            duration_ms: ms,
            outcome: AliasFetchOutcome::Failed,
        };
        return Err((
            anyhow!(
                "secret '{}': no backend instance '{}' is registered — \
                 add it to [backends.{}] in config.toml",
                secret.env_var,
                target.scheme,
                target.scheme
            ),
            timing,
        ));
    };
    let backend: &dyn Backend = backend;
    span.record_backend_type(BackendType::from_runtime_str(backend.backend_type()));

    // v0.18 Phase 4 — `secretenv.backend.probe` schema-reserved span
    // (Arch-M6 subset). Sized as a sibling of `secretenv.backend.fetch`
    // wrapping the same `backend.get` call (per Arch-M1 deferred to
    // v0.20, span topology stays flat — the parent-child intent in
    // spec §4.1 surfaces by name only in v0.18). The probe captures
    // the connectivity-and-permission outcome; the fetch span
    // captures the value-fetch outcome. Both currently share the
    // same get() invocation; future cycles may split them when a
    // dedicated `Backend::probe` trait method materialises.
    //
    // Child `secretenv.backend.fetch` span scopes the actual
    // backend.get call. Closed via Drop at end-of-scope (before the
    // outer resolution span's outcome is set).
    let op_label = format!("{}::get (secret '{}')", target.scheme, secret.env_var);
    let fetch_started = std::time::Instant::now();
    let fetch_result = {
        let (mut probe_span, _probe_guard) = SecretEnvSpan::start("secretenv.backend.probe");
        probe_span
            .record_backend_type(BackendType::from_runtime_str(backend.backend_type()))
            .record_backend_instance(&target.scheme)
            .record_backend_probe_level(BackendProbeLevel::Connectivity)
            .record_backend_fetch_attempt(1);

        let (mut fetch_span, _fetch_guard) = SecretEnvSpan::start("secretenv.backend.fetch");
        fetch_span
            .record_alias_name(&alias_name)
            .record_backend_type(BackendType::from_runtime_str(backend.backend_type()))
            .record_backend_instance(&target.scheme);
        let r = crate::with_timeout(backend.timeout(), &op_label, backend.get(target)).await;
        let fetch_ms = u64::try_from(fetch_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        fetch_span.record_backend_fetch_duration_ms(fetch_ms);
        let probe_outcome = if r.is_ok() {
            fetch_span.record_backend_fetch_outcome(FetchOutcome::Ok);
            BackendProbeOutcome::Success
        } else {
            fetch_span.record_backend_fetch_outcome(FetchOutcome::Error);
            BackendProbeOutcome::Error
        };
        probe_span.record_backend_probe_outcome(probe_outcome);
        r
    };

    let fetch_ms = u64::try_from(fetch_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let backend_type_str = backend.backend_type();

    match fetch_result {
        Ok(value) => {
            let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            span.record_resolution_outcome(ResolutionOutcome::Success)
                .record_resolution_latency_ms(ms);
            // v0.17 Phase 8b — emit the spec'd histogram points so
            // the metrics instruments declared in Phase 4 aren't dead.
            secretenv_telemetry::metrics::record_backend_fetch_duration(
                fetch_ms,
                backend_type_str,
                &target.scheme,
                FetchOutcome::Ok,
            );
            let timing = AliasTiming {
                alias_name: alias_name.clone(),
                backend_instance: target.scheme.clone(),
                duration_ms: ms,
                outcome: AliasFetchOutcome::Ok,
            };
            Ok((
                Some(EnvEntry { key: secret.env_var.clone(), alias_name: Some(alias_name), value }),
                timing,
            ))
        }
        Err(e) => {
            let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            span.record_resolution_outcome(ResolutionOutcome::Failure)
                .record_resolution_latency_ms(ms);
            secretenv_telemetry::metrics::record_backend_fetch_duration(
                fetch_ms,
                backend_type_str,
                &target.scheme,
                FetchOutcome::Error,
            );
            Err((
                e.context(format!(
                    "secret '{}': failed to fetch from '{}'",
                    secret.env_var, target.raw
                )),
                AliasTiming {
                    alias_name,
                    backend_instance: target.scheme.clone(),
                    duration_ms: ms,
                    outcome: AliasFetchOutcome::Failed,
                },
            ))
        }
    }
}

/// Combine N>1 fetch failures into a single anyhow error whose
/// `{:#}` rendering lists every failure on its own line. For N=1
/// returns the original error unwrapped so single-failure messages
/// don't get decorated with a misleading "2 aliases failed" header.
///
/// # Preconditions (v0.14.x code-hygiene)
///
/// `errors` must be non-empty. The sole caller in [`build_env`] only
/// invokes `aggregate_errors` inside a `!errors.is_empty()` guard, so
/// the empty-input branch is unreachable in practice. Passing an
/// empty `Vec` panics on `swap_remove(0)`; this is a programming
/// error, not a recoverable runtime condition — surface it as a
/// panic rather than a silent `Ok(())`-style fallthrough that would
/// hide the missing guard at a future call site.
fn aggregate_errors(mut errors: Vec<anyhow::Error>) -> anyhow::Error {
    if errors.len() == 1 {
        // Single-failure path: preserve the original error chain
        // intact so operators see the same shape as v0.1 when only
        // one alias was broken. `swap_remove(0)` is bounds-safe by
        // the just-checked len.
        return errors.swap_remove(0);
    }
    let count = errors.len();
    let body = errors.iter().map(|e| format!("  - {e:#}")).collect::<Vec<_>>().join("\n");
    anyhow!("{count} secrets failed to resolve:\n{body}")
}

/// SecretEnv-reserved env vars scrubbed from the child process
/// environment before `exec`/`spawn`. These carry CLI-layer
/// configuration (registry selection, config path) and should not leak
/// their provenance into whatever command the user ran.
///
/// **v0.14.x `DiD` chip L5.** This list is the explicit denylist for the
/// CI-grep regression gate; the actual runtime scrub uses the
/// `SECRETENV_*` *prefix wildcard* via [`scrub_secretenv_env`] so any
/// future `SECRETENV_TOKEN` / `SECRETENV_OTLP_…` added after this list
/// drifts is still scrubbed. The CI gate at
/// `scripts/check_secretenv_env_consts.sh` keeps the explicit list and
/// the prefix scrub honest.
const RESERVED_ENV_VARS: &[&str] = &["SECRETENV_REGISTRY", "SECRETENV_CONFIG"];

/// Remove every `SECRETENV_*` env var from `cmd`'s child environment
/// before `spawn`/`exec`. Prefix scrub closes the regression window
/// where a new `SECRETENV_TOKEN`-style const is added to the codebase
/// without being added to [`RESERVED_ENV_VARS`].
///
/// The std `Command` API has no direct "remove by prefix"; we walk
/// `std::env::vars_os` once and call `env_remove` for each matching
/// key. The cost is negligible (env size is small) and the scrub
/// always runs in the parent process's pre-exec window.
/// Inject every resolved [`EnvEntry`] into the child environment via
/// `env_set(&key, &value)`. Centralised so the three spawn paths
/// (tokio pipe-redact, unix `exec()`, non-unix `spawn()`) all use
/// the same iteration shape — v0.14.x code-hygiene chip.
fn inject_env_entries<F: FnMut(&str, &str)>(env: &[EnvEntry], mut env_set: F) {
    for entry in env {
        env_set(&entry.key, entry.value.as_str_internal());
    }
}

fn scrub_secretenv_env<F: FnMut(&std::ffi::OsStr)>(mut env_remove: F) {
    for (key, _val) in std::env::vars_os() {
        if let Some(s) = key.to_str() {
            if s.starts_with("SECRETENV_") {
                env_remove(&key);
            }
        }
    }
    // Explicit denylist as belt-and-braces: catches names that
    // somehow exist in the child env without being in the parent's
    // `vars_os()` snapshot (e.g. set via clap layer before this loop
    // runs in a future code path). Idempotent with the prefix scrub.
    for reserved in RESERVED_ENV_VARS {
        env_remove(std::ffi::OsStr::new(reserved));
    }
}

#[cfg(unix)]
fn exec_with_env(command: &[String], env: &[EnvEntry]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let program = &command[0];
    let args = &command[1..];
    let mut cmd = Command::new(program);
    cmd.args(args);
    // v0.18 Phase 4 — `secretenv.exec.prepare` schema-reserved span
    // (Arch-M6 subset). Wraps the env-block assembly between the
    // post-fetch `Vec<EnvEntry>` and the actual exec call. Span ends
    // (via _guard drop at end of scope) BEFORE flush_before_exec so
    // the span itself is flushed to OTel before execve replaces the
    // process. Sibling of `secretenv.exec.flush` (deferred to v0.20
    // per Arch-M6 split — requires `pre_exec` hook integration).
    {
        let (mut prepare_span, _prepare_guard) =
            secretenv_telemetry::SecretEnvSpan::start("secretenv.exec.prepare");
        prepare_span.record_process_env_var_count(env.len() as u64);
        scrub_secretenv_env(|k| {
            cmd.env_remove(k);
        });
        inject_env_entries(env, |k, v| {
            cmd.env(k, v);
        });
    }
    // SEC-INV-22: flush pending OTel spans before `execve` replaces this
    // process — Drop on the CLI's TelemetryGuard would otherwise never
    // run. Bounded at 1s so a slow collector can't turn `secretenv run`
    // into a latency cliff; on timeout, pending spans drop.
    secretenv_telemetry::flush_before_exec(std::time::Duration::from_secs(1));
    // exec() replaces the current process on success and only returns
    // on failure — so the io::Error it produces is always a real one.
    let err = cmd.exec();
    Err(anyhow!("failed to exec '{program}': {err}"))
}

#[cfg(not(unix))]
fn exec_with_env(command: &[String], env: &[EnvEntry]) -> Result<()> {
    let program = &command[0];
    let args = &command[1..];
    let mut cmd = Command::new(program);
    cmd.args(args);
    // v0.18 Phase 4 — `secretenv.exec.prepare` schema-reserved span
    // (Arch-M6 subset). See the unix branch above for rationale.
    {
        let (mut prepare_span, _prepare_guard) =
            secretenv_telemetry::SecretEnvSpan::start("secretenv.exec.prepare");
        prepare_span.record_process_env_var_count(env.len() as u64);
        scrub_secretenv_env(|k| {
            cmd.env_remove(k);
        });
        inject_env_entries(env, |k, v| {
            cmd.env(k, v);
        });
    }
    let status = cmd.status().with_context(|| format!("failed to spawn '{program}'"))?;
    // std::process::exit skips destructors — flush before exit so the
    // CLI's TelemetryGuard doesn't strand pending spans.
    secretenv_telemetry::flush_before_exec(std::time::Duration::from_secs(1));
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::*;
    use crate::backend::BackendFactory;
    use crate::config::{BackendConfig, Config};
    use crate::status::BackendStatus;
    use crate::uri::BackendUri;

    /// Fake backend that returns canned `get()` values keyed by
    /// URI.path, counts `get()` invocations, and optionally sleeps
    /// (for parallelism-regression tests) or fails on a set of paths
    /// (for multi-error aggregation tests).
    struct FakeValueBackend {
        backend_type: String,
        instance_name: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Vec<String>,
        delay: std::time::Duration,
    }

    #[async_trait]
    impl Backend for FakeValueBackend {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn instance_name(&self) -> &str {
            &self.instance_name
        }
        async fn check(&self) -> BackendStatus {
            BackendStatus::Ok { cli_version: "fake/1.0".into(), identity: "fake".into() }
        }
        async fn check_extensive(&self, _: &BackendUri) -> Result<usize> {
            Ok(0)
        }
        async fn get(&self, uri: &BackendUri) -> Result<Secret<String>> {
            self.get_count.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail_on.iter().any(|p| p == &uri.path) {
                bail!("simulated backend error for path '{}'", uri.path);
            }
            self.values
                .get(&uri.path)
                .cloned()
                .map(Secret::new)
                .ok_or_else(|| anyhow!("no canned value for path '{}'", uri.path))
        }
        async fn set(&self, _: &BackendUri, _: &str) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &BackendUri) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: &BackendUri) -> Result<Vec<(String, String)>> {
            Ok(vec![])
        }
    }

    #[derive(Clone)]
    struct FakeValueFactory {
        backend_type: String,
        values: HashMap<String, String>,
        get_count: Arc<AtomicUsize>,
        fail_on: Vec<String>,
        delay: std::time::Duration,
    }

    impl BackendFactory for FakeValueFactory {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn create(
            &self,
            instance_name: &str,
            _: &HashMap<String, toml::Value>,
        ) -> Result<Box<dyn Backend>> {
            Ok(Box::new(FakeValueBackend {
                backend_type: self.backend_type.clone(),
                instance_name: instance_name.to_owned(),
                values: self.values.clone(),
                get_count: self.get_count.clone(),
                fail_on: self.fail_on.clone(),
                delay: self.delay,
            }))
        }
    }

    fn set_up(
        values: &[(&str, &str)],
        fail_on: Option<&str>,
    ) -> (BackendRegistry, Arc<AtomicUsize>) {
        set_up_full(
            values,
            &fail_on.map_or_else(Vec::new, |p| vec![p.to_owned()]),
            std::time::Duration::ZERO,
        )
    }

    fn set_up_full(
        values: &[(&str, &str)],
        fail_on: &[String],
        delay: std::time::Duration,
    ) -> (BackendRegistry, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut backends = BackendRegistry::new();
        backends.register_factory(Box::new(FakeValueFactory {
            backend_type: "fake".into(),
            values: values.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            get_count: counter.clone(),
            fail_on: fail_on.to_vec(),
            delay,
        }));
        let config = Config {
            backends: std::iter::once((
                "fake".to_owned(),
                BackendConfig { backend_type: "fake".into(), raw_fields: HashMap::new() },
            ))
            .collect(),
            ..Default::default()
        };
        backends.load_from_config(&config).unwrap();
        (backends, counter)
    }

    fn secret_alias(env_var: &str, uri: &str) -> ResolvedSecret {
        let parsed = BackendUri::parse(uri).unwrap();
        ResolvedSecret {
            env_var: env_var.to_owned(),
            // Tests don't exercise cascade-source surfacing; use the
            // target URI as the source placeholder.
            source: ResolvedSource::Uri {
                target: parsed.clone(),
                source: parsed,
                alias_name: format!("test_{}", env_var.to_lowercase()),
            },
        }
    }

    fn secret_default(env_var: &str, value: &str) -> ResolvedSecret {
        ResolvedSecret {
            env_var: env_var.to_owned(),
            source: ResolvedSource::Default(value.to_owned()),
        }
    }

    // ---- build_env happy path ----

    #[tokio::test]
    async fn build_env_fetches_uris_and_passes_defaults_through() {
        let (backends, count) =
            set_up(&[("/prod/stripe", "sk_live_123"), ("/prod/db", "postgres://x")], None);
        let resolved = vec![
            secret_alias("STRIPE", "fake:///prod/stripe"),
            secret_default("LOG_LEVEL", "info"),
            secret_alias("DATABASE_URL", "fake:///prod/db"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();

        assert_eq!(env.len(), 3);
        assert_eq!(env[0].key, "STRIPE");
        assert_eq!(env[0].value(), "sk_live_123");
        assert_eq!(env[1].key, "LOG_LEVEL");
        assert_eq!(env[1].value(), "info");
        assert_eq!(env[2].key, "DATABASE_URL");
        assert_eq!(env[2].value(), "postgres://x");
        assert_eq!(count.load(Ordering::SeqCst), 2, "fetched both Uris, default skipped");
    }

    // ---- dry-run never calls Backend::get ----

    #[tokio::test]
    async fn dry_run_skips_backend_get_entirely() {
        let (backends, count) = set_up(&[("/prod/stripe", "sk_live_123")], None);
        let resolved = vec![
            secret_alias("STRIPE", "fake:///prod/stripe"),
            secret_default("LOG_LEVEL", "info"),
        ];
        let env = build_env(&resolved, &backends, true, false).await.unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 0, "dry-run must not fetch");
        // Env still includes Default entries (they're non-secret manifest data).
        let default = env.iter().find(|e| e.key == "LOG_LEVEL").unwrap();
        assert_eq!(default.value(), "info");
        // Uri entries are omitted in dry-run mode.
        assert!(env.iter().all(|e| e.key != "STRIPE"));
    }

    // ---- Missing backend instance ----

    #[tokio::test]
    async fn missing_backend_instance_errors_with_env_var_name() {
        let (backends, _) = set_up(&[("/x", "v")], None);
        let resolved = vec![secret_alias("KEY", "nonexistent:///x")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("KEY"), "error names env-var: {msg}");
        assert!(msg.contains("nonexistent"), "error names missing instance: {msg}");
    }

    // ---- Backend fetch error propagates ----

    #[tokio::test]
    async fn backend_get_error_propagates_with_context() {
        let (backends, _) = set_up(&[], Some("/locked"));
        let resolved = vec![secret_alias("LOCKED", "fake:///locked")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("LOCKED"), "env-var in context: {msg}");
        assert!(msg.contains("fake:///locked"), "uri in context: {msg}");
        assert!(msg.contains("simulated backend error"), "root cause preserved: {msg}");
    }

    // ---- Parallel fetch + multi-error aggregation (Phase 2) ----

    /// Parallelism regression: 5 aliases, each with a 50 ms simulated
    /// backend round-trip. Serial execution would take ≥ 250 ms; a
    /// healthy concurrent path finishes in close to 50 ms. We assert
    /// "well under the serial bound" rather than a tight wall-time —
    /// CI machines are noisy and a flaky timing assertion is worse
    /// than a loose one.
    #[tokio::test]
    async fn build_env_fetches_aliased_secrets_concurrently() {
        let values: Vec<(&str, &str)> = (0..5)
            .map(|i| match i {
                0 => ("/a", "va"),
                1 => ("/b", "vb"),
                2 => ("/c", "vc"),
                3 => ("/d", "vd"),
                _ => ("/e", "ve"),
            })
            .collect();
        let (backends, count) = set_up_full(&values, &[], std::time::Duration::from_millis(50));
        let resolved = vec![
            secret_alias("A", "fake:///a"),
            secret_alias("B", "fake:///b"),
            secret_alias("C", "fake:///c"),
            secret_alias("D", "fake:///d"),
            secret_alias("E", "fake:///e"),
        ];

        let start = std::time::Instant::now();
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(env.len(), 5, "every alias returned");
        assert_eq!(count.load(Ordering::SeqCst), 5, "every alias fetched exactly once");
        // Serial lower bound would be 5 × 50 = 250 ms. Anything under
        // 200 ms proves fetches overlapped. Generous upper bound to
        // avoid CI flakes.
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "expected concurrent fetch (< 200 ms), elapsed = {elapsed:?}"
        );
    }

    /// Declaration order must be preserved even when backends return
    /// out of dispatch order (which they can in concurrent mode).
    #[tokio::test]
    async fn build_env_preserves_declaration_order_with_parallel_fetch() {
        let (backends, _) =
            set_up_full(&[("/a", "1"), ("/b", "2"), ("/c", "3")], &[], std::time::Duration::ZERO);
        let resolved = vec![
            secret_alias("FIRST", "fake:///a"),
            secret_default("MIDDLE", "middle"),
            secret_alias("THIRD", "fake:///b"),
            secret_alias("LAST", "fake:///c"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let keys: Vec<_> = env.iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, vec!["FIRST", "MIDDLE", "THIRD", "LAST"]);
    }

    /// When multiple aliases fail, the returned error enumerates
    /// **every** failure in one message — not just the first one
    /// the concurrent dispatch happened to complete.
    #[tokio::test]
    async fn build_env_aggregates_all_fetch_errors() {
        let (backends, count) = set_up_full(
            &[("/ok", "good")],
            &["/bad1".to_owned(), "/bad2".to_owned()],
            std::time::Duration::ZERO,
        );
        let resolved = vec![
            secret_alias("ALPHA", "fake:///bad1"),
            secret_alias("BETA", "fake:///ok"),
            secret_alias("GAMMA", "fake:///bad2"),
        ];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error on two failing aliases");
        };
        let msg = format!("{err:#}");

        assert!(msg.contains("ALPHA"), "error names first failing env-var: {msg}");
        assert!(msg.contains("GAMMA"), "error names second failing env-var: {msg}");
        assert!(msg.contains("fake:///bad1"), "error includes first bad URI: {msg}");
        assert!(msg.contains("fake:///bad2"), "error includes second bad URI: {msg}");
        assert!(msg.contains("2 secrets failed"), "header surfaces the count: {msg}");
        // GAMMA-after-ALPHA preserves `resolved`'s declaration order
        // in the aggregated message (regardless of completion order).
        assert!(
            msg.find("ALPHA").unwrap() < msg.find("GAMMA").unwrap(),
            "aggregation preserves declaration order: {msg}"
        );
        // Every alias was dispatched — aggregation does not short-circuit.
        assert_eq!(count.load(Ordering::SeqCst), 3, "all 3 alias fetches dispatched");
    }

    /// Single failure: the aggregation path should NOT wrap the error
    /// in a "1 secrets failed:" header. Preserves v0.1-style single-
    /// failure error shape for operators with one broken alias.
    #[tokio::test]
    async fn build_env_single_failure_passes_error_through_unwrapped() {
        let (backends, _) = set_up_full(&[], &["/only".to_owned()], std::time::Duration::ZERO);
        let resolved = vec![secret_alias("ONLY", "fake:///only")];
        let Err(err) = build_env(&resolved, &backends, false, false).await else {
            panic!("expected build_env to error");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("ONLY"), "env-var present: {msg}");
        assert!(msg.contains("fake:///only"), "uri present: {msg}");
        assert!(msg.contains("simulated backend error"), "root cause preserved: {msg}");
        assert!(!msg.contains("secrets failed to resolve"), "no aggregation header: {msg}");
    }

    // ---- run() command-level errors ----

    #[tokio::test]
    async fn run_errors_when_command_is_empty() {
        let (backends, _) = set_up(&[], None);
        let resolved: Vec<ResolvedSecret> = vec![];
        let Err(err) = run(&resolved, &backends, &[], false, false).await else {
            panic!("expected run to error on empty command");
        };
        assert!(format!("{err:#}").contains("no command"));
    }

    #[tokio::test]
    async fn run_errors_when_exec_target_is_missing() {
        // Use a path guaranteed not to exist. On exec-failure, run()
        // returns; it doesn't replace our test process.
        let (backends, _) = set_up(&[], None);
        let resolved: Vec<ResolvedSecret> = vec![];
        let bogus = "/definitely/not/a/real/binary-abc123".to_owned();
        let Err(err) = run(&resolved, &backends, std::slice::from_ref(&bogus), false, false).await
        else {
            panic!("expected run to error on bogus program");
        };
        let msg = format!("{err:#}");
        assert!(msg.contains(&bogus), "error names bogus program: {msg}");
    }

    // ---- Order preservation ----

    #[tokio::test]
    async fn build_env_preserves_declaration_order() {
        let (backends, _) = set_up(&[("/a", "1"), ("/b", "2"), ("/c", "3")], None);
        let resolved = vec![
            secret_alias("FIRST", "fake:///a"),
            secret_alias("SECOND", "fake:///b"),
            secret_alias("THIRD", "fake:///c"),
        ];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        let keys: Vec<_> = env.iter().map(|e| e.key.clone()).collect();
        assert_eq!(keys, vec!["FIRST", "SECOND", "THIRD"]);
    }

    // ---- Secret<String> smoke test ----

    #[tokio::test]
    async fn env_entries_can_be_consumed_as_str() {
        let (backends, _) = set_up(&[("/k", "the-secret-value")], None);
        let resolved = vec![secret_alias("K", "fake:///k")];
        let env = build_env(&resolved, &backends, false, false).await.unwrap();
        // Sanity: `value()` returns `&str` without exposing the inner
        // `Secret<String>` newtype; consumers (the exec path) only
        // ever borrow.
        let s: &str = env[0].value();
        assert_eq!(s, "the-secret-value");
    }

    // ---- Reserved env-var scrub (CV-7 / SEC-1) ----

    #[test]
    fn reserved_env_vars_contains_registry_and_config() {
        // Ensures any future SECRETENV_* var intended to pass CLI config
        // into the process is added here before it leaks to child procs.
        assert!(RESERVED_ENV_VARS.contains(&"SECRETENV_REGISTRY"));
        assert!(RESERVED_ENV_VARS.contains(&"SECRETENV_CONFIG"));
    }
}
