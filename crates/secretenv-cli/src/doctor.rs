// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `secretenv doctor` — health checks for every configured backend.
//!
//! - **Default (Level 1+2):** is the native CLI installed and is the
//!   backend authenticated? Renders a human tree; `--json` emits a
//!   machine-readable shape for CI pre-flight gating.
//! - **`--fix`:** when a backend reports `NotAuthenticated`, run the
//!   canonical remediation CLI interactively (`aws sso login`, `op
//!   signin`, `gcloud auth login`, `az login`, `vault login`), then
//!   re-run the health check and render the post-remediation report.
//! - **`--extensive` (Level 3):** for each backend that's `Ok`, read
//!   every registry source it serves and count the aliases found,
//!   surfacing permission scope ("can read" vs "denied").
//!
//! Runs all backend `check()` calls concurrently via
//! `futures::future::join_all`. Depth probes also run concurrently per
//! backend instance.
//!
//! Exit semantics: if any backend reports a non-`Ok` status (after
//! remediation, when `--fix` is set), the command returns `Err` so the
//! process exits non-zero. Depth-probe failures are reported but do
//! not change the exit code on their own — a non-`Ok` Level 2 status
//! always dominates.
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::process::Stdio;

use anyhow::{anyhow, Result};
use futures::future::join_all;
use secretenv_core::{
    with_timeout, Backend, BackendRegistry, BackendStatus, BackendUri, Config,
    DEFAULT_CHECK_TIMEOUT,
};
use serde::Serialize;

/// Knobs for [`run_doctor`]. Kept as a struct so future flag additions
/// don't grow the function signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct DoctorOpts {
    pub json: bool,
    pub fix: bool,
    pub extensive: bool,
}

/// Machine-readable shape for `--json`.
///
/// Wraps [`secretenv_core::BackendStatus`] to keep `serde` out of
/// core's public API. Kept internal to the CLI.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DoctorStatus {
    Ok { cli_version: String, identity: String },
    NotAuthenticated { hint: String },
    CliMissing { cli_name: String, install_hint: String },
    Error { message: String },
}

impl From<BackendStatus> for DoctorStatus {
    fn from(s: BackendStatus) -> Self {
        match s {
            BackendStatus::Ok { cli_version, identity } => Self::Ok { cli_version, identity },
            BackendStatus::NotAuthenticated { hint } => Self::NotAuthenticated { hint },
            BackendStatus::CliMissing { cli_name, install_hint } => {
                Self::CliMissing { cli_name, install_hint }
            }
            BackendStatus::Error { message } => Self::Error { message },
        }
    }
}

impl DoctorStatus {
    const fn variant_key(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::NotAuthenticated { .. } => "not_authenticated",
            Self::CliMissing { .. } => "cli_missing",
            Self::Error { .. } => "error",
        }
    }
}

/// One Level 3 depth-probe result for a single registry source URI
/// served by a backend instance. Populated only when `--extensive` is set.
#[derive(Debug, Clone, Serialize)]
struct DepthProbe {
    uri: String,
    #[serde(flatten)]
    outcome: DepthOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "depth_status", rename_all = "snake_case")]
enum DepthOutcome {
    /// `list()` succeeded; backend returned this many entries.
    Read { entry_count: usize },
    /// `list()` failed — typically a permissions issue or missing
    /// resource. Original error message preserved.
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
struct DoctorEntry {
    instance_name: String,
    backend_type: String,
    #[serde(flatten)]
    status: DoctorStatus,
    /// Empty unless `--extensive` ran AND this backend was `Ok`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depth: Vec<DepthProbe>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorSummary {
    total: usize,
    ok: usize,
    not_authenticated: usize,
    cli_missing: usize,
    error: usize,
}

impl DoctorSummary {
    fn from_entries(entries: &[DoctorEntry]) -> Self {
        let mut s =
            Self { total: entries.len(), ok: 0, not_authenticated: 0, cli_missing: 0, error: 0 };
        for entry in entries {
            match entry.status.variant_key() {
                "ok" => s.ok += 1,
                "not_authenticated" => s.not_authenticated += 1,
                "cli_missing" => s.cli_missing += 1,
                "error" => s.error += 1,
                _ => {}
            }
        }
        s
    }

    const fn all_ok(&self) -> bool {
        self.ok == self.total
    }
}

/// Per-registry-source reachability report for the `Registries` section.
///
/// "Reachable" means the backend instance referenced by the source's
/// scheme has a passing Level 2 check — not that the URI itself was
/// fetched. The heavier per-URI probe lives in `--extensive` (Level 3,
/// rendered alongside the backend it targets).
#[derive(Debug, Clone, Serialize)]
struct RegistrySourceReport {
    uri: String,
    /// Parse failure or unregistered scheme produces a source-local
    /// `Error` variant so the cascade always renders a line per source.
    #[serde(flatten)]
    status: DoctorStatus,
}

#[derive(Debug, Clone, Serialize)]
struct RegistryReport {
    name: String,
    sources: Vec<RegistrySourceReport>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    backends: Vec<DoctorEntry>,
    /// Per-registry cascade reachability. Empty when no `[registries.*]`
    /// blocks are configured (e.g. a `--registry <uri>`-only setup).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    registries: Vec<RegistryReport>,
    summary: DoctorSummary,
    /// Set when `--fix` ran. Records each remediation attempt — the
    /// canonical CLI argv invoked and whether the child process
    /// reported success. The post-remediation re-check populates the
    /// `backends` array; this field is the audit trail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fix_actions: Vec<FixAction>,
}

#[derive(Debug, Clone, Serialize)]
struct FixAction {
    instance_name: String,
    backend_type: String,
    command: Vec<String>,
    success: bool,
    /// Populated only when the spawn itself failed (the binary was
    /// missing, etc.) — distinct from a child-exit-non-zero failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spawn_error: Option<String>,
}

/// Run `check()` on every registered backend concurrently, build a
/// per-registry cascade reachability report, and print the combined
/// output.
///
/// Behavior depends on `opts`:
/// - `opts.fix`: each `NotAuthenticated` backend triggers an
///   interactive remediation child process; the report rendered is
///   the post-remediation state.
/// - `opts.extensive`: each `Ok` backend gets per-source depth probes
///   rendered alongside its tree node and serialized into the
///   `backends[*].depth` JSON array.
///
/// Exit semantics: the non-zero exit is driven by the post-`--fix`
/// `Backends` summary only. Depth-probe failures and registry-source
/// errors are informational. Backend-level failures already propagate
/// into every registry source that uses them, so duplicating the
/// signal would double-count.
///
/// # Errors
/// Returns `Err` — and thus a non-zero exit code — if any backend
/// reports a non-`Ok` status (after remediation, when `--fix` is on),
/// even though the human report is still printed normally. This makes
/// `secretenv doctor` usable as a CI pre-flight gate.
pub async fn run_doctor(
    config: &Config,
    backends: &BackendRegistry,
    opts: DoctorOpts,
) -> Result<()> {
    let list: Vec<&dyn Backend> = backends.all().collect();

    // ---- Pass 1: initial Level 1+2 check across all backends ----
    let mut statuses = check_all_backends(&list).await;

    // ---- Optional --fix pass ----
    let mut fix_actions: Vec<FixAction> = Vec::new();
    if opts.fix {
        let needs_remediation: Vec<usize> = statuses
            .iter()
            .enumerate()
            .filter_map(|(i, s)| matches!(s, BackendStatus::NotAuthenticated { .. }).then_some(i))
            .collect();
        for i in needs_remediation {
            let backend = list[i];
            if let Some(action) = remediate(backend).await {
                fix_actions.push(action);
            }
        }
        // Re-check only if we actually attempted at least one remediation
        // — otherwise the second pass is just network for nothing.
        if !fix_actions.is_empty() {
            statuses = check_all_backends(&list).await;
        }
    }

    // ---- Build entries (post-fix view) ----
    // Dedupe-by-scheme lookup so a registry source referencing an
    // already-checked backend instance reuses its status instead of
    // re-running `check()`. Keyed by `instance_name` (the scheme).
    let mut statuses_by_instance: HashMap<String, DoctorStatus> = HashMap::new();
    let mut entries: Vec<DoctorEntry> = Vec::with_capacity(list.len());
    for (b, s) in list.iter().zip(statuses) {
        let doctor_status: DoctorStatus = s.into();
        statuses_by_instance.insert(b.instance_name().to_owned(), doctor_status.clone());
        entries.push(DoctorEntry {
            instance_name: b.instance_name().to_owned(),
            backend_type: b.backend_type().to_owned(),
            status: doctor_status,
            depth: Vec::new(),
        });
    }
    entries.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));

    // ---- Per-registry cascade reachability ----
    let mut registry_names: Vec<&String> = config.registries.keys().collect();
    registry_names.sort();
    let mut registries: Vec<RegistryReport> = Vec::with_capacity(registry_names.len());
    for name in registry_names {
        let cfg = &config.registries[name];
        let mut sources: Vec<RegistrySourceReport> = Vec::with_capacity(cfg.sources.len());
        for raw in &cfg.sources {
            let status = source_status(raw, &statuses_by_instance);
            sources.push(RegistrySourceReport { uri: raw.clone(), status });
        }
        registries.push(RegistryReport { name: name.clone(), sources });
    }

    // ---- Optional --extensive depth probes ----
    if opts.extensive {
        run_depth_probes(&list, &mut entries, &registries).await;
    }

    let summary = DoctorSummary::from_entries(&entries);
    let report = DoctorReport { backends: entries, registries, summary, fix_actions };

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_human(&report));
    }

    if report.summary.all_ok() {
        Ok(())
    } else {
        Err(anyhow!(
            "{} of {} backend(s) are not ready — see the report above",
            report.summary.total - report.summary.ok,
            report.summary.total
        ))
    }
}

/// Run `check()` against every backend concurrently. Each call is
/// wrapped in its own timeout so one wedged backend cannot hang the
/// whole doctor run; a timeout surfaces as a synthesized
/// `BackendStatus::Error` so the JSON shape stays uniform.
async fn check_all_backends(list: &[&dyn Backend]) -> Vec<BackendStatus> {
    join_all(list.iter().map(|b| async {
        let label = format!("{}::check", b.instance_name());
        match with_timeout(DEFAULT_CHECK_TIMEOUT, &label, async { Ok(b.check().await) }).await {
            Ok(status) => status,
            Err(err) => BackendStatus::Error { message: err.to_string() },
        }
    }))
    .await
}

/// The canonical interactive remediation argv for a backend type. The
/// remediation IS always the native CLI's auth command — no
/// abstraction; just a lookup. `local` (no auth) and any unknown
/// backend type return `None`.
fn remediation_argv(backend_type: &str) -> Option<&'static [&'static str]> {
    match backend_type {
        "aws-ssm" | "aws-secrets" => Some(&["aws", "sso", "login"]),
        "1password" => Some(&["op", "signin"]),
        "gcp" => Some(&["gcloud", "auth", "login"]),
        "azure" => Some(&["az", "login"]),
        "vault" => Some(&["vault", "login"]),
        _ => None,
    }
}

/// Spawn the remediation CLI with inherited stdio so the user can
/// complete an interactive auth flow (SSO browser handoff, MFA prompt,
/// password entry). Returns `Some(FixAction)` describing the attempt;
/// `None` only when no remediation is known for this backend type.
async fn remediate(backend: &dyn Backend) -> Option<FixAction> {
    let argv = remediation_argv(backend.backend_type())?;
    let command: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    eprintln!(
        "→ remediating '{}' [{}]: {}",
        backend.instance_name(),
        backend.backend_type(),
        command.join(" ")
    );
    let mut cmd = tokio::process::Command::new(argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    match cmd.status().await {
        Ok(status) => Some(FixAction {
            instance_name: backend.instance_name().to_owned(),
            backend_type: backend.backend_type().to_owned(),
            command,
            success: status.success(),
            spawn_error: None,
        }),
        Err(err) => {
            // Most likely cause: the remediation CLI itself is missing
            // from PATH (the same problem `CliMissing` flags for the
            // primary check). Surface it the same way.
            let msg = format!("failed to spawn '{}': {err}", argv[0]);
            eprintln!("  ✗ {msg}");
            Some(FixAction {
                instance_name: backend.instance_name().to_owned(),
                backend_type: backend.backend_type().to_owned(),
                command,
                success: false,
                spawn_error: Some(msg),
            })
        }
    }
}

/// Per-`Ok`-backend Level 3 probes. For each backend that's `Ok`, find
/// every registry source URI in any `[registries.*]` block whose scheme
/// matches the backend's `instance_name`, then run `check_extensive`
/// against each one. Probes for one backend run sequentially against
/// that backend (most have only one source); the outer loop across
/// backends runs sequentially too — `check_extensive` is itself a CLI
/// shell-out per source, so the headline parallelism that matters
/// (multiple backends checking concurrently) was already captured by
/// `check_all_backends` above.
async fn run_depth_probes(
    list: &[&dyn Backend],
    entries: &mut [DoctorEntry],
    registries: &[RegistryReport],
) {
    for backend in list {
        let Some(entry_idx) =
            entries.iter().position(|e| e.instance_name == backend.instance_name())
        else {
            continue;
        };
        if !matches!(entries[entry_idx].status, DoctorStatus::Ok { .. }) {
            continue;
        }
        // Collect every source URI across every registry that targets
        // this backend instance. Dedupe — a config that lists the same
        // URI in two cascades would otherwise probe it twice.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for reg in registries {
            for src in &reg.sources {
                if let Ok(parsed) = BackendUri::parse(&src.uri) {
                    if parsed.scheme == backend.instance_name() && seen.insert(src.uri.clone()) {
                        let outcome = match backend.check_extensive(&parsed).await {
                            Ok(count) => DepthOutcome::Read { entry_count: count },
                            Err(err) => DepthOutcome::Failed { error: format!("{err:#}") },
                        };
                        entries[entry_idx].depth.push(DepthProbe { uri: src.uri.clone(), outcome });
                    }
                }
            }
        }
    }
}

/// Map a raw `sources = [...]` entry to its reachability status:
///
/// - Parse error → source-local `Error`.
/// - Scheme with no registered backend → source-local `Error` naming
///   the instance and pointing at config.toml.
/// - Everything else → reuse the already-computed backend status.
fn source_status(raw: &str, statuses_by_instance: &HashMap<String, DoctorStatus>) -> DoctorStatus {
    match BackendUri::parse(raw) {
        Ok(uri) => {
            statuses_by_instance.get(&uri.scheme).cloned().unwrap_or_else(|| DoctorStatus::Error {
                message: format!(
                    "backend instance '{}' is not configured in config.toml",
                    uri.scheme
                ),
            })
        }
        Err(e) => DoctorStatus::Error { message: format!("source '{raw}' failed to parse: {e}") },
    }
}

// `writeln!`/`write!` into a `String` is infallible — `String`'s `fmt::Write`
// impl never returns `Err`. The `.unwrap()` calls below can never panic at
// runtime, so the workspace `clippy::unwrap_used` warning is suppressed on
// these functions specifically.
#[allow(clippy::unwrap_used)]
fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    writeln!(out, "secretenv doctor").unwrap();
    writeln!(out, "================\n").unwrap();

    if !report.fix_actions.is_empty() {
        writeln!(out, "Remediation actions ({})", report.fix_actions.len()).unwrap();
        for action in &report.fix_actions {
            let tick = if action.success { "✓" } else { "✗" };
            writeln!(
                out,
                "  {tick} {} [{}] — {}",
                action.instance_name,
                action.backend_type,
                action.command.join(" ")
            )
            .unwrap();
            if let Some(err) = &action.spawn_error {
                writeln!(out, "      → {err}").unwrap();
            }
        }
        writeln!(out).unwrap();
    }

    if report.backends.is_empty() {
        writeln!(out, "No backends configured in config.toml.").unwrap();
        return out;
    }

    writeln!(out, "Backends ({} configured)", report.summary.total).unwrap();

    let last = report.backends.len() - 1;
    for (i, entry) in report.backends.iter().enumerate() {
        let branch = if i == last { "└──" } else { "├──" };
        let indent = if i == last { "    " } else { "│   " };
        writeln!(out, "{branch} {} [{}]", entry.instance_name, entry.backend_type).unwrap();
        render_status_block(&mut out, indent, &entry.status);
        if !entry.depth.is_empty() {
            render_depth_block(&mut out, indent, &entry.depth);
        }
    }

    if !report.registries.is_empty() {
        writeln!(out).unwrap();
        render_registries(&mut out, &report.registries);
    }

    writeln!(out).unwrap();
    write!(out, "Summary: {}/{} OK", report.summary.ok, report.summary.total).unwrap();
    if report.summary.not_authenticated > 0 {
        write!(out, ", {} not authenticated", report.summary.not_authenticated).unwrap();
    }
    if report.summary.cli_missing > 0 {
        write!(out, ", {} missing CLI", report.summary.cli_missing).unwrap();
    }
    if report.summary.error > 0 {
        write!(out, ", {} error", report.summary.error).unwrap();
    }
    writeln!(out).unwrap();

    out
}

#[allow(clippy::unwrap_used)]
fn render_registries(out: &mut String, registries: &[RegistryReport]) {
    writeln!(out, "Registries ({} configured)", registries.len()).unwrap();
    for reg in registries {
        writeln!(out, "  {}", reg.name).unwrap();
        for source in &reg.sources {
            let tick = if matches!(source.status, DoctorStatus::Ok { .. }) { "✓" } else { "✗" };
            let suffix = source_status_suffix(&source.status);
            writeln!(out, "    {tick} {}   {suffix}", source.uri).unwrap();
            // For non-OK statuses, render a second indented line with
            // the remediation hint if one is available. Keeps the
            // one-line-per-source scan readable for a healthy cascade.
            if let Some(hint) = source_status_hint(&source.status) {
                writeln!(out, "        → {hint}").unwrap();
            }
        }
    }
}

#[allow(clippy::unwrap_used)]
fn render_depth_block(out: &mut String, indent: &str, depth: &[DepthProbe]) {
    writeln!(
        out,
        "{indent}  depth probe ({} {})",
        depth.len(),
        pluralize("source", "sources", depth.len())
    )
    .unwrap();
    for probe in depth {
        match &probe.outcome {
            DepthOutcome::Read { entry_count } => {
                writeln!(
                    out,
                    "{indent}    ✓ {}   {} {} readable",
                    probe.uri,
                    entry_count,
                    pluralize("alias", "aliases", *entry_count)
                )
                .unwrap();
            }
            DepthOutcome::Failed { error } => {
                writeln!(out, "{indent}    ✗ {}   read failed", probe.uri).unwrap();
                writeln!(out, "{indent}        → {error}").unwrap();
            }
        }
    }
}

const fn pluralize(singular: &'static str, plural: &'static str, n: usize) -> &'static str {
    if n == 1 {
        singular
    } else {
        plural
    }
}

/// One-line suffix describing the source's status — appended to the
/// `<tick> <uri>   ` line. For `Ok` status, this is "reachable" (the
/// per-source depth probe in `--extensive` reports counts separately).
/// For failure states, it's a short classification like "not authenticated".
fn source_status_suffix(status: &DoctorStatus) -> String {
    match status {
        DoctorStatus::Ok { .. } => "reachable".to_owned(),
        DoctorStatus::NotAuthenticated { .. } => "backend not authenticated".to_owned(),
        DoctorStatus::CliMissing { cli_name, .. } => format!("backend CLI '{cli_name}' missing"),
        DoctorStatus::Error { .. } => "backend error".to_owned(),
    }
}

/// The actionable fix-it hint for non-OK source statuses. `None` for
/// `Ok` (no remediation needed).
fn source_status_hint(status: &DoctorStatus) -> Option<&str> {
    match status {
        DoctorStatus::Ok { .. } => None,
        DoctorStatus::NotAuthenticated { hint } => Some(hint),
        DoctorStatus::CliMissing { install_hint, .. } => Some(install_hint),
        DoctorStatus::Error { message } => Some(message),
    }
}

#[allow(clippy::unwrap_used)]
fn render_status_block(out: &mut String, indent: &str, status: &DoctorStatus) {
    match status {
        DoctorStatus::Ok { cli_version, identity } => {
            writeln!(out, "{indent}✓ ready").unwrap();
            writeln!(out, "{indent}  cli:      {cli_version}").unwrap();
            writeln!(out, "{indent}  identity: {identity}").unwrap();
        }
        DoctorStatus::NotAuthenticated { hint } => {
            writeln!(out, "{indent}✗ not authenticated").unwrap();
            writeln!(out, "{indent}  {hint}").unwrap();
        }
        DoctorStatus::CliMissing { cli_name, install_hint } => {
            writeln!(out, "{indent}✗ CLI '{cli_name}' not found on PATH").unwrap();
            writeln!(out, "{indent}  install: {install_hint}").unwrap();
        }
        DoctorStatus::Error { message } => {
            writeln!(out, "{indent}✗ error").unwrap();
            writeln!(out, "{indent}  {message}").unwrap();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(instance: &str, ty: &str, status: DoctorStatus) -> DoctorEntry {
        DoctorEntry {
            instance_name: instance.to_owned(),
            backend_type: ty.to_owned(),
            status,
            depth: Vec::new(),
        }
    }

    fn entry_with_depth(
        instance: &str,
        ty: &str,
        status: DoctorStatus,
        depth: Vec<DepthProbe>,
    ) -> DoctorEntry {
        DoctorEntry {
            instance_name: instance.to_owned(),
            backend_type: ty.to_owned(),
            status,
            depth,
        }
    }

    fn report(entries: Vec<DoctorEntry>) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, registries: Vec::new(), summary, fix_actions: Vec::new() }
    }

    fn report_with_registries(
        entries: Vec<DoctorEntry>,
        registries: Vec<RegistryReport>,
    ) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, registries, summary, fix_actions: Vec::new() }
    }

    fn report_with_fix(entries: Vec<DoctorEntry>, fix_actions: Vec<FixAction>) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, registries: Vec::new(), summary, fix_actions }
    }

    // ---- From<BackendStatus> ----

    #[test]
    fn status_from_backend_status_ok() {
        let s: DoctorStatus =
            BackendStatus::Ok { cli_version: "aws-cli/2".into(), identity: "x".into() }.into();
        assert_eq!(s.variant_key(), "ok");
    }

    #[test]
    fn status_from_backend_status_not_authenticated() {
        let s: DoctorStatus = BackendStatus::NotAuthenticated { hint: "op signin".into() }.into();
        assert_eq!(s.variant_key(), "not_authenticated");
    }

    #[test]
    fn status_from_backend_status_cli_missing() {
        let s: DoctorStatus = BackendStatus::CliMissing {
            cli_name: "aws".into(),
            install_hint: "brew install awscli".into(),
        }
        .into();
        assert_eq!(s.variant_key(), "cli_missing");
    }

    #[test]
    fn status_from_backend_status_error() {
        let s: DoctorStatus = BackendStatus::Error { message: "boom".into() }.into();
        assert_eq!(s.variant_key(), "error");
    }

    // ---- Summary counting ----

    #[test]
    fn summary_counts_each_variant() {
        let entries = vec![
            entry("a", "local", DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() }),
            entry("b", "aws-ssm", DoctorStatus::NotAuthenticated { hint: "h".into() }),
            entry(
                "c",
                "op",
                DoctorStatus::CliMissing { cli_name: "op".into(), install_hint: "hint".into() },
            ),
            entry("d", "local", DoctorStatus::Error { message: "m".into() }),
            entry("e", "local", DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() }),
        ];
        let s = DoctorSummary::from_entries(&entries);
        assert_eq!(s.total, 5);
        assert_eq!(s.ok, 2);
        assert_eq!(s.not_authenticated, 1);
        assert_eq!(s.cli_missing, 1);
        assert_eq!(s.error, 1);
        assert!(!s.all_ok());
    }

    #[test]
    fn summary_all_ok_when_every_backend_ok() {
        let entries = vec![
            entry("a", "local", DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() }),
            entry("b", "local", DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() }),
        ];
        let s = DoctorSummary::from_entries(&entries);
        assert!(s.all_ok());
    }

    // ---- Human renderer ----

    #[test]
    fn render_human_includes_tree_and_ticks() {
        let r = report(vec![
            entry(
                "local",
                "local",
                DoctorStatus::Ok { cli_version: "local".into(), identity: "filesystem".into() },
            ),
            entry(
                "aws-ssm-prod",
                "aws-ssm",
                DoctorStatus::NotAuthenticated { hint: "aws sso login".into() },
            ),
        ]);
        let out = render_human(&r);
        assert!(out.contains("Backends (2 configured)"));
        assert!(out.contains("├──"));
        assert!(out.contains("└──"));
        assert!(out.contains("✓ ready"));
        assert!(out.contains("✗ not authenticated"));
        assert!(out.contains("aws sso login"));
        assert!(out.contains("Summary: 1/2 OK, 1 not authenticated"));
    }

    #[test]
    fn render_human_reports_no_backends() {
        let r = report(vec![]);
        let out = render_human(&r);
        assert!(out.contains("No backends configured"));
    }

    #[test]
    fn render_human_cli_missing_shows_install_hint() {
        let r = report(vec![entry(
            "aws-ssm",
            "aws-ssm",
            DoctorStatus::CliMissing {
                cli_name: "aws".into(),
                install_hint: "brew install awscli".into(),
            },
        )]);
        let out = render_human(&r);
        assert!(out.contains("CLI 'aws' not found"));
        assert!(out.contains("brew install awscli"));
    }

    // ---- JSON serialization ----

    #[test]
    fn json_output_has_stable_shape() {
        let r = report(vec![
            entry(
                "local",
                "local",
                DoctorStatus::Ok { cli_version: "local".into(), identity: "filesystem".into() },
            ),
            entry(
                "aws-ssm-prod",
                "aws-ssm",
                DoctorStatus::NotAuthenticated { hint: "aws sso login".into() },
            ),
        ]);
        let json = serde_json::to_value(&r).unwrap();
        // Top-level keys
        assert!(json.get("backends").is_some());
        assert!(json.get("summary").is_some());
        // Summary keys
        let summary = &json["summary"];
        assert_eq!(summary["total"], 2);
        assert_eq!(summary["ok"], 1);
        assert_eq!(summary["not_authenticated"], 1);
        // Per-backend shape: status tag + variant fields flattened.
        let ok = &json["backends"][0];
        assert_eq!(ok["instance_name"], "local");
        assert_eq!(ok["backend_type"], "local");
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["cli_version"], "local");
        assert_eq!(ok["identity"], "filesystem");
        let na = &json["backends"][1];
        assert_eq!(na["status"], "not_authenticated");
        assert_eq!(na["hint"], "aws sso login");
        // No --fix run → no fix_actions key.
        assert!(json.get("fix_actions").is_none());
        // No --extensive → no depth array on entries.
        assert!(ok.get("depth").is_none());
    }

    // ---- Registry section ----

    fn src(uri: &str, status: DoctorStatus) -> RegistrySourceReport {
        RegistrySourceReport { uri: uri.to_owned(), status }
    }

    #[test]
    fn human_output_omits_registries_section_when_empty() {
        let r = report(vec![entry(
            "local",
            "local",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
        )]);
        let out = render_human(&r);
        assert!(!out.contains("Registries"));
    }

    #[test]
    fn human_output_renders_single_source_registry() {
        let r = report_with_registries(
            vec![entry(
                "local",
                "local",
                DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            )],
            vec![RegistryReport {
                name: "default".into(),
                sources: vec![src(
                    "local:///tmp/r.toml",
                    DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
                )],
            }],
        );
        let out = render_human(&r);
        assert!(out.contains("Registries (1 configured)"));
        assert!(out.contains("  default"));
        assert!(out.contains("✓ local:///tmp/r.toml"));
        assert!(out.contains("reachable"));
    }

    #[test]
    fn human_output_renders_cascade_with_mixed_source_status() {
        let r = report_with_registries(
            vec![
                entry(
                    "aws-ssm-dev",
                    "aws-ssm",
                    DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
                ),
                entry(
                    "aws-ssm-platform",
                    "aws-ssm",
                    DoctorStatus::NotAuthenticated {
                        hint: "aws sso login --profile platform".into(),
                    },
                ),
            ],
            vec![RegistryReport {
                name: "dev".into(),
                sources: vec![
                    src(
                        "aws-ssm-dev:///secretenv/dev-registry",
                        DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
                    ),
                    src(
                        "aws-ssm-platform:///secretenv/org-registry",
                        DoctorStatus::NotAuthenticated {
                            hint: "aws sso login --profile platform".into(),
                        },
                    ),
                ],
            }],
        );
        let out = render_human(&r);
        assert!(
            out.contains("✓ aws-ssm-dev:///secretenv/dev-registry"),
            "expected tick on reachable source:\n{out}"
        );
        assert!(
            out.contains("✗ aws-ssm-platform:///secretenv/org-registry"),
            "expected cross on unreachable source:\n{out}"
        );
        assert!(out.contains("backend not authenticated"), "suffix: {out}");
        assert!(out.contains("→ aws sso login --profile platform"), "hint rendered:\n{out}");
    }

    #[test]
    fn human_output_handles_unparseable_source_gracefully() {
        let r = report_with_registries(
            vec![entry(
                "local",
                "local",
                DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            )],
            vec![RegistryReport {
                name: "broken".into(),
                sources: vec![src(
                    "not-a-uri",
                    DoctorStatus::Error {
                        message: "source 'not-a-uri' failed to parse: malformed input".into(),
                    },
                )],
            }],
        );
        let out = render_human(&r);
        assert!(out.contains("✗ not-a-uri"));
        assert!(out.contains("backend error"));
        assert!(out.contains("failed to parse"));
    }

    #[test]
    fn json_output_includes_registries_section_when_present() {
        let r = report_with_registries(
            vec![entry(
                "aws-ssm-prod",
                "aws-ssm",
                DoctorStatus::NotAuthenticated { hint: "aws sso login".into() },
            )],
            vec![RegistryReport {
                name: "prod".into(),
                sources: vec![src(
                    "aws-ssm-prod:///secretenv/prod-reg",
                    DoctorStatus::NotAuthenticated { hint: "aws sso login".into() },
                )],
            }],
        );
        let json = serde_json::to_value(&r).unwrap();
        let registries = &json["registries"];
        assert!(registries.is_array());
        assert_eq!(registries[0]["name"], "prod");
        let first_source = &registries[0]["sources"][0];
        assert_eq!(first_source["uri"], "aws-ssm-prod:///secretenv/prod-reg");
        assert_eq!(first_source["status"], "not_authenticated");
        assert_eq!(first_source["hint"], "aws sso login");
    }

    #[test]
    fn json_output_omits_registries_key_when_empty() {
        let r = report(vec![entry(
            "local",
            "local",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
        )]);
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("registries").is_none(), "registries key should be omitted: {json}");
    }

    // ---- source_status helper ----

    #[test]
    fn source_status_uses_cached_backend_status_on_parse_ok() {
        let mut m = HashMap::new();
        m.insert(
            "aws-ssm-prod".to_owned(),
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
        );
        let got = source_status("aws-ssm-prod:///some/path", &m);
        assert_eq!(got.variant_key(), "ok");
    }

    #[test]
    fn source_status_errors_when_scheme_not_registered() {
        let m: HashMap<String, DoctorStatus> = HashMap::new();
        let got = source_status("aws-ssm-prod:///path", &m);
        match got {
            DoctorStatus::Error { message } => {
                assert!(
                    message.contains("aws-ssm-prod") && message.contains("not configured"),
                    "message: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn source_status_errors_on_unparseable_uri() {
        let m: HashMap<String, DoctorStatus> = HashMap::new();
        let got = source_status("not-a-uri-at-all", &m);
        match got {
            DoctorStatus::Error { message } => {
                assert!(message.contains("not-a-uri-at-all"), "message: {message}");
                assert!(message.contains("failed to parse"), "message: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ---- remediation_argv ----

    #[test]
    fn remediation_argv_known_backends() {
        // Lock the canonical remediation command per backend type.
        // Each entry is the contract a future backend addition must
        // either match (by reusing a known type) or extend (by adding
        // its own arm).
        assert_eq!(remediation_argv("aws-ssm"), Some(&["aws", "sso", "login"][..]));
        assert_eq!(remediation_argv("aws-secrets"), Some(&["aws", "sso", "login"][..]));
        assert_eq!(remediation_argv("1password"), Some(&["op", "signin"][..]));
        assert_eq!(remediation_argv("gcp"), Some(&["gcloud", "auth", "login"][..]));
        assert_eq!(remediation_argv("azure"), Some(&["az", "login"][..]));
        assert_eq!(remediation_argv("vault"), Some(&["vault", "login"][..]));
    }

    #[test]
    fn remediation_argv_local_is_none() {
        // `local` has no auth surface — `--fix` must not try to
        // remediate it. None means the report renders as-is.
        assert_eq!(remediation_argv("local"), None);
    }

    #[test]
    fn remediation_argv_unknown_backend_is_none() {
        // Defensive — a typo or future-unrecognized backend type
        // returns None instead of panicking. The user sees
        // NotAuthenticated stay NotAuthenticated post-fix; safe
        // default.
        assert_eq!(remediation_argv("definitely-not-real"), None);
    }

    // ---- --fix render path ----

    #[test]
    fn render_human_includes_fix_actions_section() {
        let entries = vec![entry(
            "1password-personal",
            "1password",
            DoctorStatus::Ok { cli_version: "2".into(), identity: "me".into() },
        )];
        let actions = vec![FixAction {
            instance_name: "1password-personal".into(),
            backend_type: "1password".into(),
            command: vec!["op".into(), "signin".into()],
            success: true,
            spawn_error: None,
        }];
        let r = report_with_fix(entries, actions);
        let out = render_human(&r);
        assert!(out.contains("Remediation actions (1)"), "section header: {out}");
        assert!(out.contains("✓ 1password-personal [1password] — op signin"), "row: {out}");
    }

    #[test]
    fn render_human_fix_action_failure_includes_spawn_error() {
        let entries = vec![entry(
            "vault-prod",
            "vault",
            DoctorStatus::NotAuthenticated { hint: "vault login".into() },
        )];
        let actions = vec![FixAction {
            instance_name: "vault-prod".into(),
            backend_type: "vault".into(),
            command: vec!["vault".into(), "login".into()],
            success: false,
            spawn_error: Some("failed to spawn 'vault': No such file or directory".into()),
        }];
        let r = report_with_fix(entries, actions);
        let out = render_human(&r);
        assert!(out.contains("✗ vault-prod"));
        assert!(out.contains("→ failed to spawn 'vault'"), "spawn-error indented: {out}");
    }

    #[test]
    fn json_output_includes_fix_actions_when_set() {
        let entries = vec![entry(
            "azure-prod",
            "azure",
            DoctorStatus::Ok { cli_version: "2".into(), identity: "me".into() },
        )];
        let actions = vec![FixAction {
            instance_name: "azure-prod".into(),
            backend_type: "azure".into(),
            command: vec!["az".into(), "login".into()],
            success: true,
            spawn_error: None,
        }];
        let r = report_with_fix(entries, actions);
        let json = serde_json::to_value(&r).unwrap();
        let fix = json["fix_actions"].as_array().expect("fix_actions array");
        assert_eq!(fix.len(), 1);
        assert_eq!(fix[0]["instance_name"], "azure-prod");
        assert_eq!(fix[0]["backend_type"], "azure");
        assert_eq!(fix[0]["command"], serde_json::json!(["az", "login"]));
        assert_eq!(fix[0]["success"], true);
        assert!(fix[0].get("spawn_error").is_none());
    }

    // ---- --extensive render path ----

    #[test]
    fn render_human_includes_depth_block_with_alias_count() {
        let depth = vec![DepthProbe {
            uri: "aws-ssm-prod:///secretenv/prod-registry".into(),
            outcome: DepthOutcome::Read { entry_count: 12 },
        }];
        let r = report(vec![entry_with_depth(
            "aws-ssm-prod",
            "aws-ssm",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            depth,
        )]);
        let out = render_human(&r);
        assert!(out.contains("depth probe (1 source)"), "header: {out}");
        assert!(out.contains("✓ aws-ssm-prod:///secretenv/prod-registry"), "uri line: {out}");
        assert!(out.contains("12 aliases readable"), "count + readable: {out}");
    }

    #[test]
    fn render_human_depth_failure_includes_error() {
        let depth = vec![DepthProbe {
            uri: "vault-prod:///kv/registry".into(),
            outcome: DepthOutcome::Failed {
                error: "permission denied: user lacks 'read' on secret/kv/registry".into(),
            },
        }];
        let r = report(vec![entry_with_depth(
            "vault-prod",
            "vault",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            depth,
        )]);
        let out = render_human(&r);
        assert!(out.contains("✗ vault-prod:///kv/registry"));
        assert!(out.contains("→ permission denied"), "error line: {out}");
    }

    #[test]
    fn render_human_depth_block_pluralizes_correctly() {
        let depth = vec![
            DepthProbe { uri: "x:///a".into(), outcome: DepthOutcome::Read { entry_count: 1 } },
            DepthProbe { uri: "x:///b".into(), outcome: DepthOutcome::Read { entry_count: 0 } },
        ];
        let r = report(vec![entry_with_depth(
            "x",
            "local",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            depth,
        )]);
        let out = render_human(&r);
        // "1 source" — wait, plural() returns "" for n == 1 and "es" for n != 1.
        // Source count is 2 (so "sources"); alias counts are 1 ("alias")
        // and 0 ("aliases"). Lock both forms.
        assert!(out.contains("depth probe (2 sources)"), "plural sources: {out}");
        assert!(out.contains("1 alias readable"), "singular alias: {out}");
        assert!(out.contains("0 aliases readable"), "zero is plural: {out}");
    }

    #[test]
    fn json_output_includes_depth_array_when_populated() {
        let depth = vec![
            DepthProbe {
                uri: "gcp-prod:///registry".into(),
                outcome: DepthOutcome::Read { entry_count: 7 },
            },
            DepthProbe {
                uri: "gcp-prod:///broken".into(),
                outcome: DepthOutcome::Failed { error: "denied".into() },
            },
        ];
        let r = report(vec![entry_with_depth(
            "gcp-prod",
            "gcp",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
            depth,
        )]);
        let json = serde_json::to_value(&r).unwrap();
        let probes = json["backends"][0]["depth"].as_array().expect("depth array");
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0]["uri"], "gcp-prod:///registry");
        assert_eq!(probes[0]["depth_status"], "read");
        assert_eq!(probes[0]["entry_count"], 7);
        assert_eq!(probes[1]["depth_status"], "failed");
        assert_eq!(probes[1]["error"], "denied");
    }

    #[test]
    fn json_omits_depth_key_when_empty() {
        // No --extensive ran → depth is empty → JSON shape stays the
        // same as the v0.3 default contract for non-extensive consumers.
        let r = report(vec![entry(
            "local",
            "local",
            DoctorStatus::Ok { cli_version: "v".into(), identity: "i".into() },
        )]);
        let json = serde_json::to_value(&r).unwrap();
        assert!(json["backends"][0].get("depth").is_none(), "depth omitted: {json}");
    }
}
