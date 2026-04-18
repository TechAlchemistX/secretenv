//! `secretenv doctor` — Level 1 (CLI installed) + Level 2 (authenticated)
//! health checks for every configured backend.
//!
//! Runs all backend `check()` calls concurrently via
//! `futures::future::join_all`. Renders human-readable tree output by
//! default; `--json` emits a stable machine-readable shape for CI
//! pre-flight gating.
//!
//! Exit semantics: if any backend reports a non-`Ok` status, the
//! command returns `Err` so the process exits non-zero. The human
//! report is still printed to stdout first.
#![allow(clippy::module_name_repetitions)]

use std::fmt::Write as _;

use anyhow::{anyhow, Result};
use futures::future::join_all;
use secretenv_core::{with_timeout, BackendRegistry, BackendStatus, DEFAULT_CHECK_TIMEOUT};
use serde::Serialize;

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

#[derive(Debug, Clone, Serialize)]
struct DoctorEntry {
    instance_name: String,
    backend_type: String,
    #[serde(flatten)]
    status: DoctorStatus,
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

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    backends: Vec<DoctorEntry>,
    summary: DoctorSummary,
}

/// Run `check()` on every registered backend concurrently and print
/// the report.
///
/// # Errors
/// Returns `Err` — and thus a non-zero exit code — if any backend
/// reports a non-`Ok` status, even though the human report is still
/// printed normally. This makes `secretenv doctor` usable as a CI
/// pre-flight gate.
pub async fn run_doctor(backends: &BackendRegistry, json: bool) -> Result<()> {
    let list: Vec<&dyn secretenv_core::Backend> = backends.all().collect();
    // Each check() wrapped in its own timeout so one wedged backend
    // cannot hang the whole doctor run. A timeout surfaces as a
    // synthesized `BackendStatus::Error` so the JSON shape stays
    // uniform.
    let statuses: Vec<BackendStatus> = join_all(list.iter().map(|b| async {
        let label = format!("{}::check", b.instance_name());
        match with_timeout(DEFAULT_CHECK_TIMEOUT, &label, async { Ok(b.check().await) }).await
        {
            Ok(status) => status,
            Err(err) => BackendStatus::Error { message: err.to_string() },
        }
    }))
    .await;

    let mut entries: Vec<DoctorEntry> = list
        .iter()
        .zip(statuses)
        .map(|(b, s)| DoctorEntry {
            instance_name: b.instance_name().to_owned(),
            backend_type: b.backend_type().to_owned(),
            status: s.into(),
        })
        .collect();
    entries.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));

    let summary = DoctorSummary::from_entries(&entries);
    let report = DoctorReport { backends: entries, summary };

    if json {
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

// `writeln!`/`write!` into a `String` is infallible — `String`'s `fmt::Write`
// impl never returns `Err`. The `.unwrap()` calls below can never panic at
// runtime, so the workspace `clippy::unwrap_used` warning is suppressed on
// these two functions specifically.
#[allow(clippy::unwrap_used)]
fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    writeln!(out, "secretenv doctor").unwrap();
    writeln!(out, "================\n").unwrap();

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
        DoctorEntry { instance_name: instance.to_owned(), backend_type: ty.to_owned(), status }
    }

    fn report(entries: Vec<DoctorEntry>) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, summary }
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
    }
}
