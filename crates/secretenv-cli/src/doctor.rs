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

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{anyhow, Result};
use futures::future::join_all;
use secretenv_core::{
    with_timeout, BackendRegistry, BackendStatus, BackendUri, Config, DEFAULT_CHECK_TIMEOUT,
};
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

/// Per-registry-source reachability report for the `Registries` section.
///
/// "Reachable" means the backend instance referenced by the source's
/// scheme has a passing Level 2 check — not that the URI itself was
/// fetched. This is deliberate: the heavier per-URI probe (`list()` on
/// the actual source doc) is `doctor --extensive` territory, deferred
/// to v0.3. Today we surface "can this environment talk to the backend
/// that serves this cascade source at all?"
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
}

/// Run `check()` on every registered backend concurrently, build a
/// per-registry cascade reachability report, and print the combined
/// output.
///
/// Exit semantics: the non-zero exit is driven by the `Backends`
/// summary only — a backend-level failure already propagates into
/// every registry source that uses it, so duplicating the signal
/// would double-count. The `Registries` section is informational.
///
/// # Errors
/// Returns `Err` — and thus a non-zero exit code — if any backend
/// reports a non-`Ok` status, even though the human report is still
/// printed normally. This makes `secretenv doctor` usable as a CI
/// pre-flight gate.
pub async fn run_doctor(config: &Config, backends: &BackendRegistry, json: bool) -> Result<()> {
    let list: Vec<&dyn secretenv_core::Backend> = backends.all().collect();
    // Each check() wrapped in its own timeout so one wedged backend
    // cannot hang the whole doctor run. A timeout surfaces as a
    // synthesized `BackendStatus::Error` so the JSON shape stays
    // uniform.
    let statuses: Vec<BackendStatus> = join_all(list.iter().map(|b| async {
        let label = format!("{}::check", b.instance_name());
        match with_timeout(DEFAULT_CHECK_TIMEOUT, &label, async { Ok(b.check().await) }).await {
            Ok(status) => status,
            Err(err) => BackendStatus::Error { message: err.to_string() },
        }
    }))
    .await;

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
        });
    }
    entries.sort_by(|a, b| a.instance_name.cmp(&b.instance_name));

    // Per-registry cascade reachability. Sort registry names for
    // deterministic output (HashMap iteration is non-deterministic).
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

    let summary = DoctorSummary::from_entries(&entries);
    let report = DoctorReport { backends: entries, registries, summary };

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

/// One-line suffix describing the source's status — appended to the
/// `<tick> <uri>   ` line. For `Ok` status, this is "reachable via
/// <backend-type>" (surfaces which backend serves the source). For
/// failure states, it's a short classification like "not authenticated".
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
        DoctorEntry { instance_name: instance.to_owned(), backend_type: ty.to_owned(), status }
    }

    fn report(entries: Vec<DoctorEntry>) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, registries: Vec::new(), summary }
    }

    fn report_with_registries(
        entries: Vec<DoctorEntry>,
        registries: Vec<RegistryReport>,
    ) -> DoctorReport {
        let summary = DoctorSummary::from_entries(&entries);
        DoctorReport { backends: entries, registries, summary }
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

    // ---- Registry section (Phase 9) ----

    fn src(uri: &str, status: DoctorStatus) -> RegistrySourceReport {
        RegistrySourceReport { uri: uri.to_owned(), status }
    }

    #[test]
    fn human_output_omits_registries_section_when_empty() {
        // No registries configured → the section header should not
        // appear. Guards against a regression where the header renders
        // unconditionally even for a `--registry <uri>`-only setup.
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
        // Both source lines rendered with distinct ticks/crosses.
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
        // A malformed source URI should render as a cross with the
        // parse error — not panic, not skip the line.
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
        // `skip_serializing_if = "Vec::is_empty"` means a config with
        // no registries yields JSON without a `registries` key at all
        // — backward-compat with v0.1 doctor consumers.
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
}
