// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! v0.18 Phase 4 regression test — Arch-M6 subset (5 of 6
//! schema-reserved spans).
//!
//! Five schema-reserved spans from `docs/reference/opentelemetry.md`
//! §4.1/§4.3 land in v0.18 Phase 4:
//!
//! - `secretenv.manifest.load`     — wired into `Manifest::load_from`
//! - `secretenv.registry.load`     — wired into `resolve_registry`
//! - `secretenv.backend.probe`     — wired into `fetch_one`
//! - `secretenv.exec.prepare`      — wired into `exec_with_env`
//! - `secretenv.doctor.registry`   — wired into `run_doctor`
//!
//! `secretenv.exec.flush` deferred to v0.20 per Arch-M6 split
//! (execve-aware `pre_exec` hook + manual flush sequencing).
//!
//! This test drives each span via the typed builder + the new
//! Phase 4 typed setters against an `InMemorySpanExporter` and
//! asserts (a) every span name appears in the exported trace,
//! (b) every Phase 4 typed-setter attribute is emitted with the
//! expected canonical value. The full production path through
//! `Manifest::load_from` / `resolve_registry` / etc. is exercised
//! by the live smoke harness in Phase 8 — this test guards the
//! `SecretEnvSpan` setter contract that the production paths
//! consume.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use opentelemetry::global;
use opentelemetry::Value;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};

use secretenv_telemetry::{
    BackendProbeLevel, BackendProbeOutcome, BackendType, DoctorCheckLevel, ManifestOutcome,
    RegistrySelectionKind, SecretEnvSpan,
};

fn install_in_memory_exporter() -> InMemorySpanExporter {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    global::set_tracer_provider(provider);
    exporter
}

fn attr<'a>(span: &'a opentelemetry_sdk::trace::SpanData, key: &str) -> Option<&'a Value> {
    span.attributes.iter().find(|kv| kv.key.as_str() == key).map(|kv| &kv.value)
}

#[test]
fn phase4_schema_reserved_spans_emit_with_typed_attributes() {
    let exporter = install_in_memory_exporter();

    // --- secretenv.manifest.load ---
    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.manifest.load");
        span.record_manifest_path_relative(std::path::Path::new("secretenv.toml"))
            .record_manifest_alias_count(7)
            .record_manifest_default_count(2)
            .record_manifest_outcome(ManifestOutcome::Ok);
    }

    // --- secretenv.registry.load ---
    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.registry.load");
        span.record_registry_selection(RegistrySelectionKind::ByName)
            .record_registry_name("prod")
            .record_registry_source_count(3)
            .record_registry_source_index(1);
    }

    // --- secretenv.backend.probe ---
    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.backend.probe");
        span.record_backend_type(BackendType::AwsSsm)
            .record_backend_instance("payments")
            .record_backend_probe_level(BackendProbeLevel::Connectivity)
            .record_backend_fetch_attempt(1)
            .record_backend_probe_outcome(BackendProbeOutcome::Success);
    }

    // --- secretenv.exec.prepare ---
    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.exec.prepare");
        span.record_process_env_var_count(12);
    }

    // --- secretenv.doctor.registry ---
    {
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.doctor.registry");
        span.record_doctor_check_level(DoctorCheckLevel::Extensive)
            .record_doctor_backend_count(15)
            .record_doctor_failure_count(2);
    }

    let spans = exporter.get_finished_spans().expect("InMemorySpanExporter unreadable");
    let by_name: std::collections::HashMap<&str, &opentelemetry_sdk::trace::SpanData> =
        spans.iter().map(|s| (s.name.as_ref(), s)).collect();

    // --- Arm 1: every schema-reserved span name is present ---
    for expected in [
        "secretenv.manifest.load",
        "secretenv.registry.load",
        "secretenv.backend.probe",
        "secretenv.exec.prepare",
        "secretenv.doctor.registry",
    ] {
        assert!(
            by_name.contains_key(expected),
            "Phase 4 regression: span `{expected}` missing from export. Observed: {:?}",
            by_name.keys().collect::<Vec<_>>()
        );
    }

    // --- Arm 2: per-span typed attributes emit with canonical values ---
    let manifest = by_name["secretenv.manifest.load"];
    assert_eq!(
        attr(manifest, "secretenv.manifest.path"),
        Some(&Value::from("secretenv.toml".to_owned()))
    );
    assert_eq!(attr(manifest, "secretenv.manifest.alias_count"), Some(&Value::I64(7)));
    assert_eq!(attr(manifest, "secretenv.manifest.default_count"), Some(&Value::I64(2)));
    assert_eq!(attr(manifest, "secretenv.manifest.outcome"), Some(&Value::from("ok")));

    let registry = by_name["secretenv.registry.load"];
    assert_eq!(attr(registry, "secretenv.registry.selection"), Some(&Value::from("by_name")));
    assert_eq!(attr(registry, "secretenv.registry.name"), Some(&Value::from("prod".to_owned())));
    assert_eq!(attr(registry, "secretenv.registry.source_count"), Some(&Value::I64(3)));
    assert_eq!(attr(registry, "secretenv.registry.source_index"), Some(&Value::I64(1)));

    let probe = by_name["secretenv.backend.probe"];
    assert_eq!(attr(probe, "secretenv.backend.probe.level"), Some(&Value::from("connectivity")));
    assert_eq!(attr(probe, "secretenv.backend.probe.outcome"), Some(&Value::from("success")));
    assert_eq!(attr(probe, "secretenv.backend.fetch.attempt"), Some(&Value::I64(1)));
    assert_eq!(attr(probe, "secretenv.backend.type"), Some(&Value::from("aws-ssm".to_owned())));

    let exec = by_name["secretenv.exec.prepare"];
    assert_eq!(attr(exec, "secretenv.run.env_var_count"), Some(&Value::I64(12)));

    let doctor = by_name["secretenv.doctor.registry"];
    assert_eq!(attr(doctor, "secretenv.doctor.check_level"), Some(&Value::from("extensive")));
    assert_eq!(attr(doctor, "secretenv.doctor.backend_count"), Some(&Value::I64(15)));
    assert_eq!(attr(doctor, "secretenv.doctor.failure_count"), Some(&Value::I64(2)));
}
