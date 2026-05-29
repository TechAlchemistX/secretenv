// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 4 integration test: drives every public emission function in
//! `secretenv_telemetry::metrics` against an `InMemoryMetricExporter`
//! and asserts:
//!
//! 1. All 10 expected metric names appear after `force_flush`.
//! 2. Histograms + gauges never carry an `alias.name` attribute
//!    (the v0.17 cardinality contract from
//!    `docs/reference/opentelemetry.md` §5).
//!
//! Driven through the global `MeterProvider` the same way the
//! production CLI emits, so this exercises the real shape of the
//! typed setters, not a parallel mock.

use std::collections::HashSet;

use opentelemetry::global;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

use secretenv_telemetry::metrics::{
    increment_backend_probe, increment_doctor_failure, increment_mcp_tool_call,
    increment_migrate_operation, increment_redact_event, increment_resolution_count,
    observe_registry_alias_count, record_backend_fetch_duration, record_mcp_tool_duration,
    record_resolution_duration, AliasCountBucket, FetchOutcome, MatchContext, McpOutcome,
    McpToolName, ProbeLevel, ProbeOutcome, RedactMode, ResolutionOutcome,
};
use secretenv_telemetry::{MigrateOutcome, MigratePhase};

/// Build + install a meter provider backed by an in-memory exporter,
/// register our instruments against it, and return the exporter so
/// the caller can read flushed metrics after invoking `force_flush`.
fn install_in_memory_meter() -> (SdkMeterProvider, InMemoryMetricExporter) {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    global::set_meter_provider(provider.clone());
    // Register the typed instruments against the freshly installed
    // global meter — same code path `crate::init::install` runs.
    secretenv_telemetry::metrics::init(&global::meter("secretenv"));
    (provider, exporter)
}

#[test]
fn every_instrument_emits_and_alias_name_is_absent_from_histograms_and_gauges() {
    let (provider, exporter) = install_in_memory_meter();

    // Drive each emission API once. Inputs span the closed-enum and
    // bucketed-int attribute slots so the assertions can confirm the
    // typed paths are alive.
    record_resolution_duration(125, "default", ResolutionOutcome::Success, AliasCountBucket::Small);
    increment_resolution_count("default", ResolutionOutcome::Success);
    increment_backend_probe("aws-ssm", "payments", ProbeLevel::L2Auth, ProbeOutcome::Ok);
    record_backend_fetch_duration(45, "aws-ssm", "payments", FetchOutcome::Ok);
    increment_redact_event(RedactMode::Runtime, MatchContext::Exact);
    increment_mcp_tool_call(McpToolName::Doctor, McpOutcome::Success);
    record_mcp_tool_duration(7, McpToolName::Doctor, McpOutcome::Success);
    increment_doctor_failure("vault", "prod", ProbeOutcome::Timeout);
    increment_migrate_operation(MigratePhase::Write, MigrateOutcome::Ok);
    observe_registry_alias_count(42, "default", 0);

    // PeriodicReader collects on a timer; force_flush drives it now.
    let _ = provider.force_flush();

    let Ok(batches) = exporter.get_finished_metrics() else {
        panic!("InMemoryMetricExporter unreadable");
    };
    assert!(!batches.is_empty(), "at least one ResourceMetrics batch flushed");

    // Flatten name → AggregatedMetrics across all flushed batches.
    let mut by_name: std::collections::HashMap<String, &AggregatedMetrics> =
        std::collections::HashMap::new();
    for rm in &batches {
        for sm in rm.scope_metrics() {
            for m in sm.metrics() {
                by_name.insert(m.name().to_owned(), m.data());
            }
        }
    }

    let expected_names: &[&str] = &[
        "secretenv.resolution.duration",
        "secretenv.resolution.count",
        "secretenv.backend.probe.count",
        "secretenv.backend.fetch.duration",
        "secretenv.redact.events",
        "secretenv.mcp.tool.calls",
        "secretenv.mcp.tool.duration",
        "secretenv.doctor.failure.count",
        "secretenv.migrate.operation.count",
        "secretenv.registry.alias_count",
    ];
    let present: HashSet<&str> = by_name.keys().map(String::as_str).collect();
    for name in expected_names {
        assert!(present.contains(name), "expected metric '{name}' not flushed; got: {present:?}");
    }

    // Cardinality contract: alias.name attribute must NOT appear on
    // any histogram or gauge data point. Survey every data point we
    // emitted and assert absence.
    for (name, data) in &by_name {
        match data {
            AggregatedMetrics::U64(MetricData::Histogram(h)) => {
                for dp in h.data_points() {
                    for kv in dp.attributes() {
                        assert_ne!(
                            kv.key.as_str(),
                            "secretenv.alias.name",
                            "histogram '{name}' must not carry alias.name (cardinality rule)",
                        );
                    }
                }
            }
            AggregatedMetrics::U64(MetricData::Gauge(g)) => {
                for dp in g.data_points() {
                    for kv in dp.attributes() {
                        assert_ne!(
                            kv.key.as_str(),
                            "secretenv.alias.name",
                            "gauge '{name}' must not carry alias.name (cardinality rule)",
                        );
                    }
                }
            }
            _ => {
                // Counters / sums / other shapes are not subject to
                // the cardinality rule in v0.17 (alias.name CAN appear
                // on the opt-in `secretenv.alias.resolution.count`
                // counter when SECRETENV_OTEL_ALIAS_METRICS=1, gated
                // by operator opt-in; not implemented in v0.17).
            }
        }
    }
}
