// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// v0.17 Phase 7 security audit H-1 regression test.
//
// **v0.18 Phase 7b update (Arch-F-1):** the structural-binding claim
// this test exercised by hand is now enforced by the type system +
// runtime guardrail:
//
// 1. Phase 2 (Sec-F-5) made `MutationSpanName::all()` the source of
//    truth for both the sampler whitelist AND the canonical span
//    name (`start_mutation` is the sole legitimate entry point;
//    sampler walks the same enum).
// 2. Phase 7b (Arch-F-1) added a debug-build `debug_assert!` in
//    `SecretEnvSpan::start(name)` that PANICS if `name` matches any
//    `MutationSpanName::all()` value, surfacing accidental bypass.
//
// What this test guards today: drive `start_mutation` for every
// variant against a `SdkTracerProvider` whose inner sampler always
// drops, with the `MutationNonDroppableSampler` wrapper. The spans
// MUST land in the `InMemorySpanExporter`. The original v0.17 leak
// (call-site / whitelist string drift) is structurally impossible
// after Phase 2, but the live sampler-override behavior is still
// worth a real end-to-end assertion.

#![allow(missing_docs)]

use opentelemetry::global;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, Sampler, SdkTracerProvider, SimpleSpanProcessor,
};

use secretenv_telemetry::{MutationNonDroppableSampler, MutationSpanName, SecretEnvSpan};

#[test]
fn live_mutation_span_names_survive_always_off_inner_sampler() {
    let exporter = InMemorySpanExporter::default();

    // Inner sampler always drops; wrapper must override for mutation names.
    let inner = Sampler::ParentBased(Box::new(Sampler::AlwaysOff));
    let wrapped = MutationNonDroppableSampler::new(inner);

    let provider = SdkTracerProvider::builder()
        .with_sampler(wrapped)
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    global::set_tracer_provider(provider.clone());

    // Walk every variant of MutationSpanName. Phase 2's structural
    // lift means adding a new variant automatically grows this test
    // — the assertion below verifies the sampler matched it.
    for variant in MutationSpanName::all() {
        let _ = SecretEnvSpan::start_mutation(*variant);
    }

    let _ = provider.force_flush();
    let Ok(spans) = exporter.get_finished_spans() else {
        panic!("InMemorySpanExporter unreadable");
    };

    let observed: std::collections::HashSet<String> =
        spans.iter().map(|s| s.name.to_string()).collect();
    for variant in MutationSpanName::all() {
        let name = variant.as_str();
        assert!(
            observed.contains(name),
            "SEC-INV-22 regression: mutation span '{name}' was dropped under \
             AlwaysOff inner sampler; the wrapper sampler failed to override \
             the drop verdict for a known MutationSpanName variant. Observed \
             spans: {observed:?}",
        );
    }
}
