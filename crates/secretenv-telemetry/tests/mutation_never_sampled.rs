// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! SEC-INV-22 regression test: the mutation-non-droppable sampler
//! forces `RecordAndSample` for span names in the mutation set,
//! regardless of the operator-configured inner sampler.
//!
//! Drives the sampler at the SDK level (not via the `SecretEnvSpan`
//! builder) so we observe the sampling decision deterministically
//! without depending on global `TracerProvider` state set by another
//! test binary.

use opentelemetry::trace::{Link, SpanKind, TraceId};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{Sampler, SamplingDecision, ShouldSample};

use secretenv_telemetry::MutationNonDroppableSampler;

fn decide(sampler: &impl ShouldSample, name: &str) -> SamplingDecision {
    sampler.should_sample(None, TraceId::INVALID, name, &SpanKind::Internal, &[], &[]).decision
}

#[test]
fn mutation_spans_survive_a_zero_ratio_inner_sampler() {
    // An operator-configured inner sampler that drops every trace.
    // Without the wrapper, a mutation span name would be lost.
    let zero_ratio = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.0)));
    let wrapped = MutationNonDroppableSampler::new(zero_ratio);

    // Sanity: a non-mutation span name is dropped by the inner.
    assert_eq!(decide(&wrapped, "secretenv.run"), SamplingDecision::Drop);
    assert_eq!(decide(&wrapped, "secretenv.resolution"), SamplingDecision::Drop);

    // Every member of the mutation set still records-and-samples.
    for name in [
        "secretenv.mcp.tool.set_alias",
        "secretenv.mcp.tool.delete_alias",
        "secretenv.mcp.tool.migrate_alias",
        "secretenv.mcp.tool.gen_password",
        "secretenv.migrate.read",
        "secretenv.migrate.write",
        "secretenv.migrate.pointer_flip",
    ] {
        assert_eq!(
            decide(&wrapped, name),
            SamplingDecision::RecordAndSample,
            "mutation span '{name}' must always sample regardless of inner sampler",
        );
    }
}

#[test]
fn non_mutation_resolution_span_obeys_ratio_inner() {
    // With ratio=1.0 the inner always samples; ensure the wrapper
    // doesn't accidentally inject a Drop or RecordOnly decision.
    let always_on = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0)));
    let wrapped = MutationNonDroppableSampler::new(always_on);

    // Both mutation and non-mutation surfaces should sample under
    // an "AlwaysOn-shaped" inner; the wrapper is a one-way upgrade.
    assert_eq!(decide(&wrapped, "secretenv.run"), SamplingDecision::RecordAndSample);
    assert_eq!(decide(&wrapped, "secretenv.mcp.tool.set_alias"), SamplingDecision::RecordAndSample,);
}

// Suppress unused-import lints that surface only when this test crate
// is built standalone; these types are referenced via macro arms above.
#[allow(dead_code)]
fn _unused_imports(_: Context, _: KeyValue, _: Link) {}
