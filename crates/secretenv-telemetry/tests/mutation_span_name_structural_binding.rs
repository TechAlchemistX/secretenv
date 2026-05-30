// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! v0.18 Phase 2 Sec-F-5 / Code-L3 / Phase 7 H-1 follow-up regression test.
//!
//! The v0.17 sampler whitelist was a hand-maintained `&[&str]` constant
//! that the call sites had to match by string equality. The Phase 7
//! audit caught a drift (call sites missing the `secretenv.` prefix);
//! Phase 7b fixed the strings AND added `mutation_real_name_sampled.rs`
//! as a regression test. But that test asserts a constant against
//! itself — a NEW mutation call site introduced with a typo at the
//! call site AND a matching typo in the whitelist array would still
//! evade both.
//!
//! Phase 2's structural lift makes the binding compile-enforced: the
//! [`MutationSpanName`] enum is the single source of truth for both
//! the span name (via [`MutationSpanName::as_str`]) AND the sampler
//! whitelist (via the sampler walking [`MutationSpanName::all`]).
//! [`SecretEnvSpan::start_mutation`] is the only entry point for
//! mutation spans and consumes the enum directly. Adding a new
//! variant automatically extends the sampler's whitelist; it is
//! impossible to add a mutation span name that the sampler does not
//! force-record without amending the enum.
//!
//! This test walks every variant of `MutationSpanName::all()` and
//! drives it through `start_mutation` against a `SdkTracerProvider`
//! whose inner sampler always drops. The non-droppable wrapper must
//! force-record every variant — a new variant gets coverage for free.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use opentelemetry::global;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, Sampler, SdkTracerProvider, SimpleSpanProcessor,
};

use secretenv_telemetry::{MutationNonDroppableSampler, MutationSpanName, SecretEnvSpan};

#[test]
fn every_mutation_span_name_variant_is_force_recorded() {
    let exporter = InMemorySpanExporter::default();

    // Inner sampler always drops; the non-droppable wrapper must
    // override for every MutationSpanName variant. If a future
    // variant slips through, this test fails before the operator
    // experiences a missing audit trail in production.
    let inner = Sampler::ParentBased(Box::new(Sampler::AlwaysOff));
    let wrapped = MutationNonDroppableSampler::new(inner);

    let provider = SdkTracerProvider::builder()
        .with_sampler(wrapped)
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    global::set_tracer_provider(provider.clone());

    let variants = MutationSpanName::all();
    assert!(
        !variants.is_empty(),
        "MutationSpanName::all() returned no variants — empty closed enum is a bug"
    );

    for &variant in variants {
        // start_mutation is the ONLY way to start a mutation span.
        // It feeds variant.as_str() to the tracer; the sampler also
        // walks MutationSpanName::all() so the two cannot drift.
        let _ = SecretEnvSpan::start_mutation(variant);
    }

    let _ = provider.force_flush();
    let spans = exporter.get_finished_spans().expect("InMemorySpanExporter unreadable");

    let observed: std::collections::HashSet<&str> = spans.iter().map(|s| s.name.as_ref()).collect();

    for variant in variants {
        let expected = variant.as_str();
        assert!(
            observed.contains(expected),
            "Structural binding regression: MutationSpanName::{variant:?} span (name `{expected}`) \
             was dropped under AlwaysOff inner sampler. The non-droppable wrapper failed to \
             force-record it, which means the sampler's iteration over MutationSpanName::all() \
             diverged from the enum. Observed spans: {observed:?}",
        );
    }
}

#[test]
fn mutation_span_name_is_predicate_matches_every_variant() {
    // Independent assertion path: the sampler's is_mutation_span()
    // predicate must return true for every variant's as_str(). This
    // tests the predicate without going through the OTel SDK round
    // trip, so a failure here points directly at the sampler's
    // iteration logic, not at a tracer/processor configuration issue.
    for &variant in MutationSpanName::all() {
        let name = variant.as_str();
        assert!(
            MutationNonDroppableSampler::<Sampler>::is_mutation_span(name),
            "is_mutation_span() returned false for MutationSpanName::{variant:?} (name `{name}`)"
        );
    }
}

#[test]
fn non_mutation_span_names_are_not_force_recorded() {
    // Negative coverage: confirm the predicate doesn't accidentally
    // claim every span is non-droppable. Random non-mutation names
    // from elsewhere in the schema must return false.
    for name in [
        "secretenv.run",
        "secretenv.resolution",
        "secretenv.backend.fetch",
        "secretenv.doctor.backend",
        "secretenv.mcp.tool.list_aliases",
        "secretenv.redact.match",
        "completely.unrelated.span.name",
        "",
    ] {
        assert!(
            !MutationNonDroppableSampler::<Sampler>::is_mutation_span(name),
            "is_mutation_span() returned true for non-mutation name `{name}` — \
             over-broad match means high-volume operators lose ratio sampling on non-mutation spans"
        );
    }
}
