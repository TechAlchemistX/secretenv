// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation-non-droppable sampler (SEC-INV-22).
//!
//! Wraps any inner [`ShouldSample`] so that span names belonging to
//! the **mutation set** (registry writes, password generation, the
//! migrate transaction's modifying phases) are always recorded and
//! exported regardless of the inner sampler's decision.
//!
//! Without this, an operator running aggressive ratio sampling for
//! high-volume CI (`OTEL_TRACES_SAMPLER=traceidratio` with
//! `OTEL_TRACES_SAMPLER_ARG=0.0001`) could lose the audit trail of
//! the very events that motivate having OTel in the first place.
//!
//! The mutation span name set is closed and small; it lives below
//! as `MUTATION_SPAN_NAMES`. Adding a new mutation tool requires
//! amending the constant — a PR-reviewed code change that surfaces
//! in code review as a deliberate audit-surface expansion.

use opentelemetry::trace::{Link, SpanKind, TraceId};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{Sampler, SamplingDecision, SamplingResult, ShouldSample};

/// The closed set of span names that must always be sampled,
/// regardless of operator-configured ratio sampling.
///
/// Order corresponds to the doc's §6 sampling list:
/// - MCP mutation tools that change registry state
/// - Registry-migrate phases that touch dest-side state
const MUTATION_SPAN_NAMES: &[&str] = &[
    "secretenv.mcp.tool.set_alias",
    "secretenv.mcp.tool.delete_alias",
    "secretenv.mcp.tool.migrate_alias",
    "secretenv.mcp.tool.gen_password",
    "secretenv.migrate.read",
    "secretenv.migrate.write",
    "secretenv.migrate.pointer_flip",
];

/// Wraps any [`ShouldSample`] with the mutation-non-droppable rule.
///
/// For spans named in [`MUTATION_SPAN_NAMES`], returns
/// [`SamplingDecision::RecordAndSample`] unconditionally. For all
/// other spans, delegates to the inner sampler.
#[derive(Debug, Clone)]
pub struct MutationNonDroppableSampler<S: ShouldSample + Clone> {
    inner: S,
}

impl<S: ShouldSample + Clone> MutationNonDroppableSampler<S> {
    /// Wrap an inner sampler with the mutation-non-droppable rule.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// True when this span name participates in the non-droppable rule.
    #[must_use]
    pub fn is_mutation_span(name: &str) -> bool {
        MUTATION_SPAN_NAMES.contains(&name)
    }
}

impl<S: ShouldSample + Clone + 'static> ShouldSample for MutationNonDroppableSampler<S> {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        span_kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        if Self::is_mutation_span(name) {
            // Force-sample. Preserve the parent's trace state if any;
            // SamplingResult::trace_state is required by the trait.
            use opentelemetry::trace::TraceContextExt as _;
            let trace_state = parent_context
                .map(|cx| cx.span().span_context().trace_state().clone())
                .unwrap_or_default();
            return SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: Vec::new(),
                trace_state,
            };
        }
        self.inner.should_sample(parent_context, trace_id, name, span_kind, attributes, links)
    }
}

/// SecretEnv's default sampler — `parentbased(always_on)` wrapped
/// in the mutation non-droppable rule.
///
/// Installed by [`crate::init`] when no operator `OTEL_TRACES_SAMPLER`
/// override is supplied.
#[must_use]
pub fn default_sampler() -> MutationNonDroppableSampler<Sampler> {
    MutationNonDroppableSampler::new(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceState;

    /// Sampler that always drops; lets us verify the wrapper overrides
    /// it for mutation span names while still delegating for others.
    #[derive(Debug, Clone)]
    struct AlwaysDrop;

    impl ShouldSample for AlwaysDrop {
        fn should_sample(
            &self,
            _parent_context: Option<&Context>,
            _trace_id: TraceId,
            _name: &str,
            _span_kind: &SpanKind,
            _attributes: &[KeyValue],
            _links: &[Link],
        ) -> SamplingResult {
            SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            }
        }
    }

    fn sample_with(sampler: &impl ShouldSample, name: &str) -> SamplingDecision {
        sampler.should_sample(None, TraceId::INVALID, name, &SpanKind::Internal, &[], &[]).decision
    }

    #[test]
    fn mutation_set_overrides_drop() {
        let sampler = MutationNonDroppableSampler::new(AlwaysDrop);
        for name in MUTATION_SPAN_NAMES {
            assert_eq!(
                sample_with(&sampler, name),
                SamplingDecision::RecordAndSample,
                "mutation span '{name}' must always sample even when inner drops",
            );
        }
    }

    #[test]
    fn non_mutation_span_defers_to_inner() {
        let sampler = MutationNonDroppableSampler::new(AlwaysDrop);
        assert_eq!(sample_with(&sampler, "secretenv.resolution"), SamplingDecision::Drop,);
        assert_eq!(sample_with(&sampler, "secretenv.run"), SamplingDecision::Drop);
        assert_eq!(sample_with(&sampler, "secretenv.doctor"), SamplingDecision::Drop);
    }

    #[test]
    fn is_mutation_span_predicate_matches_set() {
        for name in MUTATION_SPAN_NAMES {
            assert!(MutationNonDroppableSampler::<AlwaysDrop>::is_mutation_span(name));
        }
        assert!(!MutationNonDroppableSampler::<AlwaysDrop>::is_mutation_span(
            "secretenv.mcp.tool.read_alias"
        ));
        assert!(!MutationNonDroppableSampler::<AlwaysDrop>::is_mutation_span("secretenv.run"));
    }
}
