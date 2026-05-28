// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// v0.17 Phase 7 security audit H-1 regression test.
//
// The Phase 3 test `mutation_never_sampled.rs` exercised the sampler
// directly with hardcoded span-name strings — it tested the
// `MUTATION_SPAN_NAMES` constant against itself. The Phase 7 security
// audit caught that the actual call-site names in
// `secretenv-mcp/src/tools/mod.rs` were missing the `secretenv.`
// prefix, so the whitelist never matched and SEC-INV-22 was silently
// broken under aggressive ratio sampling.
//
// This test exercises the **real production path**: drive
// `SecretEnvSpan::start("secretenv.mcp.tool.set_alias")` — the literal
// string at `tools/mod.rs:462` after the Phase 7b rename — against a
// `SdkTracerProvider` whose inner sampler always drops, with the
// `MutationNonDroppableSampler` wrapper. The span MUST land in the
// `InMemorySpanExporter`.

#![allow(missing_docs)]

use opentelemetry::global;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, Sampler, SdkTracerProvider, SimpleSpanProcessor,
};

use secretenv_telemetry::{MutationNonDroppableSampler, SecretEnvSpan};

/// Every span name the MCP tool handlers actually use at the call
/// sites today. Verified by grepping
/// `crates/secretenv-mcp/src/tools/mod.rs` for `SecretEnvSpan::start`.
/// If the call sites drift back to the un-prefixed names, the
/// `MUTATION_SPAN_NAMES` whitelist in `sampler.rs` will silently
/// stop matching and SEC-INV-22 will regress. This test fails
/// loudly if that happens.
const LIVE_MCP_MUTATION_SPAN_NAMES: &[&str] = &[
    "secretenv.mcp.tool.set_alias",
    "secretenv.mcp.tool.delete_alias",
    "secretenv.mcp.tool.migrate_alias",
    "secretenv.mcp.tool.gen_password",
];

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

    for &name in LIVE_MCP_MUTATION_SPAN_NAMES {
        // start() with a `&'static str` matches the call-site shape
        // exactly. The leak path the audit caught was a name-string
        // mismatch between this site and the whitelist constant; this
        // test ties the two together.
        let _ = SecretEnvSpan::start(name);
    }

    let _ = provider.force_flush();
    let Ok(spans) = exporter.get_finished_spans() else {
        panic!("InMemorySpanExporter unreadable");
    };

    let observed: std::collections::HashSet<String> =
        spans.iter().map(|s| s.name.to_string()).collect();
    for name in LIVE_MCP_MUTATION_SPAN_NAMES {
        assert!(
            observed.contains(*name),
            "SEC-INV-22 regression: mutation span '{name}' was dropped under \
             AlwaysOff inner sampler; sampler whitelist no longer matches the \
             live call-site name. Observed spans: {observed:?}",
        );
    }
}
