// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! TS-12 threat-scenario regression test (v0.18 D-5.2).
//!
//! Threat model: an operator opts into
//! `secretenv run --otel-include-error-detail` to debug a backend
//! failure from their trace UI. The backend returns a stderr blob
//! containing an internal hostname + a secret path
//! (`vault.prod.internal:8200/v1/secret/payments/stripe`). The TS-12
//! invariant: the URL fragment is structurally absent from the
//! emitted `secretenv.backend.error.message` `OTel` attribute, having
//! been replaced by the SEC-INV-20 scrubber's placeholder. Only by
//! holding a `BackendErrorStderr` can the call site emit the
//! attribute at all; the newtype's constructor IS the scrubber.
//!
//! Drives the typed setter directly against an `InMemorySpanExporter`
//! and inspects the flushed span attributes. The opt-out side
//! (`opt_in = false` → attribute structurally absent) is also tested
//! to lock in the dual-state classification from
//! `crate::policy::AttributeClassification::DenyByDefault`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use opentelemetry::global;
use opentelemetry::Value;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};

use secretenv_telemetry::{BackendErrorStderr, SecretEnvSpan};

const ATTRIBUTE_NAME: &str = "secretenv.backend.error.message";

/// The synthetic backend stderr the threat model centres on. Contains
/// an internal hostname + port + secret path. The substrings the
/// test asserts are structurally absent are: `vault.prod.internal`,
/// `payments`, `stripe`, and the literal URL `vault.prod.internal:8200/v1/secret/payments/stripe`.
const SYNTHETIC_BACKEND_STDERR: &str =
    "fetch failed: GET https://vault.prod.internal:8200/v1/secret/payments/stripe returned 403";

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

/// Single `#[test]` function asserts both opt-in and opt-out
/// behavior. Why one function: each `tests/<file>.rs` is its own test
/// binary, but `#[test]` functions within one binary may run in
/// parallel and racily swap the global `TracerProvider`. The
/// canonical pattern in this crate (see
/// `tests/span_attributes_emitted.rs`) is one `#[test]` per test
/// binary; we follow it. Both assertions share the same exporter.
#[test]
fn ts12_stderr_scrubber_round_trip() {
    let exporter = install_in_memory_exporter();

    // --- Arm 1: opt_in = true → emit the scrubbed text, never the URL ---
    {
        let scrubbed = BackendErrorStderr::scrub(SYNTHETIC_BACKEND_STDERR);
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.test.ts12_opt_in");
        span.record_backend_error_message_scrubbed(&scrubbed, true);
    }

    // --- Arm 2: opt_in = false → attribute is structurally absent ---
    {
        let scrubbed = BackendErrorStderr::scrub(SYNTHETIC_BACKEND_STDERR);
        let (mut span, _guard) = SecretEnvSpan::start("secretenv.test.ts12_opt_out");
        span.record_backend_error_message_scrubbed(&scrubbed, false);
    }

    let spans = exporter.get_finished_spans().expect("InMemorySpanExporter unreadable");

    let opt_in =
        spans.iter().find(|s| s.name == "secretenv.test.ts12_opt_in").expect("opt_in span missing");
    let opt_out = spans
        .iter()
        .find(|s| s.name == "secretenv.test.ts12_opt_out")
        .expect("opt_out span missing");

    // Arm 1 assertions: attribute present, fully scrubbed.
    let Some(Value::String(emitted)) = attr(opt_in, ATTRIBUTE_NAME) else {
        panic!("opt-in mode must emit the {ATTRIBUTE_NAME} attribute");
    };
    let emitted = emitted.as_ref();

    for forbidden in [
        "vault.prod.internal",
        "vault.prod.internal:8200/v1/secret/payments/stripe",
        "/v1/secret/payments/stripe",
        "payments",
        "stripe",
        "https://vault.prod.internal",
        "8200",
    ] {
        assert!(
            !emitted.contains(forbidden),
            "TS-12 violation: forbidden substring `{forbidden}` present in emitted attribute: `{emitted}`"
        );
    }
    assert!(
        emitted.contains("uri-stripped"),
        "scrubber placeholder absent from emitted attribute: `{emitted}`"
    );
    assert!(
        emitted.contains("fetch failed") || emitted.contains("returned"),
        "scrubber over-stripped non-sensitive context: `{emitted}`"
    );

    // Arm 2 assertion: attribute structurally absent.
    assert!(
        attr(opt_out, ATTRIBUTE_NAME).is_none(),
        "opt-out mode leaked {ATTRIBUTE_NAME}: {:?}",
        attr(opt_out, ATTRIBUTE_NAME),
    );
}
