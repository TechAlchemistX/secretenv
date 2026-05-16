// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// SEC-INV-19 compile-time guard.
//
// The `secretenv.redact.alias_name` attribute is **DENY** for OTel
// emission per [[v0.14-plus-security-invariants]] §2.5 + §9. The
// `SecretEnvSpan` typed attribute builder must NOT expose a
// `record_redact_alias_name` setter — adding it back at any point
// in the future will fail to compile here.
//
// The operator-local terminal token (`[redacted:<alias>]`) remains
// available via `secretenv_core::redact::SubstitutionToken::AliasAware`;
// that surface is unaffected.
//
// CI: `.github/workflows/ci.yml` runs `cargo test -p secretenv-telemetry
// --tests --test no_redact_alias_in_otel`. The harness runs in two
// stages:
//
//   1. A normal-mode `#[test]` that uses `RedactionPolicy` to assert
//      the canonical matrix classifies the attribute as `Deny`.
//   2. A `trybuild` compile-fail case that proves calling
//      `record_redact_alias_name(...)` does not compile.
//
// If a future contributor adds the setter back, both stages fail.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use secretenv_telemetry::{AttributeClassification, RedactionPolicy};

#[test]
fn sec_inv_19_policy_table_marks_redact_alias_name_as_deny() {
    // The CANONICAL policy table at `policy.rs::CANONICAL` is the
    // declarative source of truth. If a future contributor flips
    // this attribute back to `Allow` they'll break the assertion
    // AND the trybuild compile-fail below.
    let policy = RedactionPolicy::canonical();
    let classification = policy
        .classify("secretenv.redact.alias_name")
        .expect("attribute is documented in the matrix");
    assert!(
        matches!(classification, AttributeClassification::Deny),
        "SEC-INV-19 violated: `secretenv.redact.alias_name` is classified {classification:?}, expected Deny",
    );
}

#[test]
fn sec_inv_19_record_redact_alias_name_setter_does_not_exist() {
    // Driven by trybuild: the deliberate-misuse case in
    // `tests/ui_sec_inv_19/record_redact_alias_name_absent.rs` must
    // fail to compile. If it succeeds (i.e. someone re-added the
    // setter), trybuild fails this test.
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_sec_inv_19/record_redact_alias_name_absent.rs");
}
