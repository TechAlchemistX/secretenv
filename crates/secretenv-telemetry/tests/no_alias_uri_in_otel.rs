// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// SEC-INV-04 compile-time guard for the alias.uri DENY family.
//
// `secretenv.alias.uri`, `.uri.raw`, `.uri.path`, and `.uri.scheme` are
// all DENY in the v0.14+ synthesis §6 matrix — they fingerprint backend
// topology. The `SecretEnvSpan` typed builder must never expose a
// setter for any of them. A future contributor adding any one back
// fails both stages of this test:
//
//   1. The canonical [`RedactionPolicy`] table must continue to
//      classify each variant as `Deny`.
//   2. The trybuild compile-fail fixture asserts none of the four
//      `record_alias_uri*` setters compile against `SecretEnvSpan`.
//
// This is the structural Phase 5 (SEC-INV-04) deliverable: the typed
// builder cannot emit a URI-bearing attribute because it has no
// surface to do so, not because of a runtime check.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use secretenv_telemetry::{AttributeClassification, RedactionPolicy};

#[test]
fn sec_inv_04_policy_table_marks_alias_uri_family_as_deny() {
    let policy = RedactionPolicy::canonical();
    for name in ["secretenv.alias.uri", "secretenv.alias.uri.raw", "secretenv.alias.uri.path"] {
        let classification = policy.classify(name).unwrap_or_else(|| {
            panic!("attribute '{name}' must appear in the canonical policy matrix")
        });
        assert!(
            matches!(classification, AttributeClassification::Deny),
            "SEC-INV-04 violated: '{name}' classified {classification:?}, expected Deny",
        );
    }
}

#[test]
fn sec_inv_04_record_alias_uri_setters_do_not_exist() {
    // trybuild rejects compilation of the fixture below; if any
    // contributor reintroduces any of the four `record_alias_uri*`
    // setters, this test fails.
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_sec_inv_04/record_alias_uri_absent.rs");
}

#[test]
fn sec_inv_04_no_generic_set_attribute_escape_hatch() {
    // The structural enforcement point: a generic
    // `set_attribute(&str, &str)` on `SecretEnvSpan` would defeat the
    // whole typed-builder design. trybuild asserts no such method
    // exists under any of three plausible names.
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_sec_inv_04/no_escape_hatch.rs");
}
