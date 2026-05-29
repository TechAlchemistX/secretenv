// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// SEC-INV-12 compile-time guard.
//
// `secretenv.mcp.argument_reason` is the operator's free-form rationale
// captured by MCP elicitation prompts. It is a prompt-injection vehicle
// and must NEVER cross into OTel attributes — it lives in the append-only
// audit log only. `secretenv.mcp.resolved_value` and
// `secretenv.mcp.tool.output_raw` are secret values and equally forbidden.
//
// All three are DENY per `docs/reference/opentelemetry.md` §2.8. The
// `SecretEnvSpan` typed builder must NOT expose a setter for any of
// them. A future contributor adding any one back fails both stages:
//
//   1. The canonical [`RedactionPolicy`] table must continue to
//      classify each as `Deny`.
//   2. The trybuild compile-fail fixture asserts none of the three
//      `record_mcp_*` setters compile against `SecretEnvSpan`.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use secretenv_telemetry::{AttributeClassification, RedactionPolicy};

#[test]
fn sec_inv_12_policy_table_marks_mcp_deny_family_as_deny() {
    let policy = RedactionPolicy::canonical();
    for name in [
        "secretenv.mcp.argument_reason",
        "secretenv.mcp.resolved_value",
        "secretenv.mcp.tool.output_raw",
    ] {
        let classification = policy.classify(name).unwrap_or_else(|| {
            panic!("attribute '{name}' must appear in the canonical policy matrix")
        });
        assert!(
            matches!(classification, AttributeClassification::Deny),
            "SEC-INV-12 violated: '{name}' classified {classification:?}, expected Deny",
        );
    }
}

#[test]
fn sec_inv_12_record_mcp_deny_setters_do_not_exist() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui_sec_inv_12/record_mcp_argument_reason_absent.rs");
}
