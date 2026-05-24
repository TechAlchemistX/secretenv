// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `SEC-INV-02` — structural boundary harness for the `secretenv-mcp`
//! crate.
//!
//! Runtime complement to the `clippy.toml` `disallowed-types` rule
//! (the static gate against naming `secretenv_core::Secret`), the
//! `tests/secret_not_serializable.rs` trybuild guard (the static gate
//! against `Secret: Serialize`), and the Phase 8 live-smoke value-grep
//! (the runtime gate against value bytes appearing in response
//! payloads).
//!
//! # Field-name exhaustiveness
//!
//! Every response struct in [`secretenv_mcp::boundary`] is registered
//! here via [`assert_no_banned_field_names`]. The set of banned
//! identifiers — `value`, `secret`, `password`, `token`, `raw` —
//! mirrors the documentation rule in `src/boundary.rs`. A new tool
//! adds its response struct here when its handler lands.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use schemars::schema_for;
use secretenv_mcp::boundary::GettingStartedResponse;

/// Field identifiers that may not appear in any response struct
/// reachable from a tool handler. Mirrors `src/boundary.rs`
/// documentation rule.
const BANNED_FIELD_NAMES: &[&str] = &["value", "secret", "password", "token", "raw"];

/// Walk a JSON Schema and collect every `properties.<key>` identifier
/// found anywhere in the tree (recurses into nested objects and array
/// item schemas). The schema-driven walk catches transitive field
/// names that a literal `std::any::type_name` inspection would miss.
fn collect_property_names(schema: &serde_json::Value, out: &mut Vec<String>) {
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (k, v) in props {
            out.push(k.clone());
            collect_property_names(v, out);
        }
    }
    if let Some(items) = schema.get("items") {
        collect_property_names(items, out);
    }
    if let Some(defs) = schema.get("$defs").and_then(|v| v.as_object()) {
        for v in defs.values() {
            collect_property_names(v, out);
        }
    }
}

fn assert_no_banned_field_names<T: schemars::JsonSchema>(struct_name: &str) {
    let schema = schema_for!(T);
    let schema_value = serde_json::to_value(&schema).expect("schema should serialize");
    let mut names = Vec::new();
    collect_property_names(&schema_value, &mut names);

    for banned in BANNED_FIELD_NAMES {
        assert!(
            !names.iter().any(|n| n == banned),
            "response struct `{struct_name}` exposes a banned field name `{banned}`. \
             SEC-INV-02: tool response payloads must not name `value`/`secret`/\
             `password`/`token`/`raw` anywhere in the schema tree. Schema fields \
             observed: {names:?}"
        );
    }
}

#[test]
fn getting_started_response_has_no_banned_fields() {
    assert_no_banned_field_names::<GettingStartedResponse>("GettingStartedResponse");
}

// Per-tool registration block — extend as Phase 3-6 handlers land.
// Adding a tool here without adding its response struct to
// `src/boundary.rs` first will fail to compile, which is the point.
