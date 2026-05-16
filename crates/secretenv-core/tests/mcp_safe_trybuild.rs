// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// Trybuild harness for the `mcp-safe` feature.
//
// Only runs when `secretenv-core` is compiled with `--features mcp-safe`,
// which is NOT enabled by the default workspace build (Cargo's feature
// unification would otherwise cascade `mcp-safe` to all 15 backends and
// break them).
//
// Invoke explicitly via:
//
//     cargo test -p secretenv-core --features mcp-safe --test mcp_safe_trybuild
//
// CI runs this as a dedicated job (see `.github/workflows/ci.yml`).

#![allow(missing_docs)]
#![cfg(feature = "mcp-safe")]

#[test]
fn mcp_safe_compile_failures() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/mcp_safe_ui/expose_secret_is_gated.rs");
    t.compile_fail("tests/mcp_safe_ui/backend_not_re_exported.rs");
    // Added in Phase 7 review (security audit B1 + H4):
    t.compile_fail("tests/mcp_safe_ui/build_env_not_re_exported.rs");
    t.compile_fail("tests/mcp_safe_ui/env_entry_value_is_gated.rs");
}
