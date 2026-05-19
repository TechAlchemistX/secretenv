// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// Trybuild harness for the `value-access` feature (v0.15 polarity flip
// per [[v0.14-issues/04-v0.15-architectural-followups]] arch-H2).
//
// Runs ONLY when `secretenv-core` is compiled WITHOUT the
// `value-access` feature — i.e. on the SAFE default surface. The
// fixtures assert that value-producing APIs are NOT reachable when
// `value-access` is disabled: `Secret::expose_secret`, the `Backend`
// re-export, the `runner::*` re-exports, and `EnvEntry::value()`
// must all fail to compile.
//
// Invoke explicitly via:
//
//     cargo test -p secretenv-core --no-default-features --test value_access_trybuild
//
// CI runs this as a dedicated job (see `.github/workflows/ci.yml`).

#![allow(missing_docs)]
#![cfg(not(feature = "value-access"))]

#[test]
fn value_access_surface_is_unreachable_on_safe_default() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/value_access_ui/expose_secret_is_gated.rs");
    t.compile_fail("tests/value_access_ui/backend_not_re_exported.rs");
    // Added in v0.14 Phase 7 review (security audit B1 + H4):
    t.compile_fail("tests/value_access_ui/build_env_not_re_exported.rs");
    t.compile_fail("tests/value_access_ui/env_entry_value_is_gated.rs");
}
