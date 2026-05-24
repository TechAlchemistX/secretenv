// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// SEC-INV-02 compile-fail guard: asserts that `secretenv_core::Secret<T>`
// does NOT implement `serde::Serialize`. See the fixture comment in
// `boundary_ui/secret_is_not_serializable.rs` for the threat model and
// why this matters for the `secretenv-mcp` boundary.

#![allow(missing_docs)]

#[test]
fn secret_is_not_serializable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/boundary_ui/secret_is_not_serializable.rs");
}
