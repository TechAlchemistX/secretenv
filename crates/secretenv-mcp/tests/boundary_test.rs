// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `SEC-INV-02` — structural boundary harness for the `secretenv-mcp`
//! crate.
//!
//! This is the runtime complement to the `clippy.toml`
//! `disallowed-types` rule and the Phase 8 live-smoke value-grep —
//! together they form the three-gate enforcement stack documented in
//! `crates/secretenv-mcp/src/lib.rs`.
//!
//! # Phase 1b scope
//!
//! Phase 1b lands the test harness (file exists, `cargo test
//! -p secretenv-mcp` finds it, CI runs it) with a structural
//! placeholder. Per-tool assertions land alongside their handlers in
//! Phases 3-6:
//!
//! - **Negative-bound assertion** that `secretenv_core::Secret` does
//!   NOT implement `serde::Serialize`. Land as a `trybuild`
//!   compile-fail fixture in Phase 3 — `trybuild` is the right tool
//!   for "this should fail to compile" assertions and is already used
//!   by `secretenv-core` for the `value-access` boundary.
//! - **Per-tool response-struct exhaustiveness checks** — every
//!   response type defined in `src/boundary.rs` is registered here
//!   and the test asserts it has no field named `value`, `secret`,
//!   `password`, `token`, or `raw`. Lands per-tool in Phases 3-6.
//!
//! The Phase 1b placeholder below is intentionally trivial — its
//! purpose is to establish that the integration-test target compiles
//! and runs under the same `clippy.toml` constraints as the library.

#[test]
fn boundary_harness_compiles() {
    // Phase 1b placeholder: the act of compiling this file under
    // `crates/secretenv-mcp/clippy.toml` is itself the assertion —
    // any future addition here that names `secretenv_core::Secret`
    // outside `src/internal/` will fail CI.
    //
    // Real per-tool assertions land in Phases 3-6.
}
