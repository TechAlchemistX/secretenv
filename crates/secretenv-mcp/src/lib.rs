// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `secretenv-mcp` — `MCP` (Model Context Protocol) server library.
//!
//! Stdio-only `MCP` server giving AI agents structured access to the
//! `SecretEnv` registry **without ever exposing a resolved secret
//! value**.
//!
//! # Structural no-leak invariant (SEC-INV-02)
//!
//! This crate **structurally cannot** construct, deserialize, or
//! serialize a [`secretenv_core::Secret`]. The enforcement stack:
//!
//! - **clippy.toml** bans naming `secretenv_core::Secret` via
//!   `disallowed-types`. Escape hatches via `#[allow(...)]` are
//!   permitted only inside [`internal`] modules.
//! - **`tests/boundary_test.rs`** holds compile-time assertions:
//!   `Secret: !Serialize` (negative-bound) + per-tool response-struct
//!   exhaustiveness checks banning the field names `value`, `secret`,
//!   `password`, `token`, `raw`.
//! - **Phase 8 live-smoke value-grep** injects a fixture secret and
//!   asserts its bytes never appear in any tool response payload.
//!
//! The `secretenv-core` dep is declared with `default-features = false`
//! (does NOT opt into v0.15's `value-access` feature). Workspace
//! feature unification means in-workspace builds still resolve
//! `secretenv-core` with `value-access` enabled because `secretenv-cli`
//! opts in — so the feature gate is documentation, not the structural
//! guarantee. The three gates above are.
//!
//! # Module layout (Phase 1b skeleton)
//!
//! - [`boundary`] — `McpBoundary` safe response types (filled per-tool
//!   in Phases 3-6).
//! - [`tools`] — one module per `MCP` tool handler (filled in Phases 3-6).
//! - [`internal`] — the single subtree allowed to name value-bearing
//!   types. Houses `gen_engine` (the wrapper-first password generation
//!   engine; Phase 5).
//! - [`config`] — `[mcp]` config-section parsing (Phase 2).
//! - [`audit_log`] — mutation audit log writer (Phase 4).
//!
//! Phase 2 adds the `rmcp` SDK dep + transport scaffold; Phase 6 adds
//! the `secretenv-migrate` dep for the `migrate_alias` tool.

pub mod audit_log;
pub mod boundary;
pub mod config;
pub mod error;
pub mod internal;
pub mod policy;
pub mod server;
pub mod tools;

pub use server::{disable, disable_sentinel_path, enable, serve};
