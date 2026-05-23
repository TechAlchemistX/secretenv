// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! MCP boundary types — the closed surface of structs that may be
//! serialized into a tool response payload.
//!
//! Phase 1b: skeleton only. Per-tool response structs land with their
//! handler in Phases 3-6. Every struct defined here is subject to the
//! [`tests/boundary_test.rs`](../tests/boundary_test.rs) field-name
//! exhaustiveness check — no field named `value`, `secret`, `password`,
//! `token`, or `raw` may appear in any type reachable from this module.
