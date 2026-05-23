// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! MCP tool handlers — one module per tool.
//!
//! Phase 1b: skeleton only. The 13-tool surface is enumerated in
//! [`../tools-inventory.yaml`](../tools-inventory.yaml) and
//! [[build-plan-v0.16-mcp]] §8. Handlers land per tool across
//! Phases 3-6:
//!
//! - **Phase 3 (read-only, 8 tools):** `getting_started`,
//!   `version_info`, `list_aliases`, `list_backends`,
//!   `resolve_status`, `detect_password_managers`, `doctor`,
//!   `redact_status`.
//! - **Phase 4 (mutation, 4 tools):** `set_alias`, `delete_alias`,
//!   `init_project`, `redact_file`.
//! - **Phase 5:** `gen_password` (highest-risk; ships last).
//! - **Phase 6:** `migrate_alias` (wraps the v0.16 Phase 1a
//!   `secretenv-migrate` library).
//!
//! Every handler entry function must call
//! `secretenv_telemetry::span::SecretEnvSpan` (the v0.17 `OTel` seam) at
//! its entry point — even before tool logic exists — so the
//! observability hook pattern is established from commit one.
