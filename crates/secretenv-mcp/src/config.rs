// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Backward-compat shim — the `[mcp]` config types live in the
//! `secretenv-mcp-config` crate as of v0.16.2 D.5. Re-exported here
//! so existing `secretenv_mcp::config::{AllowMutations, ConfirmVia,
//! McpConfig}` imports continue to resolve unchanged.
//!
//! See [`secretenv_mcp_config`] for the canonical definitions.

pub use secretenv_mcp_config::{AllowMutations, ConfirmVia, McpConfig};
