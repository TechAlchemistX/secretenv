// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`McpSafe`] sealed marker trait.
//!
//! Types implementing `McpSafe` are explicitly approved for exposure
//! over the MCP server boundary (v0.16+). The trait is sealed via the
//! [`sealed::Sealed`] supertrait so downstream crates cannot add new
//! impls — every new MCP-exposed type must be reviewed in this crate.
//!
//! Critically, [`Secret`](crate::Secret) and any type that
//! transitively contains a `Secret` field are **not** sealed and
//! **must not** be sealed in the future. The MCP server's tool
//! signatures are typed against `T: McpSafe`, so a missing impl is a
//! compile-time refusal to expose values.
//!
//! In v0.14 only [`HistoryEntry`](crate::HistoryEntry) is sealed.
//! v0.16 (the MCP cycle) will add impls for `AliasList`,
//! `ResolveStatus`, and `DoctorReport` once those types crystallize.

use crate::HistoryEntry;

/// Sealed marker trait: implementing types are safe to expose across
/// the MCP boundary.
///
/// See module docs for the seal rationale.
pub trait McpSafe: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

// --- v0.14 seals ---------------------------------------------------------

impl sealed::Sealed for HistoryEntry {}
impl McpSafe for HistoryEntry {}

// --- v0.16+ TODO ---------------------------------------------------------
// AliasList, ResolveStatus, DoctorReport seals will land alongside the
// MCP server in v0.16 (per [[build-plan-v0.14-redact]] §Phase 1 and
// [[build-plan-v0.16-mcp]]). The DoctorReport type currently lives in
// `secretenv-cli`; v0.16 either moves it into core or seals it from
// the CLI crate with `mcp-safe` cfg-gated re-exports.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_entry_is_mcp_safe() {
        fn assert_mcp_safe<T: McpSafe>() {}
        assert_mcp_safe::<HistoryEntry>();
    }
}
