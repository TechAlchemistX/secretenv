// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Mutation audit log writer.
//!
//! Phase 1b: skeleton only. Phase 4 fills in. Per mutation tool call,
//! one JSON Lines entry is appended at mode `0600`:
//!
//! ```json
//! {
//!   "ts": "2026-05-23T14:00:00Z",
//!   "tool_name": "set_alias",
//!   "alias_name": "stripe-key",
//!   "backend_instance": "vault-prod",
//!   "agent_reason": "<the agent's stated reason>",
//!   "operator_decision": "approved" | "denied" | "timeout",
//!   "mcp_client_id": "<rmcp client identifier>"
//! }
//! ```
//!
//! `agent_reason` is recorded here but NEVER echoed back to the agent
//! and NEVER set as an `OTel` attribute (SEC-INV-12).
