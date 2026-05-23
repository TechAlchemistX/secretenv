// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `[mcp]` config-section parsing for the `SecretEnv` `MCP` server.
//!
//! Phase 1b: skeleton only. Phase 2 fills in parsing of:
//!
//! ```toml
//! [mcp]
//! allow_mutations = "confirm"   # never | confirm | always
//! confirm_via     = "tty"       # tty | notification | none
//! disabled_tools  = []
//! mutation_log    = "$XDG_STATE_HOME/secretenv/mcp-mutations.log"
//! ```
