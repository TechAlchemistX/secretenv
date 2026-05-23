// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `MCP` server entry point — stdio transport.
//!
//! Phase 2a: bare scaffold. `serve()` instantiates a [`crate::tools::Server`]
//! with all 14 tool stubs registered, binds it to `rmcp::transport::stdio`,
//! and runs until the transport closes. Capability handshake + `tools/list`
//! work out of the box via the `#[tool_handler]` macro expansion in
//! [`crate::tools::Server`].
//!
//! Phase 2b will add the disable-sentinel + enable-with-expiry checks
//! before the server actually binds.

use anyhow::Result;
use rmcp::transport::stdio;
use rmcp::ServiceExt;

use crate::tools::Server;

/// Run the `SecretEnv` `MCP` server over stdio until the transport closes.
///
/// # Errors
///
/// Returns an error if the `rmcp` `serve` call fails to perform the
/// initialize handshake, or if the underlying transport errors during
/// the service lifetime.
pub async fn serve() -> Result<()> {
    let service = Server::new()
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("rmcp serve failed during initialize: {e}"))?;

    service.waiting().await.map_err(|e| anyhow::anyhow!("rmcp service join error: {e}"))?;

    Ok(())
}
