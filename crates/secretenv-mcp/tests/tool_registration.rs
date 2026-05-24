// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 2a end-of-phase gate: the `#[tool_router]` macro expansion
//! actually registers all 14 tools from `tools-inventory.yaml`.
//!
//! Runtime check that complements the build-time CI gate
//! (`mcp-tools-inventory`) — the file count and the registration
//! count must agree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use secretenv_core::Config;
use secretenv_mcp::audit_log::MutationLog;
use secretenv_mcp::config::McpConfig;
use secretenv_mcp::tools::Server;
use tempfile::tempdir;

fn test_server() -> Server {
    // Per-test ephemeral audit-log path keeps the test suite from
    // touching the user's real $XDG_STATE_HOME.
    let dir = tempdir().unwrap();
    let log = MutationLog::open(dir.path().join("audit.log")).unwrap();
    // Leak the tempdir so the file outlives this fn (only acceptable
    // because every test process is short-lived); avoid by passing
    // a dir-owning struct if these tests grow.
    std::mem::forget(dir);
    Server::new(Arc::new(Config::default()), Arc::new(McpConfig::default()), Arc::new(log))
}

#[test]
fn server_registers_14_tools() {
    let server = test_server();
    let tools = server.tool_router.list_all();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(tools.len(), 14, "expected 14 tools registered; got {}: {:?}", tools.len(), names);
}

#[test]
fn all_inventory_tools_are_registered() {
    // Source of truth: tools-inventory.yaml lists 14 tool names. This
    // test enumerates them inline so a drift between the macro
    // expansion and the inventory fails locally + in CI without
    // requiring a YAML parser dependency.
    let expected: &[&str] = &[
        // Phase 3 — read-only (8)
        "getting_started",
        "version_info",
        "list_aliases",
        "list_backends",
        "resolve_status",
        "detect_password_managers",
        "doctor",
        "redact_status",
        // Phase 4 — mutation (4)
        "set_alias",
        "delete_alias",
        "init_project",
        "redact_file",
        // Phase 5 — gen
        "gen_password",
        // Phase 6 — migrate
        "migrate_alias",
    ];

    let server = test_server();
    let registered: std::collections::BTreeSet<String> =
        server.tool_router.list_all().into_iter().map(|t| t.name.into_owned()).collect();

    for tool in expected {
        assert!(
            registered.contains(*tool),
            "expected tool `{tool}` not registered; registered = {registered:?}"
        );
    }

    assert_eq!(
        registered.len(),
        expected.len(),
        "registered set size differs from expected; \
         registered = {registered:?}, expected = {expected:?}"
    );
}
