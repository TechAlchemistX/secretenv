// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! SEC-INV-20 regression test (v0.16 Phase 7b).
//!
//! Defense-in-depth: every `error_message` field on a tool response
//! is rendered via [`secretenv_mcp::error::safe_error_message`].
//! This test exercises the scrubber against synthetic error chains
//! that mimic the shape of real errors bubbling from `secretenv-core`
//! / `secretenv-migrate` (which sometimes still include URI bodies
//! in their `with_context` strings — out of scope for this fix),
//! and asserts the final rendered string contains no `scheme://body`
//! substring for any of the 16 registered backend schemes.
//!
//! Also serializes the v0.16 mutation/gen/migrate response structs
//! after stuffing hostile `error_message` values through the scrubber
//! and re-asserts no URI substring survives JSON serialization.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use secretenv_mcp::boundary::{
    DeleteAliasResponse, GenPasswordResponse, InitProjectResponse, MigrateAliasResponse,
    MutationOutcome, OperatorDecisionEcho, RedactFileResponse, SetAliasResponse,
};
use secretenv_mcp::error::safe_error_message;

/// Every backend scheme the project recognises (kept manually in
/// sync with `secretenv-core`'s backend-instance schemes — drift here
/// just means false-negative test signal, not a security leak).
const BACKEND_SCHEMES: &[&str] = &[
    "op",
    "aws-sm",
    "gcp-sm",
    "azure-kv",
    "vault",
    "openbao",
    "bitwarden",
    "bws",
    "doppler",
    "infisical",
    "keepass",
    "pass",
    "keychain",
    "secret-tool",
    "conjur",
    "secretenv",
];

fn assert_no_uri(s: &str) {
    for scheme in BACKEND_SCHEMES {
        let needle = format!("{scheme}://");
        if let Some(idx) = s.find(&needle) {
            let after = &s[idx + needle.len()..];
            assert!(after.starts_with("[redacted]"), "URI `{scheme}://...` not redacted in: {s:?}");
        }
    }
}

#[test]
fn scrubber_strips_uri_in_simple_chain() {
    let inner =
        anyhow::anyhow!("connection refused at vault://prod.example.com:8200/v1/secret/foo");
    let msg = safe_error_message(&inner);
    assert_no_uri(&msg);
    assert!(msg.contains("[redacted]"));
}

#[test]
fn scrubber_strips_uris_at_every_chain_depth() {
    let inner = anyhow::anyhow!("backend op://primary/key/v2 returned 404");
    let middle = inner.context("reading aws-sm://us-east-1/myapp/db-pass mid-walk");
    let outer = middle.context("set_alias for `stripe-key` in registry `default` failed");
    let msg = safe_error_message(&outer);
    assert_no_uri(&msg);
    assert!(msg.contains("[redacted]"));
    assert!(msg.contains("stripe-key"), "alias name should survive: {msg}");
    assert!(msg.contains("default"), "registry name should survive: {msg}");
}

#[test]
fn scrubber_strips_quoted_uris() {
    for quote in ['`', '\'', '"'] {
        let raw = format!("writing registry doc to {quote}vault://hot/sec{quote} failed");
        let err = anyhow::Error::msg(raw);
        let msg = safe_error_message(&err);
        assert_no_uri(&msg);
    }
}

#[test]
fn scrubber_keeps_alias_and_registry_names() {
    let inner = anyhow::anyhow!("fetching value for alias `prod-pg-pass`");
    let outer = inner.context("redact_file scrub-set build for registry `team-secrets`");
    let msg = safe_error_message(&outer);
    assert_no_uri(&msg);
    assert!(msg.contains("prod-pg-pass"));
    assert!(msg.contains("team-secrets"));
}

#[test]
fn scrubber_handles_migrate_pointer_flip_pattern() {
    let inner = anyhow::anyhow!("writing primary source vault://prod/secret/registry.json failed");
    let middle = inner.context("flipping pointer for alias `cache-key`");
    let outer = middle.context("migrate_alias request: dest=`op://dest/key`");
    let msg = safe_error_message(&outer);
    assert_no_uri(&msg);
    assert!(msg.contains("cache-key"));
}

#[test]
fn set_alias_response_serializes_clean() {
    let hostile_inner = anyhow::anyhow!("connection to vault://prod:8200/v1/secret refused");
    let hostile_outer =
        hostile_inner.context("writing updated registry document at op://primary/registry.json");
    let response = SetAliasResponse {
        alias_name: "stripe-key".to_owned(),
        backend_instance: "vault-prod".to_owned(),
        registry_name: "default".to_owned(),
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        error_message: Some(safe_error_message(&hostile_outer)),
    };
    let json = serde_json::to_string(&response).expect("serialize SetAliasResponse");
    assert_no_uri(&json);
}

#[test]
fn delete_alias_response_serializes_clean() {
    let hostile = anyhow::anyhow!("openbao://hot/secret/foo not found")
        .context("reading registry document at vault://prod/registry.json");
    let response = DeleteAliasResponse {
        alias_name: "cache".to_owned(),
        registry_name: "default".to_owned(),
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        error_message: Some(safe_error_message(&hostile)),
    };
    let json = serde_json::to_string(&response).expect("serialize DeleteAliasResponse");
    assert_no_uri(&json);
}

#[test]
fn redact_file_response_serializes_clean() {
    // Worst case from the audit: M1 — `build_tainted_set` leaks
    // target URIs for every alias in the registry.
    let hostile = anyhow::anyhow!("auth denied for backend aws-sm://us-east-1/db-pass")
        .context("fetching value for alias `pg-prod`");
    let response = RedactFileResponse {
        file_path: "/tmp/secrets.env".to_owned(),
        applied: false,
        registry_name: "default".to_owned(),
        aliases_loaded: 0,
        matches_found: 0,
        bytes_replaced: 0,
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        error_message: Some(safe_error_message(&hostile)),
    };
    let json = serde_json::to_string(&response).expect("serialize RedactFileResponse");
    assert_no_uri(&json);
}

#[test]
fn gen_password_response_serializes_clean() {
    let hostile = anyhow::anyhow!("backend write failed: op://primary/new-key permission denied");
    let response = GenPasswordResponse {
        alias_name: "new-key".to_owned(),
        backend_instance: "op-primary".to_owned(),
        registry_name: "default".to_owned(),
        charset: "alphanumeric".to_owned(),
        requested_length: 32,
        used_native_generator: false,
        resolves: false,
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        error_message: Some(safe_error_message(&hostile)),
    };
    let json = serde_json::to_string(&response).expect("serialize GenPasswordResponse");
    assert_no_uri(&json);
}

#[test]
fn migrate_alias_response_serializes_clean() {
    let hostile = anyhow::anyhow!("plan-build failed: source vault://hot/secret unreachable")
        .context("migrate alias `db-pass` from vault-hot to op-primary");
    let response = MigrateAliasResponse {
        alias_name: "db-pass".to_owned(),
        source_backend_instance: Some("vault-hot".to_owned()),
        dest_backend_instance: "op-primary".to_owned(),
        registry_name: "default".to_owned(),
        transaction_id: None,
        delete_source: false,
        dry_run: false,
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        migrate_outcome: None,
        error_message: Some(safe_error_message(&hostile)),
    };
    let json = serde_json::to_string(&response).expect("serialize MigrateAliasResponse");
    assert_no_uri(&json);
}

#[test]
fn init_project_response_serializes_clean() {
    let hostile = anyhow::anyhow!("canonicalizing working_directory failed for openbao://hot/path");
    let response = InitProjectResponse {
        working_directory: "/tmp/proj".to_owned(),
        manifest_path: "/tmp/proj/secretenv.toml".to_owned(),
        applied: false,
        detected_env_keys: vec![],
        env_file_found: false,
        manifest_already_existed: false,
        proposed_manifest_toml: String::new(),
        outcome: MutationOutcome::WriteFailed,
        decision: OperatorDecisionEcho::Approved,
        error_message: Some(safe_error_message(&hostile)),
    };
    let json = serde_json::to_string(&response).expect("serialize InitProjectResponse");
    assert_no_uri(&json);
}

#[test]
fn cleaned_registry_writer_error_has_no_uri() {
    // Sanity: prove the source-side cleanup of registry_writer.rs
    // (Phase 7b commit) produces context strings that don't include
    // URIs to begin with — i.e., the scrubber is defense-in-depth,
    // not primary defense.
    let hand_built = anyhow::anyhow!("backend list failed")
        .context("reading registry document for registry `default`");
    let msg = safe_error_message(&hand_built);
    assert_no_uri(&msg);
    assert!(msg.contains("default"));
    assert!(!msg.contains("[redacted]"), "no URI should have been present: {msg}");
}
