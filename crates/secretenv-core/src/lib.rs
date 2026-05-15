// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Core types, traits, and plugin registry for SecretEnv.
//!
//! This crate defines the abstractions every backend implements: the
//! [`Backend`] and [`BackendFactory`] traits, the [`BackendRegistry`],
//! URI parsing, and the config model. All backends are wired at runtime
//! via `config.toml`; there are no compile-time feature flags for
//! backends.
//!
//! # Module map
//!
//! - [`uri`] — [`BackendUri`] and [`UriError`]
//! - [`status`] — [`BackendStatus`] (what `doctor` renders)
//! - [`backend`] — the [`Backend`] and [`BackendFactory`] traits
//! - [`config`] — [`Config`], [`RegistryConfig`], [`BackendConfig`]
//! - [`manifest`] — [`Manifest`] and [`SecretDecl`] for `secretenv.toml`
//! - [`registry`] — [`BackendRegistry`] dispatcher
//! - [`timeouts`] — per-op timeout wrapper for backend calls
#![forbid(unsafe_code)]

pub mod backend;
pub mod config;
pub mod factory_helpers;
pub mod manifest;
pub mod mcp_safe;
pub mod redact;
pub mod registry;
pub mod resolver;
pub mod runner;
pub mod secret;
pub mod status;
pub mod timeouts;
pub mod uri;

// `Backend` and the value-producing surfaces (`run`, `run_with_options`,
// `build_env`, `EnvEntry`) are intentionally re-exported only when the
// `mcp-safe` feature is OFF. Crates linking with `mcp-safe` (the v0.16
// MCP server) must reach these via their module paths
// (`secretenv_core::backend::Backend`, `secretenv_core::runner::...`)
// — a small friction tax that prevents value-producing APIs from
// leaking into MCP-exposed signatures by reflex. Per
// [[build-plan-v0.14-redact]] §Phase 1 BREAKING #2 (Q-O1.c) and the
// Phase 7 security-audit B1/H4 findings (the unconditional re-export
// of `build_env` and `EnvEntry::value` bypassed the cfg gate on
// `Secret::expose_secret`).
#[cfg(not(feature = "mcp-safe"))]
pub use backend::Backend;
pub use backend::{BackendFactory, HistoryEntry};
pub use config::{
    default_config_path_xdg, profiles_dir_for, BackendConfig, Config, RegistryConfig,
};
pub use factory_helpers::{
    optional_bool, optional_duration_secs, optional_string, required_string,
};
pub use manifest::{Manifest, SecretDecl};
pub use mcp_safe::McpSafe;
pub use registry::BackendRegistry;
pub use resolver::{
    resolve_manifest, resolve_registry, AliasMap, CascadeLayer, RegistryCache, RegistrySelection,
    ResolvedSecret, ResolvedSource,
};
#[cfg(not(feature = "mcp-safe"))]
pub use runner::{build_env, run, run_with_options, EnvEntry, RedactMode, RunOptions};
pub use secret::Secret;
pub use status::BackendStatus;
pub use timeouts::{with_timeout, DEFAULT_CHECK_TIMEOUT, DEFAULT_GET_TIMEOUT};
pub use uri::{BackendUri, FragmentError, UriError};
