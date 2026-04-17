//! Configuration types for `~/.config/secretenv/config.toml`.
//!
//! Phase 2 defines hand-rolled structs used by
//! [`BackendRegistry`](crate::BackendRegistry) to construct instances.
//! Phase 3 adds `serde::Deserialize`, XDG-aware loading, and the
//! `[registries.*]` table that this module does not yet carry.
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

/// Configuration for a single backend instance, as found under
/// `[backends.<instance_name>]` in `config.toml`.
///
/// The `type` TOML key maps to [`backend_type`](Self::backend_type).
/// Every other key-value pair under the block is collected into
/// [`raw_fields`](Self::raw_fields) without interpretation — core
/// never knows what fields a given plugin expects, by design.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// The backend type (`type = "..."` in TOML). Identifies which
    /// factory will build this instance.
    pub backend_type: String,
    /// All other fields under the block, as opaque strings. Plugins
    /// own their own validation.
    pub raw_fields: HashMap<String, String>,
}

/// The machine-level configuration loaded from
/// `~/.config/secretenv/config.toml`.
///
/// Phase 2 only wires the `[backends.*]` table — enough to build a
/// [`BackendRegistry`](crate::BackendRegistry). Phase 3 adds
/// `[registries.*]` plus `serde::Deserialize`.
#[derive(Debug, Default, Clone)]
pub struct Config {
    /// `[backends.<instance_name>]` entries, keyed by instance name.
    pub backends: HashMap<String, BackendConfig>,
}
