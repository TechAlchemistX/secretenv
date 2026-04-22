// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`Backend`] and [`BackendFactory`] traits — the two interfaces
//! every plugin implements.
//!
//! A plugin crate provides exactly two things:
//!
//! 1. A [`BackendFactory`] — typically a unit struct — that constructs
//!    named instances from raw config.
//! 2. One or more [`Backend`] implementations returned by the factory.
//!
//! Core calls the factory at startup (via
//! [`BackendRegistry`](crate::BackendRegistry)) and the resulting
//! instances are what every later runtime operation dispatches to.
//! Core never constructs a plugin directly.
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use crate::{BackendStatus, BackendUri, DEFAULT_GET_TIMEOUT};

/// One historical version of a secret or registry document, produced
/// by [`Backend::history`].
///
/// Each backend maps its native version-history shape onto this struct.
/// Fields are deliberately string-typed so backend-specific identifiers
/// (git SHAs, integer version numbers, ULIDs, RFC-3339 timestamps,
/// raw native timestamps) all fit without forcing a parse step the
/// CLI doesn't need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Backend-specific version identifier. Always non-empty. Examples:
    /// git short SHA (`local`), AWS SSM parameter version
    /// integer (`aws-ssm`), vault KV v2 metadata version (`vault`).
    pub version: String,
    /// Timestamp of when this version was created. RFC 3339 when the
    /// backend exposes a structured one; otherwise the raw native
    /// string. Always non-empty.
    pub timestamp: String,
    /// User / principal that created this version (git author email,
    /// AWS IAM ARN, vault display name, etc.). `None` when the
    /// backend doesn't expose it.
    pub actor: Option<String>,
    /// Backend-supplied note (git commit subject, vault metadata
    /// description, AWS parameter description). `None` when not
    /// available.
    pub description: Option<String>,
}

/// A live, credentialed backend instance.
///
/// Implementations are expected to wrap a native CLI (`aws`, `op`,
/// `vault`, etc.) — SecretEnv never calls cloud SDKs directly. See the
/// `wrapper-model` wiki page for the full rationale.
///
/// All I/O is async so that v0.2 can introduce parallelism without
/// changing the trait surface. v0.1 dispatches secrets sequentially.
#[async_trait]
pub trait Backend: Send + Sync {
    /// The backend type that created this instance (e.g. `aws-ssm`).
    /// Identifies *which* plugin is in use.
    fn backend_type(&self) -> &str;

    /// The instance name from `config.toml` (e.g. `aws-ssm-prod`).
    /// Doubles as the scheme on URIs that target this instance.
    fn instance_name(&self) -> &str;

    /// Per-instance deadline applied by call sites that wrap
    /// `get` / `set` / `delete` / `list` / `history` in
    /// [`crate::with_timeout`]. Defaults to
    /// [`crate::DEFAULT_GET_TIMEOUT`]; backends override when their
    /// factory reads a `timeout_secs` config field.
    ///
    /// `check` (the doctor health probe) deliberately does NOT consult
    /// this — its `DEFAULT_CHECK_TIMEOUT` is a tighter deadline so
    /// `secretenv doctor` parallelism stays predictable across
    /// instances regardless of any per-instance fetch deadlines.
    fn timeout(&self) -> Duration {
        DEFAULT_GET_TIMEOUT
    }

    /// Level 1 + Level 2 health check: is the native CLI installed and
    /// is the backend authenticated? Rendered by `secretenv doctor`.
    async fn check(&self) -> BackendStatus;

    /// Level 3 extensive check: actually attempt to `list` against
    /// `test_uri` and return the number of entries found. Used by
    /// `doctor` in verbose mode and by registry pre-flight.
    ///
    /// Default implementation calls `list(test_uri)` and returns the
    /// length — which is what every v0.2 backend was duplicating
    /// verbatim. A backend with a faster "count without materializing"
    /// CLI path may override.
    ///
    /// # Errors
    /// Returns an error if the backend is reachable but `list` fails.
    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        Ok(self.list(test_uri).await?.len())
    }

    /// Fetch the secret value at `uri`.
    ///
    /// # Errors
    /// Returns an error if the secret is missing, the caller is
    /// unauthorized, or the backend itself is unreachable. Error
    /// context includes the instance name and `uri.raw`.
    async fn get(&self, uri: &BackendUri) -> Result<String>;

    /// Write `value` at `uri`. Used by `secretenv registry set` and
    /// backend migration flows.
    ///
    /// # Errors
    /// Returns an error on any write failure. Error context includes
    /// the instance name and `uri.raw` — never the value.
    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()>;

    /// Delete the secret at `uri`.
    ///
    /// # Errors
    /// Returns an error if deletion fails or the secret does not exist
    /// (backend-dependent — some return success on missing keys).
    async fn delete(&self, uri: &BackendUri) -> Result<()>;

    /// List the `(key, value)` pairs found at `uri`. For registry
    /// documents this returns the alias → backend-URI map.
    ///
    /// # Errors
    /// Returns an error if the target is unreachable or the caller is
    /// unauthorized.
    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>>;

    /// Return a chronological list of historical versions of the
    /// secret or document at `uri`. Order is most-recent-first.
    ///
    /// Default implementation reports the operation as unsupported —
    /// backends with a native history surface (`local` via git,
    /// `aws-ssm` via `get-parameter-history`, `vault` via KV v2
    /// metadata) override.
    ///
    /// # Errors
    /// Returns an error if the backend doesn't expose history, the
    /// target is unreachable, or the caller is unauthorized. The
    /// default's "unsupported" error names the backend type so a
    /// CLI handler can distinguish it from a real failure.
    async fn history(&self, _uri: &BackendUri) -> Result<Vec<HistoryEntry>> {
        Err(anyhow!(
            "history() is not implemented for backend type '{}' — supported in v0.4: local, aws-ssm, vault",
            self.backend_type()
        ))
    }
}

/// Builds [`Backend`] instances from raw config.
///
/// Registered once per compiled-in plugin at startup via
/// [`BackendRegistry::register_factory`](crate::BackendRegistry::register_factory).
/// Core hands the factory the instance name (from the
/// `[backends.<name>]` TOML key) and a borrowed
/// `HashMap<String, toml::Value>` of every other field under that
/// block. The factory owns all validation — core never interprets
/// plugin-specific fields. Factories typically extract scalars via
/// [`toml::Value::as_str`] / `as_integer` / `as_bool` / `as_array`,
/// emit typed errors naming the offending field, and `.clone()` any
/// values they intend to store.
pub trait BackendFactory: Send + Sync {
    /// The backend type this factory builds (e.g. `aws-ssm`). Must
    /// match the `type = "..."` value used in `config.toml`.
    fn backend_type(&self) -> &str;

    /// Build an instance from the config under `[backends.<instance_name>]`.
    ///
    /// # Errors
    /// Returns an error if required fields are missing or invalid.
    /// Implementations should include the instance name in error
    /// messages so users can trace the failure back to their config.
    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>>;
}
