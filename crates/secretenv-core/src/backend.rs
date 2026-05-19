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

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use crate::{BackendStatus, BackendUri, Secret, DEFAULT_GET_TIMEOUT};

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
    /// Returns a [`Secret<String>`] wrapper. The newtype prevents the
    /// value from being accidentally logged, cloned without explicit
    /// re-wrapping, or serialized. Callers extract the inner `&str`
    /// via `expose_secret()` only at the moment of injection into the
    /// child process environment.
    ///
    /// # Errors
    /// Returns an error if the secret is missing, the caller is
    /// unauthorized, or the backend itself is unreachable. Error
    /// context includes the instance name and `uri.raw` — never the
    /// value.
    async fn get(&self, uri: &BackendUri) -> Result<Secret<String>>;

    /// Write `value` at `uri`. Used by `secretenv registry set` and
    /// backend migration flows.
    ///
    /// # Errors
    /// Returns an error on any write failure. Error context includes
    /// the instance name and `uri.raw` — never the value.
    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()>;

    /// Write `value` at `uri` as a [`Secret`] reference. v0.15
    /// migrate destination path — takes the value by `&Secret<String>`
    /// reference rather than `&str` so the borrow-not-clone invariant
    /// holds end-to-end through the migrate transaction
    /// (SEC-INV-10).
    ///
    /// Default returns
    /// [`BackendError::WriteNotSupported`](crate::BackendError::WriteNotSupported).
    /// All 15 v0.14 backends override this method as the migrate
    /// destination path:
    ///
    /// - 12 `Native` migrate destinations wrap their existing `set`
    ///   path with no per-call gate.
    /// - 3 `Gated` destinations (`1password`, `bitwarden-sm`, `keeper`)
    ///   return `WriteNotSupported` with a `reason` naming the unset
    ///   gate flag (`op_unsafe_set`, `bws_unsafe_set`,
    ///   `keeper_unsafe_set`).
    ///
    /// Per-backend strategy is captured in
    /// [[build-plan-v0.15-migrate]] §Phase 1 audit table.
    ///
    /// # Errors
    /// Returns an error on any write failure or when the backend is
    /// not a valid migrate destination (default impl, or a gated
    /// backend without its opt-in flag set). Error context never
    /// carries the value.
    async fn write_secret(&self, _uri: &BackendUri, _value: &Secret<String>) -> Result<()> {
        Err(crate::BackendError::WriteNotSupported {
            backend_type: self.backend_type().to_owned(),
            reason: "default Backend::write_secret impl — this backend has not implemented \
                     the v0.15 migrate destination path",
        }
        .into())
    }

    /// Delete the secret at `uri`.
    ///
    /// # Errors
    /// Returns an error if deletion fails or the secret does not exist
    /// (backend-dependent — some return success on missing keys).
    async fn delete(&self, uri: &BackendUri) -> Result<()>;

    /// v0.15 BREAKING (additive — default returns
    /// [`BackendError::DeleteNotSupported`](crate::BackendError::DeleteNotSupported)).
    ///
    /// The destructive cleanup leg of the v0.15 `secretenv registry
    /// migrate --delete-source` opt-in path. Distinct from
    /// [`Backend::delete`]:
    ///
    /// - `delete` is the general-purpose secret-removal entry point.
    /// - `delete_secret` is the migrate-specific cleanup leg, gated
    ///   the same way as [`Backend::write_secret`] (default refuses;
    ///   12 Native backends override with `self.delete(uri)`
    ///   passthrough; 3 Gated backends (`1password`, `bitwarden-sm`,
    ///   `keeper`) require the same `*_unsafe_set` config flag the
    ///   write path uses).
    ///
    /// Per-backend strategy is captured in
    /// [[build-plan-v0.15-migrate]] §Phase 2 audit table.
    ///
    /// # Errors
    /// Returns an error on any delete failure or when the backend is
    /// not a valid migrate-cleanup target (default impl, or a gated
    /// backend without its opt-in flag set). Error context never
    /// carries the URI body or the alias name.
    async fn delete_secret(&self, _uri: &BackendUri) -> Result<()> {
        Err(crate::BackendError::DeleteNotSupported {
            backend_type: self.backend_type().to_owned(),
            reason: "default Backend::delete_secret impl — this backend has not implemented \
                     the v0.15 migrate --delete-source cleanup path",
        }
        .into())
    }

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

    /// Whether this backend supports native password generation
    /// (e.g. `op item create --generate-password`). v0.16 routes
    /// the MCP `gen_password` tool through backends that return
    /// `true`. v0.14 default is `false`; no backend overrides yet.
    ///
    /// Per SEC-INV-16 ([[v0.14-plus-security-invariants]]), there
    /// is NO standalone `secretenv gen` CLI surface — generation
    /// rides on MCP only.
    fn supports_native_gen(&self) -> bool {
        false
    }

    /// Declares the wire format this backend uses for its registry
    /// document on disk / over the wire.
    ///
    /// Default: [`RegistryFormat::Json`]. The `local` and `1password`
    /// backends override to [`RegistryFormat::Toml`] for
    /// human-readability (`local`) and field-storage compatibility
    /// (`1password`'s field bodies are human-edited).
    ///
    /// The actual encode/decode lives in free functions
    /// [`serialize_registry_doc`] / [`deserialize_registry_doc`]; the
    /// backend just declares which format it speaks. This split
    /// (v0.15 BREAKING arch-H1) keeps wire-format responsibility off
    /// the `Backend` trait — the inverse pattern was an over-fit at
    /// v0.14 since the format selection is purely about the wire
    /// representation, not anything backend-specific.
    fn registry_format(&self) -> RegistryFormat {
        RegistryFormat::Json
    }
}

/// Wire format for an alias → backend-URI registry document.
///
/// Each [`Backend`] declares which format it serializes/deserializes
/// via [`Backend::registry_format`]. The encode/decode itself is
/// format-driven, not backend-driven; see [`serialize_registry_doc`]
/// and [`deserialize_registry_doc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryFormat {
    /// JSON encoding (`serde_json`). Default for cloud/CLI-driven
    /// backends.
    Json,
    /// TOML encoding (`toml`). Used by file-on-disk and
    /// human-field-edited backends (`local`, `1password`).
    Toml,
}

/// Serialize an alias → backend-URI registry document into the
/// declared wire format.
///
/// A [`BTreeMap`] is required: it guarantees alphabetical key order
/// so writes are deterministic and diff-friendly.
///
/// **v0.15 BREAKING (arch-H1):** moved from the `Backend` trait to
/// this free function over the format enum. Backends now declare the
/// format via [`Backend::registry_format`] and let the wire-format
/// concern stay off the trait.
///
/// # Errors
/// Returns an error if the map cannot be encoded in the target
/// wire format.
pub fn serialize_registry_doc(
    format: RegistryFormat,
    map: &BTreeMap<String, String>,
) -> Result<String> {
    match format {
        RegistryFormat::Json => serde_json::to_string(map)
            .with_context(|| "serializing registry doc as JSON".to_owned()),
        RegistryFormat::Toml => {
            toml::to_string(map).with_context(|| "serializing registry doc as TOML".to_owned())
        }
    }
}

/// Inverse of [`serialize_registry_doc`].
///
/// **v0.15 BREAKING (arch-H1):** moved from the `Backend` trait to
/// this free function over the format enum.
///
/// # Errors
/// Returns an error if `body` is not a valid wire-format
/// registry document for the declared format.
pub fn deserialize_registry_doc(
    format: RegistryFormat,
    body: &str,
) -> Result<BTreeMap<String, String>> {
    match format {
        RegistryFormat::Json => serde_json::from_str(body)
            .with_context(|| "deserializing registry doc as JSON".to_owned()),
        RegistryFormat::Toml => {
            toml::from_str(body).with_context(|| "deserializing registry doc as TOML".to_owned())
        }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{BackendError, Secret};

    /// Strict-mock backend that overrides only the required trait
    /// methods. Used to exercise the default `Backend::write_secret`
    /// impl — the v0.15 contract is that any backend NOT overriding
    /// `write_secret` returns [`BackendError::WriteNotSupported`].
    struct UnimplementedBackend;

    #[async_trait]
    impl Backend for UnimplementedBackend {
        fn backend_type(&self) -> &'static str {
            "unimpl"
        }
        fn instance_name(&self) -> &'static str {
            "unimpl-test"
        }
        async fn check(&self) -> BackendStatus {
            BackendStatus::Ok {
                identity: "unimpl-test".to_owned(),
                cli_version: "0.0.0".to_owned(),
            }
        }
        async fn get(&self, _uri: &BackendUri) -> Result<Secret<String>> {
            Ok(Secret::new(String::new()))
        }
        async fn set(&self, _uri: &BackendUri, _value: &str) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _uri: &BackendUri) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _uri: &BackendUri) -> Result<Vec<(String, String)>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn default_write_secret_returns_write_not_supported() {
        let backend = UnimplementedBackend;
        let uri = BackendUri::parse("unimpl://path").unwrap();
        let value = Secret::new("v".to_owned());

        let err = backend.write_secret(&uri, &value).await.unwrap_err();
        let typed = err.downcast::<BackendError>().expect(
            "default write_secret must return a typed BackendError, not a plain anyhow::Error",
        );
        match typed {
            BackendError::WriteNotSupported { backend_type, reason } => {
                assert_eq!(backend_type, "unimpl");
                assert!(
                    reason.contains("default"),
                    "reason should name the default-impl origin: {reason}"
                );
            }
            other => panic!("expected WriteNotSupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn default_delete_secret_returns_delete_not_supported() {
        let backend = UnimplementedBackend;
        let uri = BackendUri::parse("unimpl://path").unwrap();

        let err = backend.delete_secret(&uri).await.unwrap_err();
        let typed = err.downcast::<BackendError>().expect(
            "default delete_secret must return a typed BackendError, not a plain anyhow::Error",
        );
        match typed {
            BackendError::DeleteNotSupported { backend_type, reason } => {
                assert_eq!(backend_type, "unimpl");
                assert!(
                    reason.contains("default"),
                    "reason should name the default-impl origin: {reason}"
                );
            }
            other => panic!("expected DeleteNotSupported, got {other:?}"),
        }
    }
}
