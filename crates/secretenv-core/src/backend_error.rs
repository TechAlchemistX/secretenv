// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed errors raised by [`crate::Backend`] implementations.
//!
//! v0.1 → v0.14 used `anyhow::Result<...>` everywhere. v0.15 introduces
//! [`BackendError`] as a typed surface for error classes the
//! `secretenv registry migrate` handler and the (future) MCP layer
//! need to dispatch on structurally rather than by string-matching
//! `anyhow::Error` context.
//!
//! Variants stay `From<BackendError>`-convertible into `anyhow::Error`,
//! so existing call sites that return `anyhow::Result<()>` still
//! compile — they just lose nothing by upgrading to typed-match
//! when they actually care about the variant.
//!
//! See:
//! - [[build-plan-v0.15-migrate]] §Phase 1 — `WriteNotSupported`.
//! - [[v0.14-plus-security-invariants]] SEC-INV-04 — closed ``OTel``
//!   error-kind enum maps each variant to a stable kebab-case
//!   attribute value.
//! - [[v0.14-plus-security-invariants]] SEC-INV-14 — closed MCP
//!   error-kind enum maps each variant for the MCP boundary.

use thiserror::Error;

/// Typed error classes raised by [`crate::Backend`] implementations
/// when the v0.15 migrate handler (or any structural consumer) needs
/// to dispatch on the failure variant rather than parse context.
///
/// Every variant is `From<Self>`-convertible into `anyhow::Error` so
/// `anyhow::Result<()>`-returning call sites stay source-compatible.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BackendError {
    /// The backend declares it cannot write at this URI. Default
    /// trait-method implementations of [`crate::Backend::write_secret`]
    /// return this; backends that gate `write_secret` behind a config
    /// flag (`1password`'s `op_unsafe_set`, `bitwarden-sm`'s
    /// `bws_unsafe_set`, `keeper`'s `keeper_unsafe_set`) also return
    /// this with a `reason` naming the unset flag.
    ///
    /// Maps to:
    /// - `secretenv.error.kind = "write_not_supported"` on the `OTel`
    ///   attribute (SEC-INV-04 closed enum).
    /// - `McpErrorKind::BackendNotConfigured` on the MCP boundary
    ///   (SEC-INV-14 closed enum) — backend exists and is reachable,
    ///   but write is unavailable until the operator opts in.
    #[error("backend type '{backend_type}' cannot write at this URI: {reason}")]
    WriteNotSupported {
        /// The `backend_type()` value returned by the impl raising
        /// this error. Stable across versions; used as the `OTel`
        /// `secretenv.backend.type` attribute alongside this variant.
        ///
        /// Owned `String` rather than `&'static str` so backends can
        /// pass their `backend_type()` borrow without leaking a
        /// `Box::leak`-shaped allocation.
        backend_type: String,
        /// Operator-readable explanation of why the write is
        /// unavailable. Never carries the URI, alias name, or value.
        ///
        /// `&'static str` because the reason is always a compile-time
        /// literal at the call site (e.g. `"op_unsafe_set is false"`).
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_not_supported_renders_with_backend_type_and_reason() {
        let e = BackendError::WriteNotSupported {
            backend_type: "1password".to_owned(),
            reason: "op_unsafe_set is false",
        };
        let rendered = format!("{e}");
        assert!(rendered.contains("1password"), "{rendered}");
        assert!(rendered.contains("op_unsafe_set is false"), "{rendered}");
    }

    #[test]
    fn write_not_supported_converts_into_anyhow() {
        let e = BackendError::WriteNotSupported {
            backend_type: "keeper".to_owned(),
            reason: "keeper_unsafe_set is false",
        };
        let any: anyhow::Error = e.into();
        let chain = format!("{any:#}");
        assert!(chain.contains("keeper"), "{chain}");
    }
}
