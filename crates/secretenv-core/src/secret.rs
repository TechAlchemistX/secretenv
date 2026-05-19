// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The [`Secret`] newtype — the in-memory carrier for fetched secret
//! values.
//!
//! Every backend's [`Backend::get`](crate::Backend::get) returns a
//! `Secret<String>`. The newtype is the structural enforcement point
//! that prevents accidental value leaks via `format!`, `Display`,
//! `Serialize`, `Clone`, or `Into<String>`. The inner buffer is
//! zeroed on drop via [`zeroize::Zeroizing`].
//!
//! Access:
//!
//! - [`Secret::new`] — always available; wrap a freshly fetched value.
//! - [`Secret::expose_secret`] — gated behind
//!   `cfg(not(feature = "mcp-safe"))`. The CLI links without the
//!   feature and can read values; the MCP server (v0.16+) links with
//!   the feature on and cannot read values at all.
//! - Custom [`Debug`] — emits `Secret([REDACTED])`; never the value.
//!
//! Deliberate *non*-impls (the structural guarantees):
//!
//! - No [`Display`](std::fmt::Display) — `format!("{val}")` will not
//!   compile.
//! - No [`Clone`] — duplicating a secret requires `new(expose_secret(...).to_owned())`,
//!   making any clone-site grep-able.
//! - No [`serde::Serialize`] or [`serde::Deserialize`] — values
//!   cannot accidentally land in JSON/YAML/TOML output.
//! - No [`From<String>`] / [`Into<String>`] — implicit conversions
//!   into plain `String` are blocked.
//! - No [`PartialEq`] / [`Eq`] / [`Hash`] — timing-attack-safe equality
//!   is out of scope; equality must be explicit.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// In-memory wrapper for a fetched secret value.
///
/// Generic over the inner zeroizable type (`String` in v0.14;
/// `Vec<u8>` reserved for future binary-secret use cases). The buffer
/// is zeroized on drop via [`Zeroizing`].
///
/// See the module docs for the structural-guarantee rationale.
pub struct Secret<T>(Zeroizing<T>)
where
    T: Zeroize;

impl<T> Secret<T>
where
    T: Zeroize,
{
    /// Wrap a freshly fetched value. The caller transfers ownership
    /// into the [`Secret`]; the inner buffer is zeroed on drop.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl Secret<String> {
    /// Borrow the inner string for the duration of the borrow.
    ///
    /// Gated behind `cfg(not(feature = "mcp-safe"))`. Crates that
    /// enable the `mcp-safe` feature lose access to this method
    /// entirely — by construction, they cannot read secret values
    /// through any safe API. See [`crate::mcp_safe`].
    ///
    /// The CLI never enables `mcp-safe`; the MCP server (v0.16) does.
    #[cfg(feature = "value-access")]
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Crate-internal accessor used by the runner's `exec`/`spawn`
    /// path to inject the value into the child-process environment.
    /// Always available regardless of the `mcp-safe` feature — the
    /// public structural guarantee is about external API surface;
    /// internal injection is the one legitimate use.
    #[must_use]
    pub(crate) fn as_str_internal(&self) -> &str {
        self.0.as_str()
    }
}

impl<T> fmt::Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include the inner value or its length. A length leak
        // can be enough to identify which secret class a value belongs
        // to (e.g., 40-char Stripe key vs 32-char Anthropic key);
        // emitting just a constant marker preserves the structural
        // guarantee.
        f.write_str("Secret([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_format_is_redacted() {
        let s = Secret::new(String::from("sk_live_abc123"));
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "Secret([REDACTED])");
        assert!(!dbg.contains("sk_live"));
        assert!(!dbg.contains("abc123"));
    }

    #[test]
    fn expose_secret_round_trip() {
        let s = Secret::new(String::from("payload"));
        assert_eq!(s.expose_secret(), "payload");
    }

    #[test]
    fn new_accepts_owned_string() {
        let raw = String::from("hello");
        let s = Secret::new(raw);
        assert_eq!(s.expose_secret(), "hello");
    }
}
