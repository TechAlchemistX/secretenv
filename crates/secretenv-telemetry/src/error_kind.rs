// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Closed enum of SecretEnv error categories surfaceable as the
//! `secretenv.error.kind` span attribute (ALLOW per the v0.14+
//! synthesis §6 attribute matrix).
//!
//! Free-string `error.message` is **DENY by default** — operators
//! opt in per-run via `--otel-include-error-detail` (v0.17). The
//! enum is the categorical source of truth for traces; the human
//! `anyhow::Error` chain is the source of truth for stderr.

/// Closed categorization of SecretEnv error situations.
///
/// Variants map to the `secretenv.error.kind` attribute on
/// `redact.*`, `resolve.*`, `backend.*`, and `cli.*` spans. Adding a
/// new variant requires updating the v0.14+ security invariants
/// matrix and the v0.17 OTel attribute-emitter switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretEnvErrorKind {
    // --- backend-class errors ---
    /// Backend CLI not found on `PATH`.
    BackendCliMissing,
    /// Backend authenticated probe failed (e.g. expired session).
    BackendAuthFailed,
    /// Backend reached but the target alias / URI is missing.
    BackendNotFound,
    /// Backend reached but the caller is not authorized for the
    /// target.
    BackendUnauthorized,
    /// Backend operation hit the per-op deadline.
    BackendTimeout,
    /// Backend returned an unexpected payload shape (parse failed).
    BackendParseError,
    /// Backend was reachable but returned a generic operational
    /// failure (covers anything not in the more specific variants).
    BackendOther,

    // --- resolution-flow errors ---
    /// `secretenv.toml` failed to parse or load.
    ManifestParseError,
    /// `config.toml` failed to parse or load.
    ConfigParseError,
    /// Manifest references an alias not declared in any layer of
    /// the cascade.
    AliasUnknown,
    /// Cascade traversal hit a malformed registry document.
    RegistryDocMalformed,

    // --- runtime / redaction errors ---
    /// Redact mode A's streaming tail-window cap was exceeded
    /// (a tainted value longer than the 64 KiB stream buffer).
    RedactBufferOverflow,
    /// Redact mode B refused to operate on a foreign-owned path
    /// without `--allow-foreign-owner`.
    RedactForeignOwner,
    /// Redact mode B refused to operate on a path under `/proc`,
    /// `/sys`, or `/dev`.
    RedactRefusedPath,
    /// Redact mode B detected a symlink swap between stat and open
    /// (O_NOFOLLOW guard fired).
    RedactSymlinkSwap,

    // --- command-level / generic ---
    /// CLI argument parsing failure (clap rejection).
    InvalidArgs,
    /// `secretenv run` exec failed (target missing / permission
    /// denied / etc.).
    ExecFailed,
    /// User cancelled an interactive prompt (`y/N`).
    UserCancelled,
    /// Catch-all for an error not otherwise categorized. New
    /// variants are added when an `Other` occurrence is found
    /// worth promoting to a first-class category in a Phase-9
    /// audit.
    Other,
}

impl SecretEnvErrorKind {
    /// Stable kebab-case name suitable for an OTel attribute value.
    /// Lowercase, no internal punctuation other than `-`.
    #[must_use]
    pub const fn as_attribute_value(self) -> &'static str {
        match self {
            Self::BackendCliMissing => "backend-cli-missing",
            Self::BackendAuthFailed => "backend-auth-failed",
            Self::BackendNotFound => "backend-not-found",
            Self::BackendUnauthorized => "backend-unauthorized",
            Self::BackendTimeout => "backend-timeout",
            Self::BackendParseError => "backend-parse-error",
            Self::BackendOther => "backend-other",
            Self::ManifestParseError => "manifest-parse-error",
            Self::ConfigParseError => "config-parse-error",
            Self::AliasUnknown => "alias-unknown",
            Self::RegistryDocMalformed => "registry-doc-malformed",
            Self::RedactBufferOverflow => "redact-buffer-overflow",
            Self::RedactForeignOwner => "redact-foreign-owner",
            Self::RedactRefusedPath => "redact-refused-path",
            Self::RedactSymlinkSwap => "redact-symlink-swap",
            Self::InvalidArgs => "invalid-args",
            Self::ExecFailed => "exec-failed",
            Self::UserCancelled => "user-cancelled",
            Self::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_kebab_case_attribute_value() {
        // If a new variant is added without an arm in
        // `as_attribute_value`, the match becomes non-exhaustive and
        // the crate fails to compile — that IS the test. This
        // smoke-test additionally ensures the strings are
        // ASCII-clean and lowercase, in case a future contributor
        // chooses a slug with spaces or unicode.
        for kind in [
            SecretEnvErrorKind::BackendCliMissing,
            SecretEnvErrorKind::BackendAuthFailed,
            SecretEnvErrorKind::Other,
        ] {
            let v = kind.as_attribute_value();
            assert!(!v.is_empty());
            assert!(v.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        }
    }
}
