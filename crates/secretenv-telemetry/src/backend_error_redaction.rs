// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! SEC-INV-20 shape-based scrubber for backend stderr crossing into
//! trusted-surface emission paths (OTel span attributes, `doctor`
//! terminal output, etc.).
//!
//! v0.17's redaction strategy treated `error.message` as a flat DENY:
//! backend stderr never reached a span attribute at all. v0.18's
//! `--otel-include-error-detail` flag opens a narrow opt-in: operators
//! who run their own collector can ask for the scrubbed stderr text
//! when a backend fetch fails, so they can debug from the trace UI.
//!
//! This module is the structural gate that makes the opt-in safe.
//! [`BackendErrorStderr`] is a newtype with a private inner string;
//! the only constructor is [`BackendErrorStderr::scrub`], which runs
//! the input through the regex set below before storing it. Once you
//! hold a `BackendErrorStderr`, you can trust it has been scrubbed.
//!
//! Patterns stripped (in order):
//! 1. **URI shapes** — anything matching `https?://...` or a
//!    `host[:port][/path]` cluster. Hides internal hostnames and
//!    secret paths (`vault.prod.internal:8200/v1/secret/...`).
//! 2. **AWS 12-digit account IDs** — bare 12-digit runs surrounded by
//!    word boundaries.
//! 3. **High-entropy tokens** — runs of 32+ chars from the base64
//!    alphabet (`A-Za-z0-9+/=_-`). Catches access tokens, session
//!    cookies, and similar.
//!
//! Each match is replaced with a fixed placeholder. The substitution
//! is deliberately coarser than perfect; the goal is "no operator
//! ever leaks an internal hostname to their trace collector via this
//! path," not "produce a beautiful redacted text." When in doubt the
//! regex over-matches.
//!
//! This module lives in `secretenv-telemetry` (not `secretenv-core`)
//! because the `SecretEnvSpan::record_backend_error_message_scrubbed`
//! setter consumes `&BackendErrorStderr` and `secretenv-telemetry`
//! cannot depend on `secretenv-core` (the dep direction is the
//! reverse — core depends on telemetry for span emission).
//! `secretenv-core` re-exports the type for ergonomic use.
//!
//! See:
//! - [[v0.14-plus-security-invariants]] SEC-INV-20 — backend stderr
//!   redaction invariant.
//! - [[build-plan-v0.18-hardening]] §Phase 1 — D-5.1 + D-5.2.
//! - [[v0.17-deferred-items]] §3 D-5.1 — the deferral entry this
//!   module closes.

use regex::Regex;
use std::sync::OnceLock;

/// Backend stderr text after the SEC-INV-20 scrubber has run.
///
/// The inner [`String`] is private; the only way to construct a
/// `BackendErrorStderr` is through [`BackendErrorStderr::scrub`].
/// Holding a value of this type is the proof obligation that the
/// scrubber has executed. The OTel emission setter
/// `SecretEnvSpan::record_backend_error_message_scrubbed` takes
/// `&BackendErrorStderr`, which is structurally impossible to
/// construct from raw text.
#[derive(Debug, Clone)]
pub struct BackendErrorStderr(String);

impl BackendErrorStderr {
    /// Run the SEC-INV-20 scrubber on `raw` and wrap the result.
    ///
    /// Allocates one fresh `String`. The regex patterns are compiled
    /// once at first call via [`OnceLock`].
    #[must_use]
    pub fn scrub(raw: &str) -> Self {
        Self(scrub_backend_stderr(raw))
    }

    /// Borrow the scrubbed text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BackendErrorStderr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

const URI_REPLACEMENT: &str = "<uri-stripped>";
const AWS_ACCOUNT_REPLACEMENT: &str = "<aws-account-stripped>";
const TOKEN_REPLACEMENT: &str = "<token-stripped>";

fn uri_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Statically-valid regex; `Regex::new` cannot fail here. Pattern
    // is hand-audited; an init-time panic would surface at first
    // scrub() call, not in a production user path.
    #[allow(clippy::expect_used)]
    RE.get_or_init(|| {
        // Three arms:
        //   1. Scheme-prefixed: `https?://<non-whitespace>+`
        //   2. Bare host-with-path: `<host>(:port)?/<path>` — requires
        //      a `/` after the host segment so we don't strip every
        //      colon-prefixed value (a hex digest, for instance).
        //   3. Bare host-with-port (no path): `<host>:<port>` — added
        //      in v0.18 Phase 7b Sec-F-1. Catches stderr of the form
        //      `connection refused: vault.prod.internal:8200` that
        //      arm 2 missed. Gated on a literal port so we don't
        //      over-match arbitrary dotted prose like "filename.ext"
        //      or "module.path:42" line refs.
        //
        // Host segment: at least one dot to avoid matching plain words.
        Regex::new(
            r"(?x)
            \b
            (?:
              https?://[^\s'\u{0022}]+
              |
              [A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?
              (?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+
              (?::\d{1,5})?
              /[^\s'\u{0022}]*
              |
              [A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?
              (?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+
              :\d{1,5}\b
            )
        ",
        )
        .expect("uri regex is statically valid")
    })
}

fn aws_account_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    RE.get_or_init(|| Regex::new(r"\b\d{12}\b").expect("aws account regex is statically valid"))
}

fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // 32+ chars from base64 / token-safe alphabet, bounded by
    // non-alphanumeric or string edges. Length threshold of 32 avoids
    // matching most short identifiers while catching session tokens
    // and access keys (typical lengths 40-128).
    #[allow(clippy::expect_used)]
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9+/=_-]{32,}").expect("token regex is statically valid")
    })
}

/// Run the three-pass shape scrubber on `raw` and return a fresh
/// `String`. Pass order matters: URI first (most contextual), then
/// AWS account ID (12-digit), then high-entropy tokens.
fn scrub_backend_stderr(raw: &str) -> String {
    let mut out = uri_regex().replace_all(raw, URI_REPLACEMENT).into_owned();
    out = aws_account_regex().replace_all(&out, AWS_ACCOUNT_REPLACEMENT).into_owned();
    out = token_regex().replace_all(&out, TOKEN_REPLACEMENT).into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_https_url_with_secret_path() {
        let raw =
            "fetch failed: GET https://vault.prod.internal:8200/v1/secret/payments/stripe -> 403";
        let scrubbed = BackendErrorStderr::scrub(raw);
        let s = scrubbed.as_str();
        assert!(!s.contains("vault.prod.internal"), "host leaked: {s}");
        assert!(!s.contains("payments"), "path segment leaked: {s}");
        assert!(!s.contains("stripe"), "path segment leaked: {s}");
        assert!(s.contains(URI_REPLACEMENT), "placeholder missing: {s}");
    }

    #[test]
    fn strips_bare_host_with_path() {
        let raw = "connection refused at vault.prod.internal:8200/v1/secret/payments/stripe";
        let scrubbed = BackendErrorStderr::scrub(raw);
        let s = scrubbed.as_str();
        assert!(!s.contains("vault.prod.internal"), "host leaked: {s}");
        assert!(!s.contains("payments"), "path segment leaked: {s}");
    }

    #[test]
    fn strips_bare_host_with_port_no_path() {
        // v0.18 Phase 7b Sec-F-1 regression. The pre-Phase-7b scrubber
        // required a trailing `/path` to match the bare-host arm, so
        // a path-less `host:port` cluster preserved the internal
        // hostname — the exact topology fingerprint SEC-INV-20 is
        // meant to hide.
        let raw = "connection refused: vault.prod.internal:8200";
        let scrubbed = BackendErrorStderr::scrub(raw);
        let s = scrubbed.as_str();
        assert!(!s.contains("vault.prod.internal"), "host leaked: {s}");
        assert!(!s.contains("8200"), "port leaked: {s}");
        assert!(s.contains(URI_REPLACEMENT), "placeholder missing: {s}");
    }

    #[test]
    fn does_not_overmatch_dotted_text_without_port() {
        // The Phase 7b bare-host-port arm requires a literal port to
        // avoid stripping arbitrary dotted prose. Filenames and
        // module paths without a `:port` suffix must survive.
        let raw = "parsed module foo.bar.baz from config.toml line 42";
        let scrubbed = BackendErrorStderr::scrub(raw);
        let s = scrubbed.as_str();
        assert!(s.contains("foo.bar.baz"), "module path over-stripped: {s}");
        assert!(s.contains("config.toml"), "filename over-stripped: {s}");
    }

    #[test]
    fn strips_aws_account_id() {
        let raw = "access denied for account 123456789012 on resource arn:aws:iam";
        let scrubbed = BackendErrorStderr::scrub(raw);
        assert!(!scrubbed.as_str().contains("123456789012"), "account id leaked: {scrubbed}");
    }

    #[test]
    fn strips_high_entropy_token() {
        let raw = "auth failed with token AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE";
        let scrubbed = BackendErrorStderr::scrub(raw);
        assert!(!scrubbed.as_str().contains("AKIAIOSFODNN7EXAMPLE"), "token leaked: {scrubbed}");
    }

    #[test]
    fn preserves_short_safe_words() {
        let raw = "fetch failed with status 403";
        let scrubbed = BackendErrorStderr::scrub(raw);
        let s = scrubbed.as_str();
        assert!(s.contains("fetch failed"), "stripped too much: {s}");
        assert!(s.contains("403"), "stripped status code: {s}");
    }

    #[test]
    fn idempotent() {
        let raw = "fetch failed: https://vault.prod.internal:8200/v1/secret 403 token AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE";
        let once = BackendErrorStderr::scrub(raw);
        let twice = BackendErrorStderr::scrub(once.as_str());
        assert_eq!(once.as_str(), twice.as_str(), "second pass changed output");
    }

    #[test]
    fn strips_sha256_hex_digest_documented_overmatch() {
        // v0.19 Sec-F-6 / Sec-P9-4. The token arm is `[A-Za-z0-9+/=_-]{32,}`,
        // so a 64-char SHA-256 hex digest matches and is stripped. This
        // is a deliberate, documented OVER-match: a content hash is not
        // a secret, but the scrubber errs toward stripping any
        // high-entropy 32+ char run rather than risk leaking a real
        // token that happens to be hex-shaped (an API key, a bearer
        // token). This test pins that behavior so a future regex
        // tightening that narrowed the token arm — and silently started
        // emitting digests — would fail loudly and force a deliberate
        // decision rather than an accidental disclosure-surface change.
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(digest.len(), 64, "fixture must be a 64-char SHA-256 hex");
        let raw = format!("integrity check failed: expected {digest} got mismatch");
        let scrubbed = BackendErrorStderr::scrub(&raw);
        let s = scrubbed.as_str();
        assert!(!s.contains(digest), "64-hex digest survived the token scrubber: {s}");
        assert!(s.contains(TOKEN_REPLACEMENT), "token placeholder missing: {s}");
        // The non-entropy context around it is preserved.
        assert!(s.contains("integrity check failed"), "context over-stripped: {s}");
    }
}
