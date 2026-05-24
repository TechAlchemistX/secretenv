// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Safe error rendering for MCP response payloads.
//!
//! # SEC-INV-20 enforcement
//!
//! Every `error_message` field on a tool response is rendered through
//! [`safe_error_message`]. The function walks the `anyhow::Error`
//! chain and strips any `scheme://body` URI substrings — replacing
//! them with `scheme://[redacted]`. This is the defense-in-depth
//! layer that catches URI leaks bubbling up from `with_context`
//! layers in `secretenv-core` / `secretenv-migrate` / our own code
//! where source-level review may have missed a URI interpolation.
//!
//! The first line of defense is still source-side: never put a URI
//! body in a `format!` that flows into `with_context`. Use registry
//! names, alias names, or backend scheme tokens instead. This module
//! is the backstop.

/// Render an [`anyhow::Error`] chain as a single string with any
/// `scheme://body` URI patterns redacted to `scheme://[redacted]`.
///
/// Used in place of `format!("{e:#}")` at every site where an error
/// flows into a tool response's `error_message` field.
#[must_use]
pub fn safe_error_message(err: &anyhow::Error) -> String {
    let raw = format!("{err:#}");
    redact_uris(&raw)
}

/// Strip `scheme://body` URI substrings from `s`.
///
/// A `scheme` is any non-empty run of ASCII alphanumerics, `-`, `+`,
/// or `.` immediately preceding `://`. The `body` is the longest run
/// of characters that follows the `://` and excludes whitespace,
/// backticks, single quotes, and double quotes — the typical
/// surrounding punctuation of a URI in an error-context string.
///
/// Returns the input unchanged if no `://` substring is found.
///
/// Conservative by design: a URL like `https://docs.example.com` in
/// an error message will also be redacted to `https://[redacted]`.
/// That's acceptable — error messages rarely contain helpful
/// hyperlinks, and false-positive redaction is preferable to
/// false-negative leakage of a backend URI.
fn redact_uris(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b':' && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
            let mut scheme_start = i;
            while scheme_start > 0 {
                let b = bytes[scheme_start - 1];
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'+' || b == b'.' {
                    scheme_start -= 1;
                } else {
                    break;
                }
            }
            if scheme_start < i {
                out.push_str(&s[last..scheme_start]);
                out.push_str(&s[scheme_start..=i + 2]);
                let mut body_end = i + 3;
                while body_end < bytes.len() {
                    let b = bytes[body_end];
                    if b.is_ascii_whitespace() || matches!(b, b'`' | b'\'' | b'"') {
                        break;
                    }
                    body_end += 1;
                }
                out.push_str("[redacted]");
                last = body_end;
                i = body_end;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Convenience for non-anyhow error-context strings that may also
/// contain URIs (e.g. messages already serialized into config-parse
/// errors). Delegates to [`redact_uris`].
#[must_use]
pub fn redact_str(s: &str) -> String {
    redact_uris(s)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_passes_through() {
        assert_eq!(redact_uris(""), "");
    }

    #[test]
    fn plain_text_unchanged() {
        assert_eq!(redact_uris("no URI here, just text"), "no URI here, just text");
    }

    #[test]
    fn bare_op_uri() {
        assert_eq!(redact_uris("op://vault/secret"), "op://[redacted]");
    }

    #[test]
    fn vault_uri_in_backticks() {
        assert_eq!(
            redact_uris("reading registry document at `vault://prod/secret/foo`"),
            "reading registry document at `vault://[redacted]`",
        );
    }

    #[test]
    fn aws_sm_uri_in_quotes() {
        assert_eq!(
            redact_uris("fetching \"aws-sm://us-east-1/myapp/db-pass\" failed"),
            "fetching \"aws-sm://[redacted]\" failed",
        );
    }

    #[test]
    fn multiple_uris_in_one_chain() {
        let chain = "writing to `op://primary/key`: cause: reading `vault://hot/sec` failed";
        let want = "writing to `op://[redacted]`: cause: reading `vault://[redacted]` failed";
        assert_eq!(redact_uris(chain), want);
    }

    #[test]
    fn scheme_with_hyphen_and_digits() {
        assert_eq!(
            redact_uris("connecting to gcp-sm-2://proj/sec/v1 timed out"),
            "connecting to gcp-sm-2://[redacted] timed out",
        );
    }

    #[test]
    fn https_url_also_redacted() {
        // Documented: conservative; false-positive redaction is acceptable.
        assert_eq!(
            redact_uris("see https://docs.example.com for help"),
            "see https://[redacted] for help",
        );
    }

    #[test]
    fn standalone_double_slash_no_scheme() {
        // `://` with no scheme chars before it is left alone.
        assert_eq!(redact_uris("just :// alone"), "just :// alone");
    }

    #[test]
    fn uri_at_end_of_string() {
        assert_eq!(redact_uris("at vault://x"), "at vault://[redacted]");
    }

    #[test]
    fn uri_at_start_of_string() {
        assert_eq!(redact_uris("op://x is missing"), "op://[redacted] is missing");
    }

    #[test]
    fn truncated_colon_slash_alone() {
        // `://` with nothing follows: body is empty, gets [redacted].
        assert_eq!(redact_uris("op:// ends"), "op://[redacted] ends");
    }

    #[test]
    fn safe_error_message_walks_anyhow_chain() {
        let inner = anyhow::anyhow!("inner failure on `vault://prod/sec`");
        let wrapped = inner.context("middle layer for op://primary/x");
        let outer = wrapped.context("outer label");
        let rendered = safe_error_message(&outer);
        assert!(rendered.contains("outer label"));
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("vault://prod"));
        assert!(!rendered.contains("op://primary"));
    }
}
