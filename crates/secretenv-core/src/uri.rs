//! URI parsing for backend references.
//!
//! A backend URI is the string form `<scheme>://<path>[#<fragment>]` used
//! throughout SecretEnv to name a secret. The scheme is the instance name
//! defined in `config.toml` (e.g. `aws-ssm-prod`, `vault-ops`) except for
//! the reserved `secretenv` scheme which denotes an alias reference to the
//! active registry.
//!
//! The optional `#<fragment>` suffix indicates a sub-field of the returned
//! secret or a per-request directive (e.g. a version pin) — used from v0.2.1+
//! under a canonical `key=value[,key=value]*` grammar. [`BackendUri::parse`]
//! preserves the fragment verbatim; typed parsing happens on demand via
//! [`BackendUri::fragment_directives`], which enforces the grammar. Each
//! backend interprets its own directive keys.
//!
//! Parsing is intentionally loose at the scheme/path layer: the scheme and
//! path are split on the first `://` occurrence and returned verbatim.
//! Backend-specific validation happens in each plugin's factory; fragment
//! grammar is enforced in [`BackendUri::fragment_directives`].
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use thiserror::Error;

/// A parsed backend URI of the form `scheme://path[#fragment]`.
///
/// # Examples
///
/// ```
/// use secretenv_core::BackendUri;
///
/// let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
/// assert_eq!(uri.scheme, "aws-ssm-prod");
/// assert_eq!(uri.path, "/prod/api-key");
/// assert_eq!(uri.fragment, None);
///
/// let alias = BackendUri::parse("secretenv://stripe-key").unwrap();
/// assert!(alias.is_alias());
///
/// let fragmented = BackendUri::parse("aws-secrets-prod:///db-creds#password").unwrap();
/// assert_eq!(fragmented.path, "/db-creds");
/// assert_eq!(fragmented.fragment.as_deref(), Some("password"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendUri {
    /// Instance-name portion before `://`. For the reserved scheme
    /// `secretenv` this marks an alias reference; for any other value
    /// it must match a `[backends.<name>]` block in `config.toml`.
    pub scheme: String,
    /// Path portion after `://` and before any `#`. May or may not start
    /// with `/` — the leading slash is significant for some backends
    /// (e.g. AWS SSM) and preserved here rather than normalized. The
    /// `#fragment` suffix is *not* included here even though it remains
    /// in [`Self::raw`].
    pub path: String,
    /// Optional fragment after `#`, identifying a sub-field of the
    /// backend's returned value (e.g. a JSON key). `None` when no `#`
    /// appears in the input, or when `#` is present but followed by an
    /// empty string (trailing-`#` is treated as "no fragment").
    pub fragment: Option<String>,
    /// The original unparsed string, preserved so error messages can
    /// quote it verbatim. Includes any `#fragment` suffix.
    pub raw: String,
}

impl BackendUri {
    /// Parse a `scheme://path[#fragment]` string into a [`BackendUri`].
    ///
    /// The fragment is split off *first* — so `scheme://path#has:slash`
    /// yields `path = "path"` and `fragment = Some("has:slash")`, not
    /// something treating the `:` inside the fragment as part of another
    /// scheme delimiter.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::Malformed`] if the input is missing the `://`
    /// separator, has an empty scheme, or has an empty path.
    pub fn parse(raw: &str) -> Result<Self, UriError> {
        let (without_frag, fragment) = match raw.split_once('#') {
            Some((left, "")) => (left, None),
            Some((left, right)) => (left, Some(right.to_owned())),
            None => (raw, None),
        };
        let (scheme, path) =
            without_frag.split_once("://").ok_or_else(|| UriError::Malformed(raw.to_owned()))?;
        if scheme.is_empty() || path.is_empty() {
            return Err(UriError::Malformed(raw.to_owned()));
        }
        if !is_valid_scheme(scheme) {
            return Err(UriError::InvalidScheme { scheme: scheme.to_owned(), raw: raw.to_owned() });
        }
        if has_forbidden_control_char(path) {
            return Err(UriError::InvalidCharacter { raw: raw.to_owned() });
        }
        if let Some(frag) = fragment.as_deref() {
            if has_forbidden_control_char(frag) {
                return Err(UriError::InvalidCharacter { raw: raw.to_owned() });
            }
        }
        warn_on_bidi_override(raw);
        Ok(Self { scheme: scheme.to_owned(), path: path.to_owned(), fragment, raw: raw.to_owned() })
    }

    /// Returns `true` if this URI is an alias reference (`secretenv://<alias>`).
    #[must_use]
    pub fn is_alias(&self) -> bool {
        self.scheme == "secretenv"
    }

    /// Parse the fragment as a `key=value[,key=value]*` directive map.
    ///
    /// Returns `Ok(None)` when the URI has no fragment.
    /// Returns `Ok(Some(directives))` when the fragment parses cleanly.
    /// Returns `Err(FragmentError)` when the fragment is non-empty but
    /// does not match the grammar — shorthand form (no `=`), empty
    /// directive, empty key or value, malformed key, duplicate key, or
    /// unescaped `=` in value.
    ///
    /// # Canonical grammar
    ///
    /// ```text
    /// fragment  := directive ("," directive)*
    /// directive := key "=" value
    /// key       := [a-z][a-z0-9-]*
    /// value     := non-empty, does not contain ',' or '='
    /// ```
    ///
    /// Backends interpret their own directive keys. See each backend's
    /// spec doc and the central fragment-vocabulary registry.
    ///
    /// # Errors
    ///
    /// See [`FragmentError`] for the full list of rejection conditions.
    /// In particular, legacy plain-string fragments (`#password`, no `=`)
    /// are rejected with a migration hint as of v0.2.1.
    pub fn fragment_directives(&self) -> Result<Option<HashMap<String, String>>, FragmentError> {
        let Some(raw) = self.fragment.as_deref() else {
            return Ok(None);
        };
        parse_fragment_directives(&self.raw, raw).map(Some)
    }
}

/// A scheme must be non-empty, contain only ASCII letters, digits, `_`,
/// or `-`, and may not start with `-` or `_`. Digit-leading schemes are
/// explicitly allowed so instance names like `1password-work` parse.
fn is_valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else { return false };
    if !(first.is_ascii_alphanumeric()) {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `true` if `s` contains NUL or any ASCII control char other than tab.
/// Newline / carriage return / ESC / etc. are all rejected because they
/// break `execvp` arg marshalling, corrupt `ps` output, and let a hostile
/// registry smuggle terminal-control sequences into error messages.
fn has_forbidden_control_char(s: &str) -> bool {
    s.bytes().any(|b| b == 0 || (b < 0x20 && b != b'\t'))
}

/// Parse a fragment string under the canonical `k=v[,k=v]*` grammar.
///
/// `uri_raw` is the full URI (including scheme and path) — included in
/// error messages so users see where the bad fragment came from.
/// `frag` is the fragment body (already split off from the leading `#`).
fn parse_fragment_directives(
    uri_raw: &str,
    frag: &str,
) -> Result<HashMap<String, String>, FragmentError> {
    // Shorthand detection runs first: a fragment containing no `=` is the
    // legacy plain-string form ([[build-plan-v0.2.1-fragment-canonicalization]]).
    // We reject with a migration hint that names the canonical replacement.
    if !frag.contains('=') {
        return Err(FragmentError::ShorthandRejected {
            uri: uri_raw.to_owned(),
            raw: frag.to_owned(),
        });
    }
    let mut out: HashMap<String, String> = HashMap::new();
    for part in frag.split(',') {
        if part.is_empty() {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: "empty directive (consecutive, leading, or trailing comma)".to_owned(),
            });
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: format!("directive '{part}' has no '=' separator"),
            });
        };
        if key.is_empty() {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: format!("directive '{part}' has empty key"),
            });
        }
        if value.is_empty() {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: format!("directive '{part}' has empty value"),
            });
        }
        if value.contains('=') {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: format!(
                    "directive '{part}' value contains '=' (unescaped equals \
                     are not permitted — use commas between directives)"
                ),
            });
        }
        if !is_valid_fragment_key(key) {
            return Err(FragmentError::Malformed {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                reason: format!(
                    "directive key '{key}' must match [a-z][a-z0-9-]* \
                     (lowercase kebab-case, letter-led)"
                ),
            });
        }
        if out.contains_key(key) {
            return Err(FragmentError::DuplicateKey {
                uri: uri_raw.to_owned(),
                raw: frag.to_owned(),
                key: key.to_owned(),
            });
        }
        out.insert(key.to_owned(), value.to_owned());
    }
    Ok(out)
}

/// A fragment-directive key must start with an ASCII lowercase letter and
/// contain only lowercase letters, digits, and ASCII hyphens. Keeps the
/// directive vocabulary visually consistent across backends; no
/// `snake_case`, no `camelCase`, no punctuation.
fn is_valid_fragment_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Emit a one-line warning if `raw` contains any Unicode bidirectional
/// override codepoint. These are not rejected — they can legitimately
/// appear in right-to-left paths — but they enable "Trojan Source"-style
/// spoofing where two URIs render identically despite differing in
/// routing. Logged once per parse so `doctor` output remains greppable.
fn warn_on_bidi_override(raw: &str) {
    const BIDI_OVERRIDES: &[char] = &[
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}',
    ];
    if raw.chars().any(|c| BIDI_OVERRIDES.contains(&c)) {
        tracing::warn!(
            uri = raw,
            "backend URI contains a Unicode bidirectional-override codepoint; visually \
             identical URIs may resolve to different backends"
        );
    }
}

/// Errors returned by [`BackendUri::parse`].
#[derive(Debug, Error)]
pub enum UriError {
    /// The input was not a valid `scheme://path` string.
    #[error("invalid backend URI: '{0}' — expected scheme://path with non-empty scheme and path")]
    Malformed(String),
    /// The scheme contains characters outside `[a-zA-Z][a-zA-Z0-9_-]*`.
    #[error(
        "invalid backend URI scheme: '{scheme}' in '{raw}' — schemes must match \
         [a-zA-Z0-9][a-zA-Z0-9_-]*"
    )]
    InvalidScheme {
        /// The offending scheme string.
        scheme: String,
        /// The full URI the scheme was parsed from.
        raw: String,
    },
    /// The path or fragment contains an ASCII control character (other
    /// than tab) or a NUL byte. These would either crash `execvp` or
    /// corrupt terminal output when surfaced in error messages.
    #[error(
        "invalid character in backend URI '{raw}' — paths and fragments may not contain \
         NUL bytes or ASCII control characters (except tab)"
    )]
    InvalidCharacter {
        /// The full URI the bad character appeared in.
        raw: String,
    },
}

/// Errors returned by [`BackendUri::fragment_directives`].
///
/// The canonical fragment grammar is `key=value[,key=value]*` under rules
/// defined in the `fragment-vocabulary` doc. Any fragment that does not
/// match the grammar surfaces through this enum with enough context for
/// a caller to produce a helpful user-facing message.
#[derive(Debug, Error)]
pub enum FragmentError {
    /// The fragment is a legacy plain-string shorthand (contains no `=`).
    /// Rejected as of v0.2.1 — the canonical form is always `<key>=<value>`.
    /// Each backend documents the keys it supports.
    #[error(
        "fragment '#{raw}' on URI '{uri}' uses legacy plain-string shorthand; \
         rewrite as '#<directive>=<value>' (for example, the aws-secrets backend \
         now requires '#json-key={raw}'). See docs/fragment-vocabulary.md"
    )]
    ShorthandRejected {
        /// The full URI the shorthand fragment appeared in.
        uri: String,
        /// The raw fragment body that triggered the shorthand rejection.
        raw: String,
    },
    /// The fragment is not shorthand but does not satisfy the directive
    /// grammar — malformed key, empty value, unescaped `=` in value, etc.
    #[error(
        "fragment '#{raw}' on URI '{uri}' is malformed: {reason}. \
         See docs/fragment-vocabulary.md"
    )]
    Malformed {
        /// The full URI the malformed fragment appeared in.
        uri: String,
        /// The raw fragment body.
        raw: String,
        /// Human-readable explanation naming the offending directive or token.
        reason: String,
    },
    /// The same directive key appears more than once in the fragment.
    /// Each directive key may appear at most once; no implicit merging.
    #[error(
        "fragment '#{raw}' on URI '{uri}' repeats key '{key}'; each directive \
         key may appear at most once"
    )]
    DuplicateKey {
        /// The full URI the duplicate-key fragment appeared in.
        uri: String,
        /// The raw fragment body.
        raw: String,
        /// The key that appeared more than once.
        key: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_scheme_and_path() {
        let uri = BackendUri::parse("local:///path/to/file.toml").unwrap();
        assert_eq!(uri.scheme, "local");
        assert_eq!(uri.path, "/path/to/file.toml");
        assert_eq!(uri.raw, "local:///path/to/file.toml");
    }

    #[test]
    fn parses_instance_scheme_without_leading_slash() {
        let uri = BackendUri::parse("secretenv://stripe-key").unwrap();
        assert_eq!(uri.scheme, "secretenv");
        assert_eq!(uri.path, "stripe-key");
    }

    #[test]
    fn parses_triple_slash_form_preserving_leading_slash() {
        let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
        assert_eq!(uri.scheme, "aws-ssm-prod");
        assert_eq!(uri.path, "/prod/api-key");
    }

    #[test]
    fn parses_double_slash_form_without_leading_slash() {
        let uri = BackendUri::parse("aws-ssm://prod/api-key").unwrap();
        assert_eq!(uri.scheme, "aws-ssm");
        assert_eq!(uri.path, "prod/api-key");
    }

    #[test]
    fn is_alias_when_scheme_is_secretenv() {
        let alias = BackendUri::parse("secretenv://stripe-key").unwrap();
        let not_alias = BackendUri::parse("aws-ssm-prod:///foo").unwrap();
        assert!(alias.is_alias());
        assert!(!not_alias.is_alias());
    }

    #[test]
    fn rejects_missing_delimiter() {
        assert!(matches!(BackendUri::parse("no-delimiter-here"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn rejects_empty_scheme() {
        assert!(matches!(BackendUri::parse("://stripe-key"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn rejects_empty_path() {
        assert!(matches!(BackendUri::parse("aws-ssm://"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn rejects_empty_string() {
        assert!(matches!(BackendUri::parse(""), Err(UriError::Malformed(_))));
    }

    #[test]
    fn rejects_single_colon_separator() {
        assert!(matches!(BackendUri::parse("scheme:path"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn splits_on_first_delimiter_only() {
        let uri = BackendUri::parse("scheme://path-with://in-it").unwrap();
        assert_eq!(uri.scheme, "scheme");
        assert_eq!(uri.path, "path-with://in-it");
    }

    #[test]
    fn preserves_raw_input_verbatim() {
        let raw = "aws-ssm-prod:///prod/api-key";
        let uri = BackendUri::parse(raw).unwrap();
        assert_eq!(uri.raw, raw);
    }

    #[test]
    fn error_display_includes_offending_input() {
        let err = BackendUri::parse("garbage").unwrap_err();
        assert!(err.to_string().contains("garbage"));
    }

    #[test]
    fn clone_and_eq() {
        let a = BackendUri::parse("local:///tmp/x").unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn no_fragment_when_hash_absent() {
        let uri = BackendUri::parse("aws-secrets:///db-creds").unwrap();
        assert_eq!(uri.fragment, None);
        assert_eq!(uri.path, "/db-creds");
    }

    #[test]
    fn fragment_parsed_when_hash_present() {
        let uri = BackendUri::parse("aws-secrets:///db-creds#password").unwrap();
        assert_eq!(uri.scheme, "aws-secrets");
        assert_eq!(uri.path, "/db-creds");
        assert_eq!(uri.fragment.as_deref(), Some("password"));
    }

    #[test]
    fn trailing_hash_with_empty_fragment_is_none() {
        let uri = BackendUri::parse("aws-secrets:///db-creds#").unwrap();
        assert_eq!(uri.fragment, None);
        assert_eq!(uri.path, "/db-creds");
    }

    #[test]
    fn fragment_captures_everything_after_first_hash() {
        let uri = BackendUri::parse("aws-secrets:///k#a#b").unwrap();
        assert_eq!(uri.path, "/k");
        assert_eq!(uri.fragment.as_deref(), Some("a#b"));
    }

    #[test]
    fn raw_preserves_fragment_suffix() {
        let raw = "aws-secrets:///db-creds#password";
        let uri = BackendUri::parse(raw).unwrap();
        assert_eq!(uri.raw, raw);
    }

    #[test]
    fn fragment_split_happens_before_scheme_split() {
        // A fragment containing `://` must not be re-interpreted as a scheme.
        let uri = BackendUri::parse("local:///x#path-with://in-it").unwrap();
        assert_eq!(uri.scheme, "local");
        assert_eq!(uri.path, "/x");
        assert_eq!(uri.fragment.as_deref(), Some("path-with://in-it"));
    }

    #[test]
    fn rejects_empty_path_even_with_fragment() {
        assert!(matches!(BackendUri::parse("aws-ssm://#frag"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn hash_before_scheme_separator_yields_malformed_input() {
        // `foo#://bar` — the `#` splits off `://bar` as fragment, leaving
        // `foo` which has no `://` separator → malformed.
        assert!(matches!(BackendUri::parse("foo#://bar"), Err(UriError::Malformed(_))));
    }

    #[test]
    fn fragment_not_included_in_equality_because_it_differs_in_raw() {
        // Two URIs with different fragments must compare non-equal.
        let a = BackendUri::parse("aws-secrets:///k#a").unwrap();
        let b = BackendUri::parse("aws-secrets:///k#b").unwrap();
        let none = BackendUri::parse("aws-secrets:///k").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, none);
    }

    #[test]
    fn accepts_valid_scheme_characters() {
        // Digit-leading schemes accepted: 1password is a real backend.
        for scheme in ["aws-ssm", "vault_prod", "a", "x-1_2-3", "A", "AwsSsm", "1password", "42"] {
            let raw = format!("{scheme}://path");
            assert!(BackendUri::parse(&raw).is_ok(), "scheme '{scheme}' should be valid");
        }
    }

    #[test]
    fn rejects_scheme_starting_with_dash_or_underscore() {
        for bad in ["-aws", "_aws"] {
            let raw = format!("{bad}://path");
            let err = BackendUri::parse(&raw).unwrap_err();
            assert!(
                matches!(err, UriError::InvalidScheme { .. }),
                "scheme '{bad}' should be rejected (must start with alphanumeric)"
            );
        }
    }

    #[test]
    fn rejects_scheme_with_invalid_characters() {
        for bad in ["aws ssm", "aws.ssm", "aws/ssm", "aws@ssm", "aws+ssm"] {
            let raw = format!("{bad}://path");
            let err = BackendUri::parse(&raw).unwrap_err();
            assert!(
                matches!(err, UriError::InvalidScheme { .. }),
                "scheme '{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn rejects_scheme_with_non_ascii() {
        // Cyrillic 'o' (U+043E) masquerading as ASCII 'o' — Trojan Source
        let err = BackendUri::parse("aws-ssm-pr\u{043E}d://path").unwrap_err();
        assert!(matches!(err, UriError::InvalidScheme { .. }));
    }

    #[test]
    fn rejects_nul_in_path() {
        let err = BackendUri::parse("local:///foo\0bar").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn rejects_newline_in_path() {
        let err = BackendUri::parse("local:///foo\nbar").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn rejects_carriage_return_in_path() {
        let err = BackendUri::parse("local:///foo\rbar").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn rejects_esc_in_path() {
        let err = BackendUri::parse("local:///foo\x1bbar").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn accepts_tab_in_path() {
        // Tab is ASCII 0x09, a control char we explicitly allow.
        let uri = BackendUri::parse("local:///foo\tbar").unwrap();
        assert_eq!(uri.path, "/foo\tbar");
    }

    #[test]
    fn rejects_nul_in_fragment() {
        let err = BackendUri::parse("aws-secrets:///k#ab\0cd").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn rejects_newline_in_fragment() {
        let err = BackendUri::parse("aws-secrets:///k#ab\ncd").unwrap_err();
        assert!(matches!(err, UriError::InvalidCharacter { .. }));
    }

    #[test]
    fn invalid_scheme_error_includes_scheme_and_raw() {
        let err = BackendUri::parse("aws.ssm://foo").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("aws.ssm"), "error mentions scheme: {msg}");
        assert!(msg.contains("aws.ssm://foo"), "error mentions raw URI: {msg}");
    }

    #[test]
    fn bidi_override_codepoint_is_accepted_but_warned() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — classic Trojan Source char.
        // We don't reject (legitimate RTL paths may use these) but the
        // parse path emits `tracing::warn!` — verified manually, test
        // just confirms parse still succeeds.
        let uri = BackendUri::parse("local:///safe\u{202E}path").unwrap();
        assert_eq!(uri.scheme, "local");
    }

    // ------------------------------------------------------------------
    // fragment_directives() — canonical k=v[,k=v]* grammar (v0.2.1+)
    // ------------------------------------------------------------------

    #[test]
    fn fragment_directives_returns_none_when_no_fragment() {
        let uri = BackendUri::parse("aws-secrets:///db-creds").unwrap();
        assert!(uri.fragment_directives().unwrap().is_none());
    }

    #[test]
    fn fragment_directives_parses_single_directive() {
        let uri = BackendUri::parse("aws-secrets:///db-creds#json-key=password").unwrap();
        let dirs = uri.fragment_directives().unwrap().unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs.get("json-key").map(String::as_str), Some("password"));
    }

    #[test]
    fn fragment_directives_parses_multiple_directives() {
        let uri = BackendUri::parse("gcp:///my-secret#version=5,project=foo").unwrap();
        let dirs = uri.fragment_directives().unwrap().unwrap();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs.get("version").map(String::as_str), Some("5"));
        assert_eq!(dirs.get("project").map(String::as_str), Some("foo"));
    }

    #[test]
    fn fragment_directives_rejects_shorthand_with_migration_hint() {
        // Legacy v0.2.0 shorthand — aws-secrets previously accepted `#password`
        // as "extract the `password` JSON field." v0.2.1 rejects this and
        // points users at the canonical `#json-key=password` replacement.
        let uri = BackendUri::parse("aws-secrets:///db-creds#password").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::ShorthandRejected { .. }));
        let msg = err.to_string();
        assert!(msg.contains("shorthand"), "error names the problem: {msg}");
        assert!(msg.contains("#json-key=password"), "error suggests canonical form: {msg}");
        assert!(msg.contains("fragment-vocabulary"), "error links to doc: {msg}");
        assert!(msg.contains("aws-secrets:///db-creds#password"), "error cites URI: {msg}");
    }

    #[test]
    fn fragment_directives_rejects_empty_directive_between_commas() {
        let uri = BackendUri::parse("gcp:///s#version=5,,project=foo").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("empty directive"));
    }

    #[test]
    fn fragment_directives_rejects_leading_comma() {
        let uri = BackendUri::parse("gcp:///s#,version=5").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
    }

    #[test]
    fn fragment_directives_rejects_trailing_comma() {
        let uri = BackendUri::parse("gcp:///s#version=5,").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
    }

    #[test]
    fn fragment_directives_rejects_mixed_shorthand_and_directive() {
        // Fragment body `version=5,bare` — the whole fragment contains `=` so
        // shorthand detection passes, but the second part is missing `=` and
        // must be reported as malformed (not shorthand-rejected).
        let uri = BackendUri::parse("gcp:///s#version=5,bare").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("'bare'"), "error names the bad directive: {err}");
    }

    #[test]
    fn fragment_directives_rejects_empty_key() {
        let uri = BackendUri::parse("gcp:///s#=value").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("empty key"));
    }

    #[test]
    fn fragment_directives_rejects_empty_value() {
        let uri = BackendUri::parse("gcp:///s#version=").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("empty value"));
    }

    #[test]
    fn fragment_directives_rejects_unescaped_equals_in_value() {
        // Value contains `=` — malformed; users who need `=` in a value
        // must use a different encoding (not addressed in v0.2.1).
        let uri = BackendUri::parse("gcp:///s#json-key=a=b").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("unescaped"));
    }

    #[test]
    fn fragment_directives_rejects_duplicate_key() {
        let uri = BackendUri::parse("gcp:///s#version=5,version=6").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::DuplicateKey { .. }));
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn fragment_directives_rejects_uppercase_key() {
        let uri = BackendUri::parse("gcp:///s#Version=5").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
        assert!(err.to_string().contains("lowercase"));
    }

    #[test]
    fn fragment_directives_rejects_digit_leading_key() {
        let uri = BackendUri::parse("gcp:///s#1version=5").unwrap();
        let err = uri.fragment_directives().unwrap_err();
        assert!(matches!(err, FragmentError::Malformed { .. }));
    }

    #[test]
    fn fragment_directives_accepts_hyphenated_key() {
        // aws-secrets's `json-key` is the canonical kebab-case key.
        let uri = BackendUri::parse("aws-secrets:///s#json-key=password").unwrap();
        let dirs = uri.fragment_directives().unwrap().unwrap();
        assert!(dirs.contains_key("json-key"));
    }

    #[test]
    fn fragment_directives_accepts_digits_in_key_after_first_char() {
        let uri = BackendUri::parse("gcp:///s#version2=5").unwrap();
        let dirs = uri.fragment_directives().unwrap().unwrap();
        assert_eq!(dirs.get("version2").map(String::as_str), Some("5"));
    }

    #[test]
    fn fragment_directives_accepts_value_with_dots_and_hyphens() {
        // Real-world: a GCP secret version pin like `5.2.1-alpha.1` or an
        // Azure Key Vault version GUID `12345678-abcd-...`.
        let uri = BackendUri::parse("azure:///kv#version=12345678-abcd-1234-ef56-9876").unwrap();
        let dirs = uri.fragment_directives().unwrap().unwrap();
        assert_eq!(
            dirs.get("version").map(String::as_str),
            Some("12345678-abcd-1234-ef56-9876"),
        );
    }

    #[test]
    fn fragment_directives_error_always_includes_full_uri() {
        // Error messages must quote the URI verbatim so a caller reading the
        // log can copy-paste-search for the offender.
        let uri = BackendUri::parse("aws-secrets:///db-creds#password").unwrap();
        let msg = uri.fragment_directives().unwrap_err().to_string();
        assert!(msg.contains("aws-secrets:///db-creds#password"), "message: {msg}");
    }

    #[test]
    fn fragment_directives_is_idempotent() {
        // Calling twice returns equivalent maps — no state mutated by the
        // first call. Cheap to assert; catches an accidental `take()` or
        // caching bug down the line.
        let uri = BackendUri::parse("gcp:///s#version=5,project=foo").unwrap();
        let a = uri.fragment_directives().unwrap().unwrap();
        let b = uri.fragment_directives().unwrap().unwrap();
        assert_eq!(a, b);
    }
}
