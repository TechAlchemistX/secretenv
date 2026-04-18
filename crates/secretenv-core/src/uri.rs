//! URI parsing for backend references.
//!
//! A backend URI is the string form `<scheme>://<path>[#<fragment>]` used
//! throughout SecretEnv to name a secret. The scheme is the instance name
//! defined in `config.toml` (e.g. `aws-ssm-prod`, `vault-ops`) except for
//! the reserved `secretenv` scheme which denotes an alias reference to the
//! active registry.
//!
//! The optional `#<fragment>` suffix indicates a sub-field of the returned
//! secret — used in v0.2+ by backends whose secret values are structured
//! (e.g. AWS Secrets Manager JSON blobs). The fragment is parsed here but
//! interpreted by each backend's `get` implementation.
//!
//! Parsing is intentionally loose: the scheme and path are split on the
//! first `://` occurrence and returned verbatim. Backend-specific
//! validation happens in each plugin's factory.
#![allow(clippy::module_name_repetitions)]

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
        let (scheme, path) = without_frag
            .split_once("://")
            .ok_or_else(|| UriError::Malformed(raw.to_owned()))?;
        if scheme.is_empty() || path.is_empty() {
            return Err(UriError::Malformed(raw.to_owned()));
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            path: path.to_owned(),
            fragment,
            raw: raw.to_owned(),
        })
    }

    /// Returns `true` if this URI is an alias reference (`secretenv://<alias>`).
    #[must_use]
    pub fn is_alias(&self) -> bool {
        self.scheme == "secretenv"
    }
}

/// Errors returned by [`BackendUri::parse`].
#[derive(Debug, Error)]
pub enum UriError {
    /// The input was not a valid `scheme://path` string.
    #[error("invalid backend URI: '{0}' — expected scheme://path with non-empty scheme and path")]
    Malformed(String),
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
}
