//! URI parsing for backend references.
//!
//! A backend URI is the string form `<scheme>://<path>` used throughout
//! SecretEnv to name a secret. The scheme is the instance name defined in
//! `config.toml` (e.g. `aws-ssm-prod`, `vault-ops`) except for the
//! reserved `secretenv` scheme which denotes an alias reference to the
//! active registry.
//!
//! Parsing is intentionally loose: the scheme and path are split on the
//! first `://` occurrence and returned verbatim. Backend-specific
//! validation happens in each plugin's factory.
#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

/// A parsed backend URI of the form `scheme://path`.
///
/// # Examples
///
/// ```
/// use secretenv_core::BackendUri;
///
/// let uri = BackendUri::parse("aws-ssm-prod:///prod/api-key").unwrap();
/// assert_eq!(uri.scheme, "aws-ssm-prod");
/// assert_eq!(uri.path, "/prod/api-key");
///
/// let alias = BackendUri::parse("secretenv://stripe-key").unwrap();
/// assert!(alias.is_alias());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendUri {
    /// Instance-name portion before `://`. For the reserved scheme
    /// `secretenv` this marks an alias reference; for any other value
    /// it must match a `[backends.<name>]` block in `config.toml`.
    pub scheme: String,
    /// Path portion after `://`. May or may not start with `/` — the
    /// leading slash is significant for some backends (e.g. AWS SSM)
    /// and preserved here rather than normalized.
    pub path: String,
    /// The original unparsed string, preserved so error messages can
    /// quote it verbatim.
    pub raw: String,
}

impl BackendUri {
    /// Parse a `scheme://path` string into a [`BackendUri`].
    ///
    /// # Errors
    ///
    /// Returns [`UriError::Malformed`] if the input is missing the `://`
    /// separator, has an empty scheme, or has an empty path.
    pub fn parse(raw: &str) -> Result<Self, UriError> {
        let (scheme, path) =
            raw.split_once("://").ok_or_else(|| UriError::Malformed(raw.to_owned()))?;
        if scheme.is_empty() || path.is_empty() {
            return Err(UriError::Malformed(raw.to_owned()));
        }
        Ok(Self { scheme: scheme.to_owned(), path: path.to_owned(), raw: raw.to_owned() })
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
}
