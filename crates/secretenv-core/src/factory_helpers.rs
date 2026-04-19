//! Shared config-extraction helpers for backend factories.
//!
//! v0.2 had `required_string` / `optional_string` duplicated verbatim
//! across `secretenv-backend-{aws-ssm,aws-secrets,vault}` with only the
//! backend-type label differing. This module unifies them so v0.3
//! backends (gcp, azure) use the same error shape without copying code.
//!
//! # Error shape
//!
//! Errors follow the v0.2 convention:
//!
//! - Missing: `"<backend_type> instance '<name>': missing required field
//!   '<field>' (set <field> = \"...\" under [backends.<name>])"`.
//! - Wrong type: `"<backend_type> instance '<name>': field '<field>' must
//!   be a string, got <actual-type>"`.
//!
//! Pass the backend's type label (e.g. `"aws-ssm"`, `"gcp"`) as the first
//! argument; the label becomes the error prefix and appears in every
//! `BackendFactory::create` error.

use std::collections::HashMap;
use std::hash::BuildHasher;

use anyhow::{anyhow, Result};

/// Extract a required string field from the factory config block. Errors
/// if the field is absent OR present with a non-string value.
///
/// # Errors
///
/// See module-level docs for the exact message shapes.
pub fn required_string<S: BuildHasher>(
    config: &HashMap<String, toml::Value, S>,
    field: &str,
    backend_type: &str,
    instance_name: &str,
) -> Result<String> {
    let value = config.get(field).ok_or_else(|| {
        anyhow!(
            "{backend_type} instance '{instance_name}': missing required field '{field}' \
             (set {field} = \"...\" under [backends.{instance_name}])"
        )
    })?;
    value.as_str().map(str::to_owned).ok_or_else(|| {
        anyhow!(
            "{backend_type} instance '{instance_name}': field '{field}' must be a string, got {}",
            value.type_str()
        )
    })
}

/// Extract an optional string field from the factory config block.
/// `Ok(None)` when the field is absent; error when present with a
/// non-string value.
///
/// # Errors
///
/// Wrong-type errors follow the shape documented at the module level.
pub fn optional_string<S: BuildHasher>(
    config: &HashMap<String, toml::Value, S>,
    field: &str,
    backend_type: &str,
    instance_name: &str,
) -> Result<Option<String>> {
    config.get(field).map_or(Ok(None), |value| {
        value.as_str().map(|s| Some(s.to_owned())).ok_or_else(|| {
            anyhow!(
                "{backend_type} instance '{instance_name}': field '{field}' must be a string, got {}",
                value.type_str()
            )
        })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn config(pairs: &[(&str, toml::Value)]) -> HashMap<String, toml::Value> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect()
    }

    #[test]
    fn required_string_extracts_value() {
        let cfg = config(&[("vault_address", toml::Value::String("https://v".to_owned()))]);
        let v = required_string(&cfg, "vault_address", "vault", "vault-eng").unwrap();
        assert_eq!(v, "https://v");
    }

    #[test]
    fn required_string_errors_on_missing_with_instance_and_field_names() {
        let cfg = HashMap::new();
        let err = required_string(&cfg, "aws_region", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-ssm instance 'aws-ssm-prod'"));
        assert!(msg.contains("missing required field 'aws_region'"));
        assert!(msg.contains("set aws_region = \"...\" under [backends.aws-ssm-prod]"));
    }

    #[test]
    fn required_string_errors_on_wrong_type() {
        let cfg = config(&[("aws_region", toml::Value::Integer(1))]);
        let err = required_string(&cfg, "aws_region", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("field 'aws_region' must be a string, got integer"));
    }

    #[test]
    fn optional_string_returns_none_when_absent() {
        let cfg = HashMap::new();
        let v = optional_string(&cfg, "aws_profile", "aws-ssm", "aws-ssm-prod").unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn optional_string_returns_some_on_string() {
        let cfg = config(&[("aws_profile", toml::Value::String("prod".to_owned()))]);
        let v = optional_string(&cfg, "aws_profile", "aws-ssm", "aws-ssm-prod").unwrap();
        assert_eq!(v.as_deref(), Some("prod"));
    }

    #[test]
    fn optional_string_errors_on_wrong_type_with_labels() {
        let cfg = config(&[("aws_profile", toml::Value::Boolean(true))]);
        let err = optional_string(&cfg, "aws_profile", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-ssm instance 'aws-ssm-prod'"));
        assert!(msg.contains("field 'aws_profile' must be a string, got boolean"));
    }
}
