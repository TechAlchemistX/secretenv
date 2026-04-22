// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

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
use std::time::Duration;

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

/// Extract an optional boolean field from the factory config block.
/// `Ok(None)` when absent; error when present with a non-boolean value.
///
/// # Errors
///
/// Wrong-type errors follow the shape documented at the module level.
pub fn optional_bool<S: BuildHasher>(
    config: &HashMap<String, toml::Value, S>,
    field: &str,
    backend_type: &str,
    instance_name: &str,
) -> Result<Option<bool>> {
    config.get(field).map_or(Ok(None), |value| {
        value.as_bool().map(Some).ok_or_else(|| {
            anyhow!(
                "{backend_type} instance '{instance_name}': field '{field}' must be a boolean, got {}",
                value.type_str()
            )
        })
    })
}

/// Read an optional `timeout_secs` integer field and convert to a
/// [`Duration`]. `Ok(None)` when absent; error when present with a
/// non-integer value or a negative number.
///
/// Used by every backend factory to honor a per-instance
/// `timeout_secs = N` override of the default `with_timeout` window
/// for `get` / `set` / `delete` / `list` / `history`. The `check`
/// timeout stays on `DEFAULT_CHECK_TIMEOUT` so doctor parallelism
/// remains predictable across instances.
///
/// # Errors
///
/// - Field present and not an integer.
/// - Integer is negative or zero (`Duration::from_secs` is unsigned;
///   a zero or negative timeout makes the operation impossible).
pub fn optional_duration_secs<S: BuildHasher>(
    config: &HashMap<String, toml::Value, S>,
    field: &str,
    backend_type: &str,
    instance_name: &str,
) -> Result<Option<Duration>> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let n = value.as_integer().ok_or_else(|| {
        anyhow!(
            "{backend_type} instance '{instance_name}': field '{field}' must be an integer (seconds), got {}",
            value.type_str()
        )
    })?;
    if n <= 0 {
        return Err(anyhow!(
            "{backend_type} instance '{instance_name}': field '{field}' must be a positive \
             number of seconds, got {n}"
        ));
    }
    // u64 cast is safe — the i64 is positive (just guarded above) and
    // Rust u64 covers every positive i64. `clippy::cast_sign_loss` is
    // technically correct in the abstract but disjoint from this
    // already-guarded path.
    #[allow(clippy::cast_sign_loss)]
    let secs = n as u64;
    Ok(Some(Duration::from_secs(secs)))
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

    #[test]
    fn optional_bool_returns_none_when_absent() {
        let cfg = HashMap::new();
        let v = optional_bool(&cfg, "op_unsafe_set", "1password", "1password-team").unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn optional_bool_returns_some_on_boolean() {
        let cfg = config(&[("op_unsafe_set", toml::Value::Boolean(true))]);
        let v = optional_bool(&cfg, "op_unsafe_set", "1password", "1password-team").unwrap();
        assert_eq!(v, Some(true));
    }

    #[test]
    fn optional_bool_errors_on_wrong_type() {
        let cfg = config(&[("op_unsafe_set", toml::Value::String("yes".to_owned()))]);
        let err = optional_bool(&cfg, "op_unsafe_set", "1password", "1password-team").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("op_unsafe_set"));
        assert!(msg.contains("must be a boolean"));
    }

    #[test]
    fn optional_duration_secs_returns_none_when_absent() {
        let cfg = HashMap::new();
        let v = optional_duration_secs(&cfg, "timeout_secs", "aws-ssm", "aws-ssm-prod").unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn optional_duration_secs_converts_positive_integer() {
        let cfg = config(&[("timeout_secs", toml::Value::Integer(45))]);
        let v = optional_duration_secs(&cfg, "timeout_secs", "aws-ssm", "aws-ssm-prod").unwrap();
        assert_eq!(v, Some(Duration::from_secs(45)));
    }

    #[test]
    fn optional_duration_secs_errors_on_zero() {
        let cfg = config(&[("timeout_secs", toml::Value::Integer(0))]);
        let err =
            optional_duration_secs(&cfg, "timeout_secs", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("positive"), "rejects zero: {msg}");
    }

    #[test]
    fn optional_duration_secs_errors_on_negative() {
        let cfg = config(&[("timeout_secs", toml::Value::Integer(-5))]);
        let err =
            optional_duration_secs(&cfg, "timeout_secs", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("positive"), "rejects negative: {msg}");
    }

    #[test]
    fn optional_duration_secs_errors_on_wrong_type() {
        let cfg = config(&[("timeout_secs", toml::Value::String("30".to_owned()))]);
        let err =
            optional_duration_secs(&cfg, "timeout_secs", "aws-ssm", "aws-ssm-prod").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("integer"), "specific type error: {msg}");
    }
}
