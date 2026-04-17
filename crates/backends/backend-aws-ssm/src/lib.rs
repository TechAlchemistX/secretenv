//! AWS SSM Parameter Store backend for SecretEnv.
//!
//! Wraps the `aws` CLI — never the AWS SDK — to read and write
//! `SecureString` parameters. Supports multiple `aws-ssm-*` instances
//! via the `aws_profile` and `aws_region` config fields.
//!
//! This scaffolding crate is intentionally empty. Implementation lands in Phase 5.
#![forbid(unsafe_code)]
