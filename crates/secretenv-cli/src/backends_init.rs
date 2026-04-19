//! Build a [`BackendRegistry`] pre-populated with every shipped backend
//! factory + instances loaded from `config`.
//!
//! Shared between `main.rs` (startup wiring) and `setup.rs` (post-write
//! verification with the freshly-written config). Factored out so
//! the factory-registration list is the single source of truth.

use anyhow::{Context, Result};
use secretenv_core::{BackendRegistry, Config};

/// Register every compiled-in backend factory (`local`, `aws-ssm`,
/// `1password`, `vault`, `aws-secrets`, `gcp`, `azure`) and
/// instantiate the backends declared in `config`.
///
/// # Errors
/// Returns an error if any `[backends.<name>]` block references a
/// backend type with no registered factory, or if a factory's
/// `create()` fails validation of its config fields.
pub fn build_registry(config: &Config) -> Result<BackendRegistry> {
    let mut registry = BackendRegistry::new();
    registry.register_factory(Box::new(secretenv_backend_local::LocalFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_aws_ssm::AwsSsmFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_1password::OnePasswordFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_vault::VaultFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_aws_secrets::AwsSecretsFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_gcp::GcpFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_azure::AzureFactory::new()));
    registry.load_from_config(config).context("loading backend instances from config.toml")?;
    Ok(registry)
}
