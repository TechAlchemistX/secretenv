//! Build a [`BackendRegistry`] pre-populated with every v0.1 backend
//! factory + instances loaded from `config`.
//!
//! Shared between `main.rs` (startup wiring) and `setup.rs` (post-write
//! verification with the freshly-written config). Factored out so
//! the factory-registration list is the single source of truth.

use anyhow::{Context, Result};
use secretenv_core::{BackendRegistry, Config};

/// Register all three v0.1 factories (`local`, `aws-ssm`, `1password`)
/// and instantiate the backends declared in `config`.
///
/// # Errors
/// Returns an error if any `[backends.<name>]` block references a
/// backend type with no registered factory, or if a factory's
/// `create()` fails validation of its config fields.
pub fn build_registry(config: &Config) -> Result<BackendRegistry> {
    let mut registry = BackendRegistry::new();
    registry.register_factory(Box::new(backend_local::LocalFactory::new()));
    registry.register_factory(Box::new(backend_aws_ssm::AwsSsmFactory::new()));
    registry.register_factory(Box::new(backend_1password::OnePasswordFactory::new()));
    registry.load_from_config(config).context("loading backend instances from config.toml")?;
    Ok(registry)
}
