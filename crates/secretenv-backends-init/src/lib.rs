// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Build a [`BackendRegistry`] pre-populated with every shipped backend
//! factory + instances loaded from a [`Config`].
//!
//! Single source of truth for the compiled-in factory list. Used by
//! both `secretenv-cli` (startup wiring + `setup` post-write
//! verification) and `secretenv-mcp` (registry construction inside
//! the `doctor` / `resolve_status` tool handlers). Do not register
//! factories from anywhere else.
//!
//! **Keychain registration is unconditional across platforms.** The
//! `KeychainFactory` compiles on every target; it bails at
//! `create()` time on non-macOS with a clear error. This keeps the
//! workspace buildable on Linux / Windows CI without cfg-gating the
//! registration list.

use anyhow::{Context, Result};
use secretenv_core::{BackendRegistry, Config};

/// Register every compiled-in backend factory and instantiate the
/// backends declared in `config`.
///
/// Factories registered: `local`, `aws-ssm`, `1password`, `vault`,
/// `aws-secrets`, `gcp`, `azure`, `keychain`, `doppler`, `infisical`,
/// `keeper`, `cf-kv`, `openbao`, `conjur`, `bitwarden-sm`.
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
    registry.register_factory(Box::new(secretenv_backend_keychain::KeychainFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_doppler::DopplerFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_infisical::InfisicalFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_keeper::KeeperFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_cf_kv::CfKvFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_openbao::OpenBaoFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_conjur::ConjurFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_bitwarden_sm::BitwardenSmFactory::new()));
    registry.load_from_config(config).context("loading backend instances from config.toml")?;
    Ok(registry)
}
