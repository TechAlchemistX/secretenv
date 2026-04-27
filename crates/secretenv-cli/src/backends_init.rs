// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Build a [`BackendRegistry`] pre-populated with every shipped backend
//! factory + instances loaded from `config`.
//!
//! Shared between `main.rs` (startup wiring) and `setup.rs` (post-write
//! verification with the freshly-written config). Factored out so
//! the factory-registration list is the single source of truth.
//!
//! **Keychain registration is unconditional across platforms.** The
//! `KeychainFactory` compiles on every target; it bails at
//! `create()` time on non-macOS with a clear error. This keeps the
//! workspace buildable on Linux / Windows CI without cfg-gating the
//! registration list.
//!
//! v0.6 adds `doppler` (Doppler secrets-manager CLI wrapper).
//! v0.7 adds `infisical` (Infisical `SaaS` + self-hostable CLI wrapper).
//! v0.8 adds `keeper` (Keeper Commander CLI wrapper; requires persistent
//! login set up via `this-device register` + `persistent-login on`).
//! v0.9 adds `cf-kv` (Cloudflare Workers KV via `wrangler` CLI wrapper).
//! v0.10 adds `openbao` (Linux Foundation MPL-2.0 fork of Vault — KV
//! v1/v2 via the `bao` CLI, tap-less brew install).

use anyhow::{Context, Result};
use secretenv_core::{BackendRegistry, Config};

/// Register every compiled-in backend factory (`local`, `aws-ssm`,
/// `1password`, `vault`, `aws-secrets`, `gcp`, `azure`, `keychain`,
/// `doppler`, `infisical`, `keeper`, `cf-kv`, `openbao`) and instantiate the backends declared in `config`.
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
    registry.load_from_config(config).context("loading backend instances from config.toml")?;
    Ok(registry)
}
