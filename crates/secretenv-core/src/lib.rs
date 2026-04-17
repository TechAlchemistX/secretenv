//! Core types, traits, and plugin registry for SecretEnv.
//!
//! This crate defines the abstractions every backend implements: the
//! [`Backend`] and [`BackendFactory`] traits, the [`BackendRegistry`],
//! URI parsing, and the config model. All backends are wired at runtime
//! via `config.toml`; there are no compile-time feature flags for
//! backends.
//!
//! # Module map
//!
//! - [`uri`] — [`BackendUri`] and [`UriError`]
//! - [`status`] — [`BackendStatus`] (what `doctor` renders)
//! - [`backend`] — the [`Backend`] and [`BackendFactory`] traits
//! - [`config`] — [`Config`], [`RegistryConfig`], [`BackendConfig`]
//! - [`manifest`] — [`Manifest`] and [`SecretDecl`] for `secretenv.toml`
//! - [`registry`] — [`BackendRegistry`] dispatcher
#![forbid(unsafe_code)]

pub mod backend;
pub mod config;
pub mod manifest;
pub mod registry;
pub mod resolver;
pub mod runner;
pub mod status;
pub mod uri;

pub use backend::{Backend, BackendFactory};
pub use config::{BackendConfig, Config, RegistryConfig};
pub use manifest::{Manifest, SecretDecl};
pub use registry::BackendRegistry;
pub use resolver::{
    resolve_manifest, resolve_registry, AliasMap, RegistrySelection, ResolvedSecret, ResolvedSource,
};
pub use runner::{build_env, run, EnvEntry};
pub use status::BackendStatus;
pub use uri::{BackendUri, UriError};
