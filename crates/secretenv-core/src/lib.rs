//! Core types, traits, and plugin registry for SecretEnv.
//!
//! This crate defines the abstractions every backend implements: the
//! `Backend` and `BackendFactory` traits, the `BackendRegistry`, URI
//! parsing, and the config model. All backends are wired at runtime via
//! `config.toml`; there are no compile-time feature flags for backends.
//!
//! Phase 1 lands the foundational value types: [`BackendUri`] (and its
//! [`UriError`]) plus [`BackendStatus`]. Traits, the registry, and
//! config loading land in Phases 2 and 3.
#![forbid(unsafe_code)]

pub mod status;
pub mod uri;

pub use status::BackendStatus;
pub use uri::{BackendUri, UriError};
