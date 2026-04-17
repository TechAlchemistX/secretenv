//! Core types, traits, and plugin registry for SecretEnv.
//!
//! This crate defines the abstractions every backend implements: the
//! `Backend` and `BackendFactory` traits, the `BackendRegistry`, URI
//! parsing, and the config model. All backends are wired at runtime via
//! `config.toml`; there are no compile-time feature flags for backends.
//!
//! This scaffolding crate is intentionally empty. Types land in Phase 1.
#![forbid(unsafe_code)]
