//! Local filesystem backend for SecretEnv.
//!
//! Reads and writes a TOML key-value document on disk. Used for solo-dev
//! workflows, the `local` registry source, and the default fallback.
//!
//! This scaffolding crate is intentionally empty. Implementation lands in Phase 4.
#![forbid(unsafe_code)]
