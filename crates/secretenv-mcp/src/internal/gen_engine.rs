// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Wrapper-first password generation engine.
//!
//! Phase 1b: skeleton only. Phase 5 fills in:
//!
//! 1. If the target backend's `Backend::supports_native_gen()` returns
//!    `true`: invoke the backend's native generator (e.g.
//!    `op item create --generate-password` for 1password). The value
//!    is born in the backend's process and never enters `SecretEnv`
//!    memory.
//! 2. Otherwise: generate entropy via `getrandom` into a
//!    `Zeroizing<Vec<u8>>`, encode per the requested `charset`, wrap
//!    in `Secret<String>`, pass to `Backend::set()` as a borrow, then
//!    explicitly drop. The value lives only in this module and never
//!    in any tool response type.
//!
//! This is the **only** crate module that may legally name
//! `secretenv_core::Secret`. The `clippy.toml` `disallowed-types` rule
//! requires a per-file `#[allow(clippy::disallowed_types)]` with a
//! justifying comment when value-bearing types appear here.
