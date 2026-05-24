// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Internal modules — the **only** subtree allowed to name
//! value-bearing types like [`secretenv_core::Secret`].
//!
//! The crate-wide `clippy.toml` `disallowed-types` rule bans these
//! names everywhere; per-file `#[allow(clippy::disallowed_types)]`
//! escape hatches are permitted **only** in files under this
//! `internal/` subtree, with a documented justification comment
//! explaining why the value handling is correct (drop-on-use,
//! zeroize, no echo in error output).
//!
//! Phase 1b: scaffold only. [`gen_engine`] (Phase 5) is the wrapper-
//! first password generation engine and the first concrete consumer
//! of this escape hatch.
//!
//! Phase 4e: [`redact_file`] is the second consumer — `Backend::get`
//! returns `Secret<String>` which is consumed inline via
//! `expose_secret()` at the single point where the bytes cross into
//! the v0.14 `TaintedSet` scrubber (which owns + zeroes its bytes).

pub mod gen_engine;
pub mod redact_file;
