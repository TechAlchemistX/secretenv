// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Telemetry skeleton for SecretEnv.
//!
//! This crate defines the typed surface every downstream cycle
//! (v0.15 migrate, v0.16 MCP, v0.17 OTel) emits through. In v0.14
//! every exporter ships as a no-op — the load-bearing deliverable
//! is the **set-site enforcement of the ALLOW/DENY attribute
//! matrix** through the [`SecretEnvSpan`] typed builder. Adding a
//! new attribute requires adding a method on the builder, which
//! makes every attribute addition a code-review event by
//! construction.
//!
//! # The four pillars
//!
//! - [`SecretEnvSpan`] — typed attribute builder. One method per
//!   ALLOW attribute in the v0.14+ synthesis §6 matrix. No
//!   `set_attribute(&str, &str)` escape hatch. The v0.17 OTel
//!   exporter wires methods to span attributes 1:1.
//! - [`SecretEnvErrorKind`] — closed enum of error categories
//!   that may appear as the `secretenv.error.kind` attribute.
//!   Free-string error messages NEVER cross into spans (DENY by
//!   default; `--otel-include-error-detail` is a v0.17 opt-in).
//! - [`RedactionEvent`] — the structured event the redact module
//!   emits per match (mode A) and per scrub (mode B). Carries
//!   count + byte count + stream + source; NEVER the matched value.
//! - [`RedactionPolicy`] — declarative ALLOW/DENY classification.
//!   The v0.17 attribute-emitter consults this; v0.14 ships it as
//!   a reference table so call sites can be reviewed against a
//!   single source of truth.
//!
//! # No `opentelemetry` dependency at v0.14
//!
//! Verify with `cargo tree -p secretenv-telemetry` — no edge to
//! the `opentelemetry` crate. This is checked in CI as part of
//! the Phase 9 release-prep audit. v0.17 adds the dep behind a
//! feature flag without restructuring any v0.14 call site.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Crate-wide allows: doc_markdown flags every `secretenv.*` attribute
// name in module docs because dotted names look like identifiers
// missing backticks; backticking every occurrence in the policy
// matrix table is noise. v0.17 will revisit when the attribute
// taxonomy stabilizes.
#![allow(clippy::doc_markdown)]

pub mod error_kind;
pub mod event;
pub mod init;
pub mod metrics;
pub mod policy;
pub mod sampler;
pub mod sink;
pub mod span;

pub use error_kind::SecretEnvErrorKind;
pub use event::{RedactionEvent, RedactionSource, RedactionStream};
pub use init::{flush_before_exec, init, init_with_env, InitError, TelemetryGuard};
pub use policy::{AttributeClassification, RedactionPolicy};
pub use sampler::{default_sampler, MutationNonDroppableSampler};
pub use sink::{NoopRedactionSink, RedactionSink};
pub use span::{AliasOutcome, AuthMethod, MigrateOutcome, MigratePhase, SecretEnvSpan, SpanGuard};
