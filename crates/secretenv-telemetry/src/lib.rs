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

pub mod backend_error_redaction;
pub mod error_kind;
pub mod event;
pub mod init;
pub mod local_trace;
pub mod metrics;
pub mod policy;
pub mod sampler;
pub mod sink;
pub mod span;

pub use backend_error_redaction::BackendErrorStderr;
pub use error_kind::SecretEnvErrorKind;
pub use event::{RedactionEvent, RedactionSource, RedactionStream};
pub use init::{
    flush_before_exec, init, init_with_env, tracing_bridge_layer, InitError, TelemetryGuard,
};
pub use local_trace::{LocalTraceCapture, LocalTraceCaptureError, LocalTraceSpan};
pub use metrics::{FetchOutcome, ProbeLevel, ProbeOutcome, RedactMode, ResolutionOutcome};
pub use policy::{AttributeClassification, RedactionPolicy};
pub use sampler::{default_sampler, MutationNonDroppableSampler};
pub use sink::{NoopRedactionSink, RedactionSink};
pub use span::{
    AliasOutcome, AuthMethod, BackendType, DoctorCheckLevel, ManifestOutcome, MigrateOutcome,
    MigratePhase, MutationSpanName, RegistrySelectionKind, SecretEnvCommand, SecretEnvSpan,
    SpanGuard,
};

/// Sentinel registry name for direct-URI selections.
///
/// v0.18 Code-N3 / Arch-M2 / W-15. Used when the registry was
/// selected via a direct backend URI rather than a
/// `[registries.<name>]` entry. Emitted as `secretenv.registry.name`
/// at metric call sites and as a stable fallback wherever an
/// operator-facing string is needed but no registry name exists.
/// Single source of truth — call sites import this constant rather
/// than re-typing the string.
pub const REGISTRY_NAME_DIRECT_URI: &str = "<direct-uri>";

/// Sentinel for the `argv[0]` slot when the run's `command` slice
/// is empty.
///
/// v0.18 Code-N2. Should never fire in practice (the CLI rejects
/// empty `--`-terminated invocations), but reserved as a constant
/// rather than a magic string so call sites stay consistent.
pub const PROCESS_COMMAND_NAME_EMPTY: &str = "<empty>";

/// Generate a fresh per-invocation run ID.
///
/// Returns a 32-char lowercase hex string sourced from 16 random
/// bytes via `getrandom`. The shape matches a `UUIDv4` rendered
/// without hyphens, satisfying the `docs/reference/opentelemetry.md`
/// §2.1 contract that `secretenv.run_id` is a `UUIDv4`-equivalent
/// random identifier.
///
/// # v0.18 Arch-M3 fallback
///
/// If the OS RNG is unavailable (extremely rare on supported
/// platforms — never observed in production through v0.17) the
/// function emits a `tracing::warn!` event ONCE per process and
/// falls back to a process+time-derived non-zero ID rather than
/// the v0.17 all-zero string. The all-zero fallback was operator-
/// visible as `run_id=00000...0` without any explanation; the new
/// fallback (a) makes the failure visible in the trace pipeline at
/// init time, (b) returns a process+time-derived hex string
/// (effectively never the all-zero sentinel, though not bit-floored
/// to non-zero) so cross-correlation against e.g. CI job ID still
/// works at the operator level. Run IDs derived this way are NOT
/// unique across rapid invocations on the same PID, but the warning
/// makes the degraded state obvious.
#[must_use]
pub fn fresh_run_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        run_id_fallback_warn_once();
        return fresh_run_id_fallback();
    }
    format_run_id(&bytes)
}

/// Warn once per process when `getrandom` fails. v0.18 Arch-M3.
fn run_id_fallback_warn_once() {
    use std::sync::Once;
    static WARN: Once = Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            target: "secretenv_telemetry",
            "fresh_run_id: getrandom failed; falling back to process+time derived ID. \
             run_id correlation across rapid invocations may be ambiguous on this host."
        );
    });
}

/// Non-zero deterministic fallback when `getrandom` is unavailable.
/// v0.18 Arch-M3 + Code-L2: derive 16 bytes from `process::id()` XOR
/// the low bits of `SystemTime::now().duration_since(UNIX_EPOCH)`.
/// Format identically to the happy path so callers cannot tell the
/// difference at the string level — only the `tracing::warn!` event
/// surfaces the degraded state.
fn fresh_run_id_fallback() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = u64::from(std::process::id());
    let now_nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    // Mix pid into the low and high 64 bits of the nanos-since-epoch
    // value. The `as u64` casts deliberately truncate — we want the
    // bottom 64 bits and the next 64 bits separately to fill 16 bytes.
    #[allow(clippy::cast_possible_truncation)]
    let low = (now_nanos as u64) ^ pid;
    #[allow(clippy::cast_possible_truncation)]
    let high = (now_nanos >> 64) as u64 ^ pid.rotate_left(7);
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&high.to_be_bytes());
    bytes[8..16].copy_from_slice(&low.to_be_bytes());
    format_run_id(&bytes)
}

fn format_run_id(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod run_id_tests {
    use super::{format_run_id, fresh_run_id, fresh_run_id_fallback};

    #[test]
    fn run_id_is_32_hex_chars() {
        let id = fresh_run_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn run_ids_are_distinct() {
        assert_ne!(fresh_run_id(), fresh_run_id());
    }

    // v0.18 Arch-L-4: exercise the fallback branch directly. The
    // branch is unreachable on supported platforms via the public
    // `fresh_run_id` entry point, so we test the helper that the
    // failure path delegates to.
    #[test]
    fn fallback_produces_non_zero_hex_string() {
        let id = fresh_run_id_fallback();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(
            id, "00000000000000000000000000000000",
            "Arch-M3: fallback must not emit the v0.17 zero-string sentinel"
        );
    }

    #[test]
    fn format_run_id_round_trip_is_lowercase_hex() {
        let bytes = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xAA, 0xBB,
        ];
        let s = format_run_id(&bytes);
        assert_eq!(s, "deadbeef00112233445566778899aabb");
    }
}
