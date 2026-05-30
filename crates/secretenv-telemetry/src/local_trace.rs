// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Local in-memory trace capture for `secretenv doctor --trace`.
//!
//! Installs an isolated `SdkTracerProvider` backed by
//! `InMemorySpanExporter` + `SimpleSpanProcessor` (synchronous flush
//! at span end). The CLI uses this to render a one-shot span table
//! locally — no OTLP collector required.
//!
//! # Scoping
//!
//! The CLI deliberately does not depend on `opentelemetry_sdk`
//! directly (Phase 2 scoping rule — only `secretenv-telemetry` has
//! OTel deps). This module re-exports the minimum surface needed for
//! the doctor render path through opaque [`LocalTraceCapture`] +
//! [`LocalTraceSpan`] types so the CLI side stays OTel-free.
//!
//! # Global state interaction
//!
//! `install` replaces the global tracer provider. `doctor --trace` is
//! a one-shot operation: the process exits after rendering, so the
//! global swap has no observable consequence on production-side
//! telemetry (no caller after drain). Using this in a long-lived
//! process would clobber the production provider — don't.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use opentelemetry::global;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};

/// Module-level guard preventing more than one live
/// [`LocalTraceCapture`] from clobbering the global tracer provider
/// at the same time. Set on successful [`LocalTraceCapture::install`]
/// and cleared on `drop`.
///
/// v0.18 Sec-M-2 / Arch-F-6: repeated `install()` calls would
/// silently swap the global provider, breaking observability for any
/// span emitted between the two installs. The guard surfaces the
/// collision as a typed [`LocalTraceCaptureError`].
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// One captured span, surfaced to non-OTel callers as a plain struct
/// so the CLI can render without depending on `opentelemetry_sdk`.
#[derive(Debug, Clone)]
pub struct LocalTraceSpan {
    /// Span name (e.g. `"secretenv.doctor.backend"`).
    pub name: String,
    /// UNIX milliseconds at span start; used to sort the rendered
    /// table chronologically.
    pub start_unix_ms: u64,
    /// Total span duration in milliseconds.
    pub duration_ms: u64,
    /// All key/value attributes the span carried, stringified.
    /// Iteration order matches OTel SDK's insertion order.
    pub attributes: Vec<(String, String)>,
}

/// Handle returned by [`LocalTraceCapture::install`].
///
/// Holds the installed provider + exporter for the duration of the
/// capture window. Call [`LocalTraceCapture::drain`] to force-flush
/// and surface the captured spans.
#[must_use = "the capture must be drained to recover the spans"]
#[derive(Debug)]
pub struct LocalTraceCapture {
    provider: SdkTracerProvider,
    exporter: InMemorySpanExporter,
}

/// Failure mode from [`LocalTraceCapture::install`].
#[derive(Debug, thiserror::Error)]
pub enum LocalTraceCaptureError {
    /// A previous [`LocalTraceCapture`] is still live in this
    /// process. Drop it (or call [`LocalTraceCapture::drain`]) before
    /// installing a second capture; otherwise the second install
    /// would swap the global tracer provider and break any span
    /// emitted under the first capture's window. v0.18 Sec-M-2.
    #[error("LocalTraceCapture is already installed in this process")]
    AlreadyInstalled,
}

impl LocalTraceCapture {
    /// Build + globally install an isolated tracer provider whose
    /// only span processor writes to an in-memory exporter. The
    /// returned handle holds the provider strongly; dropping it
    /// without [`drain`](Self::drain) leaves the global provider
    /// pointing at this no-collector setup until process exit.
    ///
    /// # Errors
    ///
    /// Returns [`LocalTraceCaptureError::AlreadyInstalled`] when a
    /// previous capture is still live. v0.18 Sec-M-2: this prevents
    /// a second install from silently swapping the global tracer
    /// provider out from under the first capture's emission window.
    pub fn install() -> Result<Self, LocalTraceCaptureError> {
        if INSTALLED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(LocalTraceCaptureError::AlreadyInstalled);
        }
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
            .build();
        global::set_tracer_provider(provider.clone());
        Ok(Self { provider, exporter })
    }

    /// Force-flush + collect every span the captured window observed.
    /// Returns the spans sorted by their start time (oldest first).
    #[must_use]
    pub fn drain(self) -> Vec<LocalTraceSpan> {
        let _ = self.provider.force_flush();
        let raw = self.exporter.get_finished_spans().unwrap_or_default();
        let mut spans: Vec<LocalTraceSpan> = raw
            .into_iter()
            .map(|s| {
                let start_unix_ms = system_time_to_unix_ms(s.start_time);
                let duration_ms = duration_ms_between(s.start_time, s.end_time);
                let attributes = s
                    .attributes
                    .iter()
                    .map(|kv| (kv.key.as_str().to_owned(), value_to_string(&kv.value)))
                    .collect();
                LocalTraceSpan { name: s.name.to_string(), start_unix_ms, duration_ms, attributes }
            })
            .collect();
        spans.sort_by_key(|s| s.start_unix_ms);
        spans
    }
}

impl Drop for LocalTraceCapture {
    /// Clears the module-level installed flag so a subsequent
    /// [`LocalTraceCapture::install`] call can succeed. v0.18 Sec-M-2.
    fn drop(&mut self) {
        INSTALLED.store(false, Ordering::SeqCst);
    }
}

fn system_time_to_unix_ms(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn duration_ms_between(start: SystemTime, end: SystemTime) -> u64 {
    end.duration_since(start).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn value_to_string(v: &opentelemetry::Value) -> String {
    use opentelemetry::Value;
    match v {
        Value::Bool(b) => b.to_string(),
        Value::I64(i) => i.to_string(),
        Value::F64(f) => f.to_string(),
        Value::String(s) => s.to_string(),
        // `opentelemetry::Value` is `#[non_exhaustive]`; the Array
        // variant + any future ones fall back to the Debug rendering.
        _ => format!("{v:?}"),
    }
}
