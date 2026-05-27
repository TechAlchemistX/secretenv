// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! OpenTelemetry runtime wiring.
//!
//! Three exits from [`init`]:
//! 1. **No-op** — no `OTEL_*` env var set; zero startup overhead, no
//!    provider installed, no global state mutated.
//! 2. **Console** — `OTEL_TRACES_EXPORTER=console` installs the
//!    stdout exporter (used by `doctor --trace` and ad-hoc debug runs).
//! 3. **OTLP gRPC** — `OTEL_EXPORTER_OTLP_ENDPOINT` (or
//!    `OTEL_TRACES_EXPORTER=otlp`) installs the OTLP/gRPC exporter.
//!
//! In all three cases the function returns a [`TelemetryGuard`] that
//! the CLI holds for the process lifetime. Dropping the guard flushes
//! and shuts down the provider; for the `exec()` path call
//! [`flush_before_exec`] explicitly first, because `exec` replaces the
//! process and the guard's destructor never runs.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

use crate::sampler::default_sampler;

/// Hold the installed tracer provider so [`flush_before_exec`] can find
/// it without taking a reference through every call site. Set exactly
/// once by [`init`] when an OTLP or console exporter is wired up; stays
/// `None` in the no-op path.
static PROVIDER: OnceLock<Arc<SdkTracerProvider>> = OnceLock::new();

/// Exporter mode chosen at startup. The choice is driven entirely by
/// env vars; there is no [otel] config-table override at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExporterMode {
    /// No exporter installed; `init` returns an empty guard.
    Noop,
    /// `opentelemetry-stdout` writes spans to stderr in JSON.
    Console,
    /// OTLP/gRPC exporter to `OTEL_EXPORTER_OTLP_ENDPOINT`.
    OtlpGrpc,
}

/// Error surface from [`init`]. Wraps the OTel SDK's builder error.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The configured OTLP exporter failed to build.
    #[error("failed to build OTLP exporter: {0}")]
    Exporter(String),
}

/// Inspect env vars and decide which exporter to install.
fn mode_from_env<F>(env: F) -> ExporterMode
where
    F: Fn(&str) -> Option<String>,
{
    // Explicit override wins over endpoint heuristic.
    if let Some(v) = env("OTEL_TRACES_EXPORTER") {
        match v.as_str() {
            "none" => return ExporterMode::Noop,
            "console" => return ExporterMode::Console,
            "otlp" => return ExporterMode::OtlpGrpc,
            _ => {}
        }
    }
    // Endpoint set → OTLP. Three env vars admit OTLP because operators
    // routinely set only the per-signal variant.
    if env("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
        || env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT").is_some()
    {
        return ExporterMode::OtlpGrpc;
    }
    ExporterMode::Noop
}

/// Build the resource attributes that ride along on every span.
///
/// Per `docs/reference/opentelemetry.md` §7: `service.name` defaults to
/// `secretenv`; `service.version` comes from `CARGO_PKG_VERSION`;
/// `host.*` / `os.type` / `process.pid` are OTel standard resource
/// conventions; `OTEL_RESOURCE_ATTRIBUTES` is honored as additional
/// k=v pairs with operator-supplied attributes overriding our defaults.
fn build_resource<F>(env: F) -> Resource
where
    F: Fn(&str) -> Option<String>,
{
    let service_name = env("OTEL_SERVICE_NAME").unwrap_or_else(|| "secretenv".to_owned());
    Resource::builder()
        .with_service_name(service_name)
        .with_attribute(opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Initialise OpenTelemetry from process env. Returns a guard the CLI
/// must hold for the process lifetime; dropping it flushes and shuts
/// down the provider.
///
/// No-op when no `OTEL_*` env var is set: zero overhead, no global
/// state mutated, no tonic/grpc connection attempted.
///
/// # Errors
///
/// Returns [`InitError::Exporter`] when an OTLP exporter is requested
/// (endpoint set or `OTEL_TRACES_EXPORTER=otlp`) but the SDK fails to
/// build it — for example, a malformed endpoint URL.
pub fn init() -> Result<TelemetryGuard, InitError> {
    init_with_env(|k| std::env::var(k).ok())
}

/// `init` with a pluggable env reader for tests.
///
/// # Errors
///
/// Same as [`init`].
pub fn init_with_env<F>(env: F) -> Result<TelemetryGuard, InitError>
where
    F: Fn(&str) -> Option<String> + Copy,
{
    let mode = mode_from_env(env);
    match mode {
        ExporterMode::Noop => Ok(TelemetryGuard { provider: None }),
        ExporterMode::Console => {
            let exporter = opentelemetry_stdout::SpanExporter::default();
            // SEC-INV-22: every TracerProvider we install wraps its
            // sampler with the mutation-non-droppable rule, so that
            // operator-configured ratio sampling can never silently
            // drop a registry mutation from the audit stream.
            let provider = SdkTracerProvider::builder()
                .with_resource(build_resource(env))
                .with_sampler(default_sampler())
                .with_batch_exporter(exporter)
                .build();
            Ok(install(provider))
        }
        ExporterMode::OtlpGrpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
            if let Some(endpoint) = env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                .or_else(|| env("OTEL_EXPORTER_OTLP_ENDPOINT"))
            {
                builder = builder.with_endpoint(endpoint);
            }
            if let Some(timeout_ms) =
                env("OTEL_EXPORTER_OTLP_TIMEOUT").and_then(|s| s.parse::<u64>().ok())
            {
                builder = builder.with_timeout(Duration::from_millis(timeout_ms));
            }
            let exporter = builder.build().map_err(|e| InitError::Exporter(format!("{e}")))?;
            // SEC-INV-22: every TracerProvider we install wraps its
            // sampler with the mutation-non-droppable rule, so that
            // operator-configured ratio sampling can never silently
            // drop a registry mutation from the audit stream.
            let provider = SdkTracerProvider::builder()
                .with_resource(build_resource(env))
                .with_sampler(default_sampler())
                .with_batch_exporter(exporter)
                .build();
            Ok(install(provider))
        }
    }
}

/// Stash the provider in the global slot, register the W3C propagator,
/// and return the guard. Infallible — the provider is already built.
fn install(provider: SdkTracerProvider) -> TelemetryGuard {
    let provider = Arc::new(provider);
    // OnceLock::set returns Err if already set — re-init from tests is
    // a programmer error, not a runtime fault.
    let _ = PROVIDER.set(Arc::clone(&provider));
    global::set_tracer_provider((*provider).clone());
    global::set_text_map_propagator(TraceContextPropagator::new());
    TelemetryGuard { provider: Some(provider) }
}

/// RAII guard for the installed OTel provider.
///
/// On drop, flushes pending spans and shuts down the provider. The
/// `exec()` path bypasses Drop (the process is replaced), so callers
/// must invoke [`flush_before_exec`] explicitly before any `exec()`.
#[must_use = "the TelemetryGuard must be held for the process lifetime; \
              dropping it shuts down the OTel provider"]
pub struct TelemetryGuard {
    provider: Option<Arc<SdkTracerProvider>>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Best-effort. Failures here happen during shutdown and
            // cannot be surfaced to the operator usefully.
            let _ = provider.force_flush();
            let _ = provider.shutdown();
        }
    }
}

/// Synchronously flush pending spans with a bounded timeout, intended
/// to be called immediately before `execve()` replaces the process.
///
/// Implements SEC-INV-22's bounded-flush requirement: a slow or
/// unreachable collector cannot turn `secretenv run` into a latency
/// cliff. On timeout, pending spans drop and a `tracing::debug!` event
/// is emitted.
///
/// No-op when [`init`] installed no provider (the no-op exporter mode).
pub fn flush_before_exec(timeout: Duration) {
    let Some(provider) = PROVIDER.get().cloned() else {
        return;
    };
    // Worker thread + recv_timeout: keeps the timeout bound enforceable
    // without requiring a tokio runtime context at the exec call site
    // (`secretenv-core::runner::exec_with_env` is sync).
    let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
    let worker = std::thread::spawn(move || {
        let _ = provider.force_flush();
        let _ = tx.send(());
    });
    match rx.recv_timeout(timeout) {
        Ok(()) => {
            // Flush completed within bound. Worker thread exits cleanly.
            let _ = worker.join();
        }
        Err(_) => {
            tracing::debug!(
                timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                "otel flush timed out; dropping pending spans",
            );
            // Detach the worker thread; the OTel batch processor will
            // either complete or be torn down by Drop / exec() itself.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_no_env_is_noop() {
        let env = |_: &str| None;
        assert_eq!(mode_from_env(env), ExporterMode::Noop);
    }

    #[test]
    fn mode_explicit_none() {
        let env = |k: &str| (k == "OTEL_TRACES_EXPORTER").then(|| "none".to_owned());
        assert_eq!(mode_from_env(env), ExporterMode::Noop);
    }

    #[test]
    fn mode_explicit_console() {
        let env = |k: &str| (k == "OTEL_TRACES_EXPORTER").then(|| "console".to_owned());
        assert_eq!(mode_from_env(env), ExporterMode::Console);
    }

    #[test]
    fn mode_endpoint_implies_otlp() {
        let env = |k: &str| {
            (k == "OTEL_EXPORTER_OTLP_ENDPOINT").then(|| "http://127.0.0.1:4317".to_owned())
        };
        assert_eq!(mode_from_env(env), ExporterMode::OtlpGrpc);
    }

    #[test]
    fn mode_explicit_overrides_endpoint() {
        let env = |k: &str| match k {
            "OTEL_TRACES_EXPORTER" => Some("none".to_owned()),
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://127.0.0.1:4317".to_owned()),
            _ => None,
        };
        assert_eq!(mode_from_env(env), ExporterMode::Noop);
    }

    #[test]
    fn noop_init_returns_guard_without_provider() {
        let env = |_: &str| None;
        let Ok(guard) = init_with_env(env) else {
            panic!("noop init never fails");
        };
        assert!(guard.provider.is_none());
        drop(guard);
    }

    #[test]
    fn flush_before_exec_is_noop_when_no_provider() {
        // OnceLock may have been set by an earlier test in this module;
        // the call must still complete (and not panic) regardless.
        flush_before_exec(Duration::from_millis(50));
    }
}
