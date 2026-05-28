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
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

use crate::sampler::MutationNonDroppableSampler;

/// Hold the installed tracer provider so [`flush_before_exec`] can find
/// it without taking a reference through every call site. Set exactly
/// once by [`init`] when an OTLP or console exporter is wired up; stays
/// `None` in the no-op path.
static PROVIDER: OnceLock<Arc<SdkTracerProvider>> = OnceLock::new();

/// Hold the installed meter provider so [`flush_before_exec`] can flush
/// pending metrics alongside spans before `execve()` replaces the
/// process. Same `None`-when-no-op semantics as [`PROVIDER`].
static METER_PROVIDER: OnceLock<Arc<SdkMeterProvider>> = OnceLock::new();

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
///
/// v0.17 applies a single mode to both traces and metrics. Operators
/// who genuinely need split exporters (e.g. OTLP traces + console
/// metrics) should configure their downstream OTel collector; SecretEnv
/// itself does not implement per-signal exporter routing in v0.17.
/// `OTEL_TRACES_EXPORTER` is consulted first for backward compatibility
/// with OTel-aware operator scripts; `OTEL_METRICS_EXPORTER` and the
/// per-signal endpoint env vars participate in the OTLP-implication
/// heuristic but do not split the mode.
fn mode_from_env<F>(env: F) -> ExporterMode
where
    F: Fn(&str) -> Option<String>,
{
    // Explicit override wins over endpoint heuristic. We honour either
    // OTEL_TRACES_EXPORTER or OTEL_METRICS_EXPORTER as the signal — the
    // first one that decisively names a mode wins.
    for var in ["OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER"] {
        if let Some(v) = env(var) {
            match v.as_str() {
                "none" => return ExporterMode::Noop,
                "console" => return ExporterMode::Console,
                "otlp" => return ExporterMode::OtlpGrpc,
                _ => {}
            }
        }
    }
    // Endpoint set → OTLP. The per-signal endpoint env vars are
    // honoured because operators routinely set only the variant for
    // the signal they actually care about.
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
/// Per `docs/reference/opentelemetry.md` §7 and §2.10:
/// - `service.name` defaults to `secretenv`; overridden by `OTEL_SERVICE_NAME`.
/// - `service.version` comes from `CARGO_PKG_VERSION`.
/// - `host.name`, `host.arch`, `os.type`, `process.pid` are emitted from
///   the OTel standard resource conventions (v0.17 Phase 7b arch F-3).
/// - `OTEL_RESOURCE_ATTRIBUTES` is honored as additional k=v pairs.
///   Operator-supplied attributes override our defaults — `Resource::builder`'s
///   `with_attributes` semantics already do last-write-wins, so we
///   apply the parsed pairs after the defaults to get override behavior.
fn build_resource<F>(env: F) -> Resource
where
    F: Fn(&str) -> Option<String>,
{
    use opentelemetry::KeyValue;

    let service_name = env("OTEL_SERVICE_NAME").unwrap_or_else(|| "secretenv".to_owned());
    let host_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_owned());

    let mut builder = Resource::builder()
        .with_service_name(service_name)
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("host.name", host_name))
        .with_attribute(KeyValue::new("host.arch", std::env::consts::ARCH))
        .with_attribute(KeyValue::new("os.type", std::env::consts::OS))
        .with_attribute(KeyValue::new("process.pid", i64::from(std::process::id())));

    // Apply operator-supplied OTEL_RESOURCE_ATTRIBUTES last so they
    // override our defaults — e.g. an operator can pin
    // `deployment.environment.name=production` per the §2.10 opt-in.
    if let Some(raw) = env("OTEL_RESOURCE_ATTRIBUTES") {
        for (k, v) in parse_resource_attributes(&raw) {
            builder = builder.with_attribute(KeyValue::new(k, v));
        }
    }

    builder.build()
}

/// Parse `OTEL_RESOURCE_ATTRIBUTES` per the OTel SDK env-var spec:
/// comma-separated `key=value` pairs. Both key and value are
/// percent-decoded (the spec allows escaping `,`, `=`, and any byte
/// via `%XX`). Pairs with an empty key are dropped. Malformed pairs
/// (no `=`) are dropped silently — the spec allows this.
fn parse_resource_attributes(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            let k = percent_decode(k.trim());
            let v = percent_decode(v.trim());
            if k.is_empty() {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

/// Build the configured sampler from env vars per the OTel SDK
/// spec, wrapped in the mutation-non-droppable rule (SEC-INV-22).
///
/// Honors `OTEL_TRACES_SAMPLER` (one of `always_on`, `always_off`,
/// `traceidratio`, `parentbased_always_on`, `parentbased_always_off`,
/// `parentbased_traceidratio`) and `OTEL_TRACES_SAMPLER_ARG` (the
/// f64 ratio for the `traceidratio` variants). Defaults to
/// `parentbased_always_on` (v0.17 baseline). Unrecognised sampler
/// names degrade to the default with a `tracing::warn!` so operators
/// notice misconfiguration. Ratio is clamped to `[0.0, 1.0]`.
///
/// v0.17 Phase 7b — arch F-4. Without this, SEC-INV-22's "safe
/// under aggressive ratio sampling" story was paper-only because the
/// inner sampler was hardcoded to `AlwaysOn`.
fn sampler_from_env<F>(env: F) -> MutationNonDroppableSampler<opentelemetry_sdk::trace::Sampler>
where
    F: Fn(&str) -> Option<String>,
{
    use opentelemetry_sdk::trace::Sampler;

    let ratio = || {
        env("OTEL_TRACES_SAMPLER_ARG")
            .and_then(|s| s.parse::<f64>().ok())
            .map_or(1.0, |r| r.clamp(0.0, 1.0))
    };

    let inner = match env("OTEL_TRACES_SAMPLER").as_deref() {
        None | Some("parentbased_always_on") => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
        Some("always_on") => Sampler::AlwaysOn,
        Some("always_off") => Sampler::AlwaysOff,
        Some("traceidratio") => Sampler::TraceIdRatioBased(ratio()),
        Some("parentbased_always_off") => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        Some("parentbased_traceidratio") => {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio())))
        }
        Some(other) => {
            tracing::warn!(
                requested = other,
                "OTEL_TRACES_SAMPLER value not recognised; falling back to parentbased_always_on",
            );
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
        }
    };

    MutationNonDroppableSampler::new(inner)
}

/// Minimal RFC 3986 percent-decoder. Spec-required for the OTel
/// `RESOURCE_ATTRIBUTES` env var. Invalid `%XX` sequences are left
/// unchanged in the output (forgiving — operator env-var typos
/// degrade gracefully).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
        ExporterMode::Noop => Ok(TelemetryGuard {
            tracer_provider: None,
            meter_provider: None,
            _parent_ctx_guard: None,
        }),
        ExporterMode::Console => {
            // SEC-INV-22: every TracerProvider we install wraps its
            // sampler with the mutation-non-droppable rule, so that
            // operator-configured ratio sampling can never silently
            // drop a registry mutation from the audit stream.
            let tracer_provider = SdkTracerProvider::builder()
                .with_resource(build_resource(env))
                .with_sampler(sampler_from_env(env))
                .with_batch_exporter(opentelemetry_stdout::SpanExporter::default())
                .build();
            let meter_provider = SdkMeterProvider::builder()
                .with_resource(build_resource(env))
                .with_reader(
                    PeriodicReader::builder(opentelemetry_stdout::MetricExporter::default())
                        .build(),
                )
                .build();
            Ok(install(tracer_provider, meter_provider, env))
        }
        ExporterMode::OtlpGrpc => {
            // Span exporter.
            let mut span_builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
            if let Some(endpoint) = env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                .or_else(|| env("OTEL_EXPORTER_OTLP_ENDPOINT"))
            {
                span_builder = span_builder.with_endpoint(endpoint);
            }
            if let Some(timeout_ms) =
                env("OTEL_EXPORTER_OTLP_TIMEOUT").and_then(|s| s.parse::<u64>().ok())
            {
                span_builder = span_builder.with_timeout(Duration::from_millis(timeout_ms));
            }
            let span_exporter =
                span_builder.build().map_err(|e| InitError::Exporter(format!("{e}")))?;

            // Metric exporter — same endpoint family, with its own
            // per-signal override if the operator set one.
            let mut metric_builder = opentelemetry_otlp::MetricExporter::builder().with_tonic();
            if let Some(endpoint) = env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
                .or_else(|| env("OTEL_EXPORTER_OTLP_ENDPOINT"))
            {
                metric_builder = metric_builder.with_endpoint(endpoint);
            }
            if let Some(timeout_ms) =
                env("OTEL_EXPORTER_OTLP_TIMEOUT").and_then(|s| s.parse::<u64>().ok())
            {
                metric_builder = metric_builder.with_timeout(Duration::from_millis(timeout_ms));
            }
            let metric_exporter =
                metric_builder.build().map_err(|e| InitError::Exporter(format!("{e}")))?;

            let tracer_provider = SdkTracerProvider::builder()
                .with_resource(build_resource(env))
                .with_sampler(sampler_from_env(env))
                .with_batch_exporter(span_exporter)
                .build();
            let meter_provider = SdkMeterProvider::builder()
                .with_resource(build_resource(env))
                .with_reader(PeriodicReader::builder(metric_exporter).build())
                .build();
            Ok(install(tracer_provider, meter_provider, env))
        }
    }
}

/// Stash the providers in the global slots, register the W3C
/// propagator, build the metric instruments against the freshly
/// installed meter, extract any inbound W3C `TRACEPARENT`/`TRACESTATE`
/// from process env and attach as the current context, and return the
/// guard. Infallible — the providers are already built.
fn install<F>(
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    env: F,
) -> TelemetryGuard
where
    F: Fn(&str) -> Option<String>,
{
    let tracer_provider = Arc::new(tracer_provider);
    let meter_provider = Arc::new(meter_provider);
    // OnceLock::set returns Err if already set — re-init from tests is
    // a programmer error, not a runtime fault.
    let _ = PROVIDER.set(Arc::clone(&tracer_provider));
    let _ = METER_PROVIDER.set(Arc::clone(&meter_provider));
    global::set_tracer_provider((*tracer_provider).clone());
    global::set_meter_provider((*meter_provider).clone());
    global::set_text_map_propagator(TraceContextPropagator::new());
    // Now that the global MeterProvider is live, register our typed
    // metric instruments against it. The metrics module's OnceLock
    // ensures this is a one-shot per process.
    crate::metrics::init(&global::meter("secretenv"));
    // v0.17 Phase 7b — arch F-2. Extract inbound W3C trace context
    // from process env (typical: CI step sets TRACEPARENT and expects
    // `secretenv run` to attach as a child). The `ContextGuard` keeps
    // the parent context active for the process lifetime via
    // `TelemetryGuard`; on drop the prior context is restored (which
    // for a CLI is process exit, so the restoration is moot).
    let parent_ctx_guard = extract_inbound_parent_context(env);
    TelemetryGuard {
        tracer_provider: Some(tracer_provider),
        meter_provider: Some(meter_provider),
        _parent_ctx_guard: parent_ctx_guard,
    }
}

/// Pull `TRACEPARENT` (and optionally `TRACESTATE`) from process env
/// through the globally-registered `TraceContextPropagator` and attach
/// the resulting `Context` as current. Returns the guard whose `Drop`
/// restores the prior context — caller holds it for as long as the
/// inbound context should remain current (CLI: process lifetime).
///
/// Returns `None` when no `TRACEPARENT` is set (the common case).
fn extract_inbound_parent_context<F>(env: F) -> Option<opentelemetry::ContextGuard>
where
    F: Fn(&str) -> Option<String>,
{
    let traceparent = env("TRACEPARENT")?;
    let tracestate = env("TRACESTATE");
    let carrier = EnvCarrier { traceparent, tracestate };
    let parent_cx = global::get_text_map_propagator(|p| p.extract(&carrier));
    Some(parent_cx.attach())
}

/// Tiny `Extractor` impl that backs the propagator from the captured
/// `TRACEPARENT` / `TRACESTATE` env-var strings; avoids depending on
/// `HashMap` or `http::HeaderMap` for the two-element lookup.
struct EnvCarrier {
    traceparent: String,
    tracestate: Option<String>,
}

impl opentelemetry::propagation::Extractor for EnvCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "traceparent" => Some(self.traceparent.as_str()),
            "tracestate" => self.tracestate.as_deref(),
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        if self.tracestate.is_some() {
            vec!["traceparent", "tracestate"]
        } else {
            vec!["traceparent"]
        }
    }
}

/// RAII guard for the installed OTel providers (traces + metrics).
///
/// On drop, flushes and shuts down both providers. The `exec()` path
/// bypasses Drop (the process is replaced), so callers must invoke
/// [`flush_before_exec`] explicitly before any `exec()`.
#[must_use = "the TelemetryGuard must be held for the process lifetime; \
              dropping it shuts down the OTel providers"]
pub struct TelemetryGuard {
    tracer_provider: Option<Arc<SdkTracerProvider>>,
    meter_provider: Option<Arc<SdkMeterProvider>>,
    /// v0.17 Phase 7b — arch F-2. RAII guard for the inbound W3C
    /// `TRACEPARENT` context attachment. `None` when no `TRACEPARENT`
    /// was set in process env (the common case). When `Some`, the
    /// CLI's `let _telemetry = init()?` binding keeps the parent
    /// context current for the entire process lifetime; every span
    /// the CLI emits becomes a child of the inbound trace.
    ///
    /// NOTE: `opentelemetry::ContextGuard` is `!Send`. This makes
    /// `TelemetryGuard` `!Send` too. Acceptable because the only
    /// production holder is `main()`'s local binding (single-threaded
    /// init); the field name is `_`-prefixed so callers don't try to
    /// access it.
    _parent_ctx_guard: Option<opentelemetry::ContextGuard>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Best-effort. Failures during shutdown cannot be surfaced to
        // the operator usefully — process is exiting either way.
        if let Some(meter_provider) = self.meter_provider.take() {
            let _ = meter_provider.force_flush();
            let _ = meter_provider.shutdown();
        }
        if let Some(tracer_provider) = self.tracer_provider.take() {
            let _ = tracer_provider.force_flush();
            let _ = tracer_provider.shutdown();
        }
    }
}

/// Build the `tracing_opentelemetry` bridge layer.
///
/// Converts every `tracing::info_span!()` / `tracing::event!()` call
/// into an OTel span on the globally-installed `TracerProvider`. The
/// CLI composes this into its `tracing_subscriber::registry()` stack
/// alongside the existing `EnvFilter` + `fmt` layer.
///
/// v0.17 Phase 7b — arch F-1 / code H-1. Without this, every v0.14
/// / v0.15 / v0.16 hook site (backend `get/set/list/check/history`,
/// migrate phases, MCP tool handlers) emits as a stderr log only
/// and never reaches OTLP — only direct `SecretEnvSpan::start`
/// callers do. Installing this bridge fulfils the build plan's
/// "additive instrumentation only" framing in §27.
///
/// Returns an opaque type to keep `opentelemetry` and
/// `tracing_opentelemetry` imports out of `secretenv-cli` per the
/// Phase 2 scoping rule.
#[must_use]
pub fn tracing_bridge_layer<S>() -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    tracing_opentelemetry::layer().with_tracer(global::tracer("secretenv"))
}

/// Synchronously flush pending spans + metrics with a bounded timeout,
/// intended to be called immediately before `execve()` replaces the
/// process.
///
/// Implements SEC-INV-22's bounded-flush requirement: a slow or
/// unreachable collector cannot turn `secretenv run` into a latency
/// cliff. On timeout, pending data drops and a `tracing::debug!` event
/// is emitted.
///
/// No-op when [`init`] installed no provider (the no-op exporter mode).
pub fn flush_before_exec(timeout: Duration) {
    let tracer = PROVIDER.get().cloned();
    let meter = METER_PROVIDER.get().cloned();
    if tracer.is_none() && meter.is_none() {
        return;
    }
    // Worker thread + recv_timeout: keeps the timeout bound enforceable
    // without requiring a tokio runtime context at the exec call site
    // (`secretenv-core::runner::exec_with_env` is sync). The single
    // bound covers both signals — meter flush first because the
    // PeriodicReader's batch is usually larger than the span batch.
    let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
    let worker = std::thread::spawn(move || {
        if let Some(m) = meter {
            let _ = m.force_flush();
        }
        if let Some(t) = tracer {
            let _ = t.force_flush();
        }
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
                "otel flush timed out; dropping pending spans + metrics",
            );
            // Detach the worker thread; the OTel batch processors will
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
        assert!(guard.tracer_provider.is_none());
        assert!(guard.meter_provider.is_none());
        drop(guard);
    }

    #[test]
    fn flush_before_exec_is_noop_when_no_provider() {
        // OnceLock may have been set by an earlier test in this module;
        // the call must still complete (and not panic) regardless.
        flush_before_exec(Duration::from_millis(50));
    }
}
