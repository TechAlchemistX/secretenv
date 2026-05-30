// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! SecretEnv CLI entry point.
//!
//! Bootstrapping only — parse args, init tracing, wire the backend
//! registry, dispatch. All business logic lives in
//! [`secretenv_core`] and the per-backend crates.
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use secretenv_core::Config;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

use secretenv_backends_init as backends_init;
mod cli;
mod doctor;
mod invite;
mod profile;
mod reports;
mod setup;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // `RUST_LOG=secretenv=debug secretenv run ...` opts into detail.
    // Defaults to warn-level so the CLI stays quiet by default.
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("secretenv=warn"));

    // Init telemetry FIRST so the global TracerProvider is live when
    // the tracing-otel bridge layer installs below — otherwise the
    // bridge would capture a noop tracer reference. No-op when none
    // of `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_EXPORTER`, etc.
    // is set — zero startup cost for operators without a collector.
    // Drop flushes and shuts down; the `exec()` path bypasses Drop
    // and calls `secretenv_telemetry::flush_before_exec` explicitly.
    // v0.18 Arch-F-5: pass the CLI binary's own CARGO_PKG_VERSION
    // (not the telemetry crate's) so `service.version` on every
    // emitted span reflects the binary in use.
    let _telemetry = secretenv_telemetry::init(env!("CARGO_PKG_VERSION"))?;

    // v0.17 Phase 7b — arch F-1. Compose subscriber stack: env-filter
    // → stderr fmt layer → tracing-otel bridge. The bridge converts
    // every `tracing::info_span!()` / `event!()` call in v0.14-v0.16
    // hook sites (backend get/set/list/check, migrate phases, MCP
    // tool handlers) into OTel spans on the global TracerProvider.
    // Without the bridge those hooks emit as stderr log only.
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).without_time())
        .with(secretenv_telemetry::tracing_bridge_layer())
        .init();

    let cli = Cli::parse();
    // Setup may write to a target that doesn't exist yet — tolerate a
    // missing --config path in that case. Every other command needs an
    // actually-present config (or falls through to XDG default).
    let allow_missing = matches!(cli.command, cli::Command::Setup(_));
    let config = load_config(&cli, allow_missing)?;

    // `mcp serve` runs an introspection server — it must tolerate a
    // config whose `[backends.*]` factory validation fails so the
    // agent can call `list_backends` / `doctor` to discover what's
    // broken. The handlers that actually need a live registry build
    // one themselves at call time. Every other subcommand still
    // eagerly builds the registry so misconfigured backends fail
    // fast at startup.
    let backends = if matches!(cli.command, cli::Command::Mcp(_)) {
        secretenv_core::BackendRegistry::new()
    } else {
        backends_init::build_registry(&config)?
    };

    cli.run(&config, &backends).await
}

fn load_config(cli: &Cli, allow_missing: bool) -> Result<Config> {
    match &cli.config {
        Some(path) if allow_missing && !path.exists() => Ok(Config::default()),
        Some(path) => Config::load_from(path),
        None => Config::load(),
    }
}
