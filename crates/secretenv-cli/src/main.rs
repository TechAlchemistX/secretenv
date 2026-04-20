//! SecretEnv CLI entry point.
//!
//! Bootstrapping only — parse args, init tracing, wire the backend
//! registry, dispatch. All business logic lives in
//! [`secretenv_core`] and the per-backend crates.
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use secretenv_core::Config;
use tracing_subscriber::EnvFilter;

mod backends_init;
mod cli;
mod doctor;
mod invite;
mod setup;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    // `RUST_LOG=secretenv=debug secretenv run ...` opts into detail.
    // Defaults to warn-level so the CLI stays quiet by default.
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("secretenv=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .without_time()
        .init();

    let cli = Cli::parse();
    // Setup may write to a target that doesn't exist yet — tolerate a
    // missing --config path in that case. Every other command needs an
    // actually-present config (or falls through to XDG default).
    let allow_missing = matches!(cli.command, cli::Command::Setup(_));
    let config = load_config(&cli, allow_missing)?;

    let backends = backends_init::build_registry(&config)?;

    cli.run(&config, &backends).await
}

fn load_config(cli: &Cli, allow_missing: bool) -> Result<Config> {
    match &cli.config {
        Some(path) if allow_missing && !path.exists() => Ok(Config::default()),
        Some(path) => Config::load_from(path),
        None => Config::load(),
    }
}
