//! SecretEnv CLI entry point.
//!
//! Bootstrapping only — parse args, init tracing, wire the backend
//! registry, dispatch. All business logic lives in
//! [`secretenv_core`] and the per-backend crates.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use secretenv_core::{BackendRegistry, Config};
use tracing_subscriber::EnvFilter;

mod cli;
mod doctor;

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
    let config = load_config(&cli)?;

    let mut backends = BackendRegistry::new();
    backends.register_factory(Box::new(backend_local::LocalFactory::new()));
    backends.register_factory(Box::new(backend_aws_ssm::AwsSsmFactory::new()));
    backends.register_factory(Box::new(backend_1password::OnePasswordFactory::new()));
    backends.load_from_config(&config).context("loading backend instances from config.toml")?;

    cli.run(&config, &backends).await
}

fn load_config(cli: &Cli) -> Result<Config> {
    cli.config.as_ref().map_or_else(Config::load, |path| Config::load_from(path))
}
