//! `secretenv` CLI — clap definitions and the per-subcommand dispatch.
//!
//! Keep each handler short and focused: the heavy lifting lives in
//! `secretenv-core` (resolver, runner, backends). This module is pure
//! wiring.
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use secretenv_core::{
    resolve_manifest, resolve_registry, run as runner_run, Backend, BackendRegistry, BackendUri,
    Config, Manifest, RegistrySelection,
};

/// Command-line arguments for `secretenv`.
#[derive(Debug, Parser)]
#[command(
    name = "secretenv",
    version,
    about = "Run commands with secrets injected from any backend"
)]
pub struct Cli {
    /// Path to `config.toml`. Defaults to the XDG-standard location
    /// (`$XDG_CONFIG_HOME/secretenv/config.toml`).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command with secrets injected as env vars.
    Run(RunArgs),
    /// Registry document operations.
    #[command(subcommand)]
    Registry(RegistryCommand),
    /// Print the backend URI an alias resolves to (no fetch).
    Resolve(AliasArgs),
    /// Fetch a secret value by alias. Prompts for confirmation
    /// before printing to stdout.
    Get(GetArgs),
    /// Diagnose backend installation and auth state (Phase 10).
    Doctor(DoctorArgs),
    /// Initialize `config.toml` for a registry URI (Phase 11).
    Setup(SetupArgs),
}

/// `secretenv run [...] -- <command>`
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Registry selection — name (from `[registries.<name>]`) or a
    /// direct backend URI. Overrides `SECRETENV_REGISTRY` and the
    /// `default` registry.
    #[arg(long)]
    pub registry: Option<String>,

    /// Print what would be fetched without fetching or executing.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit fetch progress to stderr.
    #[arg(long)]
    pub verbose: bool,

    /// Program + arguments to execute. Use `--` to separate
    /// secretenv flags from the command.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// `secretenv registry <subcommand>`
#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// List all aliases in the registry.
    List {
        #[arg(long)]
        registry: Option<String>,
    },
    /// Print the backend URI for a single alias.
    Get {
        /// Alias name (the left-hand side of a registry entry).
        alias: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Set an alias to point at a backend URI.
    Set {
        alias: String,
        /// The target backend URI (e.g. `aws-ssm-prod:///prod/stripe-key`).
        uri: String,
        #[arg(long)]
        registry: Option<String>,
    },
    /// Remove an alias from the registry.
    Unset {
        alias: String,
        #[arg(long)]
        registry: Option<String>,
    },
}

/// Shared shape for `resolve <alias>`.
#[derive(Debug, Args)]
pub struct AliasArgs {
    pub alias: String,
    #[arg(long)]
    pub registry: Option<String>,
}

/// `secretenv get <alias>` — prompts for confirmation by default.
#[derive(Debug, Args)]
pub struct GetArgs {
    pub alias: String,
    #[arg(long)]
    pub registry: Option<String>,
    /// Skip the interactive confirmation prompt.
    #[arg(long, short)]
    pub yes: bool,
}

/// `secretenv doctor [--json]` — Phase 10 stub.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON instead of human output.
    #[arg(long)]
    pub json: bool,
}

/// `secretenv setup <registry-uri>` — bootstrap a fresh config.toml.
#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Backend URI the new `config.toml` should target as
    /// `[registries.default]`. The scheme becomes the backend
    /// instance name.
    pub registry_uri: String,

    /// AWS region — required for aws-ssm backends.
    #[arg(long)]
    pub region: Option<String>,

    /// AWS profile — optional, aws-ssm only.
    #[arg(long)]
    pub profile: Option<String>,

    /// 1Password account shorthand or URL — optional, 1password only.
    #[arg(long)]
    pub account: Option<String>,

    /// Overwrite an existing config.toml.
    #[arg(long)]
    pub force: bool,

    /// Skip the post-write health check.
    #[arg(long)]
    pub skip_doctor: bool,
}

impl Cli {
    /// Dispatch to the per-subcommand handler.
    ///
    /// `backends` is already populated with factories + loaded
    /// instances from `config`.
    ///
    /// # Errors
    /// Forwarded from the individual subcommand handlers.
    pub async fn run(&self, config: &Config, backends: &BackendRegistry) -> Result<()> {
        match &self.command {
            Command::Run(args) => cmd_run(args, config, backends).await,
            Command::Registry(rc) => cmd_registry(rc, config, backends).await,
            Command::Resolve(args) => cmd_resolve(args, config, backends).await,
            Command::Get(args) => cmd_get(args, config, backends).await,
            Command::Doctor(args) => crate::doctor::run_doctor(backends, args.json).await,
            Command::Setup(args) => cmd_setup(args, self.config.as_deref()).await,
        }
    }
}

// ---- Registry selection resolution --------------------------------------

/// Resolve the active registry selection per [[resolution-flow]]:
///   1. `explicit` (from `--registry <name-or-uri>` CLI flag).
///   2. `env_registry` (usually `std::env::var("SECRETENV_REGISTRY")`).
///   3. `[registries.default]` in config.
///   4. Hard error.
///
/// Taking `env_registry` as a parameter keeps the function pure —
/// tests pass `None` without having to touch process env (which is
/// `unsafe` in Rust 2024 and unsafe-forbidden in this crate).
///
/// # Errors
/// Returns an error if every fallback is exhausted, or if `explicit`
/// or `env_registry` fails to parse as a [`RegistrySelection`].
pub fn resolve_selection(
    explicit: Option<&str>,
    env_registry: Option<&str>,
    config: &Config,
) -> Result<RegistrySelection> {
    if let Some(s) = explicit {
        return s.parse().context("parsing --registry value");
    }
    if let Some(env) = env_registry {
        if !env.is_empty() {
            return env.parse().context("parsing $SECRETENV_REGISTRY");
        }
    }
    if config.registries.contains_key("default") {
        return Ok(RegistrySelection::Name("default".to_owned()));
    }
    Err(anyhow!(
        "no registry selected — pass --registry <name-or-uri>, set \
         $SECRETENV_REGISTRY, or add a [registries.default] block to config.toml"
    ))
}

/// Production call-site: read `SECRETENV_REGISTRY` from the process
/// env and delegate to [`resolve_selection`].
fn resolve_selection_from_env(
    explicit: Option<&str>,
    config: &Config,
) -> Result<RegistrySelection> {
    let env = std::env::var("SECRETENV_REGISTRY").ok();
    resolve_selection(explicit, env.as_deref(), config)
}

// ---- run ---------------------------------------------------------------

async fn cmd_run(args: &RunArgs, config: &Config, backends: &BackendRegistry) -> Result<()> {
    let starting_dir = std::env::current_dir().context("determining current directory")?;
    let manifest = Manifest::load(&starting_dir)
        .context("loading secretenv.toml (walked upward from $CWD)")?;
    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let aliases = resolve_registry(config, &selection, backends).await?;
    let resolved = resolve_manifest(&manifest, &aliases)?;
    runner_run(&resolved, backends, &args.command, args.dry_run, args.verbose).await
}

// ---- resolve -----------------------------------------------------------

async fn cmd_resolve(args: &AliasArgs, config: &Config, backends: &BackendRegistry) -> Result<()> {
    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let aliases = resolve_registry(config, &selection, backends).await?;
    let uri = aliases.get(&args.alias).ok_or_else(|| {
        anyhow!("alias '{}' not found in registry at '{}'", args.alias, aliases.source().raw)
    })?;
    println!("{}", uri.raw);
    Ok(())
}

// ---- get (with confirmation) -------------------------------------------

async fn cmd_get(args: &GetArgs, config: &Config, backends: &BackendRegistry) -> Result<()> {
    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let aliases = resolve_registry(config, &selection, backends).await?;
    let uri = aliases
        .get(&args.alias)
        .ok_or_else(|| {
            anyhow!("alias '{}' not found in registry at '{}'", args.alias, aliases.source().raw)
        })?
        .clone();

    if !args.yes && !confirm_print_secret(&args.alias)? {
        bail!("aborted by user");
    }

    let backend = backends
        .get(&uri.scheme)
        .ok_or_else(|| anyhow!("no backend instance '{}' is configured", uri.scheme))?;
    let value = backend.get(&uri).await?;
    println!("{value}");
    Ok(())
}

fn confirm_print_secret(alias: &str) -> Result<bool> {
    eprint!("about to print the secret value for '{alias}' to stdout. continue? [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("reading confirmation from stdin")?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

// ---- registry subcommands -----------------------------------------------

async fn cmd_registry(
    rc: &RegistryCommand,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    match rc {
        RegistryCommand::List { registry } => {
            registry_list(registry.as_deref(), config, backends).await
        }
        RegistryCommand::Get { alias, registry } => {
            registry_get(alias, registry.as_deref(), config, backends).await
        }
        RegistryCommand::Set { alias, uri, registry } => {
            registry_set(alias, uri, registry.as_deref(), config, backends).await
        }
        RegistryCommand::Unset { alias, registry } => {
            registry_unset(alias, registry.as_deref(), config, backends).await
        }
    }
}

async fn registry_list(
    registry: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let selection = resolve_selection_from_env(registry, config)?;
    let aliases = resolve_registry(config, &selection, backends).await?;
    let mut entries: Vec<_> = aliases.iter().map(|(a, u)| (a.clone(), u.raw.clone())).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (alias, uri) in entries {
        println!("{alias} = {uri}");
    }
    Ok(())
}

async fn registry_get(
    alias: &str,
    registry: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let selection = resolve_selection_from_env(registry, config)?;
    let aliases = resolve_registry(config, &selection, backends).await?;
    let uri = aliases.get(alias).ok_or_else(|| {
        anyhow!("alias '{alias}' not found in registry at '{}'", aliases.source().raw)
    })?;
    println!("{}", uri.raw);
    Ok(())
}

async fn registry_set(
    alias: &str,
    target_uri: &str,
    registry: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    // Validate target before any write.
    let target = BackendUri::parse(target_uri)
        .with_context(|| format!("target '{target_uri}' is not a valid URI"))?;
    if target.is_alias() {
        bail!("target must be a direct backend URI, not a secretenv:// alias");
    }
    if backends.get(&target.scheme).is_none() {
        bail!(
            "target '{target_uri}' references backend instance '{}' which is not configured",
            target.scheme
        );
    }

    let (source_uri, backend) = pick_registry_source(registry, config, backends)?;
    let current = backend
        .list(&source_uri)
        .await
        .with_context(|| format!("reading registry document at '{}'", source_uri.raw))?;
    let mut map: HashMap<String, String> = current.into_iter().collect();
    map.insert(alias.to_owned(), target_uri.to_owned());
    let serialized = serialize_registry(backend.backend_type(), &map)?;
    backend
        .set(&source_uri, &serialized)
        .await
        .with_context(|| format!("writing updated registry document to '{}'", source_uri.raw))?;
    eprintln!("set {alias} → {target_uri} in registry at '{}'", source_uri.raw);
    Ok(())
}

async fn registry_unset(
    alias: &str,
    registry: Option<&str>,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let (source_uri, backend) = pick_registry_source(registry, config, backends)?;
    let current = backend
        .list(&source_uri)
        .await
        .with_context(|| format!("reading registry document at '{}'", source_uri.raw))?;
    let mut map: HashMap<String, String> = current.into_iter().collect();
    if map.remove(alias).is_none() {
        bail!("alias '{alias}' not found in registry at '{}'", source_uri.raw);
    }
    let serialized = serialize_registry(backend.backend_type(), &map)?;
    backend
        .set(&source_uri, &serialized)
        .await
        .with_context(|| format!("writing updated registry document to '{}'", source_uri.raw))?;
    eprintln!("unset {alias} in registry at '{}'", source_uri.raw);
    Ok(())
}

fn pick_registry_source<'a>(
    registry: Option<&str>,
    config: &Config,
    backends: &'a BackendRegistry,
) -> Result<(BackendUri, &'a dyn Backend)> {
    let selection = resolve_selection_from_env(registry, config)?;
    let source_uri: BackendUri = match selection {
        RegistrySelection::Uri(u) => u,
        RegistrySelection::Name(name) => {
            let reg = config
                .registries
                .get(&name)
                .ok_or_else(|| anyhow!("no registry named '{name}' in config.toml"))?;
            let first =
                reg.sources.first().ok_or_else(|| anyhow!("registry '{name}' has no sources"))?;
            BackendUri::parse(first).with_context(|| {
                format!("registry '{name}' sources[0] = '{first}' is not a valid URI")
            })?
        }
    };
    let backend = backends.get(&source_uri.scheme).ok_or_else(|| {
        anyhow!(
            "registry source '{}' targets backend '{}' which is not configured",
            source_uri.raw,
            source_uri.scheme
        )
    })?;
    Ok((source_uri, backend))
}

/// Serialize `map` in whatever format `backend_type` uses for its
/// registry documents. Unknown types error — v0.1 supports local,
/// aws-ssm, 1password only.
fn serialize_registry(backend_type: &str, map: &HashMap<String, String>) -> Result<String> {
    match backend_type {
        "local" | "1password" => toml::to_string(map).with_context(|| {
            format!("serializing registry as TOML for backend type '{backend_type}'")
        }),
        "aws-ssm" => serde_json::to_string(map).with_context(|| {
            format!("serializing registry as JSON for backend type '{backend_type}'")
        }),
        other => Err(anyhow!(
            "writing registry documents through backend type '{other}' is not supported in v0.1"
        )),
    }
}

// ---- setup --------------------------------------------------------------

async fn cmd_setup(args: &SetupArgs, target_config: Option<&std::path::Path>) -> Result<()> {
    let opts = crate::setup::SetupOpts {
        registry_uri: args.registry_uri.clone(),
        region: args.region.clone(),
        profile: args.profile.clone(),
        account: args.account.clone(),
        force: args.force,
        skip_doctor: args.skip_doctor,
        target: target_config.map(std::path::Path::to_path_buf),
    };
    crate::setup::run_setup(&opts).await
}

// Avoid unused-import warnings on FromStr when RegistrySelection::from_str
// isn't called through the trait method directly.
const _: fn() = || {
    let _ = <RegistrySelection as FromStr>::from_str;
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use secretenv_core::{BackendConfig, RegistryConfig};

    use super::*;

    fn config_with_default() -> Config {
        Config {
            registries: HashMap::from([(
                "default".to_owned(),
                RegistryConfig { sources: vec!["local:///tmp/r.toml".to_owned()] },
            )]),
            backends: HashMap::from([(
                "local".to_owned(),
                BackendConfig { backend_type: "local".into(), raw_fields: HashMap::new() },
            )]),
        }
    }

    #[test]
    fn selection_prefers_explicit_flag() {
        let cfg = config_with_default();
        let sel = resolve_selection(Some("prod"), None, &cfg).unwrap();
        match sel {
            RegistrySelection::Name(n) => assert_eq!(n, "prod"),
            RegistrySelection::Uri(_) => panic!("expected Name"),
        }
    }

    #[test]
    fn selection_uses_env_when_flag_absent() {
        let cfg = config_with_default();
        let sel = resolve_selection(None, Some("shared"), &cfg).unwrap();
        match sel {
            RegistrySelection::Name(n) => assert_eq!(n, "shared"),
            RegistrySelection::Uri(_) => panic!("expected Name"),
        }
    }

    #[test]
    fn selection_falls_back_to_default_when_no_flag_or_env() {
        let cfg = config_with_default();
        let sel = resolve_selection(None, None, &cfg).unwrap();
        match sel {
            RegistrySelection::Name(n) => assert_eq!(n, "default"),
            RegistrySelection::Uri(_) => panic!("expected Name"),
        }
    }

    #[test]
    fn selection_errors_when_nothing_configured() {
        let cfg = Config::default();
        let err = resolve_selection(None, None, &cfg).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no registry selected"), "clear error: {msg}");
    }

    #[test]
    fn selection_interprets_triple_slash_as_uri() {
        let cfg = Config::default();
        let sel = resolve_selection(Some("local:///tmp/r.toml"), None, &cfg).unwrap();
        match sel {
            RegistrySelection::Uri(u) => assert_eq!(u.scheme, "local"),
            RegistrySelection::Name(_) => panic!("expected Uri"),
        }
    }

    #[test]
    fn selection_treats_empty_env_as_absent() {
        let cfg = config_with_default();
        let sel = resolve_selection(None, Some(""), &cfg).unwrap();
        match sel {
            RegistrySelection::Name(n) => assert_eq!(n, "default"),
            RegistrySelection::Uri(_) => panic!("expected Name"),
        }
    }

    #[test]
    fn serialize_registry_produces_toml_for_local() {
        let mut m = HashMap::new();
        m.insert("k".to_owned(), "aws-ssm:///v".to_owned());
        let s = serialize_registry("local", &m).unwrap();
        assert!(s.contains("k = \"aws-ssm:///v\""), "TOML shape: {s}");
    }

    #[test]
    fn serialize_registry_produces_json_for_aws_ssm() {
        let mut m = HashMap::new();
        m.insert("k".to_owned(), "aws-ssm:///v".to_owned());
        let s = serialize_registry("aws-ssm", &m).unwrap();
        assert!(s.starts_with('{'), "JSON shape: {s}");
        assert!(s.contains("\"k\""));
    }

    #[test]
    fn serialize_registry_rejects_unknown_type() {
        let m = HashMap::new();
        let err = serialize_registry("unknown-backend", &m).unwrap_err();
        assert!(format!("{err:#}").contains("not supported"));
    }
}
