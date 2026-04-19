//! `secretenv` CLI — clap definitions and the per-subcommand dispatch.
//!
//! Keep each handler short and focused: the heavy lifting lives in
//! `secretenv-core` (resolver, runner, backends). This module is pure
//! wiring.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use secretenv_core::{
    resolve_manifest, resolve_registry, run as runner_run, Backend, BackendRegistry, BackendUri,
    Config, Manifest, RegistryCache, RegistrySelection,
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
    /// Print the backend URI an alias resolves to (no fetch) plus
    /// the cascade source and backend auth status.
    Resolve(ResolveArgs),
    /// Fetch a secret value by alias. Prompts for confirmation
    /// before printing to stdout.
    Get(GetArgs),
    /// Diagnose backend installation and auth state (Phase 10).
    Doctor(DoctorArgs),
    /// Initialize `config.toml` for a registry URI (Phase 11).
    Setup(SetupArgs),
    /// Generate shell completion scripts.
    Completions(CompletionsArgs),
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

/// `secretenv resolve <alias>` — print the alias → URI mapping plus
/// cascade source, env-var binding, and backend auth status. Pure
/// metadata — never fetches the secret value.
#[derive(Debug, Args)]
pub struct ResolveArgs {
    pub alias: String,
    #[arg(long)]
    pub registry: Option<String>,
    /// Emit machine-readable JSON instead of human tabular output.
    #[arg(long)]
    pub json: bool,
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

    /// Vault instance URL — required for vault backends.
    #[arg(long)]
    pub vault_address: Option<String>,

    /// Vault Enterprise namespace — optional, vault only.
    #[arg(long)]
    pub vault_namespace: Option<String>,

    /// GCP project ID — required for gcp backends.
    #[arg(long)]
    pub gcp_project: Option<String>,

    /// GCP service-account email to impersonate — optional, gcp only.
    #[arg(long)]
    pub gcp_impersonate_service_account: Option<String>,

    /// Overwrite an existing config.toml.
    #[arg(long)]
    pub force: bool,

    /// Skip the post-write health check.
    #[arg(long)]
    pub skip_doctor: bool,
}

/// `secretenv completions <shell>` — emit a shell-completion script.
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Target shell. One of `bash`, `zsh`, `fish`.
    pub shell: Shell,

    /// Write the script here (chmod 0o644) instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Shells we emit completion scripts for. A deliberately small set —
/// the Big Three POSIX shells. PowerShell/Elvish can be added later
/// when a user asks; there's no reason to carry the surface preemptively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
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
            Command::Doctor(args) => crate::doctor::run_doctor(config, backends, args.json).await,
            Command::Setup(args) => cmd_setup(args, self.config.as_deref()).await,
            Command::Completions(args) => cmd_completions(args),
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
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    let resolved = resolve_manifest(&manifest, &aliases)?;
    runner_run(&resolved, backends, &args.command, args.dry_run, args.verbose).await
}

// ---- resolve -----------------------------------------------------------

async fn cmd_resolve(
    args: &ResolveArgs,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    use secretenv_core::{Manifest, DEFAULT_CHECK_TIMEOUT};

    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;

    let (target, source) = aliases.get(&args.alias).ok_or_else(|| {
        anyhow!(
            "alias '{}' not found in registry cascade [{}]",
            args.alias,
            format_sources(&aliases)
        )
    })?;
    let target = target.clone();
    let source = source.clone();

    // Cascade layer index — position in `aliases.sources()` whose URI
    // matches the source we just resolved.
    let layer_index = aliases.sources().position(|u| u.raw == source.raw).unwrap_or(0);

    // Reverse-lookup env var from the manifest. Best-effort: if no
    // manifest exists (user is in a repo without `secretenv.toml`),
    // the env-var row shows `(none)` / null instead of erroring —
    // `resolve` is a debugging tool that should work anywhere.
    let env_var = std::env::current_dir()
        .ok()
        .and_then(|cwd| Manifest::load(&cwd).ok())
        .and_then(|m| manifest_env_var_for_alias(&m, &args.alias));

    // Backend auth status. Timed out per the Phase 0.5 check-timeout
    // wrapper. Resolve still succeeds even if check fails — operators
    // debug broken auth by seeing the status line, not by being
    // denied the alias→URI mapping.
    // Backend::check returns a bare BackendStatus (no Result), so wrap
    // it in Ok(..) inside an async block so with_timeout's
    // Future<Output = Result<T>> bound is satisfied. Same idiom as
    // doctor::run_doctor.
    let backend_check = match backends.get(&target.scheme) {
        Some(b) => {
            let op_label = format!("{}::check", b.backend_type());
            let check_future = async { Ok(b.check().await) };
            match secretenv_core::with_timeout(DEFAULT_CHECK_TIMEOUT, &op_label, check_future).await
            {
                Ok(status) => ResolveBackendCheck::Checked {
                    backend_type: b.backend_type().to_owned(),
                    status,
                },
                Err(err) => ResolveBackendCheck::CheckFailed {
                    backend_type: b.backend_type().to_owned(),
                    message: format!("{err:#}"),
                },
            }
        }
        None => ResolveBackendCheck::UnregisteredScheme,
    };

    let report = ResolveReport {
        alias: args.alias.clone(),
        env_var,
        resolved: target.raw.clone(),
        source_uri: source.raw.clone(),
        layer_index,
        backend_scheme: target.scheme.clone(),
        check: backend_check,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    } else {
        print!("{}", report.render_human());
    }
    Ok(())
}

/// Scan the manifest's `[secrets]` entries for the first key whose
/// `from = "secretenv://<alias>"` (or `"secretenv:///<alias>"`)
/// references the given alias. Returns `None` if nothing references
/// the alias.
fn manifest_env_var_for_alias(manifest: &secretenv_core::Manifest, alias: &str) -> Option<String> {
    for (env_var, decl) in &manifest.secrets {
        if let secretenv_core::SecretDecl::Alias { from } = decl {
            let Ok(parsed) = secretenv_core::BackendUri::parse(from) else {
                continue;
            };
            if parsed.is_alias() {
                let found = parsed.path.trim_start_matches('/');
                if found == alias {
                    return Some(env_var.clone());
                }
            }
        }
    }
    None
}

/// Backend-check outcome for a resolved alias. Kept separate from
/// `doctor::DoctorStatus` so the resolve handler doesn't depend on
/// doctor's internal shape.
enum ResolveBackendCheck {
    Checked { backend_type: String, status: secretenv_core::BackendStatus },
    CheckFailed { backend_type: String, message: String },
    UnregisteredScheme,
}

struct ResolveReport {
    alias: String,
    env_var: Option<String>,
    resolved: String,
    source_uri: String,
    layer_index: usize,
    backend_scheme: String,
    check: ResolveBackendCheck,
}

impl ResolveReport {
    fn render_human(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        writeln!(out, "alias:      {}", self.alias).ok();
        writeln!(out, "env var:    {}", self.env_var.as_deref().unwrap_or("(none)")).ok();
        writeln!(out, "resolved:   {}", self.resolved).ok();
        writeln!(out, "source:     {}  (cascade layer {})", self.source_uri, self.layer_index).ok();
        writeln!(out, "backend:    {}", self.render_backend_line()).ok();
        out
    }

    fn render_backend_line(&self) -> String {
        use secretenv_core::BackendStatus;
        match &self.check {
            ResolveBackendCheck::Checked { backend_type, status } => {
                let (state, detail) = match status {
                    BackendStatus::Ok { cli_version: _, identity } => {
                        ("authenticated".to_owned(), format!("({identity})"))
                    }
                    BackendStatus::NotAuthenticated { hint } => {
                        ("NOT authenticated".to_owned(), format!("(hint: {hint})"))
                    }
                    BackendStatus::CliMissing { cli_name, install_hint } => {
                        (format!("CLI '{cli_name}' missing"), format!("(install: {install_hint})"))
                    }
                    BackendStatus::Error { message } => {
                        ("error".to_owned(), format!("({message})"))
                    }
                };
                format!("{backend_type} instance '{}' — {state} {detail}", self.backend_scheme)
            }
            ResolveBackendCheck::CheckFailed { backend_type, message } => {
                format!(
                    "{backend_type} instance '{}' — check failed ({message})",
                    self.backend_scheme
                )
            }
            ResolveBackendCheck::UnregisteredScheme => {
                format!(
                    "instance '{}' is not registered in config.toml (resolve succeeded; fetch would fail)",
                    self.backend_scheme
                )
            }
        }
    }

    fn to_json(&self) -> serde_json::Value {
        use secretenv_core::BackendStatus;
        let check = match &self.check {
            ResolveBackendCheck::Checked { backend_type, status } => {
                let (status_key, detail) = match status {
                    BackendStatus::Ok { cli_version, identity } => (
                        "ok",
                        serde_json::json!({
                            "cli_version": cli_version,
                            "identity": identity,
                        }),
                    ),
                    BackendStatus::NotAuthenticated { hint } => {
                        ("not_authenticated", serde_json::json!({ "hint": hint }))
                    }
                    BackendStatus::CliMissing { cli_name, install_hint } => (
                        "cli_missing",
                        serde_json::json!({
                            "cli_name": cli_name,
                            "install_hint": install_hint,
                        }),
                    ),
                    BackendStatus::Error { message } => {
                        ("error", serde_json::json!({ "message": message }))
                    }
                };
                serde_json::json!({
                    "backend_type": backend_type,
                    "instance": self.backend_scheme,
                    "status": status_key,
                    "detail": detail,
                })
            }
            ResolveBackendCheck::CheckFailed { backend_type, message } => serde_json::json!({
                "backend_type": backend_type,
                "instance": self.backend_scheme,
                "status": "check_failed",
                "detail": { "message": message },
            }),
            ResolveBackendCheck::UnregisteredScheme => serde_json::json!({
                "instance": self.backend_scheme,
                "status": "unregistered_scheme",
                "detail": {},
            }),
        };
        serde_json::json!({
            "alias": self.alias,
            "env_var": self.env_var,
            "resolved": self.resolved,
            "source": {
                "uri": self.source_uri,
                "layer": self.layer_index,
            },
            "backend": check,
        })
    }
}

// ---- get (with confirmation) -------------------------------------------

async fn cmd_get(args: &GetArgs, config: &Config, backends: &BackendRegistry) -> Result<()> {
    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    let target = aliases
        .get(&args.alias)
        .ok_or_else(|| {
            anyhow!(
                "alias '{}' not found in registry cascade [{}]",
                args.alias,
                format_sources(&aliases)
            )
        })?
        .0
        .clone();

    if !args.yes && !confirm_print_secret(&args.alias)? {
        bail!("aborted by user");
    }

    let backend = backends
        .get(&target.scheme)
        .ok_or_else(|| anyhow!("no backend instance '{}' is configured", target.scheme))?;
    let value = backend.get(&target).await?;
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
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    // Effective cascade view — shadowed entries are filtered out by
    // AliasMap::iter. Sort alphabetically for deterministic output.
    let mut entries: Vec<_> =
        aliases.iter().map(|(a, target, _source)| (a.clone(), target.raw.clone())).collect();
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
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    let (target, _source) = aliases.get(alias).ok_or_else(|| {
        anyhow!("alias '{alias}' not found in registry cascade [{}]", format_sources(&aliases))
    })?;
    println!("{}", target.raw);
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
    // BTreeMap: deterministic ordering on write. HashMap in v0.1
    // produced non-reproducible diffs on every `registry set`.
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
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
    let mut map: BTreeMap<String, String> = current.into_iter().collect();
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
/// registry documents. Unknown types error — v0.2 supports local,
/// aws-ssm, 1password only.
///
/// A `BTreeMap` is required (not just preferred): it guarantees
/// alphabetical key order, so `registry set`/`unset` writes are
/// deterministic and diff-friendly.
fn serialize_registry(backend_type: &str, map: &BTreeMap<String, String>) -> Result<String> {
    match backend_type {
        "local" | "1password" => toml::to_string(map).with_context(|| {
            format!("serializing registry as TOML for backend type '{backend_type}'")
        }),
        // `vault` stores registry documents as a single KV secret whose
        // value is a JSON alias→URI map — same wire shape as aws-ssm.
        // `aws-secrets` uses the same shape (one AWS secret, JSON body).
        "aws-ssm" | "vault" | "aws-secrets" | "gcp" => {
            serde_json::to_string(map).with_context(|| {
                format!("serializing registry as JSON for backend type '{backend_type}'")
            })
        }
        other => Err(anyhow!(
            "writing registry documents through backend type '{other}' is not supported"
        )),
    }
}

/// Join every cascade source URI into a comma-separated list for
/// error messages. Used when an alias is not found in any layer.
fn format_sources(aliases: &secretenv_core::AliasMap) -> String {
    aliases.sources().map(|u| u.raw.as_str()).collect::<Vec<_>>().join(", ")
}

// ---- setup --------------------------------------------------------------

async fn cmd_setup(args: &SetupArgs, target_config: Option<&std::path::Path>) -> Result<()> {
    let opts = crate::setup::SetupOpts {
        registry_uri: args.registry_uri.clone(),
        region: args.region.clone(),
        profile: args.profile.clone(),
        account: args.account.clone(),
        vault_address: args.vault_address.clone(),
        vault_namespace: args.vault_namespace.clone(),
        gcp_project: args.gcp_project.clone(),
        gcp_impersonate_service_account: args.gcp_impersonate_service_account.clone(),
        force: args.force,
        skip_doctor: args.skip_doctor,
        target: target_config.map(std::path::Path::to_path_buf),
    };
    crate::setup::run_setup(&opts).await
}

// ---- completions --------------------------------------------------------

fn cmd_completions(args: &CompletionsArgs) -> Result<()> {
    use std::io::IsTerminal as _;

    let mut cmd = Cli::command();
    let bin = "secretenv";
    let mut buf: Vec<u8> = Vec::new();
    match args.shell {
        Shell::Bash => {
            clap_complete::generate(clap_complete::shells::Bash, &mut cmd, bin, &mut buf);
        }
        Shell::Zsh => {
            clap_complete::generate(clap_complete::shells::Zsh, &mut cmd, bin, &mut buf);
        }
        Shell::Fish => {
            clap_complete::generate(clap_complete::shells::Fish, &mut cmd, bin, &mut buf);
        }
    }

    if let Some(path) = &args.output {
        std::fs::write(path, &buf)
            .with_context(|| format!("writing completion script to '{}'", path.display()))?;
        // Best-effort chmod 0o644. On non-Unix this is a no-op.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).with_context(
                || format!("chmod 0o644 on completion script '{}'", path.display()),
            )?;
        }
        eprintln!("wrote {} completion script to '{}'", args.shell.name(), path.display());
    } else {
        std::io::Write::write_all(&mut std::io::stdout(), &buf)
            .context("writing completion script to stdout")?;
        // If we're printing to a TTY, the user ran this interactively
        // — point them at the canonical install location. Silent on
        // redirect (the usual `secretenv completions zsh > _secretenv`
        // pipeline).
        if std::io::stdout().is_terminal() {
            eprintln!();
            eprintln!("{}", args.shell.install_hint());
        }
    }
    Ok(())
}

impl Shell {
    const fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    const fn install_hint(self) -> &'static str {
        match self {
            Self::Bash => {
                "# install: add to ~/.bashrc (or /etc/bash_completion.d/):\n\
                 #   source <(secretenv completions bash)"
            }
            Self::Zsh => {
                "# install (replace PATH with a directory in your fpath):\n\
                 #   secretenv completions zsh > \"$HOME/.zsh/completions/_secretenv\"\n\
                 # then ensure your ~/.zshrc has:\n\
                 #   fpath=(~/.zsh/completions $fpath)\n\
                 #   autoload -U compinit && compinit"
            }
            Self::Fish => {
                "# install:\n\
                 #   secretenv completions fish > \"$HOME/.config/fish/completions/secretenv.fish\""
            }
        }
    }
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
        let mut m = BTreeMap::new();
        m.insert("k".to_owned(), "aws-ssm:///v".to_owned());
        let s = serialize_registry("local", &m).unwrap();
        assert!(s.contains("k = \"aws-ssm:///v\""), "TOML shape: {s}");
    }

    #[test]
    fn serialize_registry_produces_json_for_aws_ssm() {
        let mut m = BTreeMap::new();
        m.insert("k".to_owned(), "aws-ssm:///v".to_owned());
        let s = serialize_registry("aws-ssm", &m).unwrap();
        assert!(s.starts_with('{'), "JSON shape: {s}");
        assert!(s.contains("\"k\""));
    }

    #[test]
    fn serialize_registry_rejects_unknown_type() {
        let m = BTreeMap::new();
        let err = serialize_registry("unknown-backend", &m).unwrap_err();
        assert!(format!("{err:#}").contains("not supported"));
    }

    /// `BTreeMap` must produce alphabetical output for both TOML and
    /// JSON, independent of insertion order. This is the v0.2 CV-4
    /// determinism fix.
    #[test]
    fn serialize_registry_is_alphabetical_regardless_of_insertion_order() {
        let mut m = BTreeMap::new();
        m.insert("zeta".to_owned(), "local:///z".to_owned());
        m.insert("alpha".to_owned(), "local:///a".to_owned());
        m.insert("mu".to_owned(), "local:///m".to_owned());

        let toml_out = serialize_registry("local", &m).unwrap();
        let alpha = toml_out.find("alpha").unwrap();
        let mu = toml_out.find("mu").unwrap();
        let zeta = toml_out.find("zeta").unwrap();
        assert!(alpha < mu && mu < zeta, "TOML not alphabetical: {toml_out}");

        let json_out = serialize_registry("aws-ssm", &m).unwrap();
        let j_alpha = json_out.find("alpha").unwrap();
        let j_mu = json_out.find("mu").unwrap();
        let j_zeta = json_out.find("zeta").unwrap();
        assert!(j_alpha < j_mu && j_mu < j_zeta, "JSON not alphabetical: {json_out}");
    }
}
