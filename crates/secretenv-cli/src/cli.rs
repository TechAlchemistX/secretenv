// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

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
    resolve_manifest, resolve_registry, Backend, BackendRegistry, BackendUri, Config, HistoryEntry,
    Manifest, RegistryCache, RegistrySelection,
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
    /// Distribution profile operations — install, list, update, and
    /// uninstall shared config fragments (v0.4).
    #[command(subcommand)]
    Profile(ProfileCommand),
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
    /// Post-hoc redaction: scrub secret values out of an existing
    /// file or stream. Reads every alias's resolved value into the
    /// tainted set and rewrites the file with `[redacted:<alias>]`
    /// substitutions (or `--redact-token <fixed>`).
    Redact(RedactArgs),
}

/// `secretenv redact <path> [...]` — Mode B post-hoc file scrubber.
#[derive(Debug, Args)]
pub struct RedactArgs {
    /// Path to the file to scrub. Use `-` for stdin (writes to stdout).
    pub path: String,
    /// Registry selection — name or direct URI. Same semantics as
    /// `secretenv run --registry`. Determines which aliases'
    /// resolved values populate the tainted set.
    #[arg(long)]
    pub registry: Option<String>,
    /// Restrict the tainted set to these alias names. Repeatable;
    /// comma-separated values also accepted. Default: every alias
    /// resolvable from the active manifest + registry cascade.
    #[arg(long, value_delimiter = ',')]
    pub alias: Vec<String>,
    /// Rewrite the file in place (atomic rename). Without this flag,
    /// the scrubbed output is written to stdout and the original
    /// file is untouched.
    #[arg(long, conflicts_with = "dry_run")]
    pub in_place: bool,
    /// When `--in-place` is set, also keep a backup of the original
    /// content at `<path><suffix>` (e.g. `--backup=.bak`).
    #[arg(long, requires = "in_place")]
    pub backup: Option<String>,
    /// Count matches without writing any output. Implies neither
    /// `--in-place` nor stdout emission.
    #[arg(long)]
    pub dry_run: bool,
    /// Allow scrubbing a file owned by a different UID. Off by
    /// default; enabling this re-enables the foreign-owner refusal
    /// (mode B's defense against a maliciously-planted log file).
    #[arg(long)]
    pub allow_foreign_owner: bool,
    /// Override the substitution token. Default is
    /// `[redacted:<alias-name>]`; pass e.g. `--redact-token '***'`
    /// for the paranoid fixed-string form.
    #[arg(long)]
    pub redact_token: Option<String>,
}

/// `secretenv profile <subcommand>` — distribution-profile operations.
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Download a profile from the canonical host (or an explicit URL)
    /// and install it into the profiles directory. Auto-merges on the
    /// next config load — no manual editing of `config.toml` needed.
    Install {
        /// Profile name. Determines both the URL (when --url is absent)
        /// and the on-disk filename under `profiles/`.
        name: String,
        /// Override the fetch URL. Useful for private / staged /
        /// filesystem-hosted (file://) profiles.
        #[arg(long)]
        url: Option<String>,
    },
    /// List installed profiles with their source URLs + install times.
    List {
        /// Emit machine-readable JSON instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Re-fetch a profile (or all profiles when no name is given) from
    /// their stored source URL. Uses `ETag` for conditional re-fetch.
    Update {
        /// Profile name. Omit to update every installed profile.
        name: Option<String>,
    },
    /// Remove an installed profile (both the .toml and .meta.json).
    Uninstall { name: String },
}

/// `secretenv run [...] -- <command>`
///
/// `clippy::struct_excessive_bools`: this is a clap-derived
/// arg struct; refactoring booleans into a state-enum loses the
/// flag/argument-name automation. The mutex constraints between
/// `--redact` / `--no-redact` / `--i-know` are enforced by clap's
/// `conflicts_with` + `requires` attrs above.
#[allow(clippy::struct_excessive_bools)]
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

    /// Force pipe-based stdout/stderr redaction even when stdin is
    /// a TTY. PTY-bound programs (`psql`, `vim`, `ssh`) may
    /// misbehave under pipe-based stdio; use only when you've
    /// confirmed your child works without a controlling terminal.
    #[arg(long, conflicts_with = "no_redact")]
    pub redact: bool,

    /// Disable runtime stdout/stderr redaction. Falls back to the
    /// pre-v0.14 `exec()` path. Requires `--i-know` on non-TTY
    /// parents so CI logs don't accidentally print secret values
    /// when a developer typos away the default protection.
    #[arg(long, conflicts_with = "redact", requires = "i_know")]
    pub no_redact: bool,

    /// Acknowledge the audit consequences of `--no-redact` on a
    /// non-TTY parent. Required by `--no-redact` per the v0.14
    /// security invariants (SEC-INV-09).
    #[arg(long)]
    pub i_know: bool,

    /// Override the substitution token. Default is
    /// `[redacted:<alias-name>]`. Same syntax as `redact
    /// --redact-token`.
    #[arg(long)]
    pub redact_token: Option<String>,

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
    /// Show version history for the secret an alias resolves to.
    /// Output is most-recent-first; backends with no native history
    /// API report "unsupported".
    History {
        /// Alias name. Resolved through the cascade just like `get`.
        alias: String,
        #[arg(long)]
        registry: Option<String>,
        /// Emit machine-readable JSON instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Emit a copy-pasteable config.toml snippet + IAM/RBAC grant
    /// command for onboarding a new collaborator to the named registry.
    Invite {
        /// Registry name. Defaults to the `default` registry / value
        /// of `$SECRETENV_REGISTRY`.
        #[arg(long)]
        registry: Option<String>,
        /// Identifier (IAM username, email, etc.) the inviter wants
        /// in the grant command. Defaults to a `<INVITEE>` placeholder.
        #[arg(long)]
        invitee: Option<String>,
        /// Emit machine-readable JSON instead of the human sections.
        #[arg(long)]
        json: bool,
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

/// `secretenv doctor [--json] [--fix] [--extensive]`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON instead of human output.
    #[arg(long)]
    pub json: bool,
    /// For each `NotAuthenticated` backend, run the canonical
    /// remediation CLI (`aws sso login`, `op signin`, `gcloud auth
    /// login`, `az login`, `vault login`) interactively, then re-run
    /// the health check and render the post-remediation report.
    #[arg(long)]
    pub fix: bool,
    /// Level 3 depth probe — for each `Ok` backend, read each
    /// registry source it serves and count the aliases found, surfacing
    /// permission scope ("can read" vs "denied").
    #[arg(long)]
    pub extensive: bool,
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

    /// Azure Key Vault HTTPS URL — required for azure backends.
    #[arg(long)]
    pub azure_vault_url: Option<String>,

    /// Azure tenant ID or domain — optional, azure only.
    #[arg(long)]
    pub azure_tenant: Option<String>,

    /// Azure subscription ID — optional, azure only.
    #[arg(long)]
    pub azure_subscription: Option<String>,

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
            Command::Doctor(args) => {
                crate::doctor::run_doctor(
                    config,
                    backends,
                    crate::doctor::DoctorOpts {
                        json: args.json,
                        fix: args.fix,
                        extensive: args.extensive,
                    },
                )
                .await
            }
            Command::Profile(pc) => cmd_profile(pc, self.config.as_deref()).await,
            Command::Setup(args) => cmd_setup(args, self.config.as_deref()).await,
            Command::Completions(args) => cmd_completions(args),
            Command::Redact(args) => cmd_redact(args, config, backends).await,
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
    use secretenv_core::{run_with_options, RedactMode, RunOptions};

    let starting_dir = std::env::current_dir().context("determining current directory")?;
    let manifest = Manifest::load(&starting_dir)
        .context("loading secretenv.toml (walked upward from $CWD)")?;
    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    let resolved = resolve_manifest(&manifest, &aliases)?;

    let redact = if args.no_redact {
        RedactMode::ForceExec
    } else if args.redact {
        RedactMode::ForcePipe
    } else {
        RedactMode::Auto
    };
    let options = RunOptions {
        dry_run: args.dry_run,
        verbose: args.verbose,
        redact,
        redact_token: args.redact_token.clone(),
    };
    run_with_options(&resolved, backends, &args.command, &options).await
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
    println!("{}", value.expose_secret());
    Ok(())
}

// ---- redact (Mode B post-hoc) -----------------------------------------

async fn cmd_redact(args: &RedactArgs, config: &Config, backends: &BackendRegistry) -> Result<()> {
    use secretenv_core::redact::{
        scrub_file_in_place, Scrubber, SubstitutionToken, TaintedSet, TaintedValue,
    };

    let selection = resolve_selection_from_env(args.registry.as_deref(), config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;

    // Build the alias filter: either explicit `--alias <names>` or
    // every alias in the resolved cascade.
    let alias_names: Vec<String> = if args.alias.is_empty() {
        aliases.iter().map(|(name, _target, _source)| name.clone()).collect()
    } else {
        args.alias.clone()
    };

    if alias_names.is_empty() {
        bail!(
            "secretenv redact: no aliases to redact — registry cascade is empty \
             ({}). Add aliases via `secretenv registry set` first.",
            format_sources(&aliases),
        );
    }

    // Fetch each alias's value, build the tainted set.
    let mut tainted = TaintedSet::new();
    for name in &alias_names {
        let Some((target, _src)) = aliases.get(name) else {
            bail!("alias '{name}' not found in registry cascade [{}]", format_sources(&aliases),);
        };
        let backend = backends
            .get(&target.scheme)
            .ok_or_else(|| anyhow!("no backend instance '{}' is configured", target.scheme))?;
        let value = backend.get(target).await.with_context(|| {
            format!("fetching value for alias '{name}' (target='{}')", target.raw)
        })?;
        tainted.insert(TaintedValue::from_alias(name.clone(), value.expose_secret()));
    }

    let token = args
        .redact_token
        .as_ref()
        .map_or(SubstitutionToken::AliasAware, |s| SubstitutionToken::Fixed(s.clone()));
    let Some(scrubber) = Scrubber::new(&tainted, token)? else {
        eprintln!(
            "secretenv redact: tainted set is empty after the {}-byte minimum filter; \
             nothing to redact.",
            secretenv_core::redact::MIN_TAINTED_LEN,
        );
        return Ok(());
    };

    let path = std::path::Path::new(&args.path);

    // Dispatch: --dry-run (count only), --in-place (atomic rename), or
    // default (stdout).
    if args.dry_run {
        let mut sink = std::io::sink();
        let mut reader = secretenv_core::redact::open_no_follow(path)?;
        let rep = scrubber.scrub_reader(&mut reader, &mut sink)?;
        eprintln!(
            "secretenv redact: would redact {} match(es) totaling {} byte(s) in '{}'",
            rep.match_count,
            rep.byte_count,
            path.display(),
        );
        return Ok(());
    }

    if args.in_place {
        let rep =
            scrub_file_in_place(path, &scrubber, args.backup.as_deref(), args.allow_foreign_owner)?;
        eprintln!(
            "secretenv redact: rewrote '{}' — {} match(es), {} byte(s) replaced{}",
            path.display(),
            rep.match_count,
            rep.byte_count,
            args.backup
                .as_deref()
                .map_or(String::new(), |s| format!("; backup at '{}{s}'", path.display())),
        );
        return Ok(());
    }

    // Default: stream to stdout.
    secretenv_core::redact::refuse_special_paths(path)?;
    secretenv_core::redact::refuse_foreign_owner(path, args.allow_foreign_owner)?;
    let mut reader = secretenv_core::redact::open_no_follow(path)
        .with_context(|| format!("redact: opening '{}' with O_NOFOLLOW", path.display()))?;
    let mut stdout = io::stdout().lock();
    let rep = scrubber.scrub_reader(&mut reader, &mut stdout)?;
    drop(stdout);
    eprintln!(
        "secretenv redact: {} match(es), {} byte(s) replaced in '{}'",
        rep.match_count,
        rep.byte_count,
        path.display(),
    );
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
        RegistryCommand::History { alias, registry, json } => {
            registry_history(alias, registry.as_deref(), *json, config, backends).await
        }
        RegistryCommand::Invite { registry, invitee, json } => {
            registry_invite(registry.as_deref(), invitee.as_deref(), *json, config)
        }
    }
}

fn registry_invite(
    registry: Option<&str>,
    invitee: Option<&str>,
    json: bool,
    config: &Config,
) -> Result<()> {
    let selection = resolve_selection_from_env(registry, config)?;
    let invitation = crate::invite::build_invitation(config, &selection, invitee)?;
    if json {
        println!("{}", crate::invite::render_json(&invitation)?);
    } else {
        print!("{}", crate::invite::render_human(&invitation));
    }
    Ok(())
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
    let serialized = backend.serialize_registry_doc(&map)?;
    backend
        .set(&source_uri, &serialized)
        .await
        .with_context(|| format!("writing updated registry document to '{}'", source_uri.raw))?;
    eprintln!("set {alias} → {target_uri} in registry at '{}'", source_uri.raw);
    Ok(())
}

async fn registry_history(
    alias: &str,
    registry: Option<&str>,
    json: bool,
    config: &Config,
    backends: &BackendRegistry,
) -> Result<()> {
    let selection = resolve_selection_from_env(registry, config)?;
    let mut cache = RegistryCache::new();
    let aliases = resolve_registry(config, &selection, backends, &mut cache).await?;
    let (target, _source) = aliases.get(alias).ok_or_else(|| {
        anyhow!("alias '{alias}' not found in registry cascade [{}]", format_sources(&aliases))
    })?;
    let target = target.clone();
    let backend = backends
        .get(&target.scheme)
        .ok_or_else(|| anyhow!("no backend instance '{}' is configured", target.scheme))?;
    let entries = backend.history(&target).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&render_history_json(alias, &target.raw, &entries))?
        );
    } else {
        print!("{}", render_history_human(alias, &target.raw, &entries));
    }
    Ok(())
}

/// Tabular human format: alias header + per-version rows. Width-aware
/// so a long actor or description doesn't push the table to one
/// column-per-row. Empty `entries` renders an explanatory line — the
/// backend reported zero versions (locally-untracked file, fresh
/// secret, etc.) without erroring.
#[allow(clippy::write_literal)] // Header literals + width-aligned format read more clearly as positional args.
fn render_history_human(alias: &str, uri: &str, entries: &[HistoryEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "alias:    {alias}");
    let _ = writeln!(out, "resolved: {uri}");
    let _ = writeln!(out);
    if entries.is_empty() {
        let _ = writeln!(out, "(no versions reported by the backend)");
        return out;
    }
    // Column widths derived from the longest cell in each.
    let v_w = entries.iter().map(|e| e.version.len()).max().unwrap_or(7).max(7);
    let t_w = entries.iter().map(|e| e.timestamp.len()).max().unwrap_or(20).max(20);
    let a_w =
        entries.iter().map(|e| e.actor.as_deref().unwrap_or("-").len()).max().unwrap_or(6).max(6);
    let _ = writeln!(
        out,
        "{:<v_w$}  {:<t_w$}  {:<a_w$}  {}",
        "VERSION",
        "TIMESTAMP",
        "ACTOR",
        "DESCRIPTION",
        v_w = v_w,
        t_w = t_w,
        a_w = a_w
    );
    for e in entries {
        let _ = writeln!(
            out,
            "{:<v_w$}  {:<t_w$}  {:<a_w$}  {}",
            e.version,
            e.timestamp,
            e.actor.as_deref().unwrap_or("-"),
            e.description.as_deref().unwrap_or(""),
            v_w = v_w,
            t_w = t_w,
            a_w = a_w
        );
    }
    out
}

fn render_history_json(alias: &str, uri: &str, entries: &[HistoryEntry]) -> serde_json::Value {
    serde_json::json!({
        "alias": alias,
        "resolved": uri,
        "versions": entries
            .iter()
            .map(|e| serde_json::json!({
                "version": e.version,
                "timestamp": e.timestamp,
                "actor": e.actor,
                "description": e.description,
            }))
            .collect::<Vec<_>>(),
    })
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
    let serialized = backend.serialize_registry_doc(&map)?;
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
        azure_vault_url: args.azure_vault_url.clone(),
        azure_tenant: args.azure_tenant.clone(),
        azure_subscription: args.azure_subscription.clone(),
        force: args.force,
        skip_doctor: args.skip_doctor,
        target: target_config.map(std::path::Path::to_path_buf),
    };
    crate::setup::run_setup(&opts).await
}

// ---- profile ------------------------------------------------------------

async fn cmd_profile(pc: &ProfileCommand, target_config: Option<&std::path::Path>) -> Result<()> {
    // The profiles dir sits next to the active config.toml. If the user
    // passed `--config <path>`, use that path's parent; otherwise fall
    // back to the XDG-default location. Both paths go through the
    // `profiles_dir_for` core helper so the logic matches the loader.
    let config_path: std::path::PathBuf = match target_config {
        Some(p) => p.to_path_buf(),
        None => secretenv_core::default_config_path_xdg()?,
    };
    let opts = crate::profile::ProfileOpts {
        profiles_dir: secretenv_core::profiles_dir_for(&config_path),
    };

    match pc {
        ProfileCommand::Install { name, url } => {
            crate::profile::install(name, url.as_deref(), &opts).await
        }
        ProfileCommand::List { json } => {
            let installed = crate::profile::list(&opts)?;
            render_profile_list(&installed, *json)
        }
        ProfileCommand::Update { name } => {
            if let Some(n) = name {
                let outcome = crate::profile::update_one(n, &opts).await?;
                match outcome {
                    crate::profile::UpdateOutcome::UpToDate => {
                        eprintln!("Profile '{n}' is already up to date.");
                    }
                    crate::profile::UpdateOutcome::Refreshed => {
                        eprintln!("Profile '{n}' refreshed.");
                    }
                }
                Ok(())
            } else {
                let reports = crate::profile::update_all(&opts).await?;
                render_profile_update_reports(&reports)
            }
        }
        ProfileCommand::Uninstall { name } => crate::profile::uninstall(name, &opts),
    }
}

fn render_profile_list(installed: &[crate::profile::InstalledProfile], json: bool) -> Result<()> {
    if json {
        let json =
            serde_json::to_string_pretty(&installed).context("serializing profile list to JSON")?;
        println!("{json}");
        return Ok(());
    }
    if installed.is_empty() {
        println!("No profiles installed.");
        return Ok(());
    }
    println!("{:<24} {:<20} SOURCE", "NAME", "INSTALLED");
    for p in installed {
        println!("{:<24} {:<20} {}", p.name, p.installed_at, p.source_url);
    }
    Ok(())
}

fn render_profile_update_reports(reports: &[crate::profile::UpdateReport]) -> Result<()> {
    if reports.is_empty() {
        println!("No profiles installed.");
        return Ok(());
    }
    let mut had_error = false;
    for r in reports {
        match &r.outcome {
            Ok(crate::profile::UpdateOutcome::UpToDate) => {
                println!("{:<24} up to date", r.name);
            }
            Ok(crate::profile::UpdateOutcome::Refreshed) => {
                println!("{:<24} refreshed", r.name);
            }
            Err(e) => {
                had_error = true;
                println!("{:<24} ERROR: {e:#}", r.name);
            }
        }
    }
    if had_error {
        anyhow::bail!("one or more profile updates failed");
    }
    Ok(())
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

    // Pre-v0.14 `serialize_registry(backend_type, map)` helper tests
    // were removed when the dispatch moved to the `Backend` trait
    // (Phase 3 BREAKING #3). Per-backend serialization round-trips
    // are now tested inside each backend's own crate; the
    // alphabetical-ordering invariant is preserved by `BTreeMap`'s
    // intrinsic ordering and is no longer a CLI-layer concern.
}
