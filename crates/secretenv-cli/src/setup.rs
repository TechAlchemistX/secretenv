//! `secretenv setup <registry-uri>` — bootstrap a fresh `config.toml`
//! pointing at a given registry, with the right backend block wired up
//! based on the URI scheme.
//!
//! Refuses to overwrite an existing file without `--force`. Runs
//! `doctor` against the freshly-written config for immediate feedback,
//! but a doctor failure does not undo the write (the config is always
//! persisted; unhealthy state is informational).
#![allow(clippy::module_name_repetitions)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use secretenv_core::{BackendUri, Config};
use tokio::fs;

use crate::backends_init::build_registry;
use crate::doctor::run_doctor;

/// All inputs to [`run_setup`]. Lifted out of `SetupArgs` so unit
/// tests can construct it without clap.
#[derive(Debug, Clone)]
pub struct SetupOpts {
    /// The backend URI of the registry document. Its scheme becomes
    /// the backend instance name in the generated config.
    pub registry_uri: String,
    /// AWS region — required when the URI scheme resolves to `aws-ssm`.
    pub region: Option<String>,
    /// AWS profile — optional, `aws-ssm` only.
    pub profile: Option<String>,
    /// 1Password account shorthand or URL — optional, `1password` only.
    pub account: Option<String>,
    /// Vault address — required when the URI scheme resolves to `vault`.
    pub vault_address: Option<String>,
    /// Vault Enterprise namespace — optional, `vault` only.
    pub vault_namespace: Option<String>,
    /// GCP project ID — required when the URI scheme resolves to `gcp`.
    pub gcp_project: Option<String>,
    /// GCP service-account email to impersonate — optional, `gcp` only.
    pub gcp_impersonate_service_account: Option<String>,
    /// Overwrite an existing config.toml instead of erroring.
    pub force: bool,
    /// Skip the post-write `doctor` run.
    pub skip_doctor: bool,
    /// Target path. `None` uses the XDG default
    /// (`$XDG_CONFIG_HOME/secretenv/config.toml`).
    pub target: Option<PathBuf>,
}

/// Entry point for the `setup` subcommand.
///
/// # Errors
/// - `registry_uri` fails to parse as a [`BackendUri`] or uses the
///   reserved `secretenv://` scheme.
/// - Scheme doesn't map to any v0.1 backend type.
/// - `aws-ssm` scheme without `--region`.
/// - Target file exists and `force` is `false`.
/// - IO error writing the config.
pub async fn run_setup(opts: &SetupOpts) -> Result<()> {
    let uri = BackendUri::parse(&opts.registry_uri)
        .with_context(|| format!("parsing registry URI '{}'", opts.registry_uri))?;
    if uri.is_alias() {
        bail!(
            "registry URI must be a direct backend URI, not secretenv://<alias> — \
             pass something like 'aws-ssm-prod:///registries/shared' or 'local:///path/to/r.toml'"
        );
    }
    let backend_type = backend_type_from_scheme(&uri.scheme)?;

    if backend_type == "aws-ssm" && opts.region.is_none() {
        bail!(
            "aws-ssm backends require --region (e.g. `secretenv setup {} --region us-east-1`)",
            opts.registry_uri
        );
    }
    if backend_type == "aws-secrets" && opts.region.is_none() {
        bail!(
            "aws-secrets backends require --region \
             (e.g. `secretenv setup {} --region us-east-1`)",
            opts.registry_uri
        );
    }
    if backend_type == "vault" && opts.vault_address.is_none() {
        bail!(
            "vault backends require --vault-address \
             (e.g. `secretenv setup {} --vault-address https://vault.company.com`)",
            opts.registry_uri
        );
    }
    if backend_type == "gcp" && opts.gcp_project.is_none() {
        bail!(
            "gcp backends require --gcp-project \
             (e.g. `secretenv setup {} --gcp-project my-project-prod`)",
            opts.registry_uri
        );
    }

    let target = resolve_target(opts.target.as_deref())?;
    if target.exists() && !opts.force {
        bail!(
            "config already exists at '{}' — use --force to overwrite, \
             or edit the file manually",
            target.display()
        );
    }

    let content = build_config_toml(&uri, backend_type, opts);

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating parent directory '{}'", parent.display()))?;
    }
    fs::write(&target, &content)
        .await
        .with_context(|| format!("writing config.toml to '{}'", target.display()))?;

    println!("wrote config to '{}'", target.display());

    if !opts.skip_doctor {
        println!();
        let config = Config::load_from(&target)
            .with_context(|| format!("reloading just-written config at '{}'", target.display()))?;
        let backends = build_registry(&config)?;
        // Informational — a doctor failure does not un-write the config.
        if let Err(err) = run_doctor(&config, &backends, false).await {
            eprintln!(
                "\nNote: {err:#}. Fix the underlying issue and re-run `secretenv doctor` \
                 to verify."
            );
        }
    }

    Ok(())
}

/// Map a URI scheme to its backend type. Accepts exact matches
/// (`local`, `aws-ssm`, `1password`, `vault`) and dash-suffixed forms
/// (`aws-ssm-prod`, `1password-personal`, `vault-eng`) since instance
/// names can carry a suffix to distinguish credentials.
fn backend_type_from_scheme(scheme: &str) -> Result<&'static str> {
    if scheme == "local" {
        Ok("local")
    } else if scheme == "aws-ssm" || scheme.starts_with("aws-ssm-") {
        Ok("aws-ssm")
    } else if scheme == "aws-secrets" || scheme.starts_with("aws-secrets-") {
        Ok("aws-secrets")
    } else if scheme == "1password" || scheme.starts_with("1password-") {
        Ok("1password")
    } else if scheme == "vault" || scheme.starts_with("vault-") {
        Ok("vault")
    } else if scheme == "gcp" || scheme.starts_with("gcp-") {
        Ok("gcp")
    } else {
        bail!(
            "unknown backend scheme '{scheme}' — supported: local, aws-ssm(-*), \
             aws-secrets(-*), 1password(-*), vault(-*), gcp(-*). Did you mean one \
             of these?"
        )
    }
}

fn resolve_target(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    let base = directories::BaseDirs::new().ok_or_else(|| {
        anyhow::anyhow!("could not determine a home directory for XDG config lookup")
    })?;
    Ok(base.config_dir().join("secretenv").join("config.toml"))
}

// `writeln!`/`write!` into a `String` is infallible — `String`'s
// `fmt::Write` impl never returns `Err`. `.unwrap()` here can't panic
// at runtime, so the workspace `unwrap_used` warn is suppressed.
#[allow(clippy::unwrap_used)]
fn build_config_toml(uri: &BackendUri, backend_type: &str, opts: &SetupOpts) -> String {
    let mut out = String::new();
    writeln!(out, "# secretenv config — generated by `secretenv setup`").unwrap();
    writeln!(out, "# Edit freely; re-run `secretenv doctor` after changes.\n").unwrap();

    writeln!(out, "[registries.default]").unwrap();
    writeln!(out, "sources = [{}]\n", toml_string(&uri.raw)).unwrap();

    writeln!(out, "[backends.{}]", toml_key(&uri.scheme)).unwrap();
    writeln!(out, "type = {}", toml_string(backend_type)).unwrap();

    match backend_type {
        "aws-ssm" | "aws-secrets" => {
            if let Some(r) = &opts.region {
                writeln!(out, "aws_region = {}", toml_string(r)).unwrap();
            }
            if let Some(p) = &opts.profile {
                writeln!(out, "aws_profile = {}", toml_string(p)).unwrap();
            }
        }
        "1password" => {
            if let Some(a) = &opts.account {
                writeln!(out, "op_account = {}", toml_string(a)).unwrap();
            }
        }
        "vault" => {
            if let Some(addr) = &opts.vault_address {
                writeln!(out, "vault_address = {}", toml_string(addr)).unwrap();
            }
            if let Some(ns) = &opts.vault_namespace {
                writeln!(out, "vault_namespace = {}", toml_string(ns)).unwrap();
            }
        }
        "gcp" => {
            if let Some(p) = &opts.gcp_project {
                writeln!(out, "gcp_project = {}", toml_string(p)).unwrap();
            }
            if let Some(sa) = &opts.gcp_impersonate_service_account {
                writeln!(out, "gcp_impersonate_service_account = {}", toml_string(sa)).unwrap();
            }
        }
        _ => {}
    }

    out
}

/// Render `s` as a TOML string literal (`"..."`) with proper escaping.
fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

/// Render a TOML key, quoting if it contains anything outside the
/// bare-key charset (`A-Za-z0-9_-`).
fn toml_key(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        s.to_owned()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn opts(uri: &str) -> SetupOpts {
        SetupOpts {
            registry_uri: uri.to_owned(),
            region: None,
            profile: None,
            account: None,
            vault_address: None,
            vault_namespace: None,
            gcp_project: None,
            gcp_impersonate_service_account: None,
            force: false,
            skip_doctor: true,
            target: None,
        }
    }

    // ---- backend_type_from_scheme ----

    #[test]
    fn scheme_local_maps_to_local() {
        assert_eq!(backend_type_from_scheme("local").unwrap(), "local");
    }

    #[test]
    fn scheme_aws_ssm_bare_maps_to_aws_ssm() {
        assert_eq!(backend_type_from_scheme("aws-ssm").unwrap(), "aws-ssm");
    }

    #[test]
    fn scheme_aws_ssm_suffixed_maps_to_aws_ssm() {
        assert_eq!(backend_type_from_scheme("aws-ssm-prod").unwrap(), "aws-ssm");
        assert_eq!(backend_type_from_scheme("aws-ssm-dev-staging").unwrap(), "aws-ssm");
    }

    #[test]
    fn scheme_1password_bare_and_suffixed() {
        assert_eq!(backend_type_from_scheme("1password").unwrap(), "1password");
        assert_eq!(backend_type_from_scheme("1password-personal").unwrap(), "1password");
        assert_eq!(backend_type_from_scheme("1password-team").unwrap(), "1password");
    }

    #[test]
    fn scheme_vault_bare_and_suffixed() {
        assert_eq!(backend_type_from_scheme("vault").unwrap(), "vault");
        assert_eq!(backend_type_from_scheme("vault-eng").unwrap(), "vault");
        assert_eq!(backend_type_from_scheme("vault-payments").unwrap(), "vault");
    }

    #[test]
    fn scheme_gcp_bare_and_suffixed() {
        assert_eq!(backend_type_from_scheme("gcp").unwrap(), "gcp");
        assert_eq!(backend_type_from_scheme("gcp-prod").unwrap(), "gcp");
    }

    #[test]
    fn scheme_unknown_errors() {
        // Keep a genuinely-unknown scheme here; `gcp-prod` is no longer
        // unknown post-v0.3 Phase 1.
        let err = backend_type_from_scheme("azure-prod").unwrap_err();
        assert!(format!("{err:#}").contains("unknown backend scheme"));
    }

    // ---- build_config_toml ----

    #[test]
    fn toml_includes_registry_and_backend_for_local() {
        let uri = BackendUri::parse("local:///tmp/registry.toml").unwrap();
        let content = build_config_toml(&uri, "local", &opts("local:///tmp/registry.toml"));
        assert!(content.contains("[registries.default]"));
        assert!(content.contains("sources = [\"local:///tmp/registry.toml\"]"));
        assert!(content.contains("[backends.local]"));
        assert!(content.contains("type = \"local\""));
        // Local backend needs no extra fields.
        assert!(!content.contains("aws_region"));
        assert!(!content.contains("op_account"));
    }

    #[test]
    fn toml_includes_aws_region_when_provided() {
        let uri = BackendUri::parse("aws-ssm-prod:///prod/registry").unwrap();
        let mut o = opts("aws-ssm-prod:///prod/registry");
        o.region = Some("us-east-1".into());
        o.profile = Some("prod".into());
        let content = build_config_toml(&uri, "aws-ssm", &o);
        assert!(content.contains("[backends.aws-ssm-prod]"));
        assert!(content.contains("type = \"aws-ssm\""));
        assert!(content.contains("aws_region = \"us-east-1\""));
        assert!(content.contains("aws_profile = \"prod\""));
    }

    #[test]
    fn toml_includes_op_account_when_provided() {
        let uri = BackendUri::parse("1password-team://Shared/Reg/body").unwrap();
        let mut o = opts("1password-team://Shared/Reg/body");
        o.account = Some("myteam.1password.com".into());
        let content = build_config_toml(&uri, "1password", &o);
        assert!(content.contains("[backends.1password-team]"));
        assert!(content.contains("type = \"1password\""));
        assert!(content.contains("op_account = \"myteam.1password.com\""));
    }

    #[test]
    fn toml_roundtrips_through_config_loader() {
        // The whole point of this builder is to emit valid TOML that
        // Config::load_from parses without hand-holding.
        let uri = BackendUri::parse("aws-ssm-prod:///prod/r").unwrap();
        let mut o = opts("aws-ssm-prod:///prod/r");
        o.region = Some("us-east-1".into());
        let content = build_config_toml(&uri, "aws-ssm", &o);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &content).unwrap();
        let config = Config::load_from(tmp.path()).unwrap();
        assert_eq!(config.registries["default"].sources.len(), 1);
        let backend = &config.backends["aws-ssm-prod"];
        assert_eq!(backend.backend_type, "aws-ssm");
        assert_eq!(backend.raw_fields["aws_region"].as_str(), Some("us-east-1"));
    }

    // ---- toml_key edge cases ----

    #[test]
    fn toml_key_keeps_bare_when_safe() {
        assert_eq!(toml_key("aws-ssm-prod"), "aws-ssm-prod");
        assert_eq!(toml_key("1password-team"), "1password-team");
        assert_eq!(toml_key("local"), "local");
    }

    #[test]
    fn toml_key_quotes_when_needed() {
        assert_eq!(toml_key("has spaces"), "\"has spaces\"");
        assert_eq!(toml_key("has.dot"), "\"has.dot\"");
    }
}
