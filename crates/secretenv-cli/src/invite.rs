// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! `secretenv registry invite` — onboarding output for sharing a
//! registry with a new collaborator.
//!
//! Resolves the active registry's first source URI, looks up the
//! backend instance config, and emits two operator-friendly chunks:
//!
//! 1. The `config.toml` snippet the new user adds to their machine.
//! 2. The IAM / RBAC grant command the inviter runs as administrator.
//!
//! Per-backend specifics live in the [`build_invitation`] match. The
//! grant text is best-effort — it points at the canonical CLI surface
//! and parameterizes the invitee identity. We deliberately don't
//! generate fully-resolved policy documents (that requires more
//! environmental knowledge than the CLI has) — the grant lines are
//! starting points the inviter adapts.
#![allow(clippy::module_name_repetitions)]

use std::fmt::Write as _;

use anyhow::{anyhow, Context, Result};
use secretenv_core::{BackendConfig, BackendUri, Config, RegistrySelection};
use serde::Serialize;

/// Result of building an invitation. Rendered by [`render_human`] or
/// [`render_json`].
#[derive(Debug, Clone, Serialize)]
pub struct Invitation {
    /// Registry name (`default`, `prod`, ...).
    pub registry_name: String,
    /// Backend type (`local`, `aws-ssm`, `1password`, ...).
    pub backend_type: String,
    /// Backend instance name (= URI scheme).
    pub instance_name: String,
    /// Source URI (from `[registries.<name>].sources[0]`).
    pub source_uri: String,
    /// Invitee identifier as the operator typed it (`alice@example.com`,
    /// `<INVITEE>` when not supplied).
    pub invitee: String,
    /// `config.toml` snippet — copy-paste-ready.
    pub config_block: String,
    /// Inviter's grant command — copy-paste-ready (operator
    /// substitutes any remaining `<...>` placeholders).
    pub inviter_grant: String,
    /// Three steps the invitee runs to verify, in order. Universal
    /// across backends (`secretenv doctor`, `registry list`, etc.).
    pub verify_steps: Vec<String>,
}

/// Build the [`Invitation`] for the named registry. Selects the
/// canonical first source URI (a registry with multiple sources sees
/// only the head; the others are typically fallbacks).
///
/// # Errors
/// - Selected registry not in config (or no `[registries.default]`
///   configured and no name passed).
/// - Selection resolves to a `RegistrySelection::Uri` (operator passed
///   `--registry <uri>` directly) — invite needs a named registry so
///   the snippet has a name to write into the new user's config.
/// - Backend instance referenced by the source isn't in
///   `[backends.*]` — incompletely-configured environment.
pub fn build_invitation(
    config: &Config,
    selection: &RegistrySelection,
    invitee: Option<&str>,
) -> Result<Invitation> {
    let registry_name = match selection {
        RegistrySelection::Name(n) => n.clone(),
        RegistrySelection::Uri(_) => {
            return Err(anyhow!(
                "`registry invite` needs a named registry — pass --registry <name> \
                 or add a [registries.default] block to config.toml"
            ));
        }
    };
    let reg = config.registries.get(&registry_name).ok_or_else(|| {
        anyhow!(
            "no registry named '{registry_name}' in config.toml — run `secretenv registry --help` \
             to see what's available"
        )
    })?;
    let source = reg
        .sources
        .first()
        .ok_or_else(|| anyhow!("registry '{registry_name}' has no sources to invite to"))?;
    let uri = BackendUri::parse(source).with_context(|| {
        format!("registry '{registry_name}' sources[0] = '{source}' is not a valid URI")
    })?;
    let backend = config.backends.get(&uri.scheme).ok_or_else(|| {
        anyhow!(
            "registry source '{source}' targets backend instance '{}' which is not in config.toml",
            uri.scheme
        )
    })?;

    let invitee_label = invitee.unwrap_or("<INVITEE>").to_owned();
    let config_block = render_config_block(&registry_name, source, &uri.scheme, backend);
    let inviter_grant = render_inviter_grant(backend, &uri, &invitee_label);

    Ok(Invitation {
        registry_name,
        backend_type: backend.backend_type.clone(),
        instance_name: uri.scheme.clone(),
        source_uri: source.clone(),
        invitee: invitee_label,
        config_block,
        inviter_grant,
        verify_steps: vec!["secretenv doctor".into(), "secretenv registry list".into()],
    })
}

/// Render the `config.toml` snippet the invitee adds. Mirrors every
/// non-`type` field from the inviter's `[backends.<instance>]` block
/// verbatim — those are the credential coordinates the new user needs.
/// Test hooks (`*_bin` fields) are filtered out so production
/// snippets don't leak mock-binary paths.
fn render_config_block(
    registry_name: &str,
    source_uri: &str,
    instance_name: &str,
    backend: &BackendConfig,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[registries.{registry_name}]");
    let _ = writeln!(out, "sources = [\"{source_uri}\"]");
    let _ = writeln!(out);
    // Quote the instance name only when needed — bare keys keep TOML
    // tidy. Same heuristic as setup::quote_toml_key.
    let key = if needs_quoting(instance_name) {
        format!("\"{instance_name}\"")
    } else {
        instance_name.to_owned()
    };
    let _ = writeln!(out, "[backends.{key}]");
    let _ = writeln!(out, "type = \"{}\"", backend.backend_type);
    // Sorted for deterministic output across runs.
    let mut fields: Vec<(&String, &toml::Value)> =
        backend.raw_fields.iter().filter(|(k, _)| !is_test_only_field(k)).collect();
    fields.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in fields {
        let _ = writeln!(out, "{k} = {}", format_toml_value(v));
    }
    out
}

/// Per-backend grant text. Each arm is hand-tuned to point the inviter
/// at the right CLI surface; `<INVITEE>` is substituted in verbatim
/// (or the operator-supplied identifier).
fn render_inviter_grant(backend: &BackendConfig, uri: &BackendUri, invitee: &str) -> String {
    match backend.backend_type.as_str() {
        "local" => format!(
            "# `local` registries are filesystem-served — share access via filesystem\n\
             # permissions, git/SSH access to the directory containing '{path}', or by\n\
             # publishing the file to a location both you and {invitee} can read.\n\
             # No CLI grant — adjust file ACLs / repo permissions out of band.",
            path = uri.path
        ),
        "aws-ssm" | "aws-secrets" => {
            let policy = if backend.backend_type == "aws-ssm" {
                "AmazonSSMReadOnlyAccess"
            } else {
                "SecretsManagerReadWrite"
            };
            format!(
                "aws iam attach-user-policy \\\n  --user-name {invitee} \\\n  \
                 --policy-arn arn:aws:iam::aws:policy/{policy}\n\n\
                 # Or, for fine-grained access — replace with a custom policy that scopes\n\
                 # to '{path}' instead of granting account-wide read.",
                path = uri.path,
            )
        }
        "1password" => {
            let vault_hint =
                uri.path.trim_start_matches('/').split('/').next().unwrap_or("<VAULT>");
            format!(
                "op group user grant \\\n  --user {invitee} \\\n  --group <GROUP-WITH-READ-ON-{vault_hint}>\n\n\
                 # Or grant the vault directly to the user:\n\
                 op vault user grant \\\n  --user {invitee} \\\n  --vault {vault_hint} \\\n  --permissions view_items,view_and_copy_passwords"
            )
        }
        "vault" => format!(
            "# Write a read-only policy at '{path}' if you don't already have one:\n\
             vault policy write secretenv-registry-read - <<EOF\n\
             path \"{path}\" {{ capabilities = [\"read\"] }}\n\
             EOF\n\n\
             # Then issue {invitee} a token with the policy attached:\n\
             vault token create -policy=secretenv-registry-read -display-name={invitee}",
            path = uri.path.trim_start_matches('/'),
        ),
        "gcp" => format!(
            "gcloud secrets add-iam-policy-binding {secret} \\\n  \
             --member=user:{invitee} \\\n  --role=roles/secretmanager.secretAccessor",
            secret = uri.path.trim_start_matches('/'),
        ),
        "azure" => format!(
            "# Grant the Key Vault Secrets User role on the vault. The vault's resource ID\n\
             # is needed; look it up with: az keyvault show --name <vault-short-name>\n\
             az role assignment create \\\n  --assignee {invitee} \\\n  \
             --role \"Key Vault Secrets User\" \\\n  --scope <KEY-VAULT-RESOURCE-ID>"
        ),
        other => format!(
            "# No canonical grant template registered for backend type '{other}' yet —\n\
             # consult the backend documentation and add a read-only grant for {invitee}\n\
             # against URI '{}'.",
            uri.raw,
        ),
    }
}

/// Format a [`toml::Value`] back into TOML for the snippet. Strings get
/// double-quoted; integers/booleans/floats stringify directly; arrays
/// of strings render inline. Anything more exotic falls back to
/// `toml::to_string` and is trimmed.
fn format_toml_value(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => format!("\"{s}\""),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(format_toml_value).collect();
            format!("[{}]", parts.join(", "))
        }
        // Datetime / table — fall back to TOML's own serializer.
        other => toml::Value::to_string(other),
    }
}

/// Test-only field names that should never appear in a public snippet
/// (they point at strict-mock binary paths on the inviter's box).
fn is_test_only_field(field: &str) -> bool {
    matches!(field, "aws_bin" | "op_bin" | "vault_bin" | "gcloud_bin" | "az_bin")
}

/// TOML bare-key check: `[A-Za-z0-9_-]+`. Anything outside that needs
/// double-quotes. Same predicate the setup module uses.
fn needs_quoting(s: &str) -> bool {
    s.is_empty() || s.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
}

/// Human-friendly multi-section render.
#[allow(clippy::write_literal)] // Section banners read more naturally as positional args
pub fn render_human(invite: &Invitation) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "secretenv registry invite — onboarding for '{}'", invite.registry_name);
    let _ = writeln!(out, "{}", "=".repeat(48));
    let _ = writeln!(out);
    let _ = writeln!(out, "Source:   {}", invite.source_uri);
    let _ =
        writeln!(out, "Backend:  {} (instance '{}')", invite.backend_type, invite.instance_name);
    let _ = writeln!(out, "Invitee:  {}", invite.invitee);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "# 1. Invitee — add to your config.toml \
         ($XDG_CONFIG_HOME/secretenv/config.toml):\n"
    );
    let _ = write!(out, "{}", invite.config_block);
    let _ = writeln!(out);
    let _ = writeln!(out, "# 2. Inviter — grant access (run as administrator):\n");
    let _ = writeln!(out, "{}", invite.inviter_grant);
    let _ = writeln!(out);
    let _ = writeln!(out, "# 3. Invitee — verify the onboarding:");
    for step in &invite.verify_steps {
        let _ = writeln!(out, "{step}");
    }
    out
}

/// JSON shape — the same fields as [`Invitation`] (it derives
/// `Serialize`). Wrapped in this helper so the CLI dispatcher always
/// uses pretty-printed output.
///
/// # Errors
/// Returns the underlying `serde_json` error if serialization fails
/// (which it never should given that all fields are owned plain types).
pub fn render_json(invite: &Invitation) -> Result<String> {
    serde_json::to_string_pretty(invite).context("rendering invitation JSON")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use secretenv_core::RegistryConfig;

    use super::*;

    fn cfg_with(
        registry_name: &str,
        source: &str,
        instance: &str,
        backend_type: &str,
        fields: &[(&str, toml::Value)],
    ) -> Config {
        let raw_fields: HashMap<String, toml::Value> =
            fields.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
        Config {
            registries: HashMap::from([(
                registry_name.to_owned(),
                RegistryConfig { sources: vec![source.to_owned()] },
            )]),
            backends: HashMap::from([(
                instance.to_owned(),
                BackendConfig { backend_type: backend_type.to_owned(), raw_fields },
            )]),
        }
    }

    // ---- selection error paths ----

    #[test]
    fn build_errors_when_selection_is_a_uri_not_a_name() {
        let cfg = cfg_with("default", "local:///r.toml", "local", "local", &[]);
        let sel = RegistrySelection::Uri(BackendUri::parse("local:///r.toml").unwrap());
        let err = build_invitation(&cfg, &sel, None).unwrap_err();
        assert!(format!("{err:#}").contains("named registry"));
    }

    #[test]
    fn build_errors_when_named_registry_missing_from_config() {
        let cfg = Config::default();
        let sel = RegistrySelection::Name("does-not-exist".into());
        let err = build_invitation(&cfg, &sel, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("does-not-exist"));
    }

    #[test]
    fn build_errors_when_backend_instance_missing() {
        // Registry references aws-ssm-prod but config.backends has no
        // matching block — common during partial setup.
        let cfg = Config {
            registries: HashMap::from([(
                "default".into(),
                RegistryConfig { sources: vec!["aws-ssm-prod:///registries/shared".into()] },
            )]),
            backends: HashMap::new(),
        };
        let sel = RegistrySelection::Name("default".into());
        let err = build_invitation(&cfg, &sel, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("aws-ssm-prod"), "names missing instance: {msg}");
    }

    // ---- per-backend grant content ----

    #[test]
    fn aws_ssm_grant_uses_amazon_ssm_read_only_access_policy() {
        let cfg = cfg_with(
            "default",
            "aws-ssm-prod:///registries/shared",
            "aws-ssm-prod",
            "aws-ssm",
            &[
                ("aws_region", toml::Value::String("us-east-1".into())),
                ("aws_profile", toml::Value::String("prod".into())),
            ],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice")).unwrap();
        assert!(inv.inviter_grant.contains("AmazonSSMReadOnlyAccess"));
        assert!(inv.inviter_grant.contains("alice"));
        assert!(inv.config_block.contains("aws_region = \"us-east-1\""));
        assert!(inv.config_block.contains("aws_profile = \"prod\""));
    }

    #[test]
    fn aws_secrets_grant_uses_secrets_manager_policy() {
        let cfg = cfg_with(
            "default",
            "aws-secrets-prod:///shared",
            "aws-secrets-prod",
            "aws-secrets",
            &[("aws_region", toml::Value::String("us-east-1".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("bob")).unwrap();
        assert!(inv.inviter_grant.contains("SecretsManagerReadWrite"));
    }

    #[test]
    fn one_password_grant_includes_op_vault_user_grant() {
        let cfg = cfg_with(
            "default",
            "1password-personal://Engineering/Registry/main",
            "1password-personal",
            "1password",
            &[("op_account", toml::Value::String("myteam.1password.com".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice@example.com")).unwrap();
        assert!(inv.inviter_grant.contains("op vault user grant"));
        assert!(inv.inviter_grant.contains("alice@example.com"));
        // Vault hint is the first path segment.
        assert!(inv.inviter_grant.contains("--vault Engineering"));
    }

    #[test]
    fn vault_grant_includes_policy_write_and_token_create() {
        let cfg = cfg_with(
            "default",
            "vault-eng://secret/registry",
            "vault-eng",
            "vault",
            &[("vault_address", toml::Value::String("https://vault.example.com".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice")).unwrap();
        assert!(inv.inviter_grant.contains("vault policy write"));
        assert!(inv.inviter_grant.contains("vault token create"));
        assert!(inv.inviter_grant.contains("secret/registry"));
    }

    #[test]
    fn gcp_grant_uses_secret_accessor_role() {
        let cfg = cfg_with(
            "default",
            "gcp-prod:///shared-registry",
            "gcp-prod",
            "gcp",
            &[("gcp_project", toml::Value::String("my-project".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice@example.com")).unwrap();
        assert!(inv.inviter_grant.contains("gcloud secrets add-iam-policy-binding"));
        assert!(inv.inviter_grant.contains("roles/secretmanager.secretAccessor"));
        assert!(inv.inviter_grant.contains("shared-registry"));
        assert!(inv.inviter_grant.contains("alice@example.com"));
    }

    #[test]
    fn azure_grant_uses_key_vault_secrets_user_role() {
        let cfg = cfg_with(
            "default",
            "azure-prod:///registry",
            "azure-prod",
            "azure",
            &[("azure_vault_url", toml::Value::String("https://kv.vault.azure.net/".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice@example.com")).unwrap();
        assert!(inv.inviter_grant.contains("az role assignment create"));
        assert!(inv.inviter_grant.contains("Key Vault Secrets User"));
    }

    #[test]
    fn local_backend_skips_cli_grant_in_favor_of_filesystem_hint() {
        let cfg = cfg_with("default", "local:///tmp/r.toml", "local", "local", &[]);
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, None).unwrap();
        assert!(inv.inviter_grant.contains("filesystem-served"));
        assert!(inv.inviter_grant.contains("/tmp/r.toml"));
    }

    #[test]
    fn unknown_backend_type_returns_a_pointer_to_backend_docs() {
        let cfg =
            cfg_with("default", "weird-backend:///path", "weird-backend", "weird-backend", &[]);
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice")).unwrap();
        assert!(inv.inviter_grant.contains("No canonical grant template"));
        assert!(inv.inviter_grant.contains("weird-backend"));
        assert!(inv.inviter_grant.contains("alice"));
    }

    // ---- config-block correctness ----

    #[test]
    fn config_block_round_trips_through_config_loader() {
        // The snippet should parse back into a valid Config — that's
        // the whole point of "copy-paste-ready".
        let cfg = cfg_with(
            "shared",
            "aws-ssm-prod:///registries/shared",
            "aws-ssm-prod",
            "aws-ssm",
            &[
                ("aws_region", toml::Value::String("us-east-1".into())),
                ("aws_profile", toml::Value::String("prod".into())),
            ],
        );
        let sel = RegistrySelection::Name("shared".into());
        let inv = build_invitation(&cfg, &sel, None).unwrap();
        // toml::from_str should accept the snippet as a valid Config doc.
        let parsed: Config = toml::from_str(&inv.config_block).unwrap_or_else(|e| {
            panic!(
                "config_block must be valid TOML for Config: {e}\n---\n{}\n---",
                inv.config_block
            )
        });
        assert!(parsed.registries.contains_key("shared"));
        assert!(parsed.backends.contains_key("aws-ssm-prod"));
        assert_eq!(parsed.backends["aws-ssm-prod"].backend_type, "aws-ssm");
    }

    #[test]
    fn config_block_filters_test_only_aws_bin_field() {
        // `aws_bin` is the strict-mock test hook — it points at a path
        // that means nothing on the invitee's machine. Snippet should
        // omit it entirely.
        let cfg = cfg_with(
            "default",
            "aws-ssm-prod:///r",
            "aws-ssm-prod",
            "aws-ssm",
            &[
                ("aws_region", toml::Value::String("us-east-1".into())),
                ("aws_bin", toml::Value::String("/tmp/mock-aws-script".into())),
            ],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, None).unwrap();
        assert!(!inv.config_block.contains("aws_bin"), "test-only field stripped");
        assert!(!inv.config_block.contains("/tmp/mock-aws-script"), "no mock path leak");
        assert!(inv.config_block.contains("aws_region"));
    }

    #[test]
    fn config_block_uses_bare_key_for_one_password_style_instance_name() {
        // `1password-personal` starts with a digit; serde-toml's bare-
        // key rules vary by tooling, but our `needs_quoting` accepts
        // [A-Za-z0-9_-]+ as bare. Locks that the snippet doesn't quote
        // unnecessarily.
        let cfg = cfg_with(
            "default",
            "1password-personal://Engineering/Registry/main",
            "1password-personal",
            "1password",
            &[("op_account", toml::Value::String("myteam.1password.com".into()))],
        );
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, None).unwrap();
        assert!(
            inv.config_block.contains("[backends.1password-personal]"),
            "instance name rendered bare: {}",
            inv.config_block
        );
    }

    // ---- render_human / render_json ----

    #[test]
    fn render_human_includes_all_three_sections() {
        let cfg = cfg_with("default", "local:///r.toml", "local", "local", &[]);
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, None).unwrap();
        let out = render_human(&inv);
        assert!(out.contains("Invitee:  <INVITEE>"), "default placeholder: {out}");
        assert!(out.contains("# 1. Invitee — add to your config.toml"));
        assert!(out.contains("# 2. Inviter — grant access"));
        assert!(out.contains("# 3. Invitee — verify the onboarding"));
        assert!(out.contains("secretenv doctor"));
        assert!(out.contains("secretenv registry list"));
    }

    #[test]
    fn render_json_serializes_all_invitation_fields() {
        let cfg = cfg_with("default", "local:///r.toml", "local", "local", &[]);
        let sel = RegistrySelection::Name("default".into());
        let inv = build_invitation(&cfg, &sel, Some("alice")).unwrap();
        let json = render_json(&inv).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["registry_name"], "default");
        assert_eq!(parsed["backend_type"], "local");
        assert_eq!(parsed["instance_name"], "local");
        assert_eq!(parsed["invitee"], "alice");
        assert!(parsed["config_block"].as_str().unwrap().contains("[registries.default]"));
        assert!(parsed["inviter_grant"].as_str().unwrap().contains("filesystem-served"));
        assert_eq!(parsed["verify_steps"].as_array().unwrap().len(), 2);
    }
}
