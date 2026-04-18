//! Configuration types for `~/.config/secretenv/config.toml`.
//!
//! The machine-level config has two tables:
//!
//! - `[registries.<name>]` → [`RegistryConfig`] — named registry
//!   sources (backend URIs that point at alias→URI documents).
//! - `[backends.<instance_name>]` → [`BackendConfig`] — the per-
//!   instance credentialed config each backend factory consumes.
//!
//! A missing file is a non-fatal empty [`Config`]; lookups fail later
//! with context about what was needed. An explicit `--config <path>`
//! goes through [`Config::load_from`].
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use crate::uri::BackendUri;

/// The machine-level configuration loaded from
/// `$XDG_CONFIG_HOME/secretenv/config.toml` (or `~/.config/...` on
/// platforms without XDG).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[registries.<name>]` entries. Each registry lists one or more
    /// source URIs that point at an alias → backend-URI map stored
    /// inside a backend.
    #[serde(default)]
    pub registries: HashMap<String, RegistryConfig>,
    /// `[backends.<instance_name>]` entries. Each builds a live
    /// [`Backend`](crate::Backend) via the factory named by `type`.
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
}

/// A single registry as configured under `[registries.<name>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// Ordered list of backend URIs that host the registry document.
    /// v0.1 uses `sources[0]` and warns if there is more than one
    /// (cascade is a v0.2 feature).
    pub sources: Vec<String>,
}

/// Configuration for a single backend instance, as found under
/// `[backends.<instance_name>]` in `config.toml`.
///
/// Deserialized manually because the TOML key `type` is a Rust
/// reserved word. Every non-`type` field is collected into
/// [`raw_fields`](Self::raw_fields) as a [`toml::Value`] — factories
/// own all type-checking and validation of their own fields.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// The backend type (the `type = "..."` field in TOML). Identifies
    /// which factory builds this instance.
    pub backend_type: String,
    /// All non-`type` fields under the block, preserved as
    /// [`toml::Value`]s. Factories extract scalars via
    /// [`toml::Value::as_str`] (or `as_integer` / `as_bool` / `as_array`
    /// for typed fields). This keeps the core blind to plugin-specific
    /// schemas.
    pub raw_fields: HashMap<String, toml::Value>,
}

impl<'de> Deserialize<'de> for BackendConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        let mut raw: HashMap<String, toml::Value> = HashMap::deserialize(deserializer)?;
        let ty = raw.remove("type").ok_or_else(|| DeError::missing_field("type"))?;
        let backend_type = match ty {
            toml::Value::String(s) => s,
            other => {
                return Err(DeError::custom(format!(
                    "'type' must be a string, got {}",
                    other.type_str()
                )));
            }
        };
        Ok(Self { backend_type, raw_fields: raw })
    }
}

impl Config {
    /// Load the machine-level config from the XDG-standard location.
    ///
    /// Returns [`Config::default`] (empty) if the file does not exist;
    /// caller decides whether that is fatal for their operation.
    ///
    /// # Errors
    /// Returns an error if the XDG config directory cannot be
    /// determined, if the file exists but is unreadable, malformed, or
    /// contains invalid URIs.
    pub fn load() -> Result<Self> {
        let path = default_config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load_from(&path)
    }

    /// Load the config from an explicit path (typically `--config <path>`).
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, parsed, or
    /// validated.
    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config at '{}'", path.display()))?;
        let config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config at '{}'", path.display()))?;
        config.validate().with_context(|| format!("invalid config at '{}'", path.display()))?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        for (name, reg) in &self.registries {
            if reg.sources.is_empty() {
                anyhow::bail!(
                    "registry '{name}' has an empty sources list — a registry must list at \
                     least one backend URI under `sources = [...]`"
                );
            }
            for (idx, source) in reg.sources.iter().enumerate() {
                BackendUri::parse(source).with_context(|| {
                    format!("registry '{name}' sources[{idx}] = '{source}' is not a valid URI")
                })?;
            }
        }
        Ok(())
    }
}

fn default_config_path() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("could not determine a home directory for XDG config lookup"))?;
    Ok(base.config_dir().join("secretenv").join("config.toml"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn write_config(dir: &TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn loads_full_config_with_registries_and_backends() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[registries.default]
sources = ["local:///tmp/registry.toml"]

[registries.shared]
sources = ["aws-ssm-prod:///registries/shared", "1password-personal://Registry/main/content"]

[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
aws_profile = "prod"

[backends.local]
type = "local"

[backends."1password-personal"]
type = "1password"
op_account = "myteam.1password.com"
"#,
        );
        let cfg = Config::load_from(&path).unwrap();

        assert_eq!(cfg.registries.len(), 2);
        assert_eq!(cfg.registries["default"].sources, vec!["local:///tmp/registry.toml"]);
        assert_eq!(cfg.registries["shared"].sources.len(), 2);

        assert_eq!(cfg.backends.len(), 3);
        let aws = &cfg.backends["aws-ssm-prod"];
        assert_eq!(aws.backend_type, "aws-ssm");
        assert_eq!(aws.raw_fields["aws_region"].as_str(), Some("us-east-1"));
        assert_eq!(aws.raw_fields["aws_profile"].as_str(), Some("prod"));
        assert!(!aws.raw_fields.contains_key("type"), "'type' must not leak into raw_fields");

        let local = &cfg.backends["local"];
        assert_eq!(local.backend_type, "local");
        assert!(local.raw_fields.is_empty(), "backend with only 'type' has empty raw_fields");

        let op = &cfg.backends["1password-personal"];
        assert_eq!(op.backend_type, "1password");
        assert_eq!(op.raw_fields["op_account"].as_str(), Some("myteam.1password.com"));
    }

    #[test]
    fn load_from_errors_on_missing_file() {
        // `Config::load_from` is strict — missing file is an error (unlike
        // `Config::load` which returns `Config::default()` on a missing
        // XDG-default config).
        let cfg = Config::load_from(Path::new("/definitely/not/a/real/path/config.toml"));
        assert!(cfg.is_err(), "load_from errors on nonexistent path");

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        assert!(Config::load_from(&path).is_err(), "load_from errors on missing file in tempdir");
    }

    #[test]
    fn config_default_is_empty() {
        let cfg = Config::default();
        assert!(cfg.registries.is_empty());
        assert!(cfg.backends.is_empty());
    }

    #[test]
    fn backend_with_no_fields_other_than_type_parses() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.local]
type = "local"
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.backends["local"].backend_type, "local");
        assert!(cfg.backends["local"].raw_fields.is_empty());
    }

    #[test]
    fn missing_type_field_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.bad]
aws_region = "us-east-1"
"#,
        );
        let err = Config::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("type"), "error mentions missing field: {msg}");
    }

    #[test]
    fn typed_non_string_fields_are_preserved_for_factories() {
        // v0.2+ behavior: integers, booleans, and arrays pass through as
        // `toml::Value`s. Factories validate per-field types themselves.
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.vault]
type = "vault"
vault_addr = "https://vault.example.com:8200"
timeout_secs = 30
use_kv_v2 = true
scopes = ["read", "write"]
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        let fields = &cfg.backends["vault"].raw_fields;
        assert_eq!(fields["vault_addr"].as_str(), Some("https://vault.example.com:8200"));
        assert_eq!(fields["timeout_secs"].as_integer(), Some(30));
        assert_eq!(fields["use_kv_v2"].as_bool(), Some(true));
        assert_eq!(fields["scopes"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn raw_fields_hashmap_preserves_string_values() {
        // v0.1-compatibility: existing backends extract strings via
        // `toml::Value::as_str()`. Confirm the round-trip.
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
aws_profile = "prod"
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        let fields = &cfg.backends["aws-ssm-prod"].raw_fields;
        assert_eq!(fields["aws_region"].as_str(), Some("us-east-1"));
        assert_eq!(fields["aws_profile"].as_str(), Some("prod"));
    }

    #[test]
    fn invalid_registry_source_uri_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[registries.default]
sources = ["not-a-valid-uri"]
"#,
        );
        let err = Config::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("default"), "error names the registry: {msg}");
        assert!(msg.contains("not-a-valid-uri"), "error quotes the bad source: {msg}");
    }

    #[test]
    fn unknown_top_level_key_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[registries.default]
sources = ["local:///tmp/r.toml"]

[register]
extra = "typo"
"#,
        );
        let err = Config::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("register") || msg.contains("unknown"), "error hints at typo: {msg}");
    }

    #[test]
    fn empty_file_parses_as_empty_config() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "");
        let cfg = Config::load_from(&path).unwrap();
        assert!(cfg.registries.is_empty());
        assert!(cfg.backends.is_empty());
    }

    #[test]
    fn empty_sources_list_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r"
[registries.default]
sources = []
",
        );
        let err = Config::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("default"), "error names the registry: {msg}");
        assert!(msg.contains("empty sources"), "error explains the problem: {msg}");
    }
}
