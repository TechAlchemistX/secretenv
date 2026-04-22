// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

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
    /// Load the machine-level config from the XDG-standard location,
    /// auto-merging any profile files found in the `profiles/`
    /// subdirectory next to `config.toml`.
    ///
    /// Returns [`Config::default`] (empty) if neither `config.toml` nor
    /// any profile files exist; caller decides whether that is fatal.
    ///
    /// # Errors
    /// Returns an error if the XDG config directory cannot be
    /// determined, if any config file exists but is unreadable,
    /// malformed, or contains invalid URIs.
    pub fn load() -> Result<Self> {
        let path = default_config_path()?;
        let mut config = if path.exists() {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("failed to read config at '{}'", path.display()))?;
            toml::from_str::<Self>(&contents)
                .with_context(|| format!("failed to parse config at '{}'", path.display()))?
        } else {
            Self::default()
        };
        let profiles_dir = path.parent().unwrap_or_else(|| Path::new(".")).join("profiles");
        config
            .merge_profiles_from(&profiles_dir)
            .with_context(|| format!("merging profiles from '{}'", profiles_dir.display()))?;
        config.validate().with_context(|| format!("invalid config at '{}'", path.display()))?;
        Ok(config)
    }

    /// Load the config from an explicit path (typically `--config <path>`),
    /// auto-merging any profile files found in the `profiles/`
    /// subdirectory next to the given path.
    ///
    /// Profiles (installed via `secretenv profile install`) are
    /// additive — they fill in registries + backends that are *not*
    /// already defined in `config.toml`. The user's own `config.toml`
    /// always wins where both define the same key.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, parsed, or
    /// validated, or if any profile file is malformed. A missing
    /// `path` is a hard error — `--config X` is an explicit user
    /// intent, not a hint.
    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config at '{}'", path.display()))?;
        let mut config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config at '{}'", path.display()))?;

        let profiles_dir = path.parent().unwrap_or_else(|| Path::new(".")).join("profiles");
        config
            .merge_profiles_from(&profiles_dir)
            .with_context(|| format!("merging profiles from '{}'", profiles_dir.display()))?;

        config.validate().with_context(|| format!("invalid config at '{}'", path.display()))?;
        Ok(config)
    }

    /// Merge all `*.toml` files under `dir` into `self`. Profile values
    /// fill in missing keys only — existing entries in `self` always win.
    /// Files are processed in alphabetical order so the merge is
    /// deterministic. A missing or empty `dir` is a no-op.
    ///
    /// A size gate rejects any profile file larger than
    /// [`MAX_PROFILE_FILE_BYTES`] so a compromised `profiles/` directory
    /// can't OOM the load path by dropping a giant TOML. The in-binary
    /// `secretenv profile install` path also caps download size, so this
    /// is defense-in-depth against manual/alternate writes to
    /// `profiles/`.
    fn merge_profiles_from(&mut self, dir: &Path) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .with_context(|| format!("reading profiles dir '{}'", dir.display()))?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        entries.sort();

        for path in entries {
            let meta = fs::metadata(&path)
                .with_context(|| format!("stat profile '{}'", path.display()))?;
            if meta.len() > MAX_PROFILE_FILE_BYTES {
                anyhow::bail!(
                    "profile '{}' is {} bytes; refusing to load (cap is {MAX_PROFILE_FILE_BYTES}). \
                     Profiles should be small TOML fragments.",
                    path.display(),
                    meta.len()
                );
            }
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("reading profile '{}'", path.display()))?;
            let profile: Self = toml::from_str(&contents)
                .with_context(|| format!("parsing profile '{}'", path.display()))?;
            for (name, reg) in profile.registries {
                self.registries.entry(name).or_insert(reg);
            }
            for (name, backend) in profile.backends {
                self.backends.entry(name).or_insert(backend);
            }
        }
        Ok(())
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

/// Hard ceiling on an individual profile file's on-disk size. Mirrors
/// the `MAX_PROFILE_BODY_BYTES` wire cap in `secretenv-cli::profile`;
/// keep them coordinated. Profiles are TOML fragments — 1 MiB is
/// orders of magnitude more than any real profile needs and keeps a
/// compromised `profiles/` directory from OOM-ing every `secretenv`
/// invocation on load.
const MAX_PROFILE_FILE_BYTES: u64 = 1_048_576;

fn default_config_path() -> Result<PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("could not determine a home directory for XDG config lookup"))?;
    Ok(base.config_dir().join("secretenv").join("config.toml"))
}

/// Return the canonical XDG path to `config.toml`, used by the CLI's
/// `profile` subcommand to derive the profiles directory without
/// having to know XDG semantics.
///
/// # Errors
/// Returns an error if the XDG base directories cannot be determined.
#[must_use = "profile subcommand needs this path to derive its profiles dir"]
pub fn default_config_path_xdg() -> Result<PathBuf> {
    default_config_path()
}

/// Return the profiles directory that sits next to the given
/// `config.toml` path (`<parent>/profiles`). Used by the CLI's
/// `profile` subcommand.
#[must_use]
pub fn profiles_dir_for(config_path: &Path) -> PathBuf {
    config_path.parent().unwrap_or_else(|| Path::new(".")).join("profiles")
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

    // ---- profile merge ---------------------------------------------------

    fn write_profile(dir: &TempDir, name: &str, body: &str) {
        let profiles = dir.path().join("profiles");
        fs::create_dir_all(&profiles).unwrap();
        fs::write(profiles.join(name), body).unwrap();
    }

    #[test]
    fn profile_fills_in_missing_backends() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.local-main]
type = "local"
"#,
        );
        write_profile(
            &dir,
            "team.toml",
            r#"
[backends.team-ssm]
type = "aws-ssm"
aws_region = "us-east-1"

[registries.team]
sources = ["team-ssm:///teams/acme/registry"]
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        assert!(cfg.backends.contains_key("local-main"), "user-config entry preserved");
        assert!(cfg.backends.contains_key("team-ssm"), "profile entry merged in");
        assert!(cfg.registries.contains_key("team"), "profile registry merged in");
    }

    #[test]
    fn user_config_wins_over_profile_on_conflict() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.shared]
type = "local"
"#,
        );
        // Profile tries to redefine `shared` as a different backend type.
        write_profile(
            &dir,
            "team.toml",
            r#"
[backends.shared]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        let backend = cfg.backends.get("shared").unwrap();
        assert_eq!(
            backend.backend_type, "local",
            "user config must win when both define the same backend key"
        );
    }

    #[test]
    fn profiles_merged_in_alphabetical_order() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "");
        write_profile(
            &dir,
            "01-first.toml",
            r#"
[backends.ordered]
type = "local"
"#,
        );
        write_profile(
            &dir,
            "02-second.toml",
            r#"
[backends.ordered]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
        );
        let cfg = Config::load_from(&path).unwrap();
        // Alphabetical: 01 goes first → inserts `ordered` as local.
        // 02 goes second → `or_insert` no-ops. First-writer-wins among
        // profiles, user config wins over both.
        assert_eq!(cfg.backends.get("ordered").unwrap().backend_type, "local");
    }

    #[test]
    fn malformed_profile_surfaces_error_naming_the_file() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "");
        write_profile(&dir, "broken.toml", "this is = not [valid toml");
        let err = Config::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("broken.toml"), "error names the bad profile file: {msg}");
    }

    #[test]
    fn missing_profiles_dir_is_silent_noop() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
[backends.local-main]
type = "local"
"#,
        );
        // No profiles/ dir at all.
        let cfg = Config::load_from(&path).unwrap();
        assert!(cfg.backends.contains_key("local-main"));
    }
}
