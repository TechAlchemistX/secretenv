//! The `secretenv.toml` project manifest.
//!
//! `secretenv.toml` is the *only* file a project commits to declare
//! which secrets it needs. It maps environment-variable names to either
//! an alias (resolved against the active registry) or a static default.
//!
//! Direct backend URIs (like `aws-ssm:///prod/api-key`) are a **hard
//! error** at load time — the registry indirection exists precisely so
//! commits don't embed vendor-specific paths.
#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::uri::BackendUri;

/// A parsed `secretenv.toml`.
///
/// Secret declarations are held in an `IndexMap` so iteration order
/// matches the source file — important for deterministic `doctor` and
/// `resolve` output.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// `[secrets]` table: env-var-name → declaration.
    #[serde(default)]
    pub secrets: IndexMap<String, SecretDecl>,
}

/// A single entry in the `[secrets]` table.
///
/// TOML forms (both valid):
///
/// ```toml
/// [secrets]
/// DATABASE_URL = { from = "secretenv://db-url" }
/// LOG_LEVEL    = { default = "info" }
/// ```
///
/// Or:
///
/// ```toml
/// [secrets.DATABASE_URL]
/// from = "secretenv://db-url"
///
/// [secrets.LOG_LEVEL]
/// default = "info"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SecretDecl {
    /// Reference to an alias in the active registry. Must parse as
    /// `secretenv://<alias>` — direct backend URIs are rejected.
    Alias {
        /// The `secretenv://<alias>` URI.
        from: String,
    },
    /// Static default value baked into the manifest. Not secret — use
    /// only for non-sensitive config like log levels.
    Default {
        /// The literal value to inject as the env var.
        default: String,
    },
}

impl Manifest {
    /// Walk upward from `starting_dir` looking for the nearest
    /// `secretenv.toml`, then load and validate it.
    ///
    /// # Errors
    /// - No `secretenv.toml` found anywhere up to the filesystem root.
    /// - The file is unreadable, malformed TOML, or fails validation
    ///   (e.g. an alias `from` field that isn't a `secretenv://` URI).
    pub fn load(starting_dir: &Path) -> Result<Self> {
        let found = Self::find_upward(starting_dir)?;
        Self::load_from(&found)
    }

    /// Load from an explicit path. No upward search.
    ///
    /// # Errors
    /// Same as [`load`](Self::load) minus the not-found case.
    pub fn load_from(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read manifest at '{}'", path.display()))?;
        let manifest: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse manifest at '{}'", path.display()))?;
        manifest.validate().with_context(|| format!("invalid manifest at '{}'", path.display()))?;
        Ok(manifest)
    }

    /// Walk the ancestors of `starting_dir` until the nearest
    /// `secretenv.toml` is found, returning its absolute path.
    ///
    /// # Errors
    /// Returns an error if no `secretenv.toml` is found from
    /// `starting_dir` upward to the filesystem root, or if
    /// `starting_dir` cannot be canonicalized.
    pub fn find_upward(starting_dir: &Path) -> Result<PathBuf> {
        let canonical = starting_dir.canonicalize().with_context(|| {
            format!("failed to resolve starting directory '{}'", starting_dir.display())
        })?;
        for ancestor in canonical.ancestors() {
            let candidate = ancestor.join("secretenv.toml");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(anyhow!(
            "no secretenv.toml found from '{}' upward to the filesystem root",
            canonical.display()
        ))
    }

    fn validate(&self) -> Result<()> {
        for (alias, decl) in &self.secrets {
            if let SecretDecl::Alias { from } = decl {
                let uri = BackendUri::parse(from)
                    .with_context(|| format!("secret '{alias}' has a malformed 'from' URI"))?;
                if !uri.is_alias() {
                    bail!(
                        "secret '{alias}' references a direct backend URI '{from}' — \
                         secretenv.toml only accepts secretenv://<alias> references; move the \
                         direct URI into a registry instead"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn write_manifest(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("secretenv.toml");
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_alias_and_default_entries() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"
[secrets]
DATABASE_URL = { from = "secretenv://db-url" }
STRIPE_KEY   = { from = "secretenv://stripe-key" }
LOG_LEVEL    = { default = "info" }
"#,
        );
        let manifest = Manifest::load_from(&path).unwrap();
        assert_eq!(manifest.secrets.len(), 3);
        match &manifest.secrets["DATABASE_URL"] {
            SecretDecl::Alias { from } => assert_eq!(from, "secretenv://db-url"),
            SecretDecl::Default { .. } => panic!("expected Alias"),
        }
        match &manifest.secrets["LOG_LEVEL"] {
            SecretDecl::Default { default } => assert_eq!(default, "info"),
            SecretDecl::Alias { .. } => panic!("expected Default"),
        }
    }

    #[test]
    fn preserves_declaration_order() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"
[secrets]
FIRST  = { from = "secretenv://a" }
SECOND = { from = "secretenv://b" }
THIRD  = { from = "secretenv://c" }
"#,
        );
        let manifest = Manifest::load_from(&path).unwrap();
        let keys: Vec<&String> = manifest.secrets.keys().collect();
        assert_eq!(keys, vec!["FIRST", "SECOND", "THIRD"]);
    }

    #[test]
    fn direct_backend_uri_in_manifest_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"
[secrets]
BAD = { from = "aws-ssm:///prod/api-key" }
"#,
        );
        let err = Manifest::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("BAD"), "error names the offending secret: {msg}");
        assert!(msg.contains("aws-ssm:///prod/api-key"), "error quotes the bad URI: {msg}");
        assert!(msg.contains("secretenv"), "error references the allowed scheme: {msg}");
    }

    #[test]
    fn malformed_alias_uri_errors() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"
[secrets]
BAD = { from = "no-delimiter-at-all" }
"#,
        );
        let err = Manifest::load_from(&path).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("BAD"), "names the secret: {msg}");
        assert!(msg.contains("malformed"), "describes the problem: {msg}");
    }

    #[test]
    fn upward_traversal_finds_ancestor_manifest() {
        let dir = TempDir::new().unwrap();
        // Manifest at the top, starting dir nested three levels deep.
        write_manifest(
            dir.path(),
            r#"
[secrets]
TOKEN = { from = "secretenv://token" }
"#,
        );
        let nested = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();

        let manifest = Manifest::load(&nested).unwrap();
        assert!(manifest.secrets.contains_key("TOKEN"));
    }

    #[test]
    fn no_manifest_anywhere_errors() {
        let dir = TempDir::new().unwrap();
        // Never write a manifest. Starting dir is empty all the way up.
        // Use the tempdir itself as starting — no manifest will exist
        // between here and the filesystem root (unless the test host
        // has one, which would be a very unusual dev environment).
        let err = Manifest::load(dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no secretenv.toml"), "error is specific about what's missing: {msg}");
    }

    #[test]
    fn empty_manifest_parses() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(dir.path(), "");
        let manifest = Manifest::load_from(&path).unwrap();
        assert!(manifest.secrets.is_empty());
    }

    #[test]
    fn dotted_table_form_parses() {
        let dir = TempDir::new().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"
[secrets.DATABASE_URL]
from = "secretenv://db-url"

[secrets.LOG_LEVEL]
default = "info"
"#,
        );
        let manifest = Manifest::load_from(&path).unwrap();
        assert_eq!(manifest.secrets.len(), 2);
    }

    #[test]
    fn find_upward_returns_absolute_path() {
        let dir = TempDir::new().unwrap();
        write_manifest(dir.path(), "");
        let found = Manifest::find_upward(dir.path()).unwrap();
        assert!(found.is_absolute());
        assert!(found.ends_with("secretenv.toml"));
    }
}
