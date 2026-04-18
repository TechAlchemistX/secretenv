//! Registry resolution and manifest alias resolution.
//!
//! Two entry points:
//!
//! 1. [`resolve_registry`] — given a [`Config`](crate::Config), a
//!    [`RegistrySelection`], and a [`BackendRegistry`](crate::BackendRegistry),
//!    fetch the registry document from its source backend, parse each
//!    entry, and return an [`AliasMap`] of `alias → concrete backend URI`.
//! 2. [`resolve_manifest`] — given a [`Manifest`](crate::Manifest) and
//!    an [`AliasMap`], produce a list of [`ResolvedSecret`] — one per
//!    `[secrets]` entry, either a direct default value or a concrete
//!    URI the runner (Phase 8) will fetch from.
//!
//! # v0.1 scope
//!
//! - **Single-source registries only.** If a
//!   [`RegistryConfig`](crate::RegistryConfig)'s `sources` list has
//!   more than one entry, [`resolve_registry`] uses `sources[0]` and
//!   emits a stderr warning that cascade is a v0.2 feature. This
//!   keeps user config forward-compatible.
//! - **No chained aliases.** A registry value must be a direct
//!   backend URI whose scheme matches a registered backend instance.
//!   `secretenv://<alias>` on the right-hand side is rejected.
//!
//! # Format dispatch
//!
//! Each backend exposes its native registry-document format via
//! [`Backend::list`](crate::Backend::list) — local returns flat TOML,
//! aws-ssm returns JSON, 1password returns flat TOML. The resolver
//! only sees `Vec<(String, String)>` and never needs to know
//! backend-specific formats.
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};

use crate::manifest::{Manifest, SecretDecl};
use crate::registry::BackendRegistry;
use crate::uri::BackendUri;
use crate::{Config, RegistryConfig};

/// How the user selected which registry to use.
///
/// Structural disambiguation per [[resolution-flow]]: if the input
/// contains `://` it's a direct URI; otherwise it's a registry name
/// looked up in `[registries.<name>]` of `config.toml`.
#[derive(Debug, Clone)]
pub enum RegistrySelection {
    /// Lookup by name in `config.toml`.
    Name(String),
    /// A direct backend URI — bypasses the `[registries.*]` table.
    Uri(BackendUri),
}

impl FromStr for RegistrySelection {
    type Err = anyhow::Error;

    /// Parse a user-supplied registry selection string (e.g. the
    /// value of `--registry` or `$SECRETENV_REGISTRY`).
    ///
    /// # Errors
    /// Returns an error if the input contains `://` (and was therefore
    /// interpreted as a URI) but fails to parse as a [`BackendUri`].
    fn from_str(input: &str) -> Result<Self> {
        if input.contains("://") {
            let uri = BackendUri::parse(input).with_context(|| {
                format!(
                    "registry '{input}' contains '://' so was interpreted as a URI, \
                     but parsing failed"
                )
            })?;
            Ok(Self::Uri(uri))
        } else {
            Ok(Self::Name(input.to_owned()))
        }
    }
}

/// Validated map of `alias → concrete backend URI` loaded from a
/// single registry document.
///
/// Every value is a parseable [`BackendUri`] whose scheme matches a
/// [`Backend`](crate::Backend) registered in the [`BackendRegistry`]
/// at the time [`resolve_registry`] was called.
#[derive(Debug, Clone)]
pub struct AliasMap {
    source: BackendUri,
    map: HashMap<String, BackendUri>,
}

impl AliasMap {
    /// Construct an `AliasMap` directly — typically only used by
    /// [`resolve_registry`] and tests.
    #[must_use]
    pub const fn new(source: BackendUri, map: HashMap<String, BackendUri>) -> Self {
        Self { source, map }
    }

    /// Look up an alias. Returns `None` if the alias is not in the
    /// registry.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&BackendUri> {
        self.map.get(alias)
    }

    /// The source URI this map was loaded from.
    #[must_use]
    pub const fn source(&self) -> &BackendUri {
        &self.source
    }

    /// Number of aliases in the map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the registry document contained no aliases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate `(alias, uri)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &BackendUri)> + '_ {
        self.map.iter()
    }
}

/// A secret declaration from the manifest, resolved to either a
/// static default or a concrete backend URI the runner will fetch.
#[derive(Debug, Clone)]
pub struct ResolvedSecret {
    /// The environment-variable name (the key in `[secrets]`).
    pub env_var: String,
    /// Where the value comes from.
    pub source: ResolvedSource,
}

/// The resolved source of a single secret.
#[derive(Debug, Clone)]
pub enum ResolvedSource {
    /// Literal default from `default = "..."` in `secretenv.toml`.
    /// Inject as-is; never fetched from a backend.
    Default(String),
    /// Concrete backend URI. Phase 8's runner dispatches this to the
    /// appropriate [`Backend`](crate::Backend) at runtime.
    Uri(BackendUri),
}

/// Load the registry document indicated by `selection` and return a
/// validated [`AliasMap`].
///
/// # Errors
///
/// - The `selection` names a registry not present in `config.toml`.
/// - The source URI references a backend instance not registered in
///   `backends`.
/// - The backend's `list` call fails (e.g. the document doesn't exist
///   or is unparseable).
/// - Any entry in the registry is not a parseable URI.
/// - Any entry targets an `secretenv://` alias (chains not supported
///   in v0.1) or a backend instance not registered in `backends`.
pub async fn resolve_registry(
    config: &Config,
    selection: &RegistrySelection,
    backends: &BackendRegistry,
) -> Result<AliasMap> {
    let source_uri = pick_source(config, selection)?;

    let backend = backends.get(&source_uri.scheme).ok_or_else(|| {
        anyhow!(
            "registry source '{}' targets backend instance '{}' which is not \
             configured in config.toml",
            source_uri.raw,
            source_uri.scheme
        )
    })?;

    let entries = backend
        .list(&source_uri)
        .await
        .with_context(|| format!("failed to load registry document at '{}'", source_uri.raw))?;

    let mut map = HashMap::with_capacity(entries.len());
    for (alias, raw_target) in entries {
        let target = BackendUri::parse(&raw_target).with_context(|| {
            format!(
                "registry at '{}': alias '{alias}' value '{raw_target}' is not a valid URI",
                source_uri.raw
            )
        })?;
        if target.is_alias() {
            bail!(
                "registry at '{}': alias '{alias}' points at '{raw_target}' which is another \
                 secretenv:// alias — chained aliases are not supported in v0.1, use a direct \
                 backend URI",
                source_uri.raw
            );
        }
        if backends.get(&target.scheme).is_none() {
            bail!(
                "registry at '{}': alias '{alias}' targets backend instance '{}' which is \
                 not configured in config.toml",
                source_uri.raw,
                target.scheme
            );
        }
        map.insert(alias, target);
    }

    Ok(AliasMap::new(source_uri, map))
}

fn pick_source(config: &Config, selection: &RegistrySelection) -> Result<BackendUri> {
    match selection {
        RegistrySelection::Uri(uri) => Ok(uri.clone()),
        RegistrySelection::Name(name) => {
            let reg: &RegistryConfig = config.registries.get(name).ok_or_else(|| {
                anyhow!(
                    "no registry named '{name}' in config.toml — available registries: [{}]",
                    config.registries.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })?;
            warn_on_cascade(name, reg);
            let first = reg.sources.first().ok_or_else(|| {
                // Config::validate already rejects empty sources — defensive only.
                anyhow!("registry '{name}' has no sources")
            })?;
            BackendUri::parse(first).with_context(|| {
                format!("registry '{name}' sources[0] = '{first}' is not a valid URI")
            })
        }
    }
}

fn warn_on_cascade(name: &str, reg: &RegistryConfig) {
    if reg.sources.len() > 1 {
        eprintln!(
            "warning: registry '{name}' has {} sources but v0.1 uses only sources[0] \
             (cascade is a v0.2 feature)",
            reg.sources.len()
        );
    }
}

/// Resolve every `[secrets]` entry in the manifest against the
/// already-loaded registry.
///
/// # Errors
///
/// - A manifest alias's `from` field is not a parseable URI.
/// - The `from` URI does not have the `secretenv` scheme (should have
///   been caught by [`Manifest::load`](crate::Manifest::load) already;
///   re-checked here for belt-and-suspenders).
/// - The alias is not present in `aliases`.
pub fn resolve_manifest(manifest: &Manifest, aliases: &AliasMap) -> Result<Vec<ResolvedSecret>> {
    let mut out = Vec::with_capacity(manifest.secrets.len());
    for (env_var, decl) in &manifest.secrets {
        let source = match decl {
            SecretDecl::Default { default } => ResolvedSource::Default(default.clone()),
            SecretDecl::Alias { from } => {
                let uri = BackendUri::parse(from).with_context(|| {
                    format!("manifest secret '{env_var}': 'from' field is not a valid URI")
                })?;
                if !uri.is_alias() {
                    bail!(
                        "manifest secret '{env_var}': 'from' must be a secretenv://<alias> \
                         reference, got '{from}'"
                    );
                }
                // Tolerate triple-slash: `secretenv:///alias` → strip the
                // leading slash before lookup.
                let alias_name = uri.path.trim_start_matches('/');
                let target = aliases.get(alias_name).ok_or_else(|| {
                    anyhow!(
                        "manifest secret '{env_var}': alias '{alias_name}' not found in registry \
                         at '{}'",
                        aliases.source().raw
                    )
                })?;
                ResolvedSource::Uri(target.clone())
            }
        };
        out.push(ResolvedSecret { env_var: env_var.clone(), source });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::backend::{Backend, BackendFactory};
    use crate::config::BackendConfig;
    use crate::status::BackendStatus;

    // ---- FakeListBackend: returns canned list entries ----

    struct FakeListBackend {
        backend_type: String,
        instance_name: String,
        entries: Vec<(String, String)>,
    }

    #[async_trait]
    impl Backend for FakeListBackend {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn instance_name(&self) -> &str {
            &self.instance_name
        }
        async fn check(&self) -> BackendStatus {
            BackendStatus::Ok { cli_version: "fake/1.0".into(), identity: "fake".into() }
        }
        async fn check_extensive(&self, _: &BackendUri) -> Result<usize> {
            Ok(self.entries.len())
        }
        async fn get(&self, _: &BackendUri) -> Result<String> {
            Ok("fake-body".into())
        }
        async fn set(&self, _: &BackendUri, _: &str) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &BackendUri) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: &BackendUri) -> Result<Vec<(String, String)>> {
            Ok(self.entries.clone())
        }
    }

    struct FakeListFactory {
        backend_type: String,
        entries: Vec<(String, String)>,
    }

    impl BackendFactory for FakeListFactory {
        fn backend_type(&self) -> &str {
            &self.backend_type
        }
        fn create(
            &self,
            instance_name: &str,
            _: &HashMap<String, toml::Value>,
        ) -> Result<Box<dyn Backend>> {
            Ok(Box::new(FakeListBackend {
                backend_type: self.backend_type.clone(),
                instance_name: instance_name.to_owned(),
                entries: self.entries.clone(),
            }))
        }
    }

    fn build(
        registries: &[(&str, &[&str])],
        backends_decl: &[(&str, &str)],
        entries: &[(&str, &str)],
    ) -> (Config, BackendRegistry) {
        let config = Config {
            registries: registries
                .iter()
                .map(|(name, sources)| {
                    (
                        (*name).to_owned(),
                        RegistryConfig {
                            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
                        },
                    )
                })
                .collect(),
            backends: backends_decl
                .iter()
                .map(|(name, ty)| {
                    (
                        (*name).to_owned(),
                        BackendConfig {
                            backend_type: (*ty).to_owned(),
                            raw_fields: HashMap::new(),
                        },
                    )
                })
                .collect(),
        };

        let mut backends = BackendRegistry::new();
        // Register one factory per unique backend type in the config.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (_, ty) in backends_decl {
            if seen.insert((*ty).to_owned()) {
                backends.register_factory(Box::new(FakeListFactory {
                    backend_type: (*ty).to_owned(),
                    entries: entries
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                }));
            }
        }
        backends.load_from_config(&config).unwrap();
        (config, backends)
    }

    fn manifest(decls: &[(&str, SecretDecl)]) -> Manifest {
        Manifest { secrets: decls.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect() }
    }

    // ---- RegistrySelection::from_str ----

    #[test]
    fn selection_from_str_treats_triple_slash_as_uri() {
        let sel = "local:///tmp/registry.toml".parse::<RegistrySelection>().unwrap();
        assert!(matches!(sel, RegistrySelection::Uri(_)));
    }

    #[test]
    fn selection_from_str_treats_bare_name_as_name() {
        let sel = "prod".parse::<RegistrySelection>().unwrap();
        match sel {
            RegistrySelection::Name(n) => assert_eq!(n, "prod"),
            RegistrySelection::Uri(_) => panic!("expected Name"),
        }
    }

    #[test]
    fn selection_from_str_errors_on_malformed_uri_with_delimiter() {
        // Contains `://` so it's treated as URI; empty scheme fails parse.
        let err = "://nothing".parse::<RegistrySelection>().unwrap_err();
        assert!(format!("{err:#}").contains("URI"));
    }

    // ---- resolve_registry happy path ----

    #[tokio::test]
    async fn resolve_registry_loads_validated_alias_map() {
        let (config, backends) = build(
            &[("default", &["local:///tmp/registry.toml"])],
            &[("local", "local"), ("aws-ssm-prod", "aws-ssm")],
            &[("stripe-key", "aws-ssm-prod:///prod/stripe"), ("db-url", "local:///etc/db-url")],
        );
        let aliases =
            resolve_registry(&config, &RegistrySelection::Name("default".into()), &backends)
                .await
                .unwrap();
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases.get("stripe-key").unwrap().scheme, "aws-ssm-prod");
        assert_eq!(aliases.get("db-url").unwrap().scheme, "local");
        assert_eq!(aliases.source().raw, "local:///tmp/registry.toml");
    }

    #[tokio::test]
    async fn resolve_registry_by_direct_uri_selection() {
        let (_, backends) = build(&[], &[("local", "local")], &[("k", "local:///etc/k")]);
        let cfg = Config::default();
        let direct = BackendUri::parse("local:///tmp/registry.toml").unwrap();
        let aliases = resolve_registry(&cfg, &RegistrySelection::Uri(direct.clone()), &backends)
            .await
            .unwrap();
        assert_eq!(aliases.source().raw, direct.raw);
        assert_eq!(aliases.len(), 1);
    }

    // ---- resolve_registry error paths ----

    #[tokio::test]
    async fn resolve_registry_unknown_registry_name() {
        let (config, backends) = build(&[("default", &["local:///x"])], &[("local", "local")], &[]);
        let err = resolve_registry(&config, &RegistrySelection::Name("missing".into()), &backends)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing"), "names missing: {msg}");
        assert!(msg.contains("default"), "lists available: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_source_scheme_not_registered() {
        // Config names a source whose scheme has no backend instance
        // registered. Config::validate doesn't check this (it's a
        // runtime concern), so the resolver must.
        let (config, backends) =
            build(&[("default", &["unregistered:///foo"])], &[("local", "local")], &[]);
        let err = resolve_registry(&config, &RegistrySelection::Name("default".into()), &backends)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unregistered"), "names instance: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_not_a_uri() {
        let (config, backends) =
            build(&[("default", &["local:///x"])], &[("local", "local")], &[("bad", "not-a-uri")]);
        let err = resolve_registry(&config, &RegistrySelection::Name("default".into()), &backends)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bad"), "names alias: {msg}");
        assert!(msg.contains("not-a-uri"), "quotes bad value: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_unknown_scheme() {
        let (config, backends) = build(
            &[("default", &["local:///x"])],
            &[("local", "local")],
            &[("alias", "nonexistent-scheme:///foo")],
        );
        let err = resolve_registry(&config, &RegistrySelection::Name("default".into()), &backends)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("alias"), "names alias: {msg}");
        assert!(msg.contains("nonexistent-scheme"), "names missing instance: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_is_chained_alias() {
        let (config, backends) = build(
            &[("default", &["local:///x"])],
            &[("local", "local")],
            &[("alias", "secretenv://another")],
        );
        let err = resolve_registry(&config, &RegistrySelection::Name("default".into()), &backends)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("chained"), "specific error: {msg}");
        assert!(msg.contains("secretenv://another"), "quotes bad value: {msg}");
    }

    // ---- resolve_manifest ----

    #[test]
    fn resolve_manifest_happy_mix_of_alias_and_default() {
        let mut map = HashMap::new();
        map.insert(
            "stripe-key".to_owned(),
            BackendUri::parse("aws-ssm-prod:///prod/stripe").unwrap(),
        );
        let aliases = AliasMap::new(BackendUri::parse("local:///r.toml").unwrap(), map);

        let m = manifest(&[
            ("STRIPE", SecretDecl::Alias { from: "secretenv://stripe-key".into() }),
            ("LOG_LEVEL", SecretDecl::Default { default: "info".into() }),
        ]);
        let resolved = resolve_manifest(&m, &aliases).unwrap();
        assert_eq!(resolved.len(), 2);

        let stripe = resolved.iter().find(|s| s.env_var == "STRIPE").unwrap();
        match &stripe.source {
            ResolvedSource::Uri(u) => assert_eq!(u.scheme, "aws-ssm-prod"),
            ResolvedSource::Default(_) => panic!("expected Uri"),
        }
        let log = resolved.iter().find(|s| s.env_var == "LOG_LEVEL").unwrap();
        match &log.source {
            ResolvedSource::Default(v) => assert_eq!(v, "info"),
            ResolvedSource::Uri(_) => panic!("expected Default"),
        }
    }

    #[test]
    fn resolve_manifest_tolerates_triple_slash_alias_form() {
        let mut map = HashMap::new();
        map.insert("db".to_owned(), BackendUri::parse("local:///etc/db").unwrap());
        let aliases = AliasMap::new(BackendUri::parse("local:///r.toml").unwrap(), map);

        // Both forms should resolve to the same alias.
        let m = manifest(&[
            ("A", SecretDecl::Alias { from: "secretenv://db".into() }),
            ("B", SecretDecl::Alias { from: "secretenv:///db".into() }),
        ]);
        let resolved = resolve_manifest(&m, &aliases).unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn resolve_manifest_alias_missing_errors_with_source() {
        let aliases = AliasMap::new(BackendUri::parse("local:///r.toml").unwrap(), HashMap::new());
        let m =
            manifest(&[("MISSING", SecretDecl::Alias { from: "secretenv://not-there".into() })]);
        let err = resolve_manifest(&m, &aliases).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("MISSING"), "names env var: {msg}");
        assert!(msg.contains("not-there"), "names alias: {msg}");
        assert!(msg.contains("local:///r.toml"), "names source: {msg}");
    }

    #[test]
    fn resolve_manifest_preserves_declaration_order() {
        let mut map = HashMap::new();
        map.insert("a".to_owned(), BackendUri::parse("local:///a").unwrap());
        map.insert("b".to_owned(), BackendUri::parse("local:///b").unwrap());
        map.insert("c".to_owned(), BackendUri::parse("local:///c").unwrap());
        let aliases = AliasMap::new(BackendUri::parse("local:///r.toml").unwrap(), map);

        let m = manifest(&[
            ("FIRST", SecretDecl::Alias { from: "secretenv://a".into() }),
            ("SECOND", SecretDecl::Alias { from: "secretenv://b".into() }),
            ("THIRD", SecretDecl::Alias { from: "secretenv://c".into() }),
        ]);
        let resolved = resolve_manifest(&m, &aliases).unwrap();
        assert_eq!(
            resolved.iter().map(|s| s.env_var.clone()).collect::<Vec<_>>(),
            vec!["FIRST", "SECOND", "THIRD"]
        );
    }
}
