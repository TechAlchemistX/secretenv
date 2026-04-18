//! Registry resolution and manifest alias resolution.
//!
//! Two entry points:
//!
//! 1. [`resolve_registry`] — given a [`Config`](crate::Config), a
//!    [`RegistrySelection`], and a [`BackendRegistry`](crate::BackendRegistry),
//!    fetch every configured source in the registry cascade, parse each
//!    entry, and return an [`AliasMap`] — an ordered stack of
//!    [`CascadeLayer`]s.
//! 2. [`resolve_manifest`] — given a [`Manifest`](crate::Manifest) and
//!    an [`AliasMap`], produce a list of [`ResolvedSecret`] — one per
//!    `[secrets]` entry, either a direct default value or a concrete
//!    URI the runner will fetch from.
//!
//! # Cascade semantics (v0.2)
//!
//! - A registry may declare multiple `sources = [...]` entries in
//!   `config.toml`. Each source is loaded in parallel; the resulting
//!   `AliasMap` holds one [`CascadeLayer`] per source in declaration
//!   order.
//! - Alias lookup is **first-match-wins**: [`AliasMap::get`] walks
//!   layers from index 0 downward and returns the first hit.
//! - Later layers act as read-only fallbacks — there is no merging at
//!   the entry level.
//! - `sources[0]` is the single write target for `registry set/unset`.
//! - **No chained aliases.** A registry value must be a direct backend
//!   URI whose scheme matches a registered backend instance.
//!   `secretenv://<alias>` on the right-hand side is rejected.
//! - If **any** source's `list()` call fails (missing CLI, auth, I/O),
//!   the entire resolve errors. Silent fall-through to later layers
//!   would hide environment problems.
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
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use futures::future::join_all;

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

/// One loaded cascade source — its URI plus the alias→URI map parsed
/// from its registry document.
#[derive(Debug, Clone)]
pub struct CascadeLayer {
    /// The backend URI this layer was loaded from.
    pub source: BackendUri,
    /// `alias → concrete backend URI` entries from this source.
    pub map: HashMap<String, BackendUri>,
}

/// Ordered stack of loaded registry sources. Lookup is first-match-wins
/// from index 0 downward. `layers[0]` is the write target for
/// `registry set/unset`.
///
/// Every URI value in every layer is validated at load time: parseable
/// [`BackendUri`] whose scheme matches a [`Backend`](crate::Backend)
/// registered in the [`BackendRegistry`].
///
/// Layers are held as `Arc<CascadeLayer>` so [`RegistryCache`] can hand
/// out shared references without cloning the map on every resolve.
#[derive(Debug, Clone)]
pub struct AliasMap {
    layers: Vec<Arc<CascadeLayer>>,
}

impl AliasMap {
    /// Construct an `AliasMap` from pre-built layer `Arc`s — typically
    /// only used by [`resolve_registry`] and tests.
    ///
    /// # Panics
    /// Panics if `layers` is empty. [`resolve_registry`] guarantees at
    /// least one layer; tests should pass at least one.
    #[must_use]
    pub fn new(layers: Vec<Arc<CascadeLayer>>) -> Self {
        assert!(!layers.is_empty(), "AliasMap requires at least one cascade layer");
        Self { layers }
    }

    /// Look up an alias. Returns `(target_uri, source_uri)` of the
    /// first layer that contains it, or `None` if no layer does.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<(&BackendUri, &BackendUri)> {
        self.layers.iter().find_map(|l| l.map.get(alias).map(|u| (u, &l.source)))
    }

    /// Read-only view of the layer `Arc`s in declaration order.
    #[must_use]
    pub fn layers(&self) -> &[Arc<CascadeLayer>] {
        &self.layers
    }

    /// The primary (layer-0) source — the write target for
    /// `registry set` / `registry unset`.
    #[must_use]
    pub fn primary_source(&self) -> &BackendUri {
        &self.layers[0].source
    }

    /// Iterate source URIs in cascade order.
    pub fn sources(&self) -> impl Iterator<Item = &BackendUri> + '_ {
        self.layers.iter().map(|l| &l.source)
    }

    /// Total number of unique aliases visible across the cascade
    /// (first-match-wins — entries shadowed by an earlier layer count
    /// once).
    #[must_use]
    pub fn len(&self) -> usize {
        self.effective_keys().count()
    }

    /// `true` if every layer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.layers.iter().all(|l| l.map.is_empty())
    }

    /// Iterate the cascade's effective view — one `(alias, target, source)`
    /// per unique alias, first-match-wins.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &BackendUri, &BackendUri)> + '_ {
        self.layers.iter().enumerate().flat_map(move |(idx, layer)| {
            layer.map.iter().filter_map(move |(alias, target)| {
                // Shadowed by an earlier layer? Skip.
                if self.layers[..idx].iter().any(|earlier| earlier.map.contains_key(alias)) {
                    None
                } else {
                    Some((alias, target, &layer.source))
                }
            })
        })
    }

    fn effective_keys(&self) -> impl Iterator<Item = &String> + '_ {
        self.iter().map(|(alias, _, _)| alias)
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
    /// Concrete backend URI. The runner dispatches this to the
    /// appropriate [`Backend`](crate::Backend) at runtime.
    Uri {
        /// The concrete backend URI to fetch.
        target: BackendUri,
        /// The cascade source the alias was resolved from — surfaced
        /// by `--verbose` and `doctor --extensive` to help operators
        /// confirm which cascade layer a secret came from.
        source: BackendUri,
    },
}

/// Session-scoped cache for loaded [`CascadeLayer`]s.
///
/// A single `secretenv` invocation can reference the same registry
/// source multiple times (e.g. a handler that calls
/// [`resolve_registry`] during both pre-flight validation and the
/// actual resolve, or future flows that cross-check a cascade from
/// several angles). Without a cache each reference would re-invoke
/// the backend's `list` — potentially spawning a fresh `aws` or `op`
/// CLI process each time.
///
/// `RegistryCache` memoizes `list` results by source [`BackendUri`],
/// hands out shared [`Arc<CascadeLayer>`] views, and **only caches
/// registry maps (alias → URI pointers), never secret values**.
/// Secret values flow straight from backend to child env through the
/// runner; nothing about this cache changes that.
///
/// # Scope
///
/// - Process-scoped. Construct a fresh [`RegistryCache::new`] per
///   top-level command; nothing persists to disk or IPC.
/// - No eviction. The process dies on `exec()`; the cache goes with it.
/// - Not thread-hostile (the `&mut` borrow forces single-writer access)
///   but also not concurrent — for v0.2 the design target is a single
///   command dispatched sequentially, with parallelism inside each
///   `resolve_registry` call via [`futures::future::join_all`].
#[derive(Debug, Default)]
pub struct RegistryCache {
    inner: HashMap<BackendUri, Arc<CascadeLayer>>,
}

impl RegistryCache {
    /// Construct an empty cache. Call once per `secretenv` invocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch a cascade layer for `source`. On a cache hit, returns a
    /// zero-I/O [`Arc::clone`] of the previously-loaded layer. On a
    /// miss, calls `backend.list(source)` exactly once, validates
    /// every entry, stores the result under `source`, and returns a
    /// clone of the stored `Arc`.
    ///
    /// # Errors
    ///
    /// - `source` references a backend instance not registered in
    ///   `backends`.
    /// - `backend.list(source)` itself fails.
    /// - Any entry in the loaded document is not a parseable URI,
    ///   targets an `secretenv://` alias (chained), or references an
    ///   unregistered backend instance.
    pub async fn fetch(
        &mut self,
        source: &BackendUri,
        backends: &BackendRegistry,
    ) -> Result<Arc<CascadeLayer>> {
        if let Some(hit) = self.inner.get(source) {
            return Ok(Arc::clone(hit));
        }
        let layer = Arc::new(fetch_layer(source, backends).await?);
        self.inner.insert(source.clone(), Arc::clone(&layer));
        Ok(layer)
    }

    /// Concurrently fetch any source URIs in `sources` that are not
    /// already cached, inserting each result into the cache. Sources
    /// already present are left untouched.
    ///
    /// This preserves Phase 1's within-cascade parallelism while
    /// letting subsequent resolves within the same process hit the
    /// cache instead of reissuing `backend.list`.
    ///
    /// # Errors
    ///
    /// Same as [`RegistryCache::fetch`]. Any single failure aborts
    /// the warm pass — callers should treat partial cache state as
    /// untrusted when this errors.
    pub async fn warm(&mut self, sources: &[BackendUri], backends: &BackendRegistry) -> Result<()> {
        // Partition into already-cached + newly-needed URIs.
        let mut seen: std::collections::HashSet<&BackendUri> = std::collections::HashSet::new();
        let to_fetch: Vec<&BackendUri> = sources
            .iter()
            .filter(|src| !self.inner.contains_key(*src) && seen.insert(*src))
            .collect();

        if to_fetch.is_empty() {
            return Ok(());
        }

        let fetches = to_fetch.iter().map(|src| async move {
            let layer = fetch_layer(src, backends).await?;
            Ok::<_, anyhow::Error>(((*src).clone(), Arc::new(layer)))
        });
        for result in join_all(fetches).await {
            let (uri, layer) = result?;
            self.inner.insert(uri, layer);
        }
        Ok(())
    }

    /// Number of cached layers. Primarily useful for tests asserting
    /// cache-hit vs cache-miss behavior.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if no layers are cached yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Load every source in the cascade indicated by `selection` and
/// return a validated [`AliasMap`].
///
/// Sources are fetched concurrently via `cache.fetch`; repeat sources
/// within one cascade (or across resolves in the same process) hit
/// the cache. If any source fails (missing CLI, auth error, I/O
/// error, malformed document) the entire call errors — silent
/// fall-through would mask environment problems.
///
/// # Errors
///
/// - The `selection` names a registry not present in `config.toml`.
/// - A source URI references a backend instance not registered in
///   `backends`.
/// - Any source's `list` call fails (e.g. the document doesn't exist
///   or is unparseable).
/// - Any entry in any layer is not a parseable URI.
/// - Any entry targets an `secretenv://` alias (chains not supported)
///   or a backend instance not registered in `backends`.
pub async fn resolve_registry(
    config: &Config,
    selection: &RegistrySelection,
    backends: &BackendRegistry,
    cache: &mut RegistryCache,
) -> Result<AliasMap> {
    let source_uris = pick_sources(config, selection)?;

    // Warm the cache concurrently for any un-cached source URIs,
    // preserving Phase 1's within-cascade parallelism. After warm
    // returns Ok, every URI in `source_uris` is present in the cache.
    cache.warm(&source_uris, backends).await?;

    // Build the `AliasMap` from the cache. Each fetch here is a pure
    // HashMap lookup + `Arc::clone` — zero I/O. Duplicate sources in
    // a cascade yield the same `Arc` without re-invoking the backend.
    let mut layers: Vec<Arc<CascadeLayer>> = Vec::with_capacity(source_uris.len());
    for src in &source_uris {
        layers.push(cache.fetch(src, backends).await?);
    }
    Ok(AliasMap::new(layers))
}

async fn fetch_layer(source_uri: &BackendUri, backends: &BackendRegistry) -> Result<CascadeLayer> {
    let backend = backends.get(&source_uri.scheme).ok_or_else(|| {
        anyhow!(
            "registry source '{}' targets backend instance '{}' which is not \
             configured in config.toml",
            source_uri.raw,
            source_uri.scheme
        )
    })?;

    let entries = backend
        .list(source_uri)
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
                 secretenv:// alias — chained aliases are not supported, use a direct backend URI",
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
    Ok(CascadeLayer { source: source_uri.clone(), map })
}

fn pick_sources(config: &Config, selection: &RegistrySelection) -> Result<Vec<BackendUri>> {
    match selection {
        RegistrySelection::Uri(uri) => Ok(vec![uri.clone()]),
        RegistrySelection::Name(name) => {
            let reg: &RegistryConfig = config.registries.get(name).ok_or_else(|| {
                anyhow!(
                    "no registry named '{name}' in config.toml — available registries: [{}]",
                    config.registries.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })?;
            if reg.sources.is_empty() {
                // Config::validate already rejects empty sources — defensive only.
                bail!("registry '{name}' has no sources");
            }
            reg.sources
                .iter()
                .map(|raw| {
                    BackendUri::parse(raw).with_context(|| {
                        format!("registry '{name}' source '{raw}' is not a valid URI")
                    })
                })
                .collect()
        }
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
/// - The alias is not present in any cascade layer.
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
                let (target, resolved_from) = aliases.get(alias_name).ok_or_else(|| {
                    anyhow!(
                        "manifest secret '{env_var}': alias '{alias_name}' not found in \
                         registry cascade [{}]",
                        format_sources(aliases)
                    )
                })?;
                ResolvedSource::Uri { target: target.clone(), source: resolved_from.clone() }
            }
        };
        out.push(ResolvedSecret { env_var: env_var.clone(), source });
    }
    Ok(out)
}

fn format_sources(aliases: &AliasMap) -> String {
    aliases.sources().map(|u| u.raw.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::backend::{Backend, BackendFactory};
    use crate::config::BackendConfig;
    use crate::status::BackendStatus;

    // ---- FakeListBackend: returns canned list entries per-instance ----

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeListBackend {
        backend_type: String,
        instance_name: String,
        entries: Vec<(String, String)>,
        fail_list: bool,
        list_count: Arc<AtomicUsize>,
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
            self.list_count.fetch_add(1, Ordering::SeqCst);
            if self.fail_list {
                bail!("simulated list failure for instance '{}'", self.instance_name);
            }
            Ok(self.entries.clone())
        }
    }

    /// Maps `instance_name → (entries, fail_list)`.
    #[derive(Default, Clone)]
    struct InstanceTable(HashMap<String, (Vec<(String, String)>, bool)>);

    impl InstanceTable {
        fn with(mut self, instance: &str, entries: &[(&str, &str)]) -> Self {
            self.0.insert(
                instance.to_owned(),
                (entries.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(), false),
            );
            self
        }
        fn with_failing(mut self, instance: &str) -> Self {
            self.0.insert(instance.to_owned(), (vec![], true));
            self
        }
    }

    struct FakeListFactory {
        backend_type: String,
        instances: InstanceTable,
        list_count: Arc<AtomicUsize>,
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
            let (entries, fail_list) =
                self.instances.0.get(instance_name).cloned().unwrap_or_default();
            Ok(Box::new(FakeListBackend {
                backend_type: self.backend_type.clone(),
                instance_name: instance_name.to_owned(),
                entries,
                fail_list,
                list_count: self.list_count.clone(),
            }))
        }
    }

    fn build(
        registries: &[(&str, &[&str])],
        backends_decl: &[(&str, &str)],
        instances: &InstanceTable,
    ) -> (Config, BackendRegistry, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
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
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (_, ty) in backends_decl {
            if seen.insert((*ty).to_owned()) {
                backends.register_factory(Box::new(FakeListFactory {
                    backend_type: (*ty).to_owned(),
                    instances: instances.clone(),
                    list_count: counter.clone(),
                }));
            }
        }
        backends.load_from_config(&config).unwrap();
        (config, backends, counter)
    }

    fn manifest(decls: &[(&str, SecretDecl)]) -> Manifest {
        Manifest { secrets: decls.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect() }
    }

    fn single_layer(source_uri: &str, entries: &[(&str, &str)]) -> AliasMap {
        let map =
            entries.iter().map(|(a, u)| ((*a).to_owned(), BackendUri::parse(u).unwrap())).collect();
        AliasMap::new(vec![Arc::new(CascadeLayer {
            source: BackendUri::parse(source_uri).unwrap(),
            map,
        })])
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
        let err = "://nothing".parse::<RegistrySelection>().unwrap_err();
        assert!(format!("{err:#}").contains("URI"));
    }

    // ---- resolve_registry happy path ----

    #[tokio::test]
    async fn resolve_registry_loads_single_source_cascade() {
        let instances = InstanceTable::default().with(
            "local",
            &[("stripe-key", "aws-ssm-prod:///prod/stripe"), ("db-url", "local:///etc/db-url")],
        );
        let (config, backends, _) = build(
            &[("default", &["local:///tmp/registry.toml"])],
            &[("local", "local"), ("aws-ssm-prod", "aws-ssm")],
            &instances,
        );
        let aliases = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap();
        assert_eq!(aliases.layers().len(), 1);
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases.get("stripe-key").unwrap().0.scheme, "aws-ssm-prod");
        assert_eq!(aliases.get("db-url").unwrap().0.scheme, "local");
        assert_eq!(aliases.primary_source().raw, "local:///tmp/registry.toml");
    }

    #[tokio::test]
    async fn resolve_registry_by_direct_uri_selection() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///etc/k")]);
        let (_, backends, _) = build(&[], &[("local", "local")], &instances);
        let cfg = Config::default();
        let direct = BackendUri::parse("local:///tmp/registry.toml").unwrap();
        let aliases = resolve_registry(
            &cfg,
            &RegistrySelection::Uri(direct.clone()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap();
        assert_eq!(aliases.layers().len(), 1);
        assert_eq!(aliases.primary_source().raw, direct.raw);
        assert_eq!(aliases.len(), 1);
    }

    // ---- resolve_registry cascade ----

    #[tokio::test]
    async fn cascade_alias_in_first_source_only() {
        let instances = InstanceTable::default()
            .with("local-a", &[("only-in-a", "local-a:///a")])
            .with("local-b", &[]);
        let (config, backends, _) = build(
            &[("cascade", &["local-a:///tmp/a.toml", "local-b:///tmp/b.toml"])],
            &[("local-a", "local"), ("local-b", "local")],
            &instances,
        );
        let aliases = resolve_registry(
            &config,
            &RegistrySelection::Name("cascade".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap();
        assert_eq!(aliases.layers().len(), 2);
        let (target, src) = aliases.get("only-in-a").unwrap();
        assert_eq!(target.raw, "local-a:///a");
        assert_eq!(src.raw, "local-a:///tmp/a.toml");
    }

    #[tokio::test]
    async fn cascade_alias_in_second_source_only() {
        let instances = InstanceTable::default()
            .with("local-a", &[])
            .with("local-b", &[("only-in-b", "local-b:///b")]);
        let (config, backends, _) = build(
            &[("cascade", &["local-a:///tmp/a.toml", "local-b:///tmp/b.toml"])],
            &[("local-a", "local"), ("local-b", "local")],
            &instances,
        );
        let aliases = resolve_registry(
            &config,
            &RegistrySelection::Name("cascade".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap();
        let (target, src) = aliases.get("only-in-b").unwrap();
        assert_eq!(target.raw, "local-b:///b");
        assert_eq!(src.raw, "local-b:///tmp/b.toml");
    }

    #[tokio::test]
    async fn cascade_first_source_shadows_second() {
        let instances = InstanceTable::default()
            .with("local-a", &[("shared", "local-a:///a")])
            .with("local-b", &[("shared", "local-b:///b")]);
        let (config, backends, _) = build(
            &[("cascade", &["local-a:///tmp/a.toml", "local-b:///tmp/b.toml"])],
            &[("local-a", "local"), ("local-b", "local")],
            &instances,
        );
        let aliases = resolve_registry(
            &config,
            &RegistrySelection::Name("cascade".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap();
        let (target, src) = aliases.get("shared").unwrap();
        assert_eq!(target.raw, "local-a:///a", "layer 0 wins");
        assert_eq!(src.raw, "local-a:///tmp/a.toml");
        // And the effective view deduplicates — one entry, not two.
        assert_eq!(aliases.len(), 1);
    }

    // ---- resolve_registry error paths ----

    #[tokio::test]
    async fn resolve_registry_unknown_registry_name() {
        let instances = InstanceTable::default().with("local", &[]);
        let (config, backends, _) =
            build(&[("default", &["local:///x"])], &[("local", "local")], &instances);
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("missing".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing"), "names missing: {msg}");
        assert!(msg.contains("default"), "lists available: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_source_scheme_not_registered() {
        let instances = InstanceTable::default().with("local", &[]);
        let (config, backends, _) =
            build(&[("default", &["unregistered:///foo"])], &[("local", "local")], &instances);
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unregistered"), "names instance: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_not_a_uri() {
        let instances = InstanceTable::default().with("local", &[("bad", "not-a-uri")]);
        let (config, backends, _) =
            build(&[("default", &["local:///x"])], &[("local", "local")], &instances);
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bad"), "names alias: {msg}");
        assert!(msg.contains("not-a-uri"), "quotes bad value: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_unknown_scheme() {
        let instances =
            InstanceTable::default().with("local", &[("alias", "nonexistent-scheme:///foo")]);
        let (config, backends, _) =
            build(&[("default", &["local:///x"])], &[("local", "local")], &instances);
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("alias"), "names alias: {msg}");
        assert!(msg.contains("nonexistent-scheme"), "names missing instance: {msg}");
    }

    #[tokio::test]
    async fn resolve_registry_entry_is_chained_alias() {
        let instances = InstanceTable::default().with("local", &[("alias", "secretenv://another")]);
        let (config, backends, _) =
            build(&[("default", &["local:///x"])], &[("local", "local")], &instances);
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("chained"), "specific error: {msg}");
        assert!(msg.contains("secretenv://another"), "quotes bad value: {msg}");
    }

    #[tokio::test]
    async fn cascade_chained_alias_in_later_source_still_rejected() {
        let instances = InstanceTable::default()
            .with("local-a", &[("good", "local-a:///ok")])
            .with("local-b", &[("bad", "secretenv://chained")]);
        let (config, backends, _) = build(
            &[("cascade", &["local-a:///tmp/a.toml", "local-b:///tmp/b.toml"])],
            &[("local-a", "local"), ("local-b", "local")],
            &instances,
        );
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("cascade".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("chained"), "names the problem: {msg}");
        assert!(msg.contains("secretenv://chained"), "quotes the bad value: {msg}");
    }

    #[tokio::test]
    async fn cascade_source_list_failure_fails_whole_resolve() {
        let instances = InstanceTable::default()
            .with_failing("local-a")
            .with("local-b", &[("would-have-worked", "local-b:///fine")]);
        let (config, backends, _) = build(
            &[("cascade", &["local-a:///tmp/a.toml", "local-b:///tmp/b.toml"])],
            &[("local-a", "local"), ("local-b", "local")],
            &instances,
        );
        let err = resolve_registry(
            &config,
            &RegistrySelection::Name("cascade".into()),
            &backends,
            &mut RegistryCache::new(),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("local-a:///tmp/a.toml"),
            "error surfaces the failing layer's URI: {msg}"
        );
    }

    // ---- resolve_manifest ----

    #[test]
    fn resolve_manifest_happy_mix_of_alias_and_default() {
        let aliases =
            single_layer("local:///r.toml", &[("stripe-key", "aws-ssm-prod:///prod/stripe")]);

        let m = manifest(&[
            ("STRIPE", SecretDecl::Alias { from: "secretenv://stripe-key".into() }),
            ("LOG_LEVEL", SecretDecl::Default { default: "info".into() }),
        ]);
        let resolved = resolve_manifest(&m, &aliases).unwrap();
        assert_eq!(resolved.len(), 2);

        let stripe = resolved.iter().find(|s| s.env_var == "STRIPE").unwrap();
        match &stripe.source {
            ResolvedSource::Uri { target, source } => {
                assert_eq!(target.scheme, "aws-ssm-prod");
                assert_eq!(source.raw, "local:///r.toml");
            }
            ResolvedSource::Default(_) => panic!("expected Uri"),
        }
        let log = resolved.iter().find(|s| s.env_var == "LOG_LEVEL").unwrap();
        match &log.source {
            ResolvedSource::Default(v) => assert_eq!(v, "info"),
            ResolvedSource::Uri { .. } => panic!("expected Default"),
        }
    }

    #[test]
    fn resolve_manifest_tolerates_triple_slash_alias_form() {
        let aliases = single_layer("local:///r.toml", &[("db", "local:///etc/db")]);
        let m = manifest(&[
            ("A", SecretDecl::Alias { from: "secretenv://db".into() }),
            ("B", SecretDecl::Alias { from: "secretenv:///db".into() }),
        ]);
        let resolved = resolve_manifest(&m, &aliases).unwrap();
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn resolve_manifest_alias_missing_lists_all_cascade_sources() {
        let aliases = AliasMap::new(vec![
            Arc::new(CascadeLayer {
                source: BackendUri::parse("local:///primary.toml").unwrap(),
                map: HashMap::new(),
            }),
            Arc::new(CascadeLayer {
                source: BackendUri::parse("local:///fallback.toml").unwrap(),
                map: HashMap::new(),
            }),
        ]);
        let m =
            manifest(&[("MISSING", SecretDecl::Alias { from: "secretenv://not-there".into() })]);
        let err = resolve_manifest(&m, &aliases).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("MISSING"), "names env var: {msg}");
        assert!(msg.contains("not-there"), "names alias: {msg}");
        assert!(msg.contains("local:///primary.toml"), "lists primary: {msg}");
        assert!(msg.contains("local:///fallback.toml"), "lists fallback: {msg}");
    }

    #[test]
    fn resolve_manifest_preserves_declaration_order() {
        let aliases = single_layer(
            "local:///r.toml",
            &[("a", "local:///a"), ("b", "local:///b"), ("c", "local:///c")],
        );
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

    // ---- RegistryCache (Phase 3) ----

    /// Second resolve of the same registry is a zero-I/O cache hit.
    /// Uses a shared cache across two resolve calls; asserts the
    /// backend's `list()` was invoked exactly once total.
    #[tokio::test]
    async fn cache_hit_across_resolves_avoids_second_list() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///v")]);
        let (config, backends, list_count) =
            build(&[("default", &["local:///tmp/r.toml"])], &[("local", "local")], &instances);
        let mut cache = RegistryCache::new();

        let a1 = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(list_count.load(Ordering::SeqCst), 1, "first resolve loads the source");

        let a2 = resolve_registry(
            &config,
            &RegistrySelection::Name("default".into()),
            &backends,
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(
            list_count.load(Ordering::SeqCst),
            1,
            "second resolve is a pure cache hit — no additional list() call"
        );
        // Both resolves return the same single alias; equality via URI.
        assert_eq!(a1.get("k").unwrap().0.raw, a2.get("k").unwrap().0.raw);
    }

    /// Two different source URIs are independent cache entries.
    #[tokio::test]
    async fn cache_different_uris_miss_each_other() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///v")]);
        let (_, backends, list_count) = build(&[], &[("local", "local")], &instances);
        let mut cache = RegistryCache::new();

        let a = BackendUri::parse("local:///tmp/a.toml").unwrap();
        let b = BackendUri::parse("local:///tmp/b.toml").unwrap();
        let _ = cache.fetch(&a, &backends).await.unwrap();
        let _ = cache.fetch(&b, &backends).await.unwrap();

        assert_eq!(list_count.load(Ordering::SeqCst), 2, "distinct URIs → distinct list calls");
        assert_eq!(cache.len(), 2);
    }

    /// Two fetches of the same URI return pointer-equal `Arc`s —
    /// verifies that cache hits share the stored layer rather than
    /// handing back independent clones.
    #[tokio::test]
    async fn cache_second_fetch_shares_arc() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///v")]);
        let (_, backends, list_count) = build(&[], &[("local", "local")], &instances);
        let mut cache = RegistryCache::new();

        let src = BackendUri::parse("local:///tmp/r.toml").unwrap();
        let first = cache.fetch(&src, &backends).await.unwrap();
        let second = cache.fetch(&src, &backends).await.unwrap();

        assert!(Arc::ptr_eq(&first, &second), "same URI → same Arc");
        assert_eq!(list_count.load(Ordering::SeqCst), 1, "only one list() call");
    }

    /// Cascade with duplicate source URIs fetches each unique URI
    /// once, not per occurrence. Defensive regression — a user
    /// accidentally listing the same source twice in `sources = [...]`
    /// should not double-list.
    #[tokio::test]
    async fn cache_cascade_with_duplicate_source_fetches_once() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///v")]);
        let (config, backends, list_count) = build(
            &[("dup", &["local:///tmp/r.toml", "local:///tmp/r.toml"])],
            &[("local", "local")],
            &instances,
        );
        let mut cache = RegistryCache::new();
        let aliases = resolve_registry(
            &config,
            &RegistrySelection::Name("dup".into()),
            &backends,
            &mut cache,
        )
        .await
        .unwrap();

        assert_eq!(list_count.load(Ordering::SeqCst), 1, "deduped source: single list()");
        // Cascade still shows two layers (declaration order preserved),
        // but both reference the same cached Arc.
        assert_eq!(aliases.layers().len(), 2);
        assert!(Arc::ptr_eq(&aliases.layers()[0], &aliases.layers()[1]));
    }

    /// A fresh cache reports empty; after one fetch it's non-empty.
    /// Pins the `RegistryCache::len`/`is_empty` public surface.
    #[tokio::test]
    async fn cache_tracks_size_accurately() {
        let instances = InstanceTable::default().with("local", &[("k", "local:///v")]);
        let (_, backends, _) = build(&[], &[("local", "local")], &instances);
        let mut cache = RegistryCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        let src = BackendUri::parse("local:///tmp/r.toml").unwrap();
        let _ = cache.fetch(&src, &backends).await.unwrap();
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }
}
