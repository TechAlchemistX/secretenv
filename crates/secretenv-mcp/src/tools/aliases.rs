// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Alias enumeration for `list_aliases`.
//!
//! Builds the live [`BackendRegistry`] via
//! [`secretenv_backends_init::build_registry`], then for each
//! `[registries.*]` block calls [`secretenv_core::resolve_registry`]
//! and reads alias names + winning-layer source URI scheme from the
//! resulting `AliasMap`. Only the alias *name* and *backend instance
//! name* (= URI scheme) are surfaced; URI paths are dropped at this
//! seam.
//!
//! `Backend::list` (the only value-bearing path
//! [`resolve_registry`] takes) returns `Vec<(String, String)>` —
//! alias name + raw target URI string. It does NOT return a
//! [`secretenv_core::Secret`]. The value-free guarantee for this
//! tool is structural at the trait method level, not at the
//! enforcement-stack level.

use std::collections::HashMap;

use secretenv_core::{resolve_registry, AliasMap, Config, RegistryCache, RegistrySelection};

use crate::boundary::{AliasListing, RegistryAliasesProbe};

/// Result of [`enumerate_all`].
///
/// One combined alias list across every `[registries.*]` block plus
/// a per-registry probe summary (counts + errors).
pub struct AliasEnumeration {
    /// All aliases across all registries; sorted by alias name then
    /// registry name for deterministic output.
    pub aliases: Vec<AliasListing>,
    /// Per-registry enumeration summary.
    pub registries: Vec<RegistryAliasesProbe>,
}

/// Build the registry and enumerate aliases from every `[registries.*]` block.
///
/// Returns one [`AliasListing`] per alias found in any registry
/// (sorted by alias name then registry name) plus a per-registry
/// probe describing enumeration outcome.
pub async fn enumerate_all(config: &Config) -> AliasEnumeration {
    let backends = match secretenv_backends_init::build_registry(config) {
        Ok(r) => r,
        Err(e) => {
            // Whole-config failure — surface as a single synthetic
            // registry-probe entry. Mirrors the doctor handler's
            // resilience pattern.
            return AliasEnumeration {
                aliases: Vec::new(),
                registries: vec![RegistryAliasesProbe {
                    registry_name: "<registry-build-failed>".to_owned(),
                    alias_count: 0,
                    error: Some(format!("{e:#}")),
                }],
            };
        }
    };

    let backend_types: HashMap<String, String> = config
        .backends
        .iter()
        .map(|(name, cfg)| (name.clone(), cfg.backend_type.clone()))
        .collect();

    let mut all_aliases: Vec<AliasListing> = Vec::new();
    let mut probes: Vec<RegistryAliasesProbe> = Vec::with_capacity(config.registries.len());

    // Shared cache across registry enumerations so two registries
    // pointing at the same source URI don't refetch.
    let mut cache = RegistryCache::new();

    let mut registry_names: Vec<&String> = config.registries.keys().collect();
    registry_names.sort();

    for reg_name in registry_names {
        let selection = RegistrySelection::Name(reg_name.clone());
        match resolve_registry(config, &selection, &backends, &mut cache).await {
            Ok(alias_map) => {
                let alias_count =
                    collect_aliases(reg_name, &alias_map, &backend_types, &mut all_aliases);
                probes.push(RegistryAliasesProbe {
                    registry_name: reg_name.clone(),
                    alias_count,
                    error: None,
                });
            }
            Err(e) => {
                probes.push(RegistryAliasesProbe {
                    registry_name: reg_name.clone(),
                    alias_count: 0,
                    error: Some(format!("{e:#}")),
                });
            }
        }
    }

    all_aliases.sort_by(|a, b| {
        a.alias_name.cmp(&b.alias_name).then_with(|| a.registry_name.cmp(&b.registry_name))
    });

    AliasEnumeration { aliases: all_aliases, registries: probes }
}

fn collect_aliases(
    registry_name: &str,
    alias_map: &AliasMap,
    backend_types: &HashMap<String, String>,
    out: &mut Vec<AliasListing>,
) -> usize {
    let mut count = 0;
    // `AliasMap::iter()` yields `(alias, target, source)` — target is
    // the URI the alias points at (where the value actually lives),
    // source is the registry source URI we read the map from.
    for (alias_name, target_uri, _source_uri) in alias_map.iter() {
        // `target_uri.scheme` is the backend instance name that backs
        // this alias; the path portion of `target_uri` is intentionally
        // NOT surfaced (would reveal secret naming conventions).
        let instance = target_uri.scheme.clone();
        let backend_type =
            backend_types.get(&instance).cloned().unwrap_or_else(|| "<unknown>".to_owned());
        out.push(AliasListing {
            alias_name: alias_name.clone(),
            backend_instance: instance,
            backend_type,
            registry_name: registry_name.to_owned(),
        });
        count += 1;
    }
    count
}
