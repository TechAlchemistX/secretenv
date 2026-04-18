//! The [`BackendRegistry`] — the process-wide dispatcher that maps
//! instance names (URI schemes) to live [`Backend`] instances.
//!
//! Not to be confused with the *alias registry document* (the
//! `registry-document` wiki page) — that's the TOML/JSON blob stored
//! inside a backend that maps aliases to backend URIs. The
//! `BackendRegistry` here is the in-process plugin directory.
//!
//! Typical startup flow:
//!
//! ```text
//! let mut reg = BackendRegistry::new();
//! reg.register_factory(Box::new(LocalFactory));
//! reg.register_factory(Box::new(AwsSsmFactory));
//! reg.register_factory(Box::new(OnePasswordFactory));
//! reg.load_from_config(&config)?;
//! ```
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};

use crate::backend::{Backend, BackendFactory};
use crate::config::Config;

/// Registry of backend factories and live instances.
///
/// Created empty, populated in two steps: first
/// [`register_factory`](Self::register_factory) for every compiled-in
/// plugin, then [`load_from_config`](Self::load_from_config) to
/// construct a live instance for each `[backends.<name>]` block.
#[derive(Default)]
pub struct BackendRegistry {
    factories: HashMap<String, Box<dyn BackendFactory>>,
    instances: HashMap<String, Box<dyn Backend>>,
}

impl BackendRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a factory. If a factory is already registered for the
    /// same backend type, it is silently replaced — registration is a
    /// compile-time-fixed list in the CLI, so duplicates are a
    /// programmer error rather than a runtime condition.
    pub fn register_factory(&mut self, factory: Box<dyn BackendFactory>) {
        let backend_type = factory.backend_type().to_owned();
        self.factories.insert(backend_type, factory);
    }

    /// Build a live backend instance for every entry in `config.backends`.
    ///
    /// Fail-fast: returns on the first error and leaves any partially-
    /// constructed instances in place. Safe to call multiple times with
    /// non-overlapping instance-name sets.
    ///
    /// # Errors
    ///
    /// - Returns an error if any `[backends.<name>]` references a
    ///   `type` that has no registered factory. Error names both the
    ///   instance and the missing type.
    /// - Returns an error if an instance with the same name is already
    ///   loaded. This is a defensive check — the config parser
    ///   (Phase 3) should reject duplicate TOML keys before reaching
    ///   this code.
    /// - Propagates any error from a factory's `create` method, with
    ///   context pointing at the offending instance name.
    pub fn load_from_config(&mut self, config: &Config) -> Result<()> {
        for (instance_name, backend_cfg) in &config.backends {
            if self.instances.contains_key(instance_name) {
                return Err(anyhow!("backend instance '{instance_name}' is already registered"));
            }
            let factory = self.factories.get(&backend_cfg.backend_type).ok_or_else(|| {
                anyhow!(
                    "no factory registered for backend type '{}' (required by instance '{}')",
                    backend_cfg.backend_type,
                    instance_name
                )
            })?;
            let instance = factory
                .create(instance_name, &backend_cfg.raw_fields)
                .with_context(|| {
                    format!(
                        "failed to build backend instance '{instance_name}' of type '{}'",
                        backend_cfg.backend_type
                    )
                })?;
            self.instances.insert(instance_name.clone(), instance);
        }
        Ok(())
    }

    /// Look up a live backend instance by its instance name (which is
    /// also its URI scheme).
    #[must_use]
    pub fn get(&self, instance_name: &str) -> Option<&dyn Backend> {
        self.instances.get(instance_name).map(AsRef::as_ref)
    }

    /// Iterate all live backend instances. Iteration order is
    /// unspecified — callers that need determinism (e.g. `doctor`
    /// output) should sort by
    /// [`Backend::instance_name`](Backend::instance_name).
    pub fn all(&self) -> impl Iterator<Item = &dyn Backend> + '_ {
        self.instances.values().map(AsRef::as_ref)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::config::BackendConfig;
    use crate::{BackendStatus, BackendUri};

    struct FakeBackend {
        backend_type: String,
        instance_name: String,
    }

    #[async_trait]
    impl Backend for FakeBackend {
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
            Ok(0)
        }
        async fn get(&self, _: &BackendUri) -> Result<String> {
            Ok("fake-value".into())
        }
        async fn set(&self, _: &BackendUri, _: &str) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &BackendUri) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: &BackendUri) -> Result<Vec<(String, String)>> {
            Ok(vec![])
        }
    }

    struct FakeFactory(&'static str);

    impl BackendFactory for FakeFactory {
        fn backend_type(&self) -> &str {
            self.0
        }
        fn create(
            &self,
            instance_name: &str,
            _: &HashMap<String, toml::Value>,
        ) -> Result<Box<dyn Backend>> {
            Ok(Box::new(FakeBackend {
                backend_type: self.0.to_owned(),
                instance_name: instance_name.to_owned(),
            }))
        }
    }

    fn sample_config(instances: &[(&str, &str)]) -> Config {
        Config {
            backends: instances
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
            ..Default::default()
        }
    }

    #[test]
    fn new_registry_is_empty() {
        let reg = BackendRegistry::new();
        assert!(reg.get("anything").is_none());
        assert_eq!(reg.all().count(), 0);
    }

    #[test]
    fn dispatches_by_instance_name_after_load() {
        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(FakeFactory("fake-a")));
        reg.register_factory(Box::new(FakeFactory("fake-b")));
        let config = sample_config(&[("prod", "fake-a"), ("dev", "fake-b")]);
        reg.load_from_config(&config).unwrap();

        assert_eq!(reg.get("prod").unwrap().backend_type(), "fake-a");
        assert_eq!(reg.get("dev").unwrap().backend_type(), "fake-b");
        assert!(reg.get("missing").is_none());
        assert_eq!(reg.all().count(), 2);
    }

    #[test]
    fn load_errors_when_backend_type_has_no_factory() {
        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(FakeFactory("fake")));
        let config = sample_config(&[("prod", "unregistered-type")]);
        let err = reg.load_from_config(&config).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unregistered-type"), "missing type in error: {msg}");
        assert!(msg.contains("prod"), "missing instance name in error: {msg}");
    }

    #[test]
    fn load_errors_on_duplicate_instance() {
        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(FakeFactory("fake")));
        let config = sample_config(&[("prod", "fake")]);
        reg.load_from_config(&config).unwrap();
        let err = reg.load_from_config(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("prod"));
        assert!(msg.contains("already registered"));
    }

    #[test]
    fn register_factory_last_wins_on_duplicate_type() {
        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(FakeFactory("fake")));
        reg.register_factory(Box::new(FakeFactory("fake")));
        let config = sample_config(&[("prod", "fake")]);
        reg.load_from_config(&config).unwrap();
        assert!(reg.get("prod").is_some());
    }

    #[test]
    fn instance_exposes_backend_type_and_instance_name() {
        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(FakeFactory("fake")));
        let config = sample_config(&[("prod-instance", "fake")]);
        reg.load_from_config(&config).unwrap();
        let b = reg.get("prod-instance").unwrap();
        assert_eq!(b.backend_type(), "fake");
        assert_eq!(b.instance_name(), "prod-instance");
    }

    #[test]
    fn factory_create_error_is_context_chained() {
        struct ExplodingFactory(&'static str);
        impl BackendFactory for ExplodingFactory {
            fn backend_type(&self) -> &str {
                self.0
            }
            fn create(
                &self,
                _instance_name: &str,
                _config: &HashMap<String, toml::Value>,
            ) -> Result<Box<dyn Backend>> {
                Err(anyhow!("missing required field 'region'"))
            }
        }

        let mut reg = BackendRegistry::new();
        reg.register_factory(Box::new(ExplodingFactory("boom")));
        let config = sample_config(&[("prod", "boom")]);
        let err = reg.load_from_config(&config).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("prod"), "instance name should be in context: {msg}");
        assert!(msg.contains("boom"), "backend type should be in context: {msg}");
        assert!(msg.contains("missing required field 'region'"), "root cause preserved: {msg}");
    }
}
