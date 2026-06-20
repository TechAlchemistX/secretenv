# Adding a New Backend

Every backend in secretenv is an independent Rust crate implementing the `Backend` trait. Adding a new backend never touches core.

A backend crate provides:

1. A **factory**: constructs named instances from raw config
2. A **backend implementation**: implements the `Backend` trait

All backends are compiled in. The core binary registers every factory unconditionally at startup; `[backends.<name>]` blocks in `config.toml` determine which are instantiated at runtime. The factory creates instances; the trait is all core ever calls.

---

## 1. Create the Crate

```bash
cd crates/backends
cargo new --lib backend-myservice
cd backend-myservice
```

Add to workspace `Cargo.toml`:

```toml
[workspace]
members = [
  "crates/backends/secretenv-backend-myservice",
  # ...existing members
]

[workspace.dependencies]
secretenv-backend-myservice = { path = "crates/backends/secretenv-backend-myservice" }
# ...existing pins
```

Add the crate manifest at `crates/backends/secretenv-backend-myservice/Cargo.toml` inheriting workspace metadata:

```toml
[package]
name        = "secretenv-backend-myservice"
description = "MyService backend for SecretEnv"
version.workspace      = true
edition.workspace      = true
license.workspace      = true
repository.workspace   = true
homepage.workspace     = true
authors.workspace      = true
rust-version.workspace = true
keywords.workspace     = true
categories.workspace   = true
readme.workspace       = true

[dependencies]
secretenv-core.workspace = true
anyhow.workspace         = true
async-trait.workspace    = true
tokio.workspace          = true

[dev-dependencies]
tempfile.workspace = true

[lints]
workspace = true
```

---

## 2. Implement the Backend

```rust
// crates/backends/secretenv-backend-myservice/src/lib.rs

use std::collections::HashMap;
use async_trait::async_trait;
use anyhow::{Context, Result};
use secretenv_core::{
    optional_string, required_string, Backend, BackendFactory, BackendStatus, BackendUri, Secret,
};

// ── Factory ──────────────────────────────────────────────────────────────────

pub struct MyServiceFactory;

impl BackendFactory for MyServiceFactory {
    fn backend_type(&self) -> &str {
        "myservice"
    }

    fn create(
        &self,
        instance_name: &str,
        config: &HashMap<String, toml::Value>,
    ) -> Result<Box<dyn Backend>> {
        let api_url = required_string(config, "api_url", "myservice", instance_name)?;
        let token_env =
            optional_string(config, "token_env", "myservice", instance_name)?
                .unwrap_or_else(|| "MYSERVICE_TOKEN".to_owned());

        Ok(Box::new(MyServiceBackend {
            instance_name: instance_name.to_owned(),
            api_url,
            token_env,
        }))
    }
}

// ── Backend ───────────────────────────────────────────────────────────────────

struct MyServiceBackend {
    instance_name: String,
    api_url: String,
    token_env: String,
}

#[async_trait]
impl Backend for MyServiceBackend {
    fn backend_type(&self) -> &str { "myservice" }
    fn instance_name(&self) -> &str { &self.instance_name }

    async fn check(&self) -> BackendStatus {
        // Level 1: is the CLI installed?
        let version_output = match tokio::process::Command::new("myservice-cli")
            .arg("--version")
            .output()
            .await
        {
            Err(_) => return BackendStatus::CliMissing {
                cli_name: "myservice-cli".into(),
                install_hint: "brew install myservice-cli  OR  https://myservice.example.com/cli".into(),
            },
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        };

        // Level 2: are we authenticated?
        let auth_output = tokio::process::Command::new("myservice-cli")
            .args(["whoami", "--json"])
            .output()
            .await;

        match auth_output {
            Err(e) => BackendStatus::Error { message: e.to_string() },
            Ok(out) if !out.status.success() => BackendStatus::NotAuthenticated {
                hint: format!(
                    "run: myservice-cli login  (or set {} env var for CI)",
                    self.token_env
                ),
            },
            Ok(out) => {
                let identity = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .to_string();
                BackendStatus::Ok {
                    cli_version: version_output,
                    identity,
                }
            }
        }
    }

    async fn check_extensive(&self, test_uri: &BackendUri) -> Result<usize> {
        // Attempt to list keys at the test URI path.
        // Return Ok(n) where n is the number of readable keys.
        let results = self.list(test_uri).await?;
        Ok(results.len())
    }

    async fn get(&self, uri: &BackendUri) -> Result<Secret<String>> {
        let output = tokio::process::Command::new("myservice-cli")
            .args(["secret", "get", &uri.path, "--output", "raw"])
            .output()
            .await
            .context("myservice-cli not found or failed to execute")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "myservice-cli failed for '{}' (instance: '{}'): {}",
                uri.raw,
                self.instance_name,
                stderr.trim()
            );
        }

        Ok(Secret::new(
            String::from_utf8(output.stdout)
                .context("myservice returned non-UTF8 output")?
                .trim()
                .to_string(),
        ))
    }

    async fn set(&self, uri: &BackendUri, value: &str) -> Result<()> {
        let output = tokio::process::Command::new("myservice-cli")
            .args(["secret", "set", &uri.path, "--value", value])
            .output()
            .await
            .context("myservice-cli not found or failed to execute")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "myservice-cli set failed for '{}': {}",
                uri.raw,
                stderr.trim()
            );
        }

        Ok(())
    }

    async fn delete(&self, uri: &BackendUri) -> Result<()> {
        let output = tokio::process::Command::new("myservice-cli")
            .args(["secret", "delete", &uri.path])
            .output()
            .await
            .context("myservice-cli not found or failed to execute")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "myservice-cli delete failed for '{}': {}",
                uri.raw,
                stderr.trim()
            );
        }

        Ok(())
    }

    async fn list(&self, uri: &BackendUri) -> Result<Vec<(String, String)>> {
        let output = tokio::process::Command::new("myservice-cli")
            .args(["secret", "list", "--prefix", &uri.path, "--output", "json"])
            .output()
            .await
            .context("myservice-cli not found or failed to execute")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "myservice-cli list failed for '{}': {}",
                uri.raw,
                stderr.trim()
            );
        }

        // Parse the JSON response into Vec<(key, value)>
        let text = String::from_utf8(output.stdout)?;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        Ok(parsed
            .into_iter()
            .filter_map(|v| {
                let key = v["key"].as_str()?.to_string();
                let val = v["value"].as_str()?.to_string();
                Some((key, val))
            })
            .collect())
    }
}
```

---

## 3. Register at Startup

In `crates/secretenv-backends-init/src/lib.rs`, add your factory to the registration list, unconditionally, alongside the other backends:

```rust
pub fn build_registry(config: &Config) -> Result<BackendRegistry> {
    let mut registry = BackendRegistry::new();
    registry.register_factory(Box::new(secretenv_backend_local::LocalFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_aws_ssm::AwsSsmFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_1password::OnePasswordFactory::new()));
    registry.register_factory(Box::new(secretenv_backend_myservice::MyServiceFactory::new())); // ← your line
    registry.load_from_config(config)?;
    Ok(registry)
}
```

Also add the path dep to `crates/secretenv-backends-init/Cargo.toml`:

```toml
secretenv-backend-myservice.workspace = true
```

---

## 4. Write Tests

Add the shared `secretenv-testing` harness to test CLI mocks:

```toml
[dev-dependencies]
secretenv-testing.workspace = true
tempfile.workspace          = true
```

Call `install_mock` to drop a POSIX shell script on disk (ETXTBSY probe loop already handled):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_get_returns_value() {
        let dir = TempDir::new().unwrap();
        let mock = secretenv_testing::install_mock(
            dir.path(),
            "myservice",
            r#"
if [ "$1" = "secret" ] && [ "$2" = "get" ]; then
  echo "test-value"
  exit 0
fi
exit 1
            "#,
        );
        let backend = MyServiceBackend {
            instance_name: "myservice-test".into(),
            api_url: "https://myservice.example.com".into(),
            token_env: "MYSERVICE_TOKEN".into(),
            cli_bin: mock.to_string_lossy().into_owned(),
        };

        let uri = BackendUri::parse("myservice-test:///my/secret").unwrap();
        let result = backend.get(&uri).await.unwrap();
        assert_eq!(result.expose_secret(), "test-value");
    }
}
```

For well-known CLIs, `install_mock_aws` / `install_mock_op` exist as convenience wrappers. Add one in the shared crate if needed.

---

## Security Requirements

Non-negotiable. PRs that violate them will not be merged.

**1. Never use shell interpolation with URI-derived values.**

```rust
// ✅ Correct
Command::new("myservice-cli")
    .args(["secret", "get", &uri.path])

// ❌ Never, injectable
Command::new("sh")
    .arg("-c")
    .arg(format!("myservice-cli secret get {}", uri.path))
```

URI paths come from the registry. Compromised registries could inject shell commands. Argument passing prevents this structurally.

**2. Include instance name and URI in all error messages.**

```rust
// ✅ Correct
anyhow::bail!(
    "myservice-cli failed for '{}' (instance: '{}'): {}",
    uri.raw, self.instance_name, stderr.trim()
);

// ❌ Insufficient
anyhow::bail!("command failed: {}", stderr);
```

**3. Never log or print secret values.**

Debug, verbose, and error output must never include values from `get()`.

**4. Return `BackendStatus::CliMissing` with an install hint.**

Provide real, copy-pasteable install commands.

---

## Checklist Before Opening a PR

- [ ] Factory registered in `crates/secretenv-backends-init/src/lib.rs`
- [ ] All eight `Backend` trait methods implemented: `backend_type`, `instance_name`, `check`, `check_extensive`, `get`, `set`, `delete`, `list`
- [ ] `check()` implements Level 1 (CLI present) and Level 2 (authenticated)
- [ ] `check_extensive()` implemented
- [ ] All CLI calls use `.args()` with separate strings; no `sh -c`
- [ ] Error messages include instance name, `uri.raw`, and trimmed CLI stderr
- [ ] Tests via `secretenv-testing::install_mock` harness cover `get()` and `check()` success/failure
- [ ] `docs/backends/<your-backend>.md` written
- [ ] Path-dep added to `workspace.dependencies` and `crates/secretenv-backends-init/Cargo.toml`
- [ ] Crate name added to `deny.toml`'s AGPL exception list in same commit as `Cargo.toml`
- [ ] Crate added to `.github/workflows/release.yml` publish-crates in topological order

---

## Getting Help

Open a GitHub issue tagged `backend-development` before starting. This avoids duplicate effort and surfaces design considerations specific to the backend's CLI behavior.
