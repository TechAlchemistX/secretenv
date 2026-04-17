# Adding a New Backend

Every backend in secretenv is an independent Rust crate implementing a common trait. Adding a new backend never touches core. This guide walks through building one from scratch.

---

## Overview

A backend crate provides two things:

1. A **factory** — constructs named instances from raw config
2. A **backend implementation** — implements the `Backend` trait

The core binary wires factories at startup via Cargo feature flags. The factory creates instances from `config.toml` blocks. The trait is all core ever calls.

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
  "crates/backends/backend-myservice",
  # ...existing members
]

[features]
myservice = ["backend-myservice"]
```

Add dependencies to `crates/backends/backend-myservice/Cargo.toml`:

```toml
[package]
name = "backend-myservice"
version = "0.1.0"
edition = "2021"

[dependencies]
secretenv-core = { path = "../../secretenv-core" }
async-trait = "0.1"
anyhow = "1"
tokio = { version = "1", features = ["process"] }
```

---

## 2. Implement the Backend

```rust
// crates/backends/backend-myservice/src/lib.rs

use std::collections::HashMap;
use async_trait::async_trait;
use anyhow::{Context, Result};
use secretenv_core::{Backend, BackendFactory, BackendStatus, BackendUri};

// ── Factory ──────────────────────────────────────────────────────────────────

pub struct MyServiceFactory;

impl BackendFactory for MyServiceFactory {
    fn backend_type(&self) -> &str {
        "myservice"   // matches `type = "myservice"` in config.toml
    }

    fn create(
        &self,
        instance_name: &str,
        config: HashMap<String, String>,
    ) -> Result<Box<dyn Backend>> {
        // Validate and extract config fields here.
        // Return Err if required fields are missing.
        // Core surfaces the error with the instance name as context.
        let api_url = config
            .get("api_url")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(
                "backend '{}': missing required field 'api_url'", instance_name
            ))?;

        let token_env = config
            .get("token_env")
            .cloned()
            .unwrap_or_else(|| "MYSERVICE_TOKEN".to_string());

        Ok(Box::new(MyServiceBackend {
            instance_name: instance_name.to_string(),
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

    async fn get(&self, uri: &BackendUri) -> Result<String> {
        // CRITICAL: Always use .args() with separate strings.
        // Never use shell interpolation with uri.path.
        // This is a hard security requirement — see security docs.
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

        Ok(String::from_utf8(output.stdout)
            .context("myservice returned non-UTF8 output")?
            .trim()
            .to_string())
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

In `crates/secretenv-cli/src/main.rs`, add the feature-gated registration:

```rust
#[cfg(feature = "myservice")]
registry.register_factory(Box::new(backend_myservice::MyServiceFactory));
```

---

## 4. Write Tests

Each backend crate should have tests that mock the CLI binary. Use `assert_cmd` and a mock binary that returns known responses:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_returns_value() {
        // Use a mock CLI binary or environment variable to control output
        // See tests/mock_cli/ in the repository for the test harness
        let backend = MyServiceBackend {
            instance_name: "myservice-test".into(),
            api_url: "https://myservice.example.com".into(),
            token_env: "MYSERVICE_TOKEN".into(),
        };

        let uri = BackendUri::parse("myservice-test:///my/secret").unwrap();
        // With mock CLI returning "test-value":
        // let result = backend.get(&uri).await.unwrap();
        // assert_eq!(result, "test-value");
    }
}
```

---

## Security Requirements for Backend Authors

These are non-negotiable. PRs that violate them will not be merged.

**1. Never use shell interpolation with URI-derived values.**

```rust
// ✅ Correct — always
Command::new("myservice-cli")
    .args(["secret", "get", &uri.path])

// ❌ Never — injectable
Command::new("sh")
    .arg("-c")
    .arg(format!("myservice-cli secret get {}", uri.path))
```

The URI path comes from the alias registry. If the registry were compromised, a malicious path could inject shell commands. Argument passing prevents this structurally.

**2. Include the instance name and URI in all error messages.**

Users need to know which backend and which URI caused a failure. Raw CLI error messages without context make debugging impossible.

```rust
// ✅ Correct
anyhow::bail!(
    "myservice-cli failed for '{}' (instance: '{}'): {}",
    uri.raw, self.instance_name, stderr.trim()
);

// ❌ Not enough context
anyhow::bail!("command failed: {}", stderr);
```

**3. Never log or print secret values.**

Debug output, verbose output, and error messages must never include the actual value returned by `get()`.

**4. Return `BackendStatus::CliMissing` with an install hint.**

Users will encounter missing CLIs. The install hint should be a real, copy-pasteable command.

---

## Checklist Before Opening a PR

- [ ] Factory registered behind a Cargo feature flag
- [ ] All five `Backend` trait methods implemented
- [ ] `check()` implements both Level 1 (CLI present) and Level 2 (authenticated)
- [ ] `check_extensive()` implemented
- [ ] All CLI calls use `.args()` with separate strings — no `sh -c` with interpolation
- [ ] Error messages include instance name and URI
- [ ] Tests cover `get()`, `check()` success and failure cases
- [ ] `docs/backends/<your-backend>.md` written following the existing format
- [ ] Feature flag added to workspace `Cargo.toml`

---

## Getting Help

Open a GitHub issue tagged `backend-development` before starting work on a new backend. This avoids duplicate effort and lets maintainers flag any design considerations specific to that backend's CLI behavior before you've written the code.
