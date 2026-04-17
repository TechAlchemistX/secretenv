//! Integration tests that invoke the `secretenv` binary as a subprocess.
//!
//! Each test builds a self-contained tempdir with a `config.toml`, a
//! `secretenv.toml`, and (where applicable) a registry document on the
//! local filesystem. The tests use `assert_cmd` to spawn the binary
//! and assert on stdout/stderr/exit code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Write a file and return its absolute path.
fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

/// Set up a tempdir with config.toml, secretenv.toml, and a local
/// registry document. Returns the tempdir (keep it alive for the
/// duration of the test) plus the absolute config.toml path.
fn full_fixture() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let registry_path = dir.path().join("registry.toml");
    let config_path = dir.path().join("config.toml");
    let manifest_path = dir.path().join("secretenv.toml");
    let secret_path = dir.path().join("secret.toml");

    // Registry: one alias pointing at a local file.
    write_file(
        &registry_path,
        &format!("stripe-key = \"local://{}\"\n", secret_path.to_str().unwrap()),
    );

    // The actual "secret" that the alias resolves to. `local://` backend
    // returns the whole file contents as the value.
    write_file(&secret_path, "super-secret-value");

    // config.toml — one registry, one backend instance (local).
    write_file(
        &config_path,
        &format!(
            "[registries.default]\n\
             sources = [\"local://{reg}\"]\n\
             \n\
             [backends.local]\n\
             type = \"local\"\n",
            reg = registry_path.to_str().unwrap()
        ),
    );

    // secretenv.toml — one alias + one default.
    write_file(
        &manifest_path,
        "[secrets]\n\
         STRIPE = { from = \"secretenv://stripe-key\" }\n\
         LOG_LEVEL = { default = \"debug\" }\n",
    );

    let config_str = config_path.to_str().unwrap().to_owned();
    (dir, config_str)
}

fn secretenv() -> Command {
    let mut cmd = Command::cargo_bin("secretenv").unwrap();
    // Always start with SECRETENV_REGISTRY unset so tests are
    // deterministic regardless of developer env.
    cmd.env_remove("SECRETENV_REGISTRY");
    cmd
}

// ---- --version + --help ----

#[test]
fn version_flag_prints_version_and_exits_zero() {
    secretenv().arg("--version").assert().success().stdout(predicate::str::contains("secretenv"));
}

#[test]
fn help_flag_prints_subcommands() {
    secretenv()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("registry"))
        .stdout(predicate::str::contains("resolve"));
}

// ---- run: missing manifest ----

#[test]
fn run_errors_when_no_manifest_exists() {
    let dir = TempDir::new().unwrap();
    // Write an empty but valid config.toml so the error surfaces
    // from manifest loading, not config loading.
    let config_path = dir.path().join("config.toml");
    write_file(&config_path, "");
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("secretenv.toml"));
}

// ---- resolve ----

#[test]
fn resolve_prints_backend_uri_for_alias() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["resolve", "stripe-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("local://"));
}

#[test]
fn resolve_errors_on_unknown_alias() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["resolve", "not-in-registry"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not-in-registry"));
}

// ---- registry list ----

#[test]
fn registry_list_prints_aliases() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["registry", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stripe-key"))
        .stdout(predicate::str::contains("local://"));
}

// ---- registry get ----

#[test]
fn registry_get_prints_single_uri() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["registry", "get", "stripe-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("local://"));
}

// ---- run --dry-run ----

#[test]
fn run_dry_run_prints_alias_to_uri_mapping() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["run", "--dry-run", "--", "true"])
        .assert()
        .success()
        // The Uri-backed secret becomes "KEY ← uri".
        .stdout(predicate::str::contains("STRIPE"))
        .stdout(predicate::str::contains("local://"))
        // The Default-backed secret becomes "KEY = value (default)".
        .stdout(predicate::str::contains("LOG_LEVEL"))
        .stdout(predicate::str::contains("debug"));
}

// ---- no-registry error ----

#[test]
fn run_errors_when_no_registry_configured_and_no_flag() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let manifest_path = dir.path().join("secretenv.toml");

    // Config with NO registries — only a backend instance.
    write_file(&config_path, "[backends.local]\ntype = \"local\"\n");
    write_file(&manifest_path, "[secrets]\nK = { default = \"v\" }\n");

    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--registry"));
}

// ---- doctor + setup stubs ----

#[test]
fn doctor_stub_reports_phase_10() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .arg("doctor")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Phase 10"));
}

#[test]
fn setup_stub_reports_phase_11() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["setup", "local:///tmp/new-registry.toml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Phase 11"));
}

// ---- run happy path: exec-replace printenv ----

#[test]
fn run_execs_with_secrets_injected_as_env_vars() {
    let (dir, config) = full_fixture();
    // Use `sh -c` to check both env vars are present. `printenv X && printenv Y`
    // succeeds only when both are set.
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["run", "--", "sh", "-c", "echo STRIPE=$STRIPE; echo LOG_LEVEL=$LOG_LEVEL"])
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE=super-secret-value"))
        .stdout(predicate::str::contains("LOG_LEVEL=debug"));
}
