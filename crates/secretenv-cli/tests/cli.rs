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
fn doctor_human_output_lists_local_backend_as_ok() {
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Backends (1 configured)"))
        .stdout(predicate::str::contains("local [local]"))
        .stdout(predicate::str::contains("✓ ready"))
        .stdout(predicate::str::contains("Summary: 1/1 OK"));
}

#[test]
fn doctor_json_output_has_stable_schema() {
    let (dir, config) = full_fixture();
    let output = secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "doctor --json should exit 0 on happy path");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["summary"]["total"], 1);
    assert_eq!(parsed["summary"]["ok"], 1);
    let b = &parsed["backends"][0];
    assert_eq!(b["instance_name"], "local");
    assert_eq!(b["backend_type"], "local");
    assert_eq!(b["status"], "ok");
}

#[test]
fn setup_writes_config_for_local_backend() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let registry = dir.path().join("registry.toml");
    write_file(&registry, ""); // empty registry doc is a valid TOML map
    let registry_uri = format!("local://{}", registry.to_str().unwrap());

    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", &registry_uri, "--skip-doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote config"));

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(written.contains("[registries.default]"), "has registries: {written}");
    assert!(written.contains("[backends.local]"), "has backend block: {written}");
    assert!(written.contains("type = \"local\""));
}

#[test]
fn setup_aws_ssm_requires_region() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", "aws-ssm-prod:///prod/reg", "--skip-doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--region"));
    assert!(!config_path.exists(), "no config written on validation failure");
}

#[test]
fn setup_aws_ssm_writes_region_and_profile() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args([
            "setup",
            "aws-ssm-prod:///prod/reg",
            "--region",
            "us-east-1",
            "--profile",
            "prod",
            "--skip-doctor",
        ])
        .assert()
        .success();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(written.contains("[backends.aws-ssm-prod]"));
    assert!(written.contains("type = \"aws-ssm\""));
    assert!(written.contains("aws_region = \"us-east-1\""));
    assert!(written.contains("aws_profile = \"prod\""));
}

#[test]
fn setup_refuses_to_overwrite_without_force() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    write_file(&config_path, "# existing config, do not clobber\n");

    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", "local:///tmp/r.toml", "--skip-doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));

    let still_there = std::fs::read_to_string(&config_path).unwrap();
    assert!(still_there.contains("existing config"), "file unchanged: {still_there}");
}

#[test]
fn setup_force_overwrites_existing_config() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let registry = dir.path().join("registry.toml");
    write_file(&config_path, "# will be replaced\n");
    write_file(&registry, "");
    let registry_uri = format!("local://{}", registry.to_str().unwrap());

    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", &registry_uri, "--force", "--skip-doctor"])
        .assert()
        .success();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(!written.contains("will be replaced"));
    assert!(written.contains("[registries.default]"));
}

#[test]
fn setup_written_config_is_usable_by_resolve() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let registry = dir.path().join("registry.toml");
    let secret_path = dir.path().join("secret.toml");

    // Populate the registry with one alias pointing at a local secret file.
    write_file(&registry, &format!("stripe-key = \"local://{}\"\n", secret_path.to_str().unwrap()));
    write_file(&secret_path, "value");
    let registry_uri = format!("local://{}", registry.to_str().unwrap());

    // Phase 1: setup writes the config.
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", &registry_uri, "--skip-doctor"])
        .assert()
        .success();

    // Phase 2: resolve against the just-written config.
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["resolve", "stripe-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("local://"));
}

#[test]
fn setup_rejects_unknown_scheme() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    // `gcp-prod://` is a genuinely-unknown scheme post-Phase-5 (vault
    // now maps to the vault backend). Use gcp as the stand-in for
    // "a scheme we don't support yet".
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", "gcp-prod:///secrets/reg", "--skip-doctor"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown backend scheme"));
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
