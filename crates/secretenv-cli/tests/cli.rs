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
fn resolve_prints_full_report_with_alias_and_env_var_and_source() {
    // Phase 8: resolve emits tabular metadata — alias, env var,
    // resolved URI, cascade source, backend status. The fixture's
    // manifest maps `STRIPE = { from = "secretenv://stripe-key" }`,
    // so env var reverse-lookup should find STRIPE.
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["resolve", "stripe-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alias:      stripe-key"))
        .stdout(predicate::str::contains("env var:    STRIPE"))
        .stdout(predicate::str::contains("resolved:   local://"))
        .stdout(predicate::str::contains("source:"))
        .stdout(predicate::str::contains("cascade layer 0"))
        .stdout(predicate::str::contains("backend:"))
        .stdout(predicate::str::contains("local instance 'local'"));
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
        .stderr(predicate::str::contains("not-in-registry"))
        // Spec: error lists the sources checked.
        .stderr(predicate::str::contains("registry cascade"));
}

#[test]
fn resolve_json_output_has_documented_schema() {
    // Phase 8: --json emits a structured shape for editor/IDE consumers.
    let (dir, config) = full_fixture();
    let out = secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["resolve", "stripe-key", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(parsed["alias"], "stripe-key");
    assert_eq!(parsed["env_var"], "STRIPE");
    assert!(parsed["resolved"].as_str().unwrap().contains("local://"));
    assert_eq!(parsed["source"]["layer"], 0);
    assert!(parsed["source"]["uri"].is_string());
    assert_eq!(parsed["backend"]["backend_type"], "local");
    assert_eq!(parsed["backend"]["instance"], "local");
    // Local backend has no CLI so its check returns BackendStatus::Ok
    // unconditionally — status should be "ok" in the JSON.
    assert_eq!(parsed["backend"]["status"], "ok");
}

#[test]
fn resolve_env_var_is_null_when_alias_unused_in_manifest() {
    // Registry has two aliases but manifest only uses one. Resolving
    // the unused alias should still succeed; env_var shows (none) /
    // null because no secrets entry references it.
    let dir = TempDir::new().unwrap();
    let registry_path = dir.path().join("registry.toml");
    let config_path = dir.path().join("config.toml");
    let manifest_path = dir.path().join("secretenv.toml");
    let secret_path = dir.path().join("secret.toml");

    // Registry with TWO aliases — STRIPE uses one, the other is
    // unreferenced by the manifest.
    write_file(
        &registry_path,
        &format!(
            "stripe-key = \"local://{secret}\"\n\
             orphan-key = \"local://{secret}\"\n",
            secret = secret_path.to_str().unwrap()
        ),
    );
    write_file(&secret_path, "v");
    write_file(
        &config_path,
        &format!(
            "[registries.default]\nsources = [\"local://{reg}\"]\n\n[backends.local]\ntype = \"local\"\n",
            reg = registry_path.to_str().unwrap()
        ),
    );
    write_file(&manifest_path, "[secrets]\nSTRIPE = { from = \"secretenv://stripe-key\" }\n");

    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["resolve", "orphan-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alias:      orphan-key"))
        .stdout(predicate::str::contains("env var:    (none)"));
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
fn doctor_renders_registries_section_with_per_source_status() {
    // Phase 9: the Registries section shows per-source reachability.
    // Our full_fixture has `[registries.default]` with one local:/// source.
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Registries (1 configured)"))
        .stdout(predicate::str::contains("default"))
        // Local backend is always Ok, so the source renders with ✓.
        .stdout(predicate::str::contains("✓ local://"))
        .stdout(predicate::str::contains("reachable"));
}

#[test]
fn doctor_json_includes_registries_key_with_sources_array() {
    let (dir, config) = full_fixture();
    let output = secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap();
    let registries = parsed["registries"].as_array().expect("registries array");
    assert_eq!(registries.len(), 1);
    assert_eq!(registries[0]["name"], "default");
    let sources = registries[0]["sources"].as_array().expect("sources array");
    assert_eq!(sources.len(), 1);
    let src = &sources[0];
    assert!(src["uri"].as_str().unwrap().starts_with("local://"));
    assert_eq!(src["status"], "ok");
}

#[test]
fn doctor_extensive_renders_depth_probe_for_local_backend() {
    // Phase 1 (v0.4): --extensive runs check_extensive() against each
    // registry source served by an Ok backend. The local backend
    // returns the alias count (1 in the fixture) via the trait
    // default. Both human and JSON output should reflect it.
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--extensive"])
        .assert()
        .success()
        .stdout(predicate::str::contains("depth probe (1 source)"))
        .stdout(predicate::str::contains("1 alias readable"));
}

#[test]
fn doctor_extensive_json_includes_depth_array() {
    let (dir, config) = full_fixture();
    let output = secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--extensive", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "doctor --extensive --json should exit 0");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8(output.stdout).unwrap()).unwrap();
    let depth = parsed["backends"][0]["depth"].as_array().expect("depth array");
    assert_eq!(depth.len(), 1);
    assert_eq!(depth[0]["depth_status"], "read");
    assert_eq!(depth[0]["entry_count"], 1);
}

#[test]
fn doctor_fix_is_a_noop_when_all_backends_already_ok() {
    // The local backend always reports Ok, so --fix has nothing to
    // remediate. Exit must still be 0; the report should NOT show a
    // "Remediation actions" section because no actions were taken.
    let (dir, config) = full_fixture();
    let output = secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--fix"])
        .output()
        .unwrap();
    assert!(output.status.success(), "doctor --fix on healthy fixture should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("Remediation actions"), "no actions taken → no section: {stdout}");
    assert!(stdout.contains("✓ ready"));
}

#[test]
fn doctor_fix_extensive_compose_cleanly() {
    // The two flags should compose: nothing to remediate (all-Ok
    // fixture), depth probe still runs and reports counts.
    let (dir, config) = full_fixture();
    secretenv()
        .current_dir(dir.path())
        .args(["--config", &config])
        .args(["doctor", "--fix", "--extensive"])
        .assert()
        .success()
        .stdout(predicate::str::contains("depth probe"))
        .stdout(predicate::str::contains("1 alias readable"));
}

#[test]
fn doctor_help_lists_fix_and_extensive_flags() {
    // Surface-level locking — clap's --help output should advertise
    // the v0.4 Phase 1 additions so users discover them. Catches
    // accidental rename / removal regressions.
    secretenv()
        .args(["doctor", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--fix"))
        .stdout(predicate::str::contains("--extensive"));
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
    // Post v0.3 Phase 2 all in-spec schemes route (local, aws-ssm,
    // aws-secrets, 1password, vault, gcp, azure). `totally-made-up`
    // is deliberately outside the router — any future backend should
    // NOT reuse this exact scheme so the test stays valid.
    secretenv()
        .current_dir(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .args(["setup", "totally-made-up:///secrets/reg", "--skip-doctor"])
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

// ---- completions (Phase 7) ----------------------------------------------

#[test]
fn completions_zsh_emits_script_with_secretenv_completion_function() {
    // Zsh clap output defines `_secretenv` as the completion function
    // name. If the binary name ever changed, this would need updating.
    let out = secretenv().args(["completions", "zsh"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(!stdout.is_empty(), "zsh completion script should not be empty");
    assert!(
        stdout.contains("_secretenv"),
        "zsh script should define _secretenv function; got:\n{stdout}"
    );
}

#[test]
fn completions_bash_emits_non_empty_script() {
    let out = secretenv().args(["completions", "bash"]).assert().success();
    let stdout = out.get_output().stdout.clone();
    assert!(!stdout.is_empty(), "bash completion script should not be empty");
    let s = String::from_utf8(stdout).unwrap();
    assert!(
        s.contains("complete") && s.contains("secretenv"),
        "bash output should reference `complete` + `secretenv`"
    );
}

#[test]
fn completions_fish_emits_non_empty_script() {
    let out = secretenv().args(["completions", "fish"]).assert().success();
    let stdout = out.get_output().stdout.clone();
    assert!(!stdout.is_empty(), "fish completion script should not be empty");
    let s = String::from_utf8(stdout).unwrap();
    assert!(s.contains("secretenv"), "fish output should mention `secretenv`");
}

#[test]
fn completions_output_flag_writes_file_with_mode_0o644() {
    let dir = TempDir::new().unwrap();
    let out_path = dir.path().join("_secretenv");
    secretenv()
        .args(["completions", "zsh", "--output", out_path.to_str().unwrap()])
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out_path).unwrap();
    assert!(contents.contains("_secretenv"), "file should contain the zsh completion function");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "expected 0o644, got 0o{mode:o}");
    }
}

#[test]
fn completions_rejects_unknown_shell() {
    // Clap emits exit code 2 on usage errors. `pwsh` is not in the
    // `Shell` value_enum, so the subcommand rejects it before any
    // handler runs.
    secretenv()
        .args(["completions", "pwsh"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid value"));
}
