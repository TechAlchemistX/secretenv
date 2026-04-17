//! End-to-end integration tests — Phase 12.
//!
//! These tests drive the full `secretenv` binary through every
//! subcommand that matters, with real shell-based mocks of the `aws`
//! and `op` CLIs installed on a scoped `PATH`. Unlike the `cli.rs`
//! tests which only exercise the `local` backend (no shell-out), these
//! prove the wrapper-backend codepath end-to-end: parent spawns
//! `secretenv`, which spawns `aws`/`op`, which is our mock script.
//!
//! Mock-CLI harness pattern: the `install_mock_*` helpers write a
//! `#!/bin/sh` script to a tempdir, chmod 0o755, then probe-spawn in a
//! retry loop until `execve` succeeds (Linux ETXTBSY workaround
//! established in Phase 5). The helpers are copy-pasted from the
//! backend crates because they're in separate test modules; v0.2 is
//! the point to extract them into a shared `secretenv-testing` crate
//! (per the Phase 6 build-log note).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

// ---- Mock-CLI install helpers -----------------------------------------

/// Write a bash script to `dir/<bin_name>`, chmod +x, probe-retry until
/// `execve` succeeds (defeats Linux ETXTBSY race on parallel tests).
fn install_mock(dir: &TempDir, bin_name: &str, body: &str) -> PathBuf {
    let path = dir.path().join(bin_name);
    let full = format!("#!/bin/sh\n{body}\n");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(full.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        match std::process::Command::new(&path).arg("--probe").output() {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(_) | Err(_) => return path,
        }
    }
    path
}

fn install_mock_aws(dir: &TempDir, body: &str) -> PathBuf {
    install_mock(dir, "aws", body)
}

fn install_mock_op(dir: &TempDir, body: &str) -> PathBuf {
    install_mock(dir, "op", body)
}

// ---- Test fixture helpers ---------------------------------------------

/// Write a file and ensure parents exist.
fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// Build a `Command` for the `secretenv` binary with the mock dir
/// prepended to `PATH`, `SECRETENV_REGISTRY` scrubbed, and the given
/// fixture directory as CWD.
fn secretenv_with_mock(fixture: &Path, mock_dir: &Path) -> Command {
    let parent_path = std::env::var("PATH").unwrap_or_default();
    let injected = format!("{}:{}", mock_dir.display(), parent_path);
    let mut cmd = Command::cargo_bin("secretenv").unwrap();
    cmd.current_dir(fixture).env("PATH", injected).env_remove("SECRETENV_REGISTRY");
    cmd
}

// ---- Scenarios --------------------------------------------------------

/// Scenario 1: happy path end-to-end through mocked AWS SSM.
///
/// - Config names an `aws-ssm-prod` backend instance with region.
/// - Registry source is `aws-ssm-prod:///registries/shared` — mock
///   responds with a JSON alias→URI map.
/// - Alias `stripe-key` → `aws-ssm-prod:///prod/stripe` — mock
///   responds with the raw value `sk_live_abc`.
/// - secretenv.toml declares `STRIPE = { from = "secretenv://stripe-key" }`.
/// - `secretenv run -- sh -c 'echo $STRIPE'` prints `sk_live_abc`.
#[test]
fn ssm_mocked_run_injects_resolved_secret_into_child_env() {
    let mock_dir = TempDir::new().unwrap();
    install_mock_aws(
        &mock_dir,
        r#"
case "$*" in
  "--version"*)
    echo "aws-cli/2.15.17 Python/3.11.8 Darwin/23.0.0" ;;
  "sts "*)
    echo '{"UserId":"AIDA","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}' ;;
  "ssm get-parameter --with-decryption --name /registries/shared "*)
    echo '{"stripe-key":"aws-ssm-prod:///prod/stripe"}' ;;
  "ssm get-parameter --with-decryption --name /prod/stripe "*)
    echo "sk_live_abc" ;;
  *)
    echo "mock aws: unrecognized: $*" >&2
    exit 2 ;;
esac
"#,
    );

    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[registries.default]
sources = ["aws-ssm-prod:///registries/shared"]

[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
    );
    write(
        &fixture.path().join("secretenv.toml"),
        r#"
[secrets]
STRIPE = { from = "secretenv://stripe-key" }
"#,
    );

    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .args(["run", "--", "sh", "-c", "echo $STRIPE"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_live_abc"));
}

/// Scenario 2: the alias the manifest asks for isn't in the registry.
#[test]
fn ssm_mocked_missing_alias_errors_with_name() {
    let mock_dir = TempDir::new().unwrap();
    install_mock_aws(
        &mock_dir,
        r#"
case "$*" in
  "--version"*) echo "aws-cli/2.15.17" ;;
  "sts "*) echo '{"UserId":"A","Account":"1","Arn":"arn"}' ;;
  "ssm get-parameter --with-decryption --name /registries/shared "*)
    echo '{"other-alias":"aws-ssm-prod:///prod/other"}' ;;
  *) echo "mock aws: $*" >&2; exit 2 ;;
esac
"#,
    );

    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[registries.default]
sources = ["aws-ssm-prod:///registries/shared"]

[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
    );
    write(
        &fixture.path().join("secretenv.toml"),
        r#"
[secrets]
STRIPE = { from = "secretenv://stripe-key" }
"#,
    );

    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("stripe-key"))
        .stderr(predicate::str::contains("not found"));
}

/// Scenario 3: `aws sts` returns non-zero → `doctor` reports the
/// backend as `NotAuthenticated` and exits 1.
#[test]
fn doctor_flags_not_authenticated_when_sts_fails() {
    let mock_dir = TempDir::new().unwrap();
    install_mock_aws(
        &mock_dir,
        r#"
case "$*" in
  "--version"*) echo "aws-cli/2.15.17" ;;
  "sts "*)
    echo "Unable to locate credentials. You can configure credentials by running \"aws configure\"." >&2
    exit 255 ;;
  *) echo "mock aws: $*" >&2; exit 2 ;;
esac
"#,
    );

    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
    );

    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .arg("doctor")
        .assert()
        .failure()
        .stdout(predicate::str::contains("not authenticated"))
        .stdout(predicate::str::contains("Unable to locate credentials"));
}

/// Scenario 4: `--dry-run` fetches the registry document (needed to
/// know the alias set) but never fetches individual secret values.
///
/// Mock logs every `get-parameter` call to a side file; test asserts
/// exactly one call for the registry path and zero for the secret path.
#[test]
fn dry_run_fetches_registry_but_not_values() {
    let mock_dir = TempDir::new().unwrap();
    let call_log = mock_dir.path().join("calls.log");
    let call_log_str = call_log.to_str().unwrap().to_owned();

    install_mock_aws(
        &mock_dir,
        &format!(
            r#"
echo "$*" >> "{call_log_str}"
case "$*" in
  "--version"*) echo "aws-cli/2.15.17" ;;
  "sts "*) echo '{{"UserId":"A","Account":"1","Arn":"arn"}}' ;;
  "ssm get-parameter --with-decryption --name /registries/shared "*)
    echo '{{"stripe-key":"aws-ssm-prod:///prod/stripe"}}' ;;
  "ssm get-parameter --with-decryption --name /prod/stripe "*)
    echo "sk_live_abc" ;;
  *) echo "mock aws: $*" >&2; exit 2 ;;
esac
"#
        ),
    );

    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[registries.default]
sources = ["aws-ssm-prod:///registries/shared"]

[backends.aws-ssm-prod]
type = "aws-ssm"
aws_region = "us-east-1"
"#,
    );
    write(
        &fixture.path().join("secretenv.toml"),
        r#"
[secrets]
STRIPE = { from = "secretenv://stripe-key" }
"#,
    );

    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .args(["run", "--dry-run", "--", "true"])
        .assert()
        .success();

    let log = std::fs::read_to_string(&call_log).unwrap();
    let registry_hits = log.lines().filter(|l| l.contains("/registries/shared")).count();
    let value_hits = log.lines().filter(|l| l.contains("/prod/stripe")).count();
    assert_eq!(registry_hits, 1, "registry should be fetched exactly once:\n{log}");
    assert_eq!(value_hits, 0, "secret value must NOT be fetched in dry-run:\n{log}");
}

/// Scenario 5: a direct backend URI in `secretenv.toml` (anything
/// other than `secretenv://<alias>`) is rejected at manifest load —
/// the error surfaces before any network call.
#[test]
fn direct_backend_uri_in_manifest_is_rejected() {
    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[backends.local]
type = "local"
"#,
    );
    write(
        &fixture.path().join("secretenv.toml"),
        r#"
[secrets]
STRIPE = { from = "aws-ssm-prod:///prod/stripe" }
"#,
    );

    // No mocks needed — the failure happens before any backend is touched.
    let mock_dir = TempDir::new().unwrap();
    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .args(["run", "--registry", "local:///tmp/noop.toml", "--", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("direct backend URI"))
        .stderr(predicate::str::contains("STRIPE"));
}

/// Scenario 6: happy path through mocked `op` (1Password).
///
/// - Config declares `1password-personal` backend instance.
/// - Registry source is `1password-personal://Shared/Registry/body`
///   — mock returns a TOML registry document.
/// - Alias `api-key` → `1password-personal://Eng/API/key` — mock
///   returns the raw value `op_api_token_xyz`.
#[test]
fn op_mocked_run_injects_resolved_secret_into_child_env() {
    let mock_dir = TempDir::new().unwrap();
    install_mock_op(
        &mock_dir,
        r#"
case "$1" in
  --version) echo "2.30.0" ;;
  whoami)
    echo '{"url":"my.1password.com","email":"me@example.com"}' ;;
  read)
    # $2 is the op://vault/item/field URI.
    case "$2" in
      "op://Shared/Registry/body")
        cat <<'TOML'
api-key = "1password-personal://Eng/API/key"
TOML
        ;;
      "op://Eng/API/key")
        echo "op_api_token_xyz"
        ;;
      *)
        echo "mock op read: unknown URI: $2" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "mock op: unknown command: $*" >&2
    exit 2
    ;;
esac
"#,
    );

    let fixture = TempDir::new().unwrap();
    write(
        &fixture.path().join("config.toml"),
        r#"
[registries.default]
sources = ["1password-personal://Shared/Registry/body"]

[backends.1password-personal]
type = "1password"
"#,
    );
    write(
        &fixture.path().join("secretenv.toml"),
        r#"
[secrets]
API_KEY = { from = "secretenv://api-key" }
"#,
    );

    secretenv_with_mock(fixture.path(), mock_dir.path())
        .args(["--config", fixture.path().join("config.toml").to_str().unwrap()])
        .args(["run", "--", "sh", "-c", "echo $API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("op_api_token_xyz"));
}
