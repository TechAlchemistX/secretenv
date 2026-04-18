//! Shared test harness for SecretEnv backend crates.
//!
//! The only public surface today is [`install_mock`] — the POSIX-shell
//! script-writer with the ETXTBSY workaround every backend crate's
//! `tests` module used to duplicate. Two convenience wrappers,
//! [`install_mock_aws`] and [`install_mock_op`], exist because they
//! appeared verbatim in three separate locations before this crate.
//!
//! # Why this crate is unpublished
//!
//! The API is used by `secretenv-backend-aws-ssm`,
//! `secretenv-backend-1password`, and `secretenv-cli`'s e2e tests as
//! of v0.2. That's two backends + one CLI — enough to dedupe, not
//! enough to claim the shape is final. The moment Phase 5's Vault
//! backend or Phase 6's AWS Secrets Manager backend lands, the shape
//! gets re-examined. If it holds, v0.3 can publish.
//!
//! # Why probe-before-return
//!
//! On Linux, a file just created + chmodded by thread A can return
//! `ETXTBSY` (errno 26) from thread B's `execve` while the kernel
//! finishes closing the write fd. In serial tests this window is
//! invisible; under cargo's parallel test runner it surfaces on CI
//! reliably. The probe loop spin-waits up to ~500 ms for the
//! executable to be invocable before returning. macOS doesn't have
//! the race — the probe is a no-op there.
//!
//! # Non-goals for v0.2
//!
//! - No `MockCli` builder pattern with per-argv matchers. Existing
//!   callers write `#!/bin/sh ... if [ "$1 $2" = "ssm get-parameter" ]; then ...`
//!   inline in the test body and that works well. A higher-level
//!   matcher DSL would add API surface without removing real friction.
//! - No PATH-prepend helper. The `secretenv-cli` e2e tests that need
//!   that keep their local `secretenv_with_mock` builder — it's
//!   three lines of `env("PATH", ...)` and lives where it's used.

#![allow(clippy::module_name_repetitions)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Write a POSIX shell script to `dir/<bin_name>`, make it
/// executable, probe-retry past the Linux ETXTBSY race, and return
/// the path to the installed script.
///
/// `body` is the script body; the function prepends `#!/bin/sh\n`
/// and appends a trailing newline.
///
/// # Panics
///
/// Panics on any filesystem failure (file create, write, chmod).
/// Test helpers are expected to fail loudly on environmental
/// breakage — a silently-swallowed failure would only surface as a
/// mysterious downstream assertion.
#[must_use]
pub fn install_mock(dir: &Path, bin_name: &str, body: &str) -> PathBuf {
    use std::io::Write as _;

    let path = dir.join(bin_name);
    let full = format!("#!/bin/sh\n{body}\n");
    {
        // Explicit block so the write fd closes deterministically
        // before chmod — `sync_all` + drop is load-bearing for the
        // ETXTBSY workaround below.
        let mut f = std::fs::File::create(&path)
            .unwrap_or_else(|e| panic!("creating mock at {}: {e}", path.display()));
        f.write_all(full.as_bytes())
            .unwrap_or_else(|e| panic!("writing mock at {}: {e}", path.display()));
        f.sync_all().unwrap_or_else(|e| panic!("syncing mock at {}: {e}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod 0o755 on {}: {e}", path.display()));
    }
    // Probe-until-executable: retry up to ~500 ms to let any stale
    // write fd in the kernel's books clear. ETXTBSY == 26 on Linux.
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

/// Convenience wrapper: `install_mock(dir, "aws", body)`.
#[must_use]
pub fn install_mock_aws(dir: &Path, body: &str) -> PathBuf {
    install_mock(dir, "aws", body)
}

/// Convenience wrapper: `install_mock(dir, "op", body)`.
#[must_use]
pub fn install_mock_op(dir: &Path, body: &str) -> PathBuf {
    install_mock(dir, "op", body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn installed_mock_is_executable_and_runs_the_script_body() {
        let dir = TempDir::new().unwrap();
        // Raw hashes here are needed — the double-quote inside the
        // script body would terminate a plain raw string early.
        let path = install_mock(dir.path(), "hello", r#"echo "hello $1""#);
        let output = std::process::Command::new(&path).arg("world").output().expect("spawn mock");
        assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "hello world");
    }

    #[test]
    fn install_mock_aws_and_op_place_scripts_at_expected_names() {
        let dir = TempDir::new().unwrap();
        let aws = install_mock_aws(dir.path(), "echo aws-out");
        let op = install_mock_op(dir.path(), "echo op-out");
        assert_eq!(aws.file_name().and_then(|s| s.to_str()), Some("aws"));
        assert_eq!(op.file_name().and_then(|s| s.to_str()), Some("op"));
        // Both actually invoke.
        let aws_out = std::process::Command::new(&aws).output().unwrap();
        let op_out = std::process::Command::new(&op).output().unwrap();
        assert_eq!(String::from_utf8(aws_out.stdout).unwrap().trim(), "aws-out");
        assert_eq!(String::from_utf8(op_out.stdout).unwrap().trim(), "op-out");
    }

    #[cfg(unix)]
    #[test]
    fn installed_mock_has_0o755_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = install_mock(dir.path(), "perms", "true");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "expected 0o755, got 0o{mode:o}");
    }

    /// Two separate mock installs side-by-side should not collide —
    /// documenting the common "install aws + op in one tempdir" usage.
    #[test]
    fn multiple_mocks_coexist_in_one_tempdir() {
        let dir = TempDir::new().unwrap();
        let a = install_mock(dir.path(), "alpha", "echo a");
        let b = install_mock(dir.path(), "beta", "echo b");
        assert!(a.exists() && b.exists());
        let ao = std::process::Command::new(&a).output().unwrap();
        let bo = std::process::Command::new(&b).output().unwrap();
        assert_eq!(String::from_utf8(ao.stdout).unwrap().trim(), "a");
        assert_eq!(String::from_utf8(bo.stdout).unwrap().trim(), "b");
    }
}
