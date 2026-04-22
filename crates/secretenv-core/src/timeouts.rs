// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-operation timeout wrappers for backend calls.
//!
//! Every backend op (`get`, `list`, `check`, `set`, `delete`) shells out
//! to a native CLI. Without a deadline, a misconfigured profile, a slow
//! SSO flow, or a network partition keeps the parent process alive — and
//! (for `get`) keeps secrets resident in the pre-`exec()` memory window
//! — indefinitely. This module supplies a uniform `with_timeout` helper
//! that call sites wrap around each backend future.
//!
//! Default durations are conservative enough to never fire in normal
//! local-dev use but tight enough that `doctor` cannot hang CI. Future
//! work (tracked in the v0.2 build plan) will let
//! `[backends.<name>].timeout_secs` in `config.toml` override per
//! instance.
//!
//! Part of Phase 0.5 security preflight (review finding CV-5).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};

/// Default timeout for secret fetches (`get` + `list`). Generous enough
/// to cover a slow SSO refresh on a fresh login but short enough that a
/// wedged network surfaces quickly.
pub const DEFAULT_GET_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for health probes (`check`). Tighter than the fetch
/// timeout because `doctor` hitting N backends in parallel pays the
/// slowest-backend cost and must not stall CI.
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Await `future`, failing with a descriptive error if the given
/// duration elapses first.
///
/// `op_label` appears in the timeout error (e.g. `"aws-ssm-prod::get"`)
/// — use `<instance>::<op>` so messages are greppable across logs.
///
/// # Errors
/// - `Err` with a timeout message if the deadline fires. The future is
///   dropped — for `tokio::process::Command` children this causes
///   `SIGKILL` via the Child destructor, releasing the process cleanly.
/// - Propagates any `Err` from the inner future, unchanged aside from
///   an added context line naming the op.
pub async fn with_timeout<T, F>(duration: Duration, op_label: &str, future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(inner) => inner.with_context(|| op_label.to_owned()),
        Err(_elapsed) => Err(anyhow!(
            "{op_label} timed out after {}s (set [backends.<name>].timeout_secs in \
             config.toml to override)",
            duration.as_secs()
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn future_completes_before_timeout() {
        let result: Result<u32> =
            with_timeout(Duration::from_millis(500), "test::op", async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn error_from_inner_future_propagates() {
        let result: Result<u32> = with_timeout(Duration::from_millis(500), "test::op", async {
            Err(anyhow!("backend exploded"))
        })
        .await;
        let err = result.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("backend exploded"), "root error preserved: {msg}");
        assert!(msg.contains("test::op"), "op label added as context: {msg}");
    }

    #[tokio::test]
    async fn timeout_produces_descriptive_error() {
        let result: Result<()> = with_timeout(Duration::from_millis(50), "slow::op", async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("slow::op"), "timeout error names op: {msg}");
        assert!(msg.contains("timed out"), "timeout error has 'timed out' text: {msg}");
        assert!(msg.contains("0s") || msg.contains("timeout_secs"), "hints at override: {msg}");
    }

    #[tokio::test]
    async fn timeout_drops_the_inner_future() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let _: Result<()> = with_timeout(Duration::from_millis(20), "slow::op", async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            completed_clone.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
        // Small grace period so the dropped future's timer can complete
        // if it was *not* actually dropped.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!completed.load(Ordering::SeqCst), "inner future should be dropped on timeout");
    }
}
