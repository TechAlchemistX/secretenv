// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! Sec-M-2 / Arch-F-6 regression test (v0.18 Phase 1.4).
//!
//! `LocalTraceCapture::install` swaps the global `TracerProvider`.
//! v0.17 had no guard: a second `install()` call would silently
//! clobber the first, breaking observability for any span emitted
//! between the two installs. v0.18 introduces a module-level
//! `INSTALLED: AtomicBool` flag; a second `install()` while a
//! capture is still live returns
//! `Err(LocalTraceCaptureError::AlreadyInstalled)`.
//!
//! This test drives the failure mode directly: install one capture,
//! attempt a second install before dropping the first, assert the
//! second fails. Then drop the first and confirm a third install
//! succeeds (the guard is reset by `Drop`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use secretenv_telemetry::{LocalTraceCapture, LocalTraceCaptureError};

#[test]
fn double_install_returns_already_installed_error() {
    let first = LocalTraceCapture::install().expect("first install");

    let second = LocalTraceCapture::install();
    assert!(
        matches!(second, Err(LocalTraceCaptureError::AlreadyInstalled)),
        "second install while first is live must fail; got {second:?}"
    );

    // Drop the first capture — the Drop impl clears the
    // module-level guard so subsequent installs can proceed.
    drop(first);

    let third = LocalTraceCapture::install();
    assert!(
        third.is_ok(),
        "install must succeed after the previous capture was dropped; got {third:?}"
    );
}
