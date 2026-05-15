// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only
//
// Integration tests for `redact::scrub_file_in_place` — covers the
// real filesystem path that unit tests cannot exercise.

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::similar_names)]

use std::fs;
use std::io::Write;

use secretenv_core::redact::{
    scrub_file_in_place, Scrubber, SubstitutionToken, TaintedSet, TaintedValue,
};
use tempfile::TempDir;

fn taint_set(values: &[(&str, &str)]) -> TaintedSet {
    let mut set = TaintedSet::new();
    for (alias, val) in values {
        set.insert(TaintedValue::from_alias(*alias, *val));
    }
    set
}

#[test]
fn scrub_file_in_place_replaces_matches_atomically() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("build.log");
    {
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "fetching ... stripe=sk_live_abc123").unwrap();
        writeln!(f, "complete (key was sk_live_abc123)").unwrap();
    }

    let set = taint_set(&[("stripe-key", "sk_live_abc123")]);
    let scrubber =
        Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().expect("non-empty set");

    let rep = scrub_file_in_place(&path, &scrubber, None, false).unwrap();
    assert_eq!(rep.match_count, 2);
    assert_eq!(rep.byte_count, 14 + 14);

    let body = fs::read_to_string(&path).unwrap();
    assert!(body.contains("[redacted:stripe-key]"));
    assert!(!body.contains("sk_live_abc123"));
}

#[test]
fn scrub_file_in_place_writes_backup() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("build.log");
    let original = "secret=sk_live_abc123\n";
    fs::write(&path, original).unwrap();

    let set = taint_set(&[("k", "sk_live_abc123")]);
    let scrubber = Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
    let _ = scrub_file_in_place(&path, &scrubber, Some(".bak"), false).unwrap();

    let scrubbed = fs::read_to_string(&path).unwrap();
    assert_eq!(scrubbed, "secret=[redacted:k]\n");

    let backup_path = dir.path().join("build.log.bak");
    let backup = fs::read_to_string(&backup_path).unwrap();
    assert_eq!(backup, original);
}

#[test]
fn scrub_file_in_place_preserves_mode() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("readonly.log");
        fs::write(&path, "k=sk_live_abc123\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let set = taint_set(&[("k", "sk_live_abc123")]);
        let scrubber = Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let _ = scrub_file_in_place(&path, &scrubber, None, false).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode preserved across atomic rename");
    }
}

#[test]
fn scrub_file_in_place_refuses_proc() {
    let scrubber =
        Scrubber::new(&taint_set(&[("k", "sk_live_abc123")]), SubstitutionToken::AliasAware)
            .unwrap()
            .unwrap();
    let err =
        scrub_file_in_place(std::path::Path::new("/proc/self/cmdline"), &scrubber, None, false)
            .unwrap_err();
    assert!(format!("{err:#}").contains("/proc"));
}

#[test]
#[cfg(unix)]
fn scrub_file_in_place_refuses_symlink_target() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("real.log");
    let link = dir.path().join("via-symlink.log");
    fs::write(&target, "k=sk_live_abc123\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let set = taint_set(&[("k", "sk_live_abc123")]);
    let scrubber = Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
    let err = scrub_file_in_place(&link, &scrubber, None, false).unwrap_err();
    let msg = format!("{err:#}");
    // O_NOFOLLOW fires on the open call; the exact error string is
    // OS-dependent but always references the open or a system errno
    // mention.
    assert!(
        msg.contains("O_NOFOLLOW")
            || msg.contains("symbolic")
            || msg.contains("too many")
            || msg.contains("loop"),
        "expected symlink-rejection error, got: {msg}",
    );
}
