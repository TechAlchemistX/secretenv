// Copyright (C) 2026 Mandeep Patel
// SPDX-License-Identifier: AGPL-3.0-only

//! The redact engine — shared between mode A (runtime stdout/stderr
//! filter, in [`crate::runner`]) and mode B (post-hoc file scrubber,
//! invoked via the CLI's `secretenv redact <path>` subcommand).
//!
//! # Threat model
//!
//! The redact engine is a **defense-in-depth** layer, not a complete
//! protection — see `docs/security.md` for the Limits matrix. It
//! catches:
//!
//! - Application code that prints resolved env-var values to stdout
//!   (the `stripe=$STRIPE_KEY` echo pattern).
//! - Build logs / CI logs that capture command output.
//! - Post-hoc scrubbing of saved log files.
//!
//! It does NOT catch:
//!
//! - Writes to `/dev/tty` (escapes the pipe).
//! - `syslog(3)` / `journald` / kernel-level logging.
//! - `mmap`'d output.
//! - Core dumps + post-mortem analysis.
//! - Children that re-fetch values via the SDK directly.
//!
//! # Minimum value length
//!
//! Tainted values shorter than [`MIN_TAINTED_LEN`] bytes are skipped
//! with a startup warning. Reason: short values produce frequent
//! false-positive matches that destroy log readability (e.g. an
//! API key of "1" would substitute every digit "1" in the stream).
//! Per [[v0.14-plus/specialist-ux]] §5 E1.
//!
//! # Substitution token
//!
//! Default: `[redacted:<alias-name>]` (lowercase, alias-aware) per
//! Q-O2 resolution. Operators may override with a fixed string via
//! `--redact-token <string>` on the CLI.

// Module-scoped lint relaxations. Reasons inline above each.
//
// - `doc_markdown`: the security threat-model lists raw paths
//   (`/proc`, `/sys`, `/dev`, `/dev/tty`) and unix function names
//   (`syslog`, `mmap`, etc.) that would be backtick-noise to wrap.
// - `too_long_first_doc_paragraph`: the module + struct preambles
//   deliberately frontload context for security-reviewers.
// - `derivable_impls`: `SubstitutionToken::default` returns
//   `Self::AliasAware`, which is the documented v0.14 Q-O2 choice;
//   deriving Default would silently pick the first variant, which
//   happens to be the same but would lose the docstring binding.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph, clippy::derivable_impls)]

pub mod stream;

use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use tracing::warn;

pub use stream::StreamingScrubber;

/// Minimum length (in bytes) for a tainted value to be considered
/// for redaction. Values shorter than this are skipped (with a
/// `tracing::warn!`) — they produce too many false positives to
/// be worth substituting in the output stream.
pub const MIN_TAINTED_LEN: usize = 8;

/// Maximum tail-window for mode A streaming. A tainted value larger
/// than this cannot be matched mid-stream (the chunk boundary would
/// split it without sufficient overlap). Mode B (whole-file scan)
/// has no such limit since the entire file fits in memory.
pub const MODE_A_TAIL_WINDOW: usize = 64 * 1024;

/// One value the operator wants suppressed from output streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintedValue {
    /// The bytes to find and replace. UTF-8 sequences in practice,
    /// but the matcher is byte-oriented so binary blobs work too.
    pub bytes: Vec<u8>,
    /// The alias name to use when constructing the substitution
    /// token in [`SubstitutionToken::AliasAware`] mode. `None`
    /// falls back to the bare `[REDACTED]` form.
    pub alias_name: Option<String>,
}

impl TaintedValue {
    /// Build a tainted value from an alias name + plaintext value.
    /// Trims trailing newlines so a value like `"sk_live_abc\n"`
    /// (common from a CLI that emits a trailing newline) doesn't
    /// fail to match when the newline is consumed by a downstream
    /// reader.
    #[must_use]
    pub fn from_alias(alias_name: impl Into<String>, value: impl AsRef<[u8]>) -> Self {
        let bytes = value.as_ref();
        let trimmed_len =
            bytes.iter().rposition(|&b| b != b'\n' && b != b'\r').map_or(0, |i| i + 1);
        Self { bytes: bytes[..trimmed_len].to_vec(), alias_name: Some(alias_name.into()) }
    }
}

/// The set of tainted values fed to the [`Scrubber`].
///
/// Stable insertion order is preserved (deterministic
/// Aho-Corasick pattern IDs). Values shorter than
/// [`MIN_TAINTED_LEN`] are silently skipped at insertion time.
#[derive(Debug, Clone, Default)]
pub struct TaintedSet {
    values: Vec<TaintedValue>,
}

impl TaintedSet {
    /// Build an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Insert a value. Values shorter than [`MIN_TAINTED_LEN`] are
    /// dropped with a `tracing::warn!` carrying the alias name but
    /// NEVER the value or its length.
    pub fn insert(&mut self, value: TaintedValue) {
        if value.bytes.len() < MIN_TAINTED_LEN {
            warn!(
                alias = ?value.alias_name,
                min_len = MIN_TAINTED_LEN,
                "secretenv: tainted value below minimum length; skipping (alias-name only — no value, no length)",
            );
            return;
        }
        self.values.push(value);
    }

    /// Returns true when no values qualify for redaction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Number of values that will be matched.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Iterate the (preserved-order) value list.
    pub fn iter(&self) -> impl Iterator<Item = &TaintedValue> {
        self.values.iter()
    }
}

/// Format of the substitution emitted in place of a matched
/// tainted byte sequence.
#[derive(Debug, Clone)]
pub enum SubstitutionToken {
    /// `[redacted:<alias-name>]` — lowercase, alias-aware. The
    /// default, per Q-O2.
    AliasAware,
    /// A fixed string (e.g. `[REDACTED]` or `***`). Used via
    /// `--redact-token <string>` on the CLI.
    Fixed(String),
}

impl Default for SubstitutionToken {
    fn default() -> Self {
        Self::AliasAware
    }
}

impl SubstitutionToken {
    /// Render the substitution token for a matched value. The
    /// `alias_name` argument is the alias of the matched value
    /// (passed by the scrubber from the [`TaintedValue`] that
    /// produced the match).
    #[must_use]
    pub fn render(&self, alias_name: Option<&str>) -> Vec<u8> {
        match (self, alias_name) {
            (Self::AliasAware, Some(name)) => format!("[redacted:{name}]").into_bytes(),
            (Self::AliasAware, None) => b"[REDACTED]".to_vec(),
            (Self::Fixed(s), _) => s.clone().into_bytes(),
        }
    }
}

/// Aggregate result of a scrub pass. ALLOW per the v0.14+
/// synthesis §6 attribute matrix (`secretenv.redact.match_count` +
/// `secretenv.redact.byte_count` are both ALLOW).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScrubReport {
    /// Number of distinct match occurrences encountered.
    pub match_count: u64,
    /// Total bytes replaced. Sum of original lengths of matched
    /// tainted values.
    pub byte_count: u64,
}

impl ScrubReport {
    /// Identity for `+`.
    #[must_use]
    pub const fn zero() -> Self {
        Self { match_count: 0, byte_count: 0 }
    }
}

impl std::ops::Add for ScrubReport {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            match_count: self.match_count + rhs.match_count,
            byte_count: self.byte_count + rhs.byte_count,
        }
    }
}

/// Aho-Corasick byte scanner + substitution renderer. Construct
/// once per scrub session, reuse across multiple chunks (mode A) or
/// the whole file (mode B).
pub struct Scrubber {
    ac: aho_corasick::AhoCorasick,
    alias_names: Vec<Option<String>>,
    pattern_lengths: Vec<usize>,
    token: SubstitutionToken,
}

impl Scrubber {
    /// Borrow the internal Aho-Corasick automaton. Used by
    /// [`stream::StreamingScrubber`].
    pub(crate) const fn ac(&self) -> &aho_corasick::AhoCorasick {
        &self.ac
    }

    /// Look up the alias name attached to pattern `id`. Used by
    /// [`stream::StreamingScrubber`].
    pub(crate) fn alias_for(&self, id: usize) -> Option<&str> {
        self.alias_names.get(id).and_then(Option::as_deref)
    }

    /// Length of pattern `id`.
    pub(crate) fn pattern_len(&self, id: usize) -> usize {
        self.pattern_lengths[id]
    }

    /// Borrow the substitution token.
    pub(crate) const fn token(&self) -> &SubstitutionToken {
        &self.token
    }

    /// Build a scrubber over `set` with the given substitution
    /// token. Returns `Ok(None)` when the set is empty (caller can
    /// skip the scrub entirely).
    ///
    /// # Errors
    /// Returns an error if Aho-Corasick construction fails (which
    /// only happens on patterns that are empty or larger than
    /// platform-specific state-machine limits — neither possible
    /// after [`TaintedSet::insert`]'s length check).
    pub fn new(set: &TaintedSet, token: SubstitutionToken) -> Result<Option<Self>> {
        if set.is_empty() {
            return Ok(None);
        }
        let patterns: Vec<&[u8]> = set.iter().map(|v| v.bytes.as_slice()).collect();
        let alias_names: Vec<Option<String>> = set.iter().map(|v| v.alias_name.clone()).collect();
        let pattern_lengths: Vec<usize> = set.iter().map(|v| v.bytes.len()).collect();
        let ac = aho_corasick::AhoCorasick::new(&patterns)
            .context("building Aho-Corasick automaton for redact engine")?;
        Ok(Some(Self { ac, alias_names, pattern_lengths, token }))
    }

    /// Scrub the full byte slice `input` to `out`. Returns a
    /// [`ScrubReport`] aggregating matches.
    ///
    /// # Errors
    /// Returns an error if any write to `out` fails.
    pub fn scrub_bytes<W: Write>(&self, input: &[u8], out: &mut W) -> Result<ScrubReport> {
        let mut report = ScrubReport::zero();
        let mut cursor = 0usize;
        for mat in self.ac.find_iter(input) {
            // Emit any pre-match bytes verbatim.
            if mat.start() > cursor {
                out.write_all(&input[cursor..mat.start()])
                    .context("redact: writing pre-match bytes to output")?;
            }
            // Emit the substitution token.
            let pat_id = mat.pattern().as_usize();
            let alias = self.alias_names.get(pat_id).and_then(Option::as_deref);
            let token_bytes = self.token.render(alias);
            out.write_all(&token_bytes).context("redact: writing substitution token")?;
            cursor = mat.end();
            report.match_count += 1;
            report.byte_count += self.pattern_lengths[pat_id] as u64;
        }
        // Emit the trailing bytes after the last match.
        if cursor < input.len() {
            out.write_all(&input[cursor..])
                .context("redact: writing post-match trailing bytes to output")?;
        }
        Ok(report)
    }

    /// Convenience: scrub from a [`Read`] into a [`Write`]. The
    /// implementation reads the entire input into memory; suitable
    /// for mode B (whole-file scrub) but NOT mode A (which uses a
    /// streaming tail-window scanner).
    ///
    /// # Errors
    /// Returns an error on any read or write failure.
    pub fn scrub_reader<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ScrubReport> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .context("redact: reading input to memory for whole-file scrub")?;
        self.scrub_bytes(&buf, writer)
    }
}

/// Reject paths that point at kernel-pseudofile filesystems where
/// "scrubbing" is meaningless (`/proc`, `/sys`, `/dev`).
///
/// Comparison is by leading path component, after canonicalization.
/// We use the original path (not the canonicalized one) for
/// component inspection so a symlink under `/tmp` that points into
/// `/proc` is rejected on the SECOND check (the open + stat path)
/// rather than the first — the threat is "the file we open is in
/// `/proc`", not "the path string mentions `/proc`".
///
/// # Errors
/// Returns an error naming the offending top-level prefix.
pub fn refuse_special_paths(path: &Path) -> Result<()> {
    let components: Vec<_> = path.components().collect();
    if components.len() < 2 {
        return Ok(());
    }
    let first = components[1].as_os_str();
    if first == "proc" || first == "sys" || first == "dev" {
        bail!(
            "secretenv redact: refusing to scrub path '{}' — kernel pseudo-filesystems \
             (/proc, /sys, /dev) are not safe redact targets",
            path.display(),
        );
    }
    Ok(())
}

/// Stat a path using `lstat` semantics (does NOT follow symlinks)
/// and refuse if the file's owner UID differs from the current
/// effective UID, unless `allow_foreign_owner` is `true`.
///
/// # Errors
/// Returns an error if the stat fails or the file is foreign-owned
/// and `allow_foreign_owner` is `false`.
#[cfg(unix)]
pub fn refuse_foreign_owner(path: &Path, allow_foreign_owner: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(path)
        .with_context(|| format!("redact: stat('{}') for ownership check", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    if md.uid() != euid && !allow_foreign_owner {
        bail!(
            "secretenv redact: refusing to scrub '{}' — file is owned by UID {} (current EUID {}). \
             Re-run with --allow-foreign-owner if intentional",
            path.display(),
            md.uid(),
            euid,
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn refuse_foreign_owner(_path: &Path, _allow_foreign_owner: bool) -> Result<()> {
    // Windows has no analogous UID model; mode B foreign-owner
    // refusal is a Unix-only protection.
    Ok(())
}

/// Open `path` for reading with `O_NOFOLLOW`. A symlink swap
/// between the stat (in [`refuse_foreign_owner`]) and the open
/// (here) surfaces as `ELOOP` / `FILESYSTEM_LOOP`.
///
/// # Errors
/// Returns an error if `path` is a symlink (O_NOFOLLOW fires) or
/// the open itself fails.
#[cfg(unix)]
pub fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    let owned_fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    Ok(std::fs::File::from(owned_fd))
}

#[cfg(not(unix))]
pub fn open_no_follow(path: &Path) -> io::Result<std::fs::File> {
    // Best-effort on non-Unix: rely on the stat → open race window
    // being narrow. Real platform-specific protection deferred.
    std::fs::File::open(path)
}

/// Write a backup of `source` to `dest` with the source's mode bits,
/// refusing to follow a symlink at `dest` and refusing to overwrite
/// an existing file at `dest`.
///
/// Phase 7 security audit H3: the original `std::fs::copy`-based
/// path was vulnerable to a pre-planted symlink at the backup
/// destination (the in-place rename's `O_NOFOLLOW` guard didn't
/// extend to the backup path) and to inherit-existing-mode-bits if
/// the destination already existed.
///
/// # Errors
/// Returns an error on read/write/open failure, refuses if the
/// destination already exists (`O_EXCL`), and refuses if the
/// destination path resolves through a symlink (`O_NOFOLLOW`).
#[cfg(unix)]
#[allow(clippy::similar_names)] // source/dest are the natural names for a backup-write
fn write_backup_secure(source: &Path, dest: &Path) -> Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    use rustix::fs::{Mode, OFlags};

    let mut src = open_no_follow(source)
        .with_context(|| format!("redact: open backup-source '{}'", source.display()))?;
    let src_mode = src
        .metadata()
        .with_context(|| format!("redact: fstat backup-source '{}'", source.display()))?
        .permissions()
        .mode();

    let dest_mode_u16: u16 = u16::try_from(src_mode & 0o777).unwrap_or(0o600);
    let owned_fd = rustix::fs::open(
        dest,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        Mode::from_raw_mode(dest_mode_u16),
    )
    .with_context(|| {
        format!(
            "redact: create backup at '{}' (O_EXCL | O_NOFOLLOW; pre-existing or symlink \
             at destination is refused)",
            dest.display()
        )
    })?;
    let mut dst = std::fs::File::from(owned_fd);

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = src
            .read(&mut buf)
            .with_context(|| format!("redact: reading backup-source '{}'", source.display()))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])
            .with_context(|| format!("redact: writing backup at '{}'", dest.display()))?;
    }
    dst.sync_data().with_context(|| format!("redact: fsync backup at '{}'", dest.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_backup_secure(source: &Path, dest: &Path) -> Result<()> {
    // On non-Unix the O_EXCL | O_NOFOLLOW combo is not portable in
    // std::fs::OpenOptions; v0.14 falls back to a best-effort copy.
    std::fs::copy(source, dest)
        .map(|_| ())
        .with_context(|| format!("redact: writing backup at '{}'", dest.display()))
}

/// Scrub `path` in place. Atomic semantics:
///
/// 1. Stat (lstat) — refuse special paths, refuse foreign owner.
/// 2. Open with `O_NOFOLLOW` — refuses symlink swap.
/// 3. Scrub through a sibling tempfile in the same directory
///    (same filesystem → rename is atomic).
/// 4. Optionally copy the original to `<path><backup_suffix>` via
///    [`write_backup_secure`] (`O_EXCL | O_NOFOLLOW`) before the
///    rename.
/// 5. Atomic `rename(temp, path)`.
///
/// **Mode is preserved** on the renamed file (the temp inherits the
/// original's mode via `fchmod` after the scrub). **Ownership is NOT
/// preserved**: the persisted file is owned by the current EUID. For
/// the default same-EUID case this is a no-op; for root-run scrubs
/// of a sub-user-owned file the persisted file is owned by root;
/// for `--allow-foreign-owner` scrubs ownership transfers to the
/// current EUID (intentional). If true ownership preservation is
/// needed for a use case, file a v0.14.x chip.
///
/// # Errors
/// Returns an error for any of: special-path refusal, foreign-owner
/// refusal, symlink swap (O_NOFOLLOW), read/write failure, backup
/// destination already exists or is a symlink, or rename failure.
pub fn scrub_file_in_place(
    path: &Path,
    scrubber: &Scrubber,
    backup_suffix: Option<&str>,
    allow_foreign_owner: bool,
) -> Result<ScrubReport> {
    refuse_special_paths(path)?;
    refuse_foreign_owner(path, allow_foreign_owner)?;

    let mut reader = open_no_follow(path).with_context(|| {
        format!("redact: open('{}', O_NOFOLLOW) for in-place scrub", path.display())
    })?;

    let parent = path.parent().ok_or_else(|| {
        anyhow!("redact: cannot scrub '{}' in place — path has no parent directory", path.display())
    })?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!("redact: creating tempfile in '{}' for in-place scrub", parent.display())
    })?;

    let report = scrubber
        .scrub_reader(&mut reader, tmp.as_file_mut())
        .with_context(|| format!("redact: scrubbing '{}'", path.display()))?;

    if let Some(suffix) = backup_suffix {
        let mut backup_path = path.as_os_str().to_owned();
        backup_path.push(suffix);
        write_backup_secure(path, std::path::Path::new(&backup_path))?;
    }

    // Preserve mode on the renamed file. Ownership is NOT preserved
    // — non-root scrubs deliberately persist the file owned by the
    // current EUID. The build plan documents this behavior. Phase 7
    // code-review H1 caught a doc/impl mismatch fixed in the
    // function-level doc comment above.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let md = std::fs::symlink_metadata(path)
            .with_context(|| format!("redact: stat('{}') before rename", path.display()))?;
        let perms = std::fs::Permissions::from_mode(md.mode());
        tmp.as_file_mut()
            .set_permissions(perms)
            .with_context(|| format!("redact: fchmod tempfile for '{}'", path.display()))?;
    }

    tmp.persist(path).map_err(|e| {
        anyhow!("redact: atomic rename to '{}' failed: {}", path.display(), e.error)
    })?;

    Ok(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tainted_value_strips_trailing_newlines() {
        let v = TaintedValue::from_alias("stripe-key", "sk_live_abc\n\n");
        assert_eq!(v.bytes, b"sk_live_abc");
        assert_eq!(v.alias_name.as_deref(), Some("stripe-key"));
    }

    #[test]
    fn tainted_set_skips_short_values() {
        let mut set = TaintedSet::new();
        set.insert(TaintedValue::from_alias("short", "abc"));
        set.insert(TaintedValue::from_alias("long-enough", "sk_live_abc"));
        assert_eq!(set.len(), 1, "short value dropped, long retained");
    }

    #[test]
    fn substitution_token_alias_aware_default() {
        let t = SubstitutionToken::default();
        assert_eq!(t.render(Some("stripe-key")), b"[redacted:stripe-key]");
        assert_eq!(t.render(None), b"[REDACTED]");
    }

    #[test]
    fn substitution_token_fixed_override() {
        let t = SubstitutionToken::Fixed("***".to_owned());
        assert_eq!(t.render(Some("anything")), b"***");
    }

    #[test]
    fn scrubber_replaces_matches() {
        let mut set = TaintedSet::new();
        set.insert(TaintedValue::from_alias("api", "sk_live_abc123"));
        let scrubber = Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        let rep =
            scrubber.scrub_bytes(b"hello sk_live_abc123 world sk_live_abc123!", &mut out).unwrap();
        assert_eq!(rep.match_count, 2);
        assert_eq!(rep.byte_count, 14 + 14);
        assert_eq!(out, b"hello [redacted:api] world [redacted:api]!");
    }

    #[test]
    fn scrubber_returns_none_for_empty_set() {
        let set = TaintedSet::new();
        let scrubber = Scrubber::new(&set, SubstitutionToken::default()).unwrap();
        assert!(scrubber.is_none());
    }

    #[test]
    fn scrubber_handles_no_matches_cleanly() {
        let mut set = TaintedSet::new();
        set.insert(TaintedValue::from_alias("k", "tainted-value-here"));
        let scrubber = Scrubber::new(&set, SubstitutionToken::AliasAware).unwrap().unwrap();
        let mut out = Vec::new();
        let rep = scrubber.scrub_bytes(b"nothing to see here", &mut out).unwrap();
        assert_eq!(rep.match_count, 0);
        assert_eq!(rep.byte_count, 0);
        assert_eq!(out, b"nothing to see here");
    }

    #[test]
    fn refuse_special_paths_rejects_proc() {
        let r = refuse_special_paths(Path::new("/proc/self/cmdline"));
        assert!(r.is_err());
        assert!(format!("{:#}", r.unwrap_err()).contains("/proc"));
    }

    #[test]
    fn refuse_special_paths_rejects_sys() {
        assert!(refuse_special_paths(Path::new("/sys/kernel/version")).is_err());
    }

    #[test]
    fn refuse_special_paths_rejects_dev() {
        assert!(refuse_special_paths(Path::new("/dev/zero")).is_err());
    }

    #[test]
    fn refuse_special_paths_accepts_normal_path() {
        assert!(refuse_special_paths(Path::new("/tmp/foo.log")).is_ok());
        assert!(refuse_special_paths(Path::new("foo.log")).is_ok());
        // A path that LOOKS like /proc but isn't anchored at root
        // is fine — the threat is opening a kernel pseudofile, not
        // a relative filename that happens to contain the substring.
        assert!(refuse_special_paths(Path::new("/var/log/proc/foo")).is_ok());
    }

    #[test]
    fn scrub_report_sums() {
        let a = ScrubReport { match_count: 3, byte_count: 100 };
        let b = ScrubReport { match_count: 2, byte_count: 50 };
        let sum = a + b;
        assert_eq!(sum.match_count, 5);
        assert_eq!(sum.byte_count, 150);
    }
}
