//! Distribution profile system — `secretenv profile {install,list,update,uninstall}`.
//!
//! A "profile" is a TOML document hosted over HTTPS (default base URL
//! `https://secretenv.io/profiles`, overridable via the
//! `SECRETENV_PROFILE_URL` env var) that contains `[registries.*]` and
//! `[backends.*]` entries. Installed profiles drop into
//! `<config_dir>/profiles/<name>.toml` and are auto-merged into the
//! active [`Config`](secretenv_core::Config) on load — profiles fill
//! in entries that are not already defined in the user's `config.toml`,
//! so the user's own config always wins.
//!
//! Fetching uses `curl` (subprocess) rather than a new HTTP client
//! dependency — every backend already shells out to a vendor CLI, so
//! we stay consistent. A sidecar `<name>.meta.json` preserves the
//! source URL + `ETag` for `profile update` to do conditional re-fetch.
//!
//! Signing + an index file are deliberate v0.5+ concerns (see
//! build-plan-v0.4.md §Phase 4 "Design decisions" — unsigned + HTTPS +
//! `ETag` caching is the v0.4 posture).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use secretenv_core::Config;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::time::timeout;

/// Default base URL when the user says `profile install <name>` without
/// passing `--url`. Overridable via the `SECRETENV_PROFILE_URL` env var.
pub const DEFAULT_BASE_URL: &str = "https://secretenv.io/profiles";

/// Env var name users export to point `profile install <name>` at an
/// alternate host (mirror, staging, local filesystem, etc.).
pub const BASE_URL_ENV: &str = "SECRETENV_PROFILE_URL";

/// Hard ceiling on every network fetch. Profile files are small TOML
/// documents; 30 s is generous. Individual calls can be tightened via
/// `--timeout` if that ever becomes a knob users want.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard ceiling on profile body size (both on-network via `curl
/// --max-filesize` and on-disk via the `merge_profiles_from` size gate
/// in `secretenv-core::config`). Profiles are supposed to be short TOML
/// fragments — 1 MiB is orders of magnitude more than any real profile
/// would ever need and keeps a compromised host from OOM-ing the
/// process. Keep this value coordinated with
/// `secretenv_core::MAX_PROFILE_FILE_BYTES`.
const MAX_PROFILE_BODY_BYTES: u64 = 1_048_576;

/// Sidecar metadata written alongside each installed profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMeta {
    /// URL the profile was fetched from. Used by `profile update`.
    pub source_url: String,
    /// HTTP `ETag` returned by the server. Empty string if the server
    /// didn't provide one. Used for conditional re-fetch on update.
    #[serde(default)]
    pub etag: String,
    /// RFC 3339 timestamp of install / last successful update.
    pub installed_at: String,
}

/// Summary of an installed profile, returned by [`list`].
#[derive(Debug, Clone, Serialize)]
pub struct InstalledProfile {
    /// Bare profile name (filename without the `.toml` extension).
    pub name: String,
    /// Absolute path to the profile file on disk.
    pub path: PathBuf,
    /// Source URL from the sidecar meta, or `"(manual)"` if the
    /// profile was dropped in by hand (no sidecar).
    pub source_url: String,
    /// Install timestamp, or `"-"` if unknown.
    pub installed_at: String,
}

/// Opts for every profile operation — lets the CLI layer inject an
/// override profiles dir (e.g. from `--config <path>` → `<parent>/profiles`)
/// without the command handlers having to re-derive it.
#[derive(Debug, Clone)]
pub struct ProfileOpts {
    /// Directory where profiles live. Usually
    /// `<XDG_CONFIG>/secretenv/profiles` or `<parent of --config>/profiles`.
    pub profiles_dir: PathBuf,
}

// ---------------------------------------------------------------------
// Public commands
// ---------------------------------------------------------------------

/// Install a profile: fetch, validate, persist.
///
/// `url` defaults to `{base}/{name}.toml` where base is either
/// `SECRETENV_PROFILE_URL` or [`DEFAULT_BASE_URL`]. Passing `url`
/// explicitly bypasses the base — useful for private/internal mirrors.
///
/// # Errors
/// - Network / curl failure
/// - Response body doesn't parse as a SecretEnv config fragment
/// - Profiles directory cannot be created or written to
pub async fn install(name: &str, url: Option<&str>, opts: &ProfileOpts) -> Result<()> {
    validate_profile_name(name)?;
    let resolved_url = resolve_install_url(name, url);

    let fetched = fetch(&resolved_url, None).await?;
    let FetchOutcome::Fresh { body, etag } = fetched else {
        // Conditional fetch was not requested; a 304 here would mean
        // the server incorrectly returned Not Modified without an
        // If-None-Match header — treat as a fetch error.
        bail!("server returned 304 Not Modified without a conditional request");
    };

    validate_profile_body(&body, &resolved_url)?;

    let profile_path = opts.profiles_dir.join(format!("{name}.toml"));
    let meta_path = meta_path_for(&profile_path);
    fs::create_dir_all(&opts.profiles_dir)
        .with_context(|| format!("creating profiles dir '{}'", opts.profiles_dir.display()))?;
    fs::write(&profile_path, &body)
        .with_context(|| format!("writing profile '{}'", profile_path.display()))?;
    write_meta(
        &meta_path,
        &ProfileMeta { source_url: resolved_url, etag, installed_at: now_rfc3339() },
    )?;

    println!("Installed profile '{name}' → {}", profile_path.display());
    Ok(())
}

/// List all installed profiles in `opts.profiles_dir`.
///
/// # Errors
/// Returns an error only if the profiles dir exists but cannot be read.
/// A missing directory is treated as an empty list (no panic).
pub fn list(opts: &ProfileOpts) -> Result<Vec<InstalledProfile>> {
    if !opts.profiles_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(&opts.profiles_dir)
        .with_context(|| format!("reading profiles dir '{}'", opts.profiles_dir.display()))?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(std::string::ToString::to_string)
            .unwrap_or_default();
        let meta = read_meta(&meta_path_for(&path)).ok();
        let (source_url, installed_at) = meta.map_or_else(
            || ("(manual)".to_string(), "-".to_string()),
            |m| (m.source_url, m.installed_at),
        );
        out.push(InstalledProfile { name, path, source_url, installed_at });
    }
    Ok(out)
}

/// Update one installed profile by re-fetching from its stored
/// `source_url` using the stored `ETag` for conditional re-fetch.
///
/// # Errors
/// - Profile not installed
/// - Sidecar metadata missing (profile was installed by hand)
/// - Network failure
/// - Response body fails config validation
pub async fn update_one(name: &str, opts: &ProfileOpts) -> Result<UpdateOutcome> {
    validate_profile_name(name)?;
    let profile_path = opts.profiles_dir.join(format!("{name}.toml"));
    if !profile_path.is_file() {
        bail!("profile '{name}' is not installed (expected '{}')", profile_path.display());
    }
    let meta_path = meta_path_for(&profile_path);
    let meta = read_meta(&meta_path).with_context(|| {
        format!(
            "profile '{name}' has no sidecar metadata — `update` needs the stored source URL. \
             Re-run `secretenv profile install {name}` (optionally with --url) to establish it."
        )
    })?;

    let etag = if meta.etag.is_empty() { None } else { Some(meta.etag.as_str()) };
    match fetch(&meta.source_url, etag).await? {
        FetchOutcome::NotModified => Ok(UpdateOutcome::UpToDate),
        FetchOutcome::Fresh { body, etag } => {
            validate_profile_body(&body, &meta.source_url)?;
            fs::write(&profile_path, &body)
                .with_context(|| format!("writing profile '{}'", profile_path.display()))?;
            write_meta(
                &meta_path,
                &ProfileMeta { source_url: meta.source_url, etag, installed_at: now_rfc3339() },
            )?;
            Ok(UpdateOutcome::Refreshed)
        }
    }
}

/// Update every installed profile. Returns one [`UpdateReport`] per
/// profile; the caller decides how to render (and whether any errors
/// are fatal for its exit code).
///
/// # Errors
/// Returns an error only if the profiles dir cannot be read. Per-
/// profile errors are captured as `Err` inside each [`UpdateReport`].
pub async fn update_all(opts: &ProfileOpts) -> Result<Vec<UpdateReport>> {
    let installed = list(opts)?;
    let mut reports = Vec::with_capacity(installed.len());
    for p in installed {
        let outcome = update_one(&p.name, opts).await;
        reports.push(UpdateReport { name: p.name, outcome });
    }
    Ok(reports)
}

/// Remove an installed profile (both the .toml and the .meta.json).
///
/// # Errors
/// Returns an error if the profile file is missing, or if the removal
/// itself fails (filesystem error).
pub fn uninstall(name: &str, opts: &ProfileOpts) -> Result<()> {
    validate_profile_name(name)?;
    let profile_path = opts.profiles_dir.join(format!("{name}.toml"));
    if !profile_path.is_file() {
        bail!("profile '{name}' is not installed (expected '{}')", profile_path.display());
    }
    fs::remove_file(&profile_path)
        .with_context(|| format!("removing '{}'", profile_path.display()))?;
    let meta_path = meta_path_for(&profile_path);
    if meta_path.is_file() {
        fs::remove_file(&meta_path)
            .with_context(|| format!("removing '{}'", meta_path.display()))?;
    }
    println!("Uninstalled profile '{name}'");
    Ok(())
}

// ---------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------

/// Outcome of a single `update_one` call.
///
/// Marked `#[non_exhaustive]` so v0.5+ variants (e.g. `SignatureError`,
/// `Skipped`) can be added without forcing downstream match
/// exhaustiveness to break at the `SemVer` boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UpdateOutcome {
    /// Server returned 304 Not Modified; local file unchanged.
    UpToDate,
    /// Server returned 200 with new content; local file replaced.
    Refreshed,
}

/// One row from a `profile update` (no name) run.
///
/// Also marked `#[non_exhaustive]` so new per-row metadata (timing,
/// bytes transferred, retry count) can be added without breaking
/// field-init callers in v0.5+.
#[derive(Debug)]
#[non_exhaustive]
pub struct UpdateReport {
    /// Profile name.
    pub name: String,
    /// Outcome or the error that was captured for this profile.
    pub outcome: Result<UpdateOutcome>,
}

// ---------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------

fn base_url() -> String {
    std::env::var(BASE_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
}

/// Resolve the URL a `profile install <name>` call should fetch from.
/// Pure function — tests that want to exercise env-var precedence hold
/// a sync mutex while set/unset-ing `SECRETENV_PROFILE_URL` and call
/// this directly, avoiding the `await_holding_lock` clippy lint.
fn resolve_install_url(name: &str, explicit: Option<&str>) -> String {
    explicit.map_or_else(|| format!("{}/{name}.toml", base_url()), std::string::ToString::to_string)
}

/// Reserved device filenames on Windows. A profile named `con` would
/// collide with these on NTFS regardless of extension (`con.toml` still
/// hits the console device). Match case-insensitively against the bare
/// profile name (the filename stem, no extension).
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

const MAX_PROFILE_NAME_LEN: usize = 64;

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("profile name must not be empty");
    }
    if name.len() > MAX_PROFILE_NAME_LEN {
        bail!(
            "profile name '{name}' is {} characters; maximum is {MAX_PROFILE_NAME_LEN}",
            name.len()
        );
    }
    // Strict ASCII allowlist: must start with alphanumeric, then
    // alphanumeric / hyphen / underscore only. Rejects control chars,
    // NUL (POSIX filename truncation), path separators, RTL-override
    // (U+202E) and other bidi tricks, emoji, dots (which prevent the
    // ".toml" extension convention from being ambiguous), whitespace,
    // and every non-ASCII codepoint.
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => bail!(
            "profile name '{name}' must start with an ASCII letter or digit — \
             allowed chars: [A-Za-z0-9][A-Za-z0-9_-]*"
        ),
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!(
                "profile name '{name}' contains disallowed character {c:?} — \
                 allowed chars: [A-Za-z0-9][A-Za-z0-9_-]*"
            );
        }
    }
    // Windows reserved device names — case-insensitive match on the
    // bare name (NTFS ignores extension for these).
    let upper = name.to_ascii_uppercase();
    if WINDOWS_RESERVED_NAMES.iter().any(|&r| r == upper) {
        bail!(
            "profile name '{name}' is a reserved Windows device name ({upper}) — \
             pick a different name to stay portable"
        );
    }
    Ok(())
}

fn validate_profile_body(body: &str, url: &str) -> Result<()> {
    toml::from_str::<Config>(body).with_context(|| {
        format!("profile fetched from '{url}' did not parse as a SecretEnv config fragment")
    })?;
    Ok(())
}

fn meta_path_for(profile_path: &Path) -> PathBuf {
    let mut p = profile_path.to_path_buf();
    p.set_extension("meta.json");
    p
}

fn read_meta(path: &Path) -> Result<ProfileMeta> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading meta '{}'", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing meta '{}'", path.display()))
}

fn write_meta(path: &Path, meta: &ProfileMeta) -> Result<()> {
    let raw = serde_json::to_string_pretty(meta).context("serializing profile meta")?;
    fs::write(path, raw).with_context(|| format!("writing meta '{}'", path.display()))?;
    Ok(())
}

/// UNIX-epoch-derived RFC 3339 timestamp with second precision. Good
/// enough for meta; avoids pulling in `chrono`.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Format via a tiny conversion — second precision, UTC.
    // `date -u -d @<secs>` equivalent; we build the string manually so
    // we have zero extra deps.
    format_unix_secs_as_rfc3339(secs)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn format_unix_secs_as_rfc3339(secs: u64) -> String {
    // Days since 1970-01-01 (Thursday).
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day / 60) % 60;
    let sec = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Gregorian civil date from days since 1970-01-01. Standard algorithm
/// (Howard Hinnant / `chrono::NaiveDate::from_num_days_from_ce`).
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
const fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Shape returned by the curl-backed fetcher.
enum FetchOutcome {
    NotModified,
    Fresh { body: String, etag: String },
}

/// `curl -fsSL --max-time 30 -H "If-None-Match: <etag>" -w '...' ...`.
/// The `ETag` on success is parsed from the response headers we asked
/// curl to dump alongside the body.
async fn fetch(url: &str, if_none_match: Option<&str>) -> Result<FetchOutcome> {
    // Two tempfiles: one for the body, one for the response headers.
    let body_tmp = tempfile::NamedTempFile::new().context("allocating body tmpfile")?;
    let headers_tmp = tempfile::NamedTempFile::new().context("allocating headers tmpfile")?;

    let mut cmd = Command::new("curl");
    cmd.arg("-sS") // quiet progress, still show errors
        .arg("-L") // follow redirects (CloudFront ↔ origin)
        .arg("--proto") // pin scheme — don't follow a redirect that drops to plain HTTP
        .arg("=https,file") // https for the real canonical host; file:// for offline testing
        .arg("--max-time")
        .arg(FETCH_TIMEOUT.as_secs().to_string())
        .arg("--max-filesize") // cap the response body; profiles are tiny TOML fragments
        .arg(MAX_PROFILE_BODY_BYTES.to_string())
        .arg("-w")
        .arg("%{http_code}") // write HTTP status to stdout after headers/body
        .arg("-o")
        .arg(body_tmp.path())
        .arg("-D")
        .arg(headers_tmp.path());
    if let Some(etag) = if_none_match {
        // Re-wrap the opaque-tag in DQUOTEs per RFC 7232 §2.3. We
        // strip the quotes during parse (see `parse_etag`) so the
        // stored value is clean, and re-wrap at send time so origin
        // servers (CloudFront / S3) match against their quoted form
        // and actually return 304 Not Modified.
        cmd.arg("-H").arg(format!("If-None-Match: \"{etag}\""));
    }
    cmd.arg(url);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = timeout(FETCH_TIMEOUT + Duration::from_secs(5), cmd.output())
        .await
        .map_err(|_| anyhow!("timeout fetching '{url}' after {FETCH_TIMEOUT:?}"))?
        .with_context(|| format!("spawning `curl` for '{url}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("curl failed for '{url}' (exit {:?}): {}", output.status.code(), stderr.trim());
    }

    let status_str = String::from_utf8_lossy(&output.stdout);
    let trimmed = status_str.trim();
    let status_code = trimmed
        .rsplit_once('\n')
        .map_or(trimmed, |(_, last)| last)
        .parse::<u16>()
        .with_context(|| format!("parsing HTTP status from curl: '{status_str}'"))?;

    match status_code {
        304 => Ok(FetchOutcome::NotModified),
        // `200..=299` covers real HTTP(S). `0` is what curl reports for
        // `file://` URLs (no HTTP status) — exit 0 means the file was
        // read successfully, and we fall through to the same
        // body-read + no-ETag path.
        0 | 200..=299 => {
            let body = fs::read_to_string(body_tmp.path()).with_context(|| {
                format!("reading curl body tempfile '{}'", body_tmp.path().display())
            })?;
            // Headers tempfile read: a missing ETag is fine (many
            // origins omit it) but a permissions / IO failure on our
            // own tmpfile should surface — otherwise `install` pretends
            // the server returned no ETag and every subsequent `update`
            // is forced to re-fetch. Propagate the error with context.
            let headers = fs::read_to_string(headers_tmp.path()).with_context(|| {
                format!("reading curl headers tempfile '{}'", headers_tmp.path().display())
            })?;
            Ok(FetchOutcome::Fresh { body, etag: parse_etag(&headers) })
        }
        other => bail!("unexpected HTTP {other} fetching '{url}'"),
    }
}

/// Pull the `ETag` value out of a curl `-D` headers dump. We take the
/// LAST `ETag` in the dump because redirect chains may emit several and
/// the one that belongs to the final 200 is the last.
fn parse_etag(headers: &str) -> String {
    headers
        .lines()
        .rev()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.eq_ignore_ascii_case("etag") {
                Some(v.trim().trim_matches('"').to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Mutex;

    use tempfile::TempDir;

    use super::*;

    // Serialize tests that mutate SECRETENV_PROFILE_URL; env var mutation
    // isn't thread-safe and we run multiple tests that touch it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn opts(dir: &TempDir) -> ProfileOpts {
        ProfileOpts { profiles_dir: dir.path().join("profiles") }
    }

    fn write_fixture(dir: &TempDir, name: &str, body: &str) -> PathBuf {
        let p = dir.path().join(name);
        fs::write(&p, body).unwrap();
        p
    }

    const VALID_PROFILE: &str = r#"
[backends.team-ssm]
type = "aws-ssm"
aws_region = "us-east-1"

[registries.team]
sources = ["team-ssm:///teams/acme/registry"]
"#;

    #[test]
    fn profile_name_rejects_path_traversal() {
        for bad in ["", "../evil", "a/b", "a\\b", "foo:bar", "foo.bar", "foo bar"] {
            assert!(validate_profile_name(bad).is_err(), "expected '{bad}' to be rejected");
        }
        for ok in ["team-defaults", "team_a", "acme123", "a"] {
            assert!(validate_profile_name(ok).is_ok(), "expected '{ok}' to be accepted");
        }
    }

    #[test]
    fn profile_name_rejects_control_chars_and_unicode() {
        // Post-audit hardening: strict ASCII allowlist.
        let bad = [
            "evil\0nul",        // NUL truncation on POSIX
            "team\u{202E}live", // RTL override — renders deceptively
            "\u{200B}hidden",   // zero-width space
            "emoji🔥name",      // emoji / non-ASCII
            "team<bracket>",    // shell metacharacters
            "team|pipe",
            "team?wild",
            "team*glob",
            "_leading-underscore", // must start with alphanumeric
            "-leading-hyphen",     // same
        ];
        for bad_name in bad {
            assert!(
                validate_profile_name(bad_name).is_err(),
                "expected {bad_name:?} to be rejected"
            );
        }
    }

    #[test]
    fn profile_name_rejects_windows_reserved_names() {
        // Post-audit hardening: case-insensitive Windows device-name check.
        for reserved in ["con", "CON", "Con", "prn", "aux", "nul", "COM1", "lpt9"] {
            assert!(
                validate_profile_name(reserved).is_err(),
                "expected Windows-reserved {reserved:?} to be rejected"
            );
        }
        // Similar shapes but not reserved are fine.
        for ok in ["console", "com0", "lpt10", "consul"] {
            assert!(validate_profile_name(ok).is_ok(), "expected {ok:?} to be accepted");
        }
    }

    #[test]
    fn profile_name_rejects_over_length() {
        let too_long = "a".repeat(MAX_PROFILE_NAME_LEN + 1);
        assert!(validate_profile_name(&too_long).is_err());
        let at_limit = "a".repeat(MAX_PROFILE_NAME_LEN);
        assert!(validate_profile_name(&at_limit).is_ok());
    }

    #[test]
    fn body_validation_accepts_well_formed_fragment() {
        assert!(validate_profile_body(VALID_PROFILE, "test://").is_ok());
    }

    #[test]
    fn body_validation_rejects_bogus_toml() {
        let err = validate_profile_body("this is not valid = toml [x]", "test://").unwrap_err();
        assert!(err.to_string().contains("SecretEnv config fragment"));
    }

    #[test]
    fn body_validation_rejects_unknown_fields() {
        let err = validate_profile_body(
            "[registries.foo]\nsources=[\"x:///y\"]\nmystery = 1\n",
            "test://",
        )
        .unwrap_err();
        assert!(err.to_string().contains("config fragment"));
    }

    #[test]
    fn resolve_install_url_explicit_wins() {
        let u = resolve_install_url("anything", Some("https://example.com/x.toml"));
        assert_eq!(u, "https://example.com/x.toml");
    }

    #[test]
    fn resolve_install_url_falls_back_to_default_base() {
        let _g = ENV_LOCK.lock().unwrap();
        // Ensure the env var is not set for this test.
        std::env::remove_var(BASE_URL_ENV);
        let u = resolve_install_url("team-defaults", None);
        assert_eq!(u, format!("{DEFAULT_BASE_URL}/team-defaults.toml"));
    }

    #[test]
    fn resolve_install_url_respects_base_url_env() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(BASE_URL_ENV, "https://mirror.example.com/p");
        let u = resolve_install_url("team-defaults", None);
        std::env::remove_var(BASE_URL_ENV);
        assert_eq!(u, "https://mirror.example.com/p/team-defaults.toml");
    }

    #[tokio::test]
    async fn install_via_file_url_writes_toml_and_meta() {
        let dir = TempDir::new().unwrap();
        let fixture = write_fixture(&dir, "team-defaults.toml", VALID_PROFILE);
        let url = format!("file://{}", fixture.display());

        install("team-defaults", Some(&url), &opts(&dir)).await.unwrap();

        let stored = dir.path().join("profiles/team-defaults.toml");
        let meta = dir.path().join("profiles/team-defaults.meta.json");
        assert!(stored.is_file(), "profile file should be written");
        assert!(meta.is_file(), "meta sidecar should be written");

        let body = fs::read_to_string(&stored).unwrap();
        assert!(body.contains("team-ssm"));

        let m: ProfileMeta = serde_json::from_str(&fs::read_to_string(&meta).unwrap()).unwrap();
        assert_eq!(m.source_url, url);
        assert!(!m.installed_at.is_empty());
    }

    #[tokio::test]
    async fn install_rejects_malformed_body() {
        let dir = TempDir::new().unwrap();
        let fixture = write_fixture(&dir, "broken.toml", "this = is [not] toml]]]");
        let url = format!("file://{}", fixture.display());

        let err = install("broken", Some(&url), &opts(&dir)).await.unwrap_err();
        assert!(err.to_string().contains("config fragment"));
        assert!(!dir.path().join("profiles/broken.toml").exists());
    }

    #[tokio::test]
    async fn list_returns_installed_profiles_alphabetically() {
        let dir = TempDir::new().unwrap();
        for name in ["zulu", "alpha", "mike"] {
            let fx = write_fixture(&dir, &format!("{name}.toml"), VALID_PROFILE);
            install(name, Some(&format!("file://{}", fx.display())), &opts(&dir)).await.unwrap();
        }
        let got: Vec<String> = list(&opts(&dir)).unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(got, vec!["alpha", "mike", "zulu"]);
    }

    #[tokio::test]
    async fn list_on_missing_dir_is_empty() {
        let dir = TempDir::new().unwrap();
        let got = list(&opts(&dir)).unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn uninstall_removes_file_and_meta() {
        let dir = TempDir::new().unwrap();
        let fx = write_fixture(&dir, "byebye.toml", VALID_PROFILE);
        install("byebye", Some(&format!("file://{}", fx.display())), &opts(&dir)).await.unwrap();

        assert!(dir.path().join("profiles/byebye.toml").exists());
        assert!(dir.path().join("profiles/byebye.meta.json").exists());

        uninstall("byebye", &opts(&dir)).unwrap();

        assert!(!dir.path().join("profiles/byebye.toml").exists());
        assert!(!dir.path().join("profiles/byebye.meta.json").exists());
    }

    #[tokio::test]
    async fn uninstall_of_missing_profile_errors() {
        let dir = TempDir::new().unwrap();
        let err = uninstall("nope", &opts(&dir)).unwrap_err();
        assert!(err.to_string().contains("not installed"));
    }

    #[tokio::test]
    async fn update_without_meta_errors_helpfully() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("profiles")).unwrap();
        fs::write(dir.path().join("profiles/manual.toml"), VALID_PROFILE).unwrap();
        let err = update_one("manual", &opts(&dir)).await.unwrap_err();
        assert!(err.to_string().contains("no sidecar metadata"));
    }

    #[tokio::test]
    async fn update_after_source_change_refreshes_file() {
        let dir = TempDir::new().unwrap();
        let fx = write_fixture(&dir, "rot.toml", VALID_PROFILE);
        let url = format!("file://{}", fx.display());
        install("rot", Some(&url), &opts(&dir)).await.unwrap();

        // Rewrite the fixture with new content.
        let updated =
            "[backends.team-ssm-updated]\ntype = \"aws-ssm\"\naws_region = \"us-west-2\"\n";
        fs::write(&fx, updated).unwrap();

        let outcome = update_one("rot", &opts(&dir)).await.unwrap();
        assert!(matches!(outcome, UpdateOutcome::Refreshed));

        let body = fs::read_to_string(dir.path().join("profiles/rot.toml")).unwrap();
        assert!(body.contains("team-ssm-updated"));
    }

    #[test]
    fn rfc3339_format_is_well_shaped() {
        let s = format_unix_secs_as_rfc3339(1_700_000_000); // 2023-11-14T22:13:20Z
        assert_eq!(s, "2023-11-14T22:13:20Z");
        let epoch = format_unix_secs_as_rfc3339(0);
        assert_eq!(epoch, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn etag_parser_handles_quotes_and_case_insensitivity() {
        let headers = "HTTP/1.1 200 OK\r\nEtag: \"abc123\"\r\n\r\n";
        assert_eq!(parse_etag(headers), "abc123");
        let headers = "HTTP/1.1 200 OK\r\nETAG: def-xyz\r\n";
        assert_eq!(parse_etag(headers), "def-xyz");
        assert_eq!(parse_etag("HTTP/1.1 200 OK\r\n\r\n"), "");
    }
}
