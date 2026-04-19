//! Strict-mode mock CLI harness (v0.2.1+ / v0.2.2 `install_mock_strict`).
//!
//! The existing [`super::install_mock`] API takes a raw POSIX shell body and
//! trusts the caller to match argv correctly. In practice, callers write
//! `if [ "$1 $2" = "ssm get-parameter" ]; then ...` and the rest of argv is
//! silently ignored — so flag-order bugs (v0.2.0 vault BUG-1) and
//! argument-content bugs (v0.2.0 aws-secrets BUG-2) slipped through
//! `cargo test --workspace` green.
//!
//! Strict-mode mocks close that gap by matching on the **full joined argv
//! string** against a caller-declared list. Any mismatch — missing flag,
//! extra flag, wrong value, reordered flags — produces a hard failure
//! (exit 97) rather than silent passthrough. See the [strict-mode retrofit
//! plan][plan] for the series that migrates every existing backend's test
//! suite onto this harness.
//!
//! [plan]: https://github.com/TechAlchemistX/secretenv/blob/main/kb/wiki/build-plan-v0.2.x-strict-mode.md
//!
//! # Example
//!
//! ```no_run
//! use tempfile::TempDir;
//! use secretenv_testing::{StrictMock, Response};
//!
//! let dir = TempDir::new().unwrap();
//! let path = StrictMock::new("aws")
//!     .on(
//!         &["ssm", "get-parameter", "--name", "/prod/db", "--region",
//!           "us-east-1", "--with-decryption", "--query", "Parameter.Value",
//!           "--output", "text"],
//!         Response::success("postgres://db.internal/prod\n"),
//!     )
//!     .on(
//!         &["ssm", "put-parameter", "--cli-input-json",
//!           "file:///dev/stdin", "--region", "us-east-1"],
//!         Response::success_with_stdin(
//!             "",
//!             vec![r#""Name": "/prod/db""#.into()],
//!         ),
//!     )
//!     .install(dir.path());
//! ```
//!
//! # Exit code 97
//!
//! A no-match exits 97 — uncommon enough that test failures surface as a
//! visible "strict-mock no match" rather than being confused with a normal
//! backend CLI error (AWS/vault/op use 1/2/254/etc.). The stderr diagnostic
//! names the observed argv and every declared shape so a developer reading
//! `cargo test` output can see exactly what the test expected vs what the
//! backend sent.
//!
//! # Scope of v0.2.2
//!
//! This first cut implements **exact argv match** only. The
//! [plan][plan] sketches additional matchers (`PositionalThenFlags`,
//! `Regex`) — those will be added when a concrete backend retrofit needs
//! them. The `StrictMock`/`Response` types are marked `#[non_exhaustive]`
//! so variants and fields can grow without a breaking-change release.

#![allow(clippy::module_name_repetitions)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// A strict-mode mock CLI specification — a declared list of
/// `(argv, response)` rules. Rules are tried in insertion order;
/// the first whose argv matches wins.
#[must_use]
pub struct StrictMock {
    bin_name: String,
    rules: Vec<Rule>,
}

/// One invocation rule: the exact argv that triggers it + the response
/// the mock emits on match. Constructed via [`StrictMock::on`]; not
/// typically instantiated directly.
#[derive(Clone)]
struct Rule {
    argv: Vec<String>,
    stdin_must_contain: Vec<String>,
    env_must_contain: Vec<(String, String)>,
    env_must_not_contain: Vec<String>,
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// The response a matched rule emits.
///
/// Prefer the constructors [`Response::success`], [`Response::failure`],
/// [`Response::success_with_stdin`] over the struct fields directly.
#[non_exhaustive]
#[derive(Clone)]
pub struct Response {
    /// Written to stdout verbatim. No trailing newline is appended —
    /// include one in the string if the real CLI would.
    pub stdout: String,
    /// Written to stderr verbatim.
    pub stderr: String,
    /// Process exit code on match.
    pub exit_code: i32,
    /// If non-empty, the mock reads stdin once up front and verifies
    /// each listed fragment appears as a literal substring. A missing
    /// fragment exits 97 (treated identically to a no-match), so tests
    /// can assert that a secret value reached the child via stdin rather
    /// than argv ([v0.2 CV-1 discipline][cv1]).
    ///
    /// [cv1]: https://github.com/TechAlchemistX/secretenv/blob/main/kb/wiki/build-plan-v0.2.md
    pub stdin_must_contain: Vec<String>,
    /// If non-empty, each `(key, value)` pair must be present in the
    /// mock process's environment as `key=value` exactly (value compared
    /// byte-for-byte). A missing or differently-valued key exits 97.
    /// Used by backends whose CLI behavior is env-driven — e.g. the
    /// v0.2 vault backend routes `VAULT_ADDR` / `VAULT_NAMESPACE` via
    /// env rather than argv flags (PR #33 BUG-1 fix).
    ///
    /// Populate via [`Response::with_env_var`].
    pub env_must_contain: Vec<(String, String)>,
    /// If non-empty, each listed env-var key must be UNSET in the mock
    /// process's environment. A set key (even with empty value) exits
    /// 97. Used by backends that conditionally pass env vars — e.g. the
    /// vault backend must NOT set `VAULT_NAMESPACE` when a namespace
    /// isn't configured (open-source Vault rejects the flag).
    ///
    /// Populate via [`Response::with_env_absent`].
    pub env_must_not_contain: Vec<String>,
}

impl Response {
    /// 0-exit response with the given stdout; empty stderr; no stdin check.
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
            stdin_must_contain: Vec::new(),
            env_must_contain: Vec::new(),
            env_must_not_contain: Vec::new(),
        }
    }

    /// Non-zero response with the given stderr; empty stdout; no stdin check.
    ///
    /// # Panics
    ///
    /// Panics if `exit_code == 0` — by construction, `failure` models a
    /// non-zero exit. Use [`Self::success`] for 0-exit responses.
    pub fn failure(exit_code: i32, stderr: impl Into<String>) -> Self {
        assert_ne!(exit_code, 0, "Response::failure requires a non-zero exit code");
        Self {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code,
            stdin_must_contain: Vec::new(),
            env_must_contain: Vec::new(),
            env_must_not_contain: Vec::new(),
        }
    }

    /// 0-exit response that also verifies stdin contains each listed
    /// fragment as a literal substring. Used to test CV-1 discipline —
    /// secret values must reach the child process via stdin, never argv.
    pub fn success_with_stdin(stdout: impl Into<String>, stdin_must_contain: Vec<String>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
            stdin_must_contain,
            env_must_contain: Vec::new(),
            env_must_not_contain: Vec::new(),
        }
    }

    /// Chainable: attach a stderr body to any response. Useful for CLIs
    /// that emit informational output to stderr (notably AWS CLI v1,
    /// whose `aws --version` writes to stderr not stdout).
    ///
    /// ```no_run
    /// # use secretenv_testing::Response;
    /// let r = Response::success("")
    ///     .with_stderr("aws-cli/1.18.69 Python/2.7.16 Darwin/19.6.0\n");
    /// ```
    #[must_use]
    pub fn with_stderr(mut self, stderr: impl Into<String>) -> Self {
        self.stderr = stderr.into();
        self
    }

    /// Chainable: require this rule's mock subprocess to have `key=value`
    /// in its environment. Checked byte-for-byte against the value that
    /// shell sees via `$KEY`. Missing or mismatched → exit 97 with a
    /// diagnostic naming the key and expected value.
    ///
    /// Used for backends that route configuration via env rather than
    /// argv — see the vault backend's `VAULT_ADDR` / `VAULT_NAMESPACE`
    /// paths (PR #33 BUG-1 fix).
    ///
    /// `key` must match `^[A-Za-z_][A-Za-z0-9_]*$` — a POSIX-portable
    /// shell identifier. The generated script uses `${key+set}` and
    /// `"$key"` parameter expansion; a key with spaces, quotes,
    /// semicolons, or other shell metacharacters would break the
    /// generated script or (worse) inject shell. Enforced at call time
    /// via a panic so test authors learn immediately; there is no
    /// legitimate backend use case for a non-identifier env var name.
    ///
    /// # Panics
    ///
    /// Panics if `key` is empty, starts with a digit, or contains any
    /// character outside `[A-Za-z0-9_]`.
    ///
    /// ```no_run
    /// # use secretenv_testing::Response;
    /// let r = Response::success("v")
    ///     .with_env_var("VAULT_ADDR", "https://vault.example.com");
    /// ```
    #[must_use]
    pub fn with_env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        assert_env_key_shape(&key);
        self.env_must_contain.push((key, value.into()));
        self
    }

    /// Chainable: require this rule's mock subprocess to have `key` UNSET
    /// in its environment. A set key — even with an empty value — exits
    /// 97 with a diagnostic.
    ///
    /// Used by backends that conditionally pass env vars — e.g. the
    /// vault backend omits `VAULT_NAMESPACE` when a namespace isn't
    /// configured, because open-source Vault rejects the flag outright.
    ///
    /// # Panics
    ///
    /// Panics if `key` does not match `^[A-Za-z_][A-Za-z0-9_]*$`.
    /// See [`Self::with_env_var`] for rationale.
    ///
    /// ```no_run
    /// # use secretenv_testing::Response;
    /// let r = Response::success("v").with_env_absent("VAULT_NAMESPACE");
    /// ```
    #[must_use]
    pub fn with_env_absent(mut self, key: impl Into<String>) -> Self {
        let key = key.into();
        assert_env_key_shape(&key);
        self.env_must_not_contain.push(key);
        self
    }
}

impl StrictMock {
    /// Create an empty strict-mock spec for a binary named `bin_name`.
    pub fn new(bin_name: impl Into<String>) -> Self {
        Self { bin_name: bin_name.into(), rules: Vec::new() }
    }

    /// Add a rule: on the exact argv `argv` (every token matched
    /// literally, in order), emit `response`.
    ///
    /// Tokens are joined with a single space — shell `"$*"` semantics —
    /// and compared as strings. Mock argv tokens may not themselves
    /// contain spaces (breaks the join semantics); for CLI argv this is
    /// effectively never an issue.
    pub fn on(mut self, argv: &[&str], response: Response) -> Self {
        self.rules.push(Rule {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            stdin_must_contain: response.stdin_must_contain,
            env_must_contain: response.env_must_contain,
            env_must_not_contain: response.env_must_not_contain,
            stdout: response.stdout,
            stderr: response.stderr,
            exit_code: response.exit_code,
        });
        self
    }

    /// Render the declared rules as a POSIX shell script, write it to
    /// `dir/<bin_name>`, chmod 0o755, probe-retry past the Linux
    /// ETXTBSY race, and return the installed path.
    ///
    /// # Panics
    ///
    /// Panics on any filesystem failure — test helpers are expected to
    /// fail loudly so breakage surfaces as a clear message rather than
    /// a downstream mystery.
    #[must_use]
    pub fn install(self, dir: &Path) -> PathBuf {
        let body = self.render();
        super::install_mock(dir, &self.bin_name, &body)
    }

    // write! / writeln! into String is infallible (no I/O), so the
    // Result arms never fire at runtime — the unwraps are noise. Allow
    // them for this function only rather than littering `.ok()` or
    // `let _ =` everywhere.
    #[allow(clippy::unwrap_used)]
    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# generated by secretenv-testing::StrictMock (v0.2.2)\n");
        writeln!(out, "# bin: {}", self.bin_name).unwrap();
        writeln!(out, "# rules: {}\n", self.rules.len()).unwrap();
        out.push_str("joined_argv=\"$*\"\n");
        let needs_stdin = self.rules.iter().any(|r| !r.stdin_must_contain.is_empty());
        if needs_stdin {
            // Buffer stdin once up-front; matching rules below re-check
            // it via POSIX grep -F -q. Using `cat` means a rule that
            // doesn't need stdin still drains the pipe cleanly if the
            // caller wrote something (tests shouldn't rely on this but
            // we don't want to leave the parent blocked either).
            out.push_str("stdin_body=\"$(cat)\"\n");
        }
        out.push('\n');

        // Build the no-match diagnostic once — it's appended as the
        // `else` branch below OR emitted directly if there are no rules.
        let mut no_match = String::new();
        no_match.push_str("{\n");
        writeln!(
            no_match,
            "    echo \"strict-mock-no-match (bin={})\"",
            escape_for_double_quoted(&self.bin_name)
        )
        .unwrap();
        no_match.push_str("    echo \"  observed: $joined_argv\"\n");
        if self.rules.is_empty() {
            no_match.push_str("    echo \"  expected: <no rules declared>\"\n");
        } else {
            no_match.push_str("    echo \"  expected one of:\"\n");
            for rule in &self.rules {
                let joined = rule.argv.join(" ");
                writeln!(no_match, "    echo \"    {}\"", escape_for_double_quoted(&joined))
                    .unwrap();
            }
        }
        no_match.push_str("  } >&2\n");
        no_match.push_str("  exit 97\n");

        if self.rules.is_empty() {
            // No rules — every invocation is a no-match. Emit the
            // diagnostic directly; avoid an `if true; then <empty>`
            // construct which is a POSIX syntax error.
            out.push_str("  ");
            out.push_str(&no_match.replace("\n    ", "\n  ").replace("\n  }", "\n}"));
            return out;
        }

        // Chain of if/elif: first matching argv wins.
        let mut first = true;
        for rule in &self.rules {
            let joined = rule.argv.join(" ");
            let keyword = if first { "if" } else { "elif" };
            first = false;
            writeln!(out, "{keyword} [ \"$joined_argv\" = {} ]; then", sq_escape(&joined)).unwrap();
            // stdin fragment checks.
            //
            // Diagnostic redaction: tests use `stdin_must_contain` to lock
            // CV-1 discipline — the fragment IS typically the canary
            // secret value. On a mismatch (CV-1 regression), echoing the
            // full fragment to stderr would surface it in `cargo test`
            // output and CI logs. We emit only a fingerprint — the
            // fragment's length and first 4 chars followed by ellipsis —
            // enough to identify which rule failed, not enough to recover
            // the secret.
            for frag in &rule.stdin_must_contain {
                writeln!(
                    out,
                    "  printf '%s' \"$stdin_body\" | grep -F -q -- {} || {{",
                    sq_escape(frag)
                )
                .unwrap();
                writeln!(
                    out,
                    "    echo \"strict-mock stdin mismatch (bin={}): expected stdin to contain fragment {}\" >&2",
                    escape_for_double_quoted(&self.bin_name),
                    escape_for_double_quoted(&redact_fragment(frag))
                )
                .unwrap();
                out.push_str("    exit 97\n");
                out.push_str("  }\n");
            }
            // env must-contain checks — use POSIX parameter expansion
            // (`${KEY+set}`, `"$KEY"`) so values with spaces, quotes,
            // and regex metacharacters don't need grep-level escaping.
            for (key, value) in &rule.env_must_contain {
                writeln!(
                    out,
                    "  if [ \"${{{key}+set}}\" != \"set\" ] || [ \"${key}\" != {} ]; then",
                    sq_escape(value)
                )
                .unwrap();
                writeln!(
                    out,
                    "    echo \"strict-mock env mismatch (bin={}): expected {key}={}\" >&2",
                    escape_for_double_quoted(&self.bin_name),
                    escape_for_double_quoted(value)
                )
                .unwrap();
                out.push_str("    exit 97\n");
                out.push_str("  fi\n");
            }
            // env must-not-contain checks.
            for key in &rule.env_must_not_contain {
                writeln!(out, "  if [ \"${{{key}+set}}\" = \"set\" ]; then").unwrap();
                writeln!(
                    out,
                    "    echo \"strict-mock env mismatch (bin={}): {key} must not be set\" >&2",
                    escape_for_double_quoted(&self.bin_name)
                )
                .unwrap();
                out.push_str("    exit 97\n");
                out.push_str("  fi\n");
            }
            // stdout + stderr emission
            if !rule.stdout.is_empty() {
                writeln!(out, "  printf '%s' {}", sq_escape(&rule.stdout)).unwrap();
            }
            if !rule.stderr.is_empty() {
                writeln!(out, "  printf '%s' {} >&2", sq_escape(&rule.stderr)).unwrap();
            }
            writeln!(out, "  exit {}", rule.exit_code).unwrap();
        }

        out.push_str("else\n");
        out.push_str("  ");
        out.push_str(&no_match);
        out.push_str("fi\n");

        out
    }
}

/// POSIX-shell single-quote escape: wrap `s` in `'...'`, escaping any
/// embedded `'` as `'\''`. Safe for use as a single-argument literal.
fn sq_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Panics if `key` is not a valid POSIX shell identifier
/// (`^[A-Za-z_][A-Za-z0-9_]*$`). Called from [`Response::with_env_var`]
/// and [`Response::with_env_absent`] to catch malformed keys BEFORE
/// they reach the shell-script generator (where they'd either break
/// the script's parse or, worse, inject arbitrary shell via a crafted
/// value like `"KEY}; rm -rf /; :{"`).
fn assert_env_key_shape(key: &str) {
    assert!(
        !key.is_empty(),
        "strict-mock env key must be non-empty (POSIX identifier ^[A-Za-z_][A-Za-z0-9_]*$)"
    );
    let mut chars = key.chars();
    let Some(first) = chars.next() else { unreachable!("non-empty checked above") };
    assert!(
        first == '_' || first.is_ascii_alphabetic(),
        "strict-mock env key '{key}' must start with a letter or underscore (POSIX identifier)"
    );
    for ch in chars {
        assert!(
            ch == '_' || ch.is_ascii_alphanumeric(),
            "strict-mock env key '{key}' contains invalid char '{ch}' (POSIX identifier)"
        );
    }
}

/// Produce a redacted "fingerprint" of a stdin-fragment for use in
/// shell-script diagnostic output. Full fragment would leak the canary
/// secret value to CI logs on a CV-1 regression. Format:
/// `<len>-byte:<first-4-chars>…`. Short fragments (< 8 bytes) are
/// reported only as `<len>-byte:<redacted>` so no char prefix is
/// exposed.
fn redact_fragment(frag: &str) -> String {
    let len = frag.len();
    if len < 8 {
        format!("{len}-byte:<redacted>")
    } else {
        let prefix: String = frag.chars().take(4).collect();
        format!("{len}-byte:{prefix}…")
    }
}

/// Escape for embedding inside a double-quoted shell string. Only the
/// characters that have special meaning inside `"..."` need escaping:
/// `"`, `\`, `$`, and backtick. Callers MUST NOT pass strings with
/// embedded newlines — a raw newline here would break the generated
/// script's line structure. Panics on `\n` / `\r` to catch bugs early
/// rather than emitting silently-corrupted output.
///
/// # Panics
///
/// Panics if `s` contains `\n` or `\r`. Used for diagnostic strings
/// (bin name, argv joined, redacted fragment fingerprint) which must
/// never contain newlines by construction.
fn escape_for_double_quoted(s: &str) -> String {
    assert!(
        !s.contains('\n') && !s.contains('\r'),
        "escape_for_double_quoted: embedded newline in diagnostic string: {s:?}"
    );
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' | '\\' | '$' | '`' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::process::{Command, Stdio};

    use tempfile::TempDir;

    use super::*;

    /// Run the installed mock with the given argv and optional stdin,
    /// returning `(exit_code, stdout, stderr)`.
    fn run(path: &Path, argv: &[&str], stdin: Option<&str>) -> (i32, String, String) {
        run_with_env(path, argv, &[], stdin)
    }

    /// Run the installed mock with argv, explicit env-var overrides, and
    /// optional stdin. `env_clear()` is NOT called — the parent process's
    /// env propagates through except for the provided overrides.
    fn run_with_env(
        path: &Path,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: Option<&str>,
    ) -> (i32, String, String) {
        let mut cmd = Command::new(path);
        cmd.args(argv);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd.spawn().expect("spawn mock");
        if let Some(s) = stdin {
            use std::io::Write as _;
            let mut stdin_pipe = child.stdin.take().expect("stdin pipe");
            stdin_pipe.write_all(s.as_bytes()).unwrap();
            drop(stdin_pipe);
        }
        let output = child.wait_with_output().expect("wait output");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn exact_argv_match_emits_declared_response() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("aws")
            .on(&["ssm", "get-parameter", "--name", "/foo"], Response::success("the-value\n"))
            .install(dir.path());
        let (code, stdout, stderr) = run(&path, &["ssm", "get-parameter", "--name", "/foo"], None);
        assert_eq!(code, 0);
        assert_eq!(stdout, "the-value\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn argv_mismatch_emits_no_match_diagnostic_and_exits_97() {
        // Expected argv is "ssm get-parameter --name /foo" but the test
        // invokes with "--name /bar" — strict mode rejects.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("aws")
            .on(&["ssm", "get-parameter", "--name", "/foo"], Response::success("x"))
            .install(dir.path());
        let (code, stdout, stderr) = run(&path, &["ssm", "get-parameter", "--name", "/bar"], None);
        assert_eq!(code, 97, "no-match must exit 97");
        assert!(stdout.is_empty());
        assert!(stderr.contains("strict-mock-no-match"));
        assert!(stderr.contains("observed: ssm get-parameter --name /bar"));
        assert!(stderr.contains("ssm get-parameter --name /foo"), "lists expected: {stderr}");
    }

    #[test]
    fn extra_flag_in_invocation_is_rejected_even_if_prefix_matches() {
        // This is the v0.2.0 vault BUG-1 class: `case "$1 $2"` matched
        // the prefix and ignored extra flags. Strict mode rejects.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(&["kv", "get", "-format=json", "secret/foo"], Response::success("{}"))
            .install(dir.path());
        let (code, _, stderr) =
            run(&path, &["kv", "get", "-format=json", "secret/foo", "-address=http://bogus"], None);
        assert_eq!(code, 97);
        assert!(stderr.contains("observed:"));
        assert!(stderr.contains("-address=http://bogus"));
    }

    #[test]
    fn value_mismatch_in_argv_is_rejected() {
        // v0.2.0 aws-secrets BUG-2: leading slash in `--secret-id` value.
        // Strict mode compares values byte-for-byte.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("aws")
            .on(
                &["secretsmanager", "get-secret-value", "--secret-id", "myapp/cfg"],
                Response::success("{}"),
            )
            .install(dir.path());
        let (code, _, _) =
            run(&path, &["secretsmanager", "get-secret-value", "--secret-id", "/myapp/cfg"], None);
        assert_eq!(code, 97, "leading-slash value differs — strict mode rejects");
    }

    #[test]
    fn failure_response_returns_declared_exit_and_stderr() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("op")
            .on(
                &["item", "get", "missing-item"],
                Response::failure(
                    254,
                    "[ERROR] 2026/04/19 12:00:00 \"missing-item\" isn't an item.\n",
                ),
            )
            .install(dir.path());
        let (code, stdout, stderr) = run(&path, &["item", "get", "missing-item"], None);
        assert_eq!(code, 254);
        assert!(stdout.is_empty());
        assert!(stderr.contains("isn't an item"));
    }

    #[test]
    fn stdin_check_accepts_when_all_fragments_present() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("aws")
            .on(
                &["ssm", "put-parameter", "--cli-input-json", "file:///dev/stdin"],
                Response::success_with_stdin(
                    "",
                    vec![
                        r#""Name": "/foo""#.to_owned(),
                        r#""Value": "new-val""#.to_owned(),
                        r#""Overwrite": true"#.to_owned(),
                    ],
                ),
            )
            .install(dir.path());
        let stdin =
            r#"{"Name": "/foo", "Value": "new-val", "Type": "SecureString", "Overwrite": true}"#;
        let (code, _, stderr) = run(
            &path,
            &["ssm", "put-parameter", "--cli-input-json", "file:///dev/stdin"],
            Some(stdin),
        );
        assert_eq!(code, 0, "stderr: {stderr}");
    }

    #[test]
    fn stdin_check_rejects_when_fragment_missing() {
        // Secret value `"Value": "new-val"` required on stdin; caller
        // forgets — mock exits 97 naming only a REDACTED fingerprint
        // of the missing fragment (length + first 4 chars), never the
        // full secret. If the redaction regressed, canary values would
        // leak into CI logs on CV-1 test failures.
        let dir = TempDir::new().unwrap();
        let secret_fragment = r#""Value": "new-val""#;
        let path = StrictMock::new("aws")
            .on(
                &["ssm", "put-parameter", "--cli-input-json", "file:///dev/stdin"],
                Response::success_with_stdin("", vec![secret_fragment.to_owned()]),
            )
            .install(dir.path());
        let stdin = r#"{"Name": "/foo"}"#;
        let (code, _, stderr) = run(
            &path,
            &["ssm", "put-parameter", "--cli-input-json", "file:///dev/stdin"],
            Some(stdin),
        );
        assert_eq!(code, 97);
        assert!(stderr.contains("stdin mismatch"), "stderr: {stderr}");
        // Fingerprint present: length prefix + first 4 chars + ellipsis.
        let expected_len = secret_fragment.len();
        assert!(
            stderr.contains(&format!("{expected_len}-byte:")),
            "stderr names fragment length: {stderr}"
        );
        // Canary: the full secret value MUST NOT appear in stderr.
        assert!(
            !stderr.contains("new-val"),
            "secret value leaked to stderr — CV-1 diagnostic redaction regressed: {stderr}"
        );
    }

    #[test]
    fn stdin_fragment_redaction_fingerprint_hides_value_never_leaks_full() {
        // Direct unit test on the redact_fragment helper — documents
        // the contract independent of the shell roundtrip.
        assert_eq!(redact_fragment("short"), "5-byte:<redacted>");
        assert_eq!(redact_fragment("a-bit-longer-value"), "18-byte:a-bi…");
        // Full secret never present.
        let sensitive = "sk_live_TOPSECRET_canary_12345";
        let fp = redact_fragment(sensitive);
        assert!(!fp.contains("TOPSECRET"), "fingerprint must not leak secret: {fp}");
        assert!(!fp.contains("canary"), "fingerprint must not leak secret: {fp}");
    }

    #[test]
    #[should_panic(expected = "POSIX identifier")]
    fn with_env_var_panics_on_empty_key() {
        let _ = Response::success("v").with_env_var("", "val");
    }

    #[test]
    #[should_panic(expected = "POSIX identifier")]
    fn with_env_var_panics_on_leading_digit_key() {
        let _ = Response::success("v").with_env_var("3FOO", "val");
    }

    #[test]
    #[should_panic(expected = "POSIX identifier")]
    fn with_env_var_panics_on_shell_injection_in_key() {
        // A key containing `}; rm -rf / ;` would inject shell into the
        // generated mock if not caught at construction time.
        let _ = Response::success("v").with_env_var("KEY}; rm -rf /; :{", "val");
    }

    #[test]
    #[should_panic(expected = "POSIX identifier")]
    fn with_env_absent_panics_on_invalid_key() {
        let _ = Response::success("v").with_env_absent("has-dash");
    }

    #[test]
    #[should_panic(expected = "embedded newline")]
    fn escape_for_double_quoted_panics_on_newline() {
        let _ = escape_for_double_quoted("line1\nline2");
    }

    #[test]
    fn env_must_contain_accepts_when_key_equals_value() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("v\n").with_env_var("VAULT_ADDR", "https://vault.example.com"),
            )
            .install(dir.path());
        let (code, stdout, stderr) = run_with_env(
            &path,
            &["kv", "get", "-field=value", "secret/x"],
            &[("VAULT_ADDR", "https://vault.example.com")],
            None,
        );
        assert_eq!(code, 0, "stderr: {stderr}");
        assert_eq!(stdout, "v\n");
    }

    #[test]
    fn env_must_contain_rejects_when_value_mismatches() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("v").with_env_var("VAULT_ADDR", "https://vault.example.com"),
            )
            .install(dir.path());
        let (code, _, stderr) = run_with_env(
            &path,
            &["kv", "get", "-field=value", "secret/x"],
            &[("VAULT_ADDR", "https://bogus.example.com")],
            None,
        );
        assert_eq!(code, 97);
        assert!(stderr.contains("env mismatch"), "stderr: {stderr}");
        assert!(stderr.contains("VAULT_ADDR"), "stderr names key: {stderr}");
        assert!(stderr.contains("vault.example.com"), "stderr names expected value: {stderr}");
    }

    #[test]
    fn env_must_contain_rejects_when_key_absent() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("v").with_env_var("VAULT_ADDR", "https://vault.example.com"),
            )
            .install(dir.path());
        // Explicitly omit VAULT_ADDR from the child env.
        let (code, _, stderr) =
            run_with_env(&path, &["kv", "get", "-field=value", "secret/x"], &[], None);
        // Note: if the parent process already has VAULT_ADDR set, this
        // test's value may inadvertently match. Tests in this crate
        // don't set VAULT_ADDR, but a developer running with vault
        // environment pre-loaded could see a false PASS. The build-log
        // flags this as a known harness quirk.
        if std::env::var_os("VAULT_ADDR").is_none() {
            assert_eq!(code, 97);
            assert!(stderr.contains("env mismatch"), "stderr: {stderr}");
        }
    }

    #[test]
    fn env_must_not_contain_rejects_when_key_set() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("v").with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        let (code, _, stderr) = run_with_env(
            &path,
            &["kv", "get", "-field=value", "secret/x"],
            &[("VAULT_NAMESPACE", "engineering")],
            None,
        );
        assert_eq!(code, 97);
        assert!(stderr.contains("env mismatch"), "stderr: {stderr}");
        assert!(stderr.contains("VAULT_NAMESPACE"), "stderr names key: {stderr}");
        assert!(stderr.contains("must not be set"), "stderr describes violation: {stderr}");
    }

    #[test]
    fn env_must_not_contain_accepts_when_key_absent() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("vault")
            .on(
                &["kv", "get", "-field=value", "secret/x"],
                Response::success("ok").with_env_absent("VAULT_NAMESPACE"),
            )
            .install(dir.path());
        // Only VAULT_ADDR propagates (for realism); VAULT_NAMESPACE is
        // deliberately NOT set on the child.
        let (code, stdout, stderr) = run_with_env(
            &path,
            &["kv", "get", "-field=value", "secret/x"],
            &[("VAULT_ADDR", "https://vault.example.com")],
            None,
        );
        if std::env::var_os("VAULT_NAMESPACE").is_none() {
            assert_eq!(code, 0, "stderr: {stderr}");
            assert_eq!(stdout, "ok");
        }
    }

    #[test]
    fn env_value_with_special_chars_is_quoted_safely() {
        // Value contains a single quote, a dollar sign, and a space —
        // sq_escape + parameter-expansion comparison should survive all
        // three.
        let dir = TempDir::new().unwrap();
        let nasty = "it's $HOME + space";
        let path = StrictMock::new("x")
            .on(&["probe"], Response::success("ok").with_env_var("WEIRD_KEY", nasty))
            .install(dir.path());
        let (code, stdout, stderr) = run_with_env(&path, &["probe"], &[("WEIRD_KEY", nasty)], None);
        assert_eq!(code, 0, "stderr: {stderr}");
        assert_eq!(stdout, "ok");
    }

    #[test]
    fn first_matching_rule_wins() {
        // Two rules with overlapping argv: the one registered first wins.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("x")
            .on(&["a", "b"], Response::success("first"))
            .on(&["a", "b"], Response::success("second"))
            .install(dir.path());
        let (_, stdout, _) = run(&path, &["a", "b"], None);
        assert_eq!(stdout, "first");
    }

    #[test]
    fn empty_argv_matches_declared_empty_argv() {
        // Mock declared with `on(&[], ...)` — runtime invocation with
        // no argv (just the bin name) matches the empty-joined form.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("x").on(&[], Response::success("empty")).install(dir.path());
        let (code, stdout, _) = run(&path, &[], None);
        assert_eq!(code, 0);
        assert_eq!(stdout, "empty");
    }

    #[test]
    fn no_rules_declared_always_no_matches() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("x").install(dir.path());
        let (code, _, stderr) = run(&path, &["anything"], None);
        assert_eq!(code, 97);
        assert!(stderr.contains("<no rules declared>"));
    }

    #[test]
    fn embedded_single_quote_in_argv_token_does_not_break_shell() {
        // Apostrophe in an argv value (e.g. `--name "what's this"`) must
        // be quoted correctly in the generated script.
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("x")
            .on(&["--tag", "it's-mine"], Response::success("ok"))
            .install(dir.path());
        let (code, stdout, _) = run(&path, &["--tag", "it's-mine"], None);
        assert_eq!(code, 0);
        assert_eq!(stdout, "ok");
    }

    #[test]
    fn embedded_dollar_in_argv_token_does_not_expand() {
        let dir = TempDir::new().unwrap();
        let path = StrictMock::new("x")
            .on(&["--value", "${HOME}"], Response::success("ok"))
            .install(dir.path());
        // The mock should match `${HOME}` as a literal 7-char string, not
        // the expansion of $HOME.
        let (code, stdout, _) = run(&path, &["--value", "${HOME}"], None);
        assert_eq!(code, 0);
        assert_eq!(stdout, "ok");
    }

    #[test]
    #[should_panic(expected = "non-zero exit code")]
    fn response_failure_with_zero_exit_panics() {
        let _ = Response::failure(0, "oops");
    }
}
