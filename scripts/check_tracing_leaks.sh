#!/usr/bin/env bash
# SEC-INV-17 — Tracing leak guard.
#
# Refuses any `tracing::(error|warn|info|debug|trace)!` macro call
# that interpolates a known value-bearing identifier (`{value}`,
# `{secret}`, `{value.expose_secret(...)}`, `{uri.raw}`, `{stdin}`,
# `{stdout}`, `{stderr}` when bound to a Vec<u8> body) OR that names
# `Secret::expose_secret` inside the macro argument list.
#
# Local pre-push: `bash scripts/check_tracing_leaks.sh`.
# CI: `.github/workflows/ci.yml::tracing-leak-guard` job runs this.
#
# Exit codes:
#   0 — no leak patterns found (proceed)
#   1 — at least one match (build fails)
#
# This is a defense-in-depth grep gate. The structural protections
# are:
#   - `Secret<T>` newtype (no Display impl)
#   - `EnvEntry::value` cfg-gated under `not(mcp-safe)`
#   - `expose_secret` cfg-gated under `not(mcp-safe)`
# but a careless `tracing::warn!("got value: {}", entry.value())`
# is reachable in non-mcp-safe code today. This grep catches it.

set -euo pipefail

# ripgrep is preinstalled on ubuntu-latest GH Actions runners. Not
# present on stock macOS — the local pre-push falls back to grep
# across multiple invocations to approximate the multiline match.
command -v rg >/dev/null 2>&1 || {
    echo "scripts/check_tracing_leaks.sh: ripgrep (rg) is required" >&2
    echo "  install: brew install ripgrep" >&2
    exit 2
}

cd "$(dirname "$0")/.."

fail=0

# 1. Direct interpolation of a `{value}` / `{secret}` / `{stdin}` /
#    `{stdout}` / `{stderr}` placeholder inside a tracing macro arg.
#    The macro can span multiple lines (rustfmt likes to wrap), so
#    --multiline -U.
if rg --multiline -U --type=rust \
   'tracing::(error|warn|info|debug|trace)!\([^)]*\{(value|secret|stdin|stdout|stderr|raw_stdout|raw_stderr|expose_secret)[^}]*\}' \
   crates/; then
    echo "FAIL: tracing macro interpolates a value-bearing placeholder."
    fail=1
fi

# 2. Any `Secret::expose_secret` reference inside a tracing macro
#    argument list. Catches both `expose_secret()` direct calls and
#    `_value.expose_secret()` member-style.
if rg --multiline -U --type=rust \
   'tracing::(error|warn|info|debug|trace)!\([^)]*expose_secret' \
   crates/; then
    echo "FAIL: tracing macro references expose_secret() directly."
    fail=1
fi

# 3. Direct interpolation of `{uri.raw}` — the raw URI carries the
#    full backend path (Tier-1 DENY per the v0.14+ §6 attribute
#    matrix). `{uri}` alone is fine because BackendUri's Display
#    impl emits `<scheme>://...` without the path.
if rg --multiline -U --type=rust \
   'tracing::(error|warn|info|debug|trace)!\([^)]*\{uri\.raw\}' \
   crates/; then
    echo "FAIL: tracing macro interpolates uri.raw (Tier-1 DENY)."
    fail=1
fi

# 4. Catch the structured-fields form: `tracing::warn!(value = ?...)`
#    or `tracing::info!(value = %entry.value())`. The structured form
#    bypasses the placeholder check above.
#
#    v0.14.x DiD chip M3: tightened to require a `?` or `%` sigil.
#    The previous form `\bvalue\s*=` matched any field literally named
#    `value` (e.g. an unrelated config default); the sigil requirement
#    restricts to the actual tracing-structured-field form, which is
#    where the SEC-INV-17 leak lives. LHS stays scoped to `value`
#    only — backend-specific structured fields like `secret = %t.secret`
#    (doppler key name) are non-value-bearing and intentionally allowed.
if rg --multiline -U --type=rust \
   'tracing::(error|warn|info|debug|trace)!\([^)]*\bvalue\s*=\s*[?%]' \
   crates/; then
    echo "FAIL: tracing macro uses structured field 'value = ?/%...'."
    fail=1
fi

# 5. v0.14.x DiD chip M3: catch `event!(Level::INFO, ...)` form. The
#    `event!` macro is the macro-generic path that the level-named
#    macros expand to; a future call site that uses it directly
#    would bypass checks 1-4.
if rg --multiline -U --type=rust \
   '(\btracing::)?event!\([^)]*Level::[A-Z]+,[^)]*\{(value|secret|stdin|stdout|stderr|raw_stdout|raw_stderr|expose_secret)' \
   crates/; then
    echo "FAIL: tracing event!(Level::..) macro interpolates a value-bearing placeholder."
    fail=1
fi
if rg --multiline -U --type=rust \
   '(\btracing::)?event!\([^)]*Level::[A-Z]+,[^)]*\bvalue\s*=\s*[?%]' \
   crates/; then
    echo "FAIL: tracing event!(Level::..) uses structured field 'value = ?/%...'."
    fail=1
fi
if rg --multiline -U --type=rust \
   '(\btracing::)?event!\([^)]*Level::[A-Z]+,[^)]*expose_secret' \
   crates/; then
    echo "FAIL: tracing event!(Level::..) references expose_secret() directly."
    fail=1
fi

# 6. v0.14.x DiD chip M3: catch `Span::current().record("value", ...)`
#    and `span.record("value", ...)` — the direct attribute-setter
#    path that bypasses macro-arg parsing entirely.
if rg --multiline -U --type=rust \
   '\.record\(\s*"(value|secret|stdin|stdout|stderr|raw_stdout|raw_stderr|expose_secret|uri\.raw)"' \
   crates/; then
    echo "FAIL: span.record(\"value\", ...) sets a value-bearing structured attribute."
    fail=1
fi

# 7. v0.14.x DiD chip M3: catch bare `warn!`/`info!`/`error!`/`debug!`/
#    `trace!` macros (after a `use tracing::warn;` in scope) that
#    interpolate a value-bearing placeholder. Scoped to .rs files
#    that import `tracing::` to avoid false positives on unrelated
#    macros of the same name.
bare_macro_hits=$(rg --multiline -U --type=rust --files-with-matches \
    '^use tracing::' crates/ 2>/dev/null || true)
if [ -n "$bare_macro_hits" ]; then
    while IFS= read -r f; do
        if rg --multiline -U \
           '(^|[^A-Za-z0-9_:])(error|warn|info|debug|trace)!\([^)]*\{(value|secret|stdin|stdout|stderr|raw_stdout|raw_stderr|expose_secret)[^}]*\}' \
           "$f"; then
            echo "FAIL: bare tracing macro in $f interpolates a value-bearing placeholder."
            fail=1
        fi
        if rg --multiline -U \
           '(^|[^A-Za-z0-9_:])(error|warn|info|debug|trace)!\([^)]*\bvalue\s*=\s*[?%]' \
           "$f"; then
            echo "FAIL: bare tracing macro in $f uses structured field 'value = ?/%...'."
            fail=1
        fi
        if rg --multiline -U \
           '(^|[^A-Za-z0-9_:])(error|warn|info|debug|trace)!\([^)]*expose_secret' \
           "$f"; then
            echo "FAIL: bare tracing macro in $f references expose_secret() directly."
            fail=1
        fi
    done <<< "$bare_macro_hits"
fi

if [ "$fail" -eq 0 ]; then
    echo "ok: no SEC-INV-17 tracing-leak patterns found in crates/"
fi
exit "$fail"
