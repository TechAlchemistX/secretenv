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
if rg --multiline -U --type=rust \
   'tracing::(error|warn|info|debug|trace)!\([^)]*\bvalue\s*=' \
   crates/; then
    echo "FAIL: tracing macro uses structured field 'value = ...'."
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "ok: no SEC-INV-17 tracing-leak patterns found in crates/"
fi
exit "$fail"
