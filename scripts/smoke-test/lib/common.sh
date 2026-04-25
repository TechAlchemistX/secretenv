#!/usr/bin/env bash
# Shared harness helpers — sourced by provision.sh / run-tests.sh / teardown.sh.
# Resolves env-driven paths + cloud identifiers + the secretenv binary.
# Do not execute directly.

# Directory of the CALLING script (provision / run-tests / teardown).
# Works whether the script is sourced or invoked by path.
_self="${BASH_SOURCE[1]:-$0}"
SMOKE_DIR="${SMOKE_DIR:-$(cd "$(dirname "$_self")" && pwd)}"
FIXTURES_DIR="$SMOKE_DIR/fixtures"

# Transient runtime directory — staging area for fixtures + run logs.
# Default /tmp/secretenv-test keeps history: the v0.2-v0.4 validation runs
# all used this path. Override by exporting SECRETENV_SMOKE_RUNTIME.
RUNTIME_DIR="${SECRETENV_SMOKE_RUNTIME:-/tmp/secretenv-test}"

# Cloud identifiers.
AWS_REGION="${SECRETENV_TEST_AWS_REGION:-us-east-1}"
GCP_PROJECT="${SECRETENV_TEST_GCP_PROJECT:-}"
AZURE_VAULT="${SECRETENV_TEST_AZURE_VAULT:-}"

# secretenv binary — prefer an explicit override, fall back to target/release
# from the repo root of whichever checkout this harness lives in.
REPO_ROOT="$(git -C "$SMOKE_DIR" rev-parse --show-toplevel 2>/dev/null || echo "")"
BIN="${SECRETENV_BIN:-${REPO_ROOT}/target/release/secretenv}"

# ---- helpers ---------------------------------------------------------------

# Fail fast if the cloud IDs aren't set. Call from provision.sh + teardown.sh,
# plus any run-tests.sh invocation that touches cloud backends.
require_cloud_env() {
    local missing=0
    if [ -z "$GCP_PROJECT" ]; then
        echo "ERROR: SECRETENV_TEST_GCP_PROJECT is not set (your GCP project ID)" >&2
        missing=1
    fi
    if [ -z "$AZURE_VAULT" ]; then
        echo "ERROR: SECRETENV_TEST_AZURE_VAULT is not set (your Azure Key Vault name)" >&2
        missing=1
    fi
    if [ "$missing" = "1" ]; then
        echo "See scripts/smoke-test/README.md for setup." >&2
        exit 2
    fi
}

# Fail if the built binary is missing. Callers that only need fixtures
# (e.g. teardown.sh) skip this.
require_bin() {
    if [ ! -x "$BIN" ]; then
        echo "ERROR: secretenv binary not found at $BIN" >&2
        echo "Build it first: (cd \"$REPO_ROOT\" && cargo build --release)" >&2
        echo "Or set SECRETENV_BIN to an explicit path." >&2
        exit 2
    fi
}

# Substitute sentinel placeholders in a fixture file.
# Usage: render_fixture <src> <dst>
#
# Cloud identifiers fall back to syntactically-valid placeholders so the
# rendered config still parses when the user is running --local-only and
# hasn't exported SECRETENV_TEST_GCP_PROJECT / SECRETENV_TEST_AZURE_VAULT.
# The placeholders fail loudly if a cloud backend is actually invoked, but
# offline sections (1, 12, 18, 20) load the config and never touch them.
render_fixture() {
    local src="$1" dst="$2"
    local _gcp="${GCP_PROJECT:-placeholder-project}"
    local _azure="${AZURE_VAULT:-placeholder-vault}"
    mkdir -p "$(dirname "$dst")"
    sed \
        -e "s|@@RUNTIME_DIR@@|${RUNTIME_DIR}|g" \
        -e "s|@@GCP_PROJECT@@|${_gcp}|g" \
        -e "s|@@AZURE_VAULT@@|${_azure}|g" \
        "$src" > "$dst"
}

# Seed the runtime directory from the checked-in fixtures/ tree.
# Called by provision.sh before any cloud work so the local side is
# always consistent with the checked-in templates.
seed_runtime_from_fixtures() {
    mkdir -p "$RUNTIME_DIR/runs"

    # local-secrets — scalar secret values (not real, fine to commit).
    mkdir -p "$RUNTIME_DIR/local-secrets"
    cp -p "$FIXTURES_DIR/local-secrets/stripe-key.txt" \
          "$RUNTIME_DIR/local-secrets/stripe-key.txt"

    # local-registry — alias-to-URI map; needs @@RUNTIME_DIR@@ substituted.
    render_fixture \
        "$FIXTURES_DIR/local-registry/registry.toml" \
        "$RUNTIME_DIR/local-registry/registry.toml"

    # config.toml — backend wiring; needs GCP/Azure identifiers substituted.
    render_fixture \
        "$FIXTURES_DIR/config/secretenv/config.toml" \
        "$RUNTIME_DIR/config/secretenv/config.toml"

    # project-repo — the per-project manifest under test.
    mkdir -p "$RUNTIME_DIR/project-repo"
    cp -p "$FIXTURES_DIR/project-repo/secretenv.toml" \
          "$RUNTIME_DIR/project-repo/secretenv.toml"

    # v0.4 Section 17 prereq: local-secrets must be a git repo so
    # `registry history` has commits to walk. The second commit just
    # appends a trailing newline so the scalar value read by earlier
    # sections stays identical (tests in Sections 4-8 assert the
    # exact stripe-key payload).
    #
    # v0.9.1 robustness: the previous `[ ! -d .git ]` check
    # incorrectly skipped re-init when the .git directory existed
    # but was broken (e.g., empty from a prior failed run); v0.9
    # pre-tag smoke caught 8 history-section failures stuck on this
    # state. Use `git rev-parse --git-dir` as the validity gate
    # instead — it succeeds only when the repo is functional.
    needs_init=1
    if [ -d "$RUNTIME_DIR/local-secrets/.git" ]; then
        if ( cd "$RUNTIME_DIR/local-secrets" && git rev-parse --git-dir >/dev/null 2>&1 ); then
            needs_init=0
        else
            # Broken .git — wipe and reinit fresh.
            rm -rf "$RUNTIME_DIR/local-secrets/.git"
        fi
    fi
    if [ "$needs_init" = "1" ]; then
        (
            cd "$RUNTIME_DIR/local-secrets"
            git init -q
            git config user.email "smoke-test@secretenv.io"
            git config user.name  "SecretEnv Smoke Test"
            git add stripe-key.txt
            git commit -q -m "seed: initial stripe-key fixture"
            printf '\n' >> stripe-key.txt
            git add stripe-key.txt
            git commit -q -m "touch: trailing newline"
        )
    fi
}
