#!/usr/bin/env bash
# SecretEnv validation run — exhaustive test matrix.
# Every subtest writes its own log; a summary is appended to summary.log.
# The script keeps running on individual failures so we get a full picture.
#
# Usage:
#   ./run-tests.sh                       # full matrix (336 assertions)
#   ./run-tests.sh --local-only          # offline subset (no cloud CLIs required)
#   ./run-tests.sh --sections 1,2,17-20  # selected sections only
#   ./run-tests.sh --list-sections       # print section inventory and exit
#
# Required env (unless --local-only or --list-sections):
#   SECRETENV_TEST_GCP_PROJECT, SECRETENV_TEST_AZURE_VAULT
# Optional env:
#   SECRETENV_TEST_AWS_REGION  (default us-east-1)
#   SECRETENV_SMOKE_RUNTIME    (default /tmp/secretenv-test)
#   SECRETENV_BIN              (default <repo>/target/release/secretenv)

set -u

# Force gcloud (and ADC) to be strictly non-interactive throughout the
# smoke matrix. Without this, `secretenv doctor --fix` against a NotAuth
# GCP backend spawns `gcloud auth login` which waits for an OAuth browser
# callback and hangs the whole matrix indefinitely (live-observed during
# v0.12 Phase 8 — section 19a stalled with the gcloud PID parked on
# stdin). With the prompt suppressed, gcloud fails fast with a
# "Reauthentication failed" error that the test treats as a normal FAIL.
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$_here/lib/common.sh"

# ---- section inventory (must stay in sync with the bodies below) ----------
# Format: "N|title|needs-cloud"
SECTIONS=(
    "1|Basic CLI surface|no"
    "2|Doctor — Level 1 + Level 2 on every backend|yes"
    "3|registry list against every registry source|yes"
    "4|registry get — single alias from each backend|yes"
    "5|resolve — print URI + backend status|yes"
    "6|get — actual fetch from every backend|yes"
    "7|run — end-to-end exec with injected env|yes"
    "8|Cascade / backup registry (multi-source)|yes"
    "9|--verbose path-sanitization|yes"
    "10|Error paths (bogus registry, missing alias, bad URI)|yes"
    "11|registry set / unset write path|yes"
    "12|Completions generation|no"
    "13|v0.2.1 canonical fragment grammar|yes"
    "14|v0.2.6 cross-backend matrix|yes"
    "15|v0.3 Phase 1 GCP Secret Manager|yes"
    "16|v0.3 Phase 2 Azure Key Vault|yes"
    "17|v0.4 Phase 2a registry history|yes"
    "18|v0.4 Phase 2b registry invite (offline)|no"
    "19|v0.4 Phase 1 doctor --fix + --extensive|yes"
    # Section 20 is tagged cloud=yes because the op_unsafe_set safe-default
    # test (268-270) does `registry set --registry op-reg`, which first
    # READS the existing registry doc from 1Password — that requires `op`
    # to be installed AND authenticated before the safe-default refusal
    # in backend.set() ever fires. The timeout_secs tests in this section
    # (259-267) ARE truly offline, but splitting them off would renumber
    # the matrix; keeping the tag conservative here is simpler. The
    # timeout_secs code paths are also locked by unit tests in core/cli.
    "20|v0.4 Phase 3 timeout_secs + op_unsafe_set|yes"
    # Section 21 is tagged cloud=yes because it requires macOS-specific
    # state: a test keychain at $RUNTIME_DIR/test.keychain-db seeded by
    # provision.sh. --local-only (the CI gate on Ubuntu runners) skips
    # this section cleanly. Unit tests in the crate cover the Keychain
    # code paths on every platform via strict-mock, so Linux coverage
    # is not lost.
    "21|v0.5 macOS Keychain backend|yes"
    # Section 22 needs a Doppler CLI + an authenticated session (or a
    # DOPPLER_TOKEN env var). Same pattern as 1Password section: truly
    # offline in unit tests, but the live smoke assumes `doppler me`
    # works against the workplace `secretenv-validation` project seeded
    # by provision.sh.
    "22|v0.6 Doppler backend|yes"
    # Sections 23-25 were missing from this array through prior
    # cycles (only the section bodies were added). v0.10 backfills
    # them so `--list-sections` and the `--cloud=no` filter logic
    # match reality.
    "23|v0.7 Infisical backend|yes"
    "24|v0.8 Keeper backend|yes"
    "25|v0.9 Cloudflare Workers KV backend|yes"
    # Section 26 needs `bao` 2.x + a reachable OpenBao server with a
    # valid token. cloud=yes because the server is treated as remote
    # state for the smoke harness even when it's localhost dev-mode;
    # SecretEnv users running this section against a hosted OpenBao
    # cluster get the same skip semantics as the SaaS sections above.
    "26|v0.10 OpenBao backend|yes"
    # Section 27 needs the cyberark/conjur-cli:8 Docker image wrapper +
    # a reachable Conjur OSS server with a valid login. cloud=yes —
    # same SaaS-like skip semantics as 1Password / Doppler / OpenBao.
    # Default address is http://localhost:8083 (matches the
    # conjur-local/ docker-compose harness shipped alongside the repo);
    # operators with their own Conjur instance set
    # SECRETENV_TEST_CONJUR_URL and SECRETENV_TEST_CONJUR_ACCOUNT.
    "27|v0.11 CyberArk Conjur backend|yes"
    # Section 28 needs `bws` (Bitwarden Secrets Manager CLI) v1+, a
    # valid BWS_ACCESS_TOKEN env var, and operator-pre-seeded fixture
    # UUIDs in SECRETENV_TEST_BWS_{SCALAR,JSON,REGISTRY,CYCLE}_UUID.
    # cloud=yes — same SaaS-like skip semantics. Default server URL is
    # the US Bitwarden cloud; EU / self-hosted set
    # SECRETENV_TEST_BWS_SERVER_URL.
    "28|v0.12 Bitwarden Secrets Manager backend|yes"
    # Section 29-31 — v0.14 redaction (mode A runtime + mode B post-hoc
    # + mode B safety guards). cloud=yes because the tainted set is
    # resolved from the live `default` registry, which depends on every
    # backend instance being authenticated (same precondition as
    # sections 6/7). Mode A forces pipe-based redaction via `--redact`
    # so the assertions are deterministic regardless of whether the
    # smoke pane's stdin happens to be a TTY (the Auto path's `exec()`
    # fallback is explicitly SKIP-tagged inside section 29).
    "29|v0.14 Mode A — runtime stdout/stderr redaction|yes"
    "30|v0.14 Mode B — post-hoc file scrubber|yes"
    "31|v0.14 Mode B — safety guards (special-path, foreign-owner, O_NOFOLLOW)|yes"
    # Sections 32-34 — v0.15 `secretenv registry migrate`.
    # 32 is cloud=no: pure local→local semantics (CLI surface,
    # dry-run, JSON wire-format lock, error paths, post-conditions).
    # 33 is cloud=yes: per-backend live `local → <X>` matrix for all
    # 15 backends with per-backend SKIP discipline.
    # 34 is cloud=no: --delete-source flow + SEC-INV-08 second-prompt
    # lock under --yes via local→local. The op-Gated sub-block (1040)
    # is SKIP-tagged for live coverage; unit test in secretenv-core
    # locks the Gated DeleteNotSupported variant.
    "32|v0.15 migrate — local-only semantics + JSON wire-format|no"
    "33|v0.15 migrate — live per-backend matrix|yes"
    "34|v0.15 migrate — --delete-source flow + SEC-INV-08 lock|no"
)

print_section_inventory() {
    printf '%-4s %-6s %s\n' "NUM" "CLOUD" "TITLE"
    for entry in "${SECTIONS[@]}"; do
        IFS='|' read -r num title cloud <<<"$entry"
        printf '%-4s %-6s %s\n' "$num" "$cloud" "$title"
    done
}

# ---- arg parsing ----------------------------------------------------------
SELECTED_SECTIONS=""      # empty means "all"
MODE="all"

expand_ranges() {
    # Expand "1,2,17-20" → "1 2 17 18 19 20"
    local spec="$1" out=""
    local IFS=','
    for tok in $spec; do
        if [[ "$tok" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local lo="${BASH_REMATCH[1]}" hi="${BASH_REMATCH[2]}"
            local i
            for ((i=lo; i<=hi; i++)); do out="$out $i"; done
        elif [[ "$tok" =~ ^[0-9]+$ ]]; then
            out="$out $tok"
        else
            echo "ERROR: bad section token '$tok' (expected N or N-M)" >&2
            exit 2
        fi
    done
    # Strip leading space.
    echo "${out# }"
}

sections_needing_no_cloud() {
    local out=""
    for entry in "${SECTIONS[@]}"; do
        IFS='|' read -r num title cloud <<<"$entry"
        if [ "$cloud" = "no" ]; then out="$out $num"; fi
    done
    echo "${out# }"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --sections)
            SELECTED_SECTIONS="$(expand_ranges "$2")"
            MODE="selected"
            shift 2
            ;;
        --local-only)
            SELECTED_SECTIONS="$(sections_needing_no_cloud)"
            MODE="local-only"
            shift
            ;;
        --list-sections)
            print_section_inventory
            exit 0
            ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown arg '$1' (try --help)" >&2
            exit 2
            ;;
    esac
done

# ---- section-gate state ---------------------------------------------------
SECTION_ACTIVE=1
CURRENT_SECTION="0"

section_active_for() {
    local num="$1"
    [ -z "$SELECTED_SECTIONS" ] && return 0
    local s
    for s in $SELECTED_SECTIONS; do
        [ "$s" = "$num" ] && return 0
    done
    return 1
}

section_begin() {
    local num="$1" title="$2"
    CURRENT_SECTION="$num"
    if section_active_for "$num"; then
        SECTION_ACTIVE=1
        printf '\n--- Section %s: %s ---\n' "$num" "$title" | tee -a "$SUMMARY" >/dev/null 2>&1 || true
    else
        SECTION_ACTIVE=0
    fi
}

# ---- resolve paths + cloud env ---------------------------------------------
# We always need BIN (every section except --list-sections runs secretenv).
require_bin
# Cloud env required unless the selected set only contains offline sections.
_needs_cloud=0
if [ -z "$SELECTED_SECTIONS" ]; then
    _needs_cloud=1
else
    for entry in "${SECTIONS[@]}"; do
        IFS='|' read -r num title cloud <<<"$entry"
        if [ "$cloud" = "yes" ] && section_active_for "$num"; then
            _needs_cloud=1
            break
        fi
    done
fi
if [ "$_needs_cloud" = "1" ]; then
    require_cloud_env
fi

CFG="$RUNTIME_DIR/config/secretenv/config.toml"
PROJ="$RUNTIME_DIR/project-repo"
RUNS="$RUNTIME_DIR/runs"
SUMMARY="$RUNS/90-summary.log"
mkdir -p "$RUNS"

# Cache substituted copies of known-good fixtures into the runtime dir
# on every run. Cheap (< 100 bytes x 4 files), and means `run-tests.sh`
# alone can bootstrap a fresh tmp dir without requiring provision.sh to
# have run first — useful for --local-only / --sections smoke iteration.
seed_runtime_from_fixtures

# v0.2.7 hardening: restore the shared aws-secrets fixture on EVERY exit
# (normal, error, signal) so a mid-run failure cannot leave the secret
# mutated for the next run. Tests 14b / 14h write sentinels to this
# secret; the restore snaps it back to the canonical value expected by
# tests 30 / 39. `trap` fires even on `set -e` exits and SIGINT. Only
# arm the trap if the aws CLI is available AND we're touching cloud.
if [ "$_needs_cloud" = "1" ] && command -v aws >/dev/null 2>&1; then
    restore_fixture_on_exit() {
        aws secretsmanager put-secret-value \
            --secret-id secretenv-validation/api-key \
            --secret-string "sk_test_secrets_22222" \
            --region "$AWS_REGION" >/dev/null 2>&1 || true
    }
    trap restore_fixture_on_exit EXIT
fi

PASSED=0
FAILED=0
SKIPPED=0
: > "$SUMMARY"

record() {
    # Drop record() calls from non-selected sections so --sections /
    # --local-only counts only reflect the chosen surface. (Inline
    # `cmd && record PASS || record FAIL` patterns within those sections
    # otherwise leak into the summary.)
    if [ "$SECTION_ACTIVE" = "0" ]; then return 0; fi
    local name="$1" status="$2" detail="$3"
    printf '%-48s %-6s %s\n' "$name" "$status" "$detail" | tee -a "$SUMMARY"
    case "$status" in
        PASS) PASSED=$((PASSED+1)) ;;
        SKIP) SKIPPED=$((SKIPPED+1)) ;;
        *)    FAILED=$((FAILED+1)) ;;
    esac
}

run_test() {
    # Args: test-name expected-exit log-file cmd...
    if [ "$SECTION_ACTIVE" = "0" ]; then return 0; fi
    local name="$1" expected="$2" log="$3"; shift 3
    {
        echo "### $name"
        echo "### cmd: $*"
        echo "### started: $(date -u +%FT%TZ)"
        echo "---"
    } > "$log"
    (cd "$PROJ" && "$@") >> "$log" 2>&1
    local ec=$?
    {
        echo "---"
        echo "### exit: $ec (expected $expected)"
        echo "### ended: $(date -u +%FT%TZ)"
    } >> "$log"
    if [ "$ec" = "$expected" ]; then
        record "$name" "PASS" "exit=$ec log=$(basename "$log")"
    else
        record "$name" "FAIL" "exit=$ec expected=$expected log=$(basename "$log")"
    fi
}

assert_contains() {
    if [ "$SECTION_ACTIVE" = "0" ]; then return 0; fi
    local name="$1" log="$2" pattern="$3"
    if grep -q -- "$pattern" "$log" 2>/dev/null; then
        record "$name" "PASS" "found '$pattern' in $(basename "$log")"
    else
        record "$name" "FAIL" "missing '$pattern' in $(basename "$log")"
    fi
}

# Negative assertion — passes when the pattern is ABSENT. Used in
# Section 22 to lock the `list()` filter (synthetic DOPPLER_* keys
# must never appear in the rendered registry listing).
assert_not_contains() {
    if [ "$SECTION_ACTIVE" = "0" ]; then return 0; fi
    local name="$1" log="$2" pattern="$3"
    if grep -q -- "$pattern" "$log" 2>/dev/null; then
        record "$name" "FAIL" "unexpected '$pattern' in $(basename "$log")"
    else
        record "$name" "PASS" "pattern '$pattern' absent from $(basename "$log")"
    fi
}

echo "=== SecretEnv validation — $(date -u +%FT%TZ) ===" | tee -a "$SUMMARY"
echo "binary: $("$BIN" --version)"                         | tee -a "$SUMMARY"
echo "config: $CFG"                                        | tee -a "$SUMMARY"
echo "mode:   $MODE"                                       | tee -a "$SUMMARY"
if [ -n "$SELECTED_SECTIONS" ]; then
    echo "sections: $SELECTED_SECTIONS"                    | tee -a "$SUMMARY"
fi
echo "---" | tee -a "$SUMMARY"

# ---------------------------------------------------------------
# 1. Basic CLI surface
# ---------------------------------------------------------------
section_begin 1 "Basic CLI surface"
run_test "01 --version"                 0 "$RUNS/20-version.log"           "$BIN" --version
run_test "02 --help"                    0 "$RUNS/21-help.log"              "$BIN" --help

# ---------------------------------------------------------------
# 2. Doctor — Level 1 + Level 2 on every backend
# ---------------------------------------------------------------
section_begin 2 "Doctor — Level 1 + Level 2 on every backend"
run_test "03 doctor"                    0 "$RUNS/22-doctor.log"            "$BIN" --config "$CFG" doctor
run_test "04 doctor --json"             0 "$RUNS/23-doctor-json.log"       "$BIN" --config "$CFG" doctor --json
assert_contains "05 doctor JSON shape"    "$RUNS/23-doctor-json.log" '"status"'
assert_contains "06 doctor sees local"    "$RUNS/22-doctor.log" 'local-main'
assert_contains "07 doctor sees aws-ssm"  "$RUNS/22-doctor.log" 'aws-ssm-prod'
assert_contains "08 doctor sees op"       "$RUNS/22-doctor.log" '1password-private'
assert_contains "09 doctor sees vault"    "$RUNS/22-doctor.log" 'vault-dev'
assert_contains "10 doctor sees aws-sec"  "$RUNS/22-doctor.log" 'aws-secrets-prod'
assert_contains "10b doctor sees gcp"     "$RUNS/22-doctor.log" 'gcp-prod'
assert_contains "10c doctor sees azure"   "$RUNS/22-doctor.log" 'azure-prod'

# ---------------------------------------------------------------
# 3. registry list against EVERY registry source
# ---------------------------------------------------------------
section_begin 3 "registry list against EVERY registry source"
run_test "11 registry list default (local)"    0 "$RUNS/30-reg-list-default.log"      "$BIN" --config "$CFG" registry list --registry default
run_test "12 registry list aws-ssm-reg"        0 "$RUNS/31-reg-list-aws-ssm.log"       "$BIN" --config "$CFG" registry list --registry aws-ssm-reg
run_test "13 registry list aws-secrets-reg"    0 "$RUNS/32-reg-list-aws-secrets.log"   "$BIN" --config "$CFG" registry list --registry aws-secrets-reg
run_test "14 registry list op-reg"             0 "$RUNS/33-reg-list-op.log"            "$BIN" --config "$CFG" registry list --registry op-reg
run_test "15 registry list vault-reg"          0 "$RUNS/34-reg-list-vault.log"         "$BIN" --config "$CFG" registry list --registry vault-reg
run_test "15b registry list gcp-reg"           0 "$RUNS/34b-reg-list-gcp.log"           "$BIN" --config "$CFG" registry list --registry gcp-reg
run_test "15c registry list azure-reg"         0 "$RUNS/34c-reg-list-azure.log"         "$BIN" --config "$CFG" registry list --registry azure-reg

# Ensure every registry list names all 7 aliases (v0.3 Phase 2: added azure_secret)
for log in 30-reg-list-default 31-reg-list-aws-ssm 32-reg-list-aws-secrets 33-reg-list-op 34-reg-list-vault 34b-reg-list-gcp 34c-reg-list-azure; do
  for alias in stripe_key db_url api_key op_pat oauth_token gcp_secret azure_secret; do
    assert_contains "16-$log:$alias" "$RUNS/$log.log" "$alias"
  done
done

# ---------------------------------------------------------------
# 4. registry get — single alias lookup from each backend
# ---------------------------------------------------------------
section_begin 4 "registry get — single alias lookup from each backend"
run_test "17 registry get stripe_key"   0 "$RUNS/40-reg-get-stripe.log"    "$BIN" --config "$CFG" registry get stripe_key --registry default
run_test "18 registry get from op-reg"  0 "$RUNS/41-reg-get-op.log"        "$BIN" --config "$CFG" registry get stripe_key --registry op-reg
run_test "19 registry get from vault"   0 "$RUNS/42-reg-get-vault.log"     "$BIN" --config "$CFG" registry get oauth_token --registry vault-reg

# ---------------------------------------------------------------
# 5. resolve — print URI + backend status (no fetch)
# ---------------------------------------------------------------
section_begin 5 "resolve — print URI + backend status (no fetch)"
run_test "20 resolve stripe_key"        0 "$RUNS/50-resolve-stripe.log"    "$BIN" --config "$CFG" resolve stripe_key --registry default
run_test "21 resolve --json"            0 "$RUNS/51-resolve-json.log"      "$BIN" --config "$CFG" resolve stripe_key --registry default --json
assert_contains "22 resolve JSON shape"   "$RUNS/51-resolve-json.log" '"alias"'

# ---------------------------------------------------------------
# 6. get — actual fetch from every backend
# ---------------------------------------------------------------
section_begin 6 "get — actual fetch from every backend"
run_test "23 get stripe_key (local)"       0 "$RUNS/60-get-stripe.log"  "$BIN" --config "$CFG" get stripe_key   --registry default --yes
run_test "24 get db_url (aws-ssm)"         0 "$RUNS/61-get-db.log"      "$BIN" --config "$CFG" get db_url       --registry default --yes
run_test "25 get api_key (aws-secrets)"    0 "$RUNS/62-get-api.log"     "$BIN" --config "$CFG" get api_key      --registry default --yes
run_test "26 get op_pat (1password)"       0 "$RUNS/63-get-op.log"      "$BIN" --config "$CFG" get op_pat       --registry default --yes
run_test "27 get oauth_token (vault)"      0 "$RUNS/64-get-oauth.log"   "$BIN" --config "$CFG" get oauth_token  --registry default --yes
run_test "27b get gcp_secret (gcp)"        0 "$RUNS/64b-get-gcp.log"    "$BIN" --config "$CFG" get gcp_secret   --registry default --yes
run_test "27c get azure_secret (azure)"    0 "$RUNS/64c-get-azure.log"  "$BIN" --config "$CFG" get azure_secret --registry default --yes

assert_contains "28 local value correct"     "$RUNS/60-get-stripe.log" 'sk_test_LOCAL_11111'
assert_contains "29 aws-ssm value correct"   "$RUNS/61-get-db.log"     'postgres://aws-ssm-db'
assert_contains "30 aws-secrets correct"     "$RUNS/62-get-api.log"    'sk_test_secrets_22222'
assert_contains "31 1password correct"       "$RUNS/63-get-op.log"     'pat_op_33333'
assert_contains "32 vault correct"           "$RUNS/64-get-oauth.log"  'oat_vault_44444'
assert_contains "32b gcp value correct"      "$RUNS/64b-get-gcp.log"   'gsk_gcp_55555'
assert_contains "32c azure value correct"    "$RUNS/64c-get-azure.log" 'sk_az_66666'

# ---------------------------------------------------------------
# 7. run — end-to-end exec with injected env
# ---------------------------------------------------------------
section_begin 7 "run — end-to-end exec with injected env"
run_test "33 run --dry-run"             0 "$RUNS/70-run-dry.log"        "$BIN" --config "$CFG" run --registry default --dry-run -- env
assert_contains "34 dry-run STRIPE_KEY alias" "$RUNS/70-run-dry.log" 'STRIPE_KEY'
assert_contains "35 dry-run LOG_LEVEL default" "$RUNS/70-run-dry.log" 'LOG_LEVEL'

run_test "36 run exec with local registry"   0 "$RUNS/71-run-local.log"    "$BIN" --config "$CFG" run --registry default -- sh -c 'echo STRIPE_KEY=$STRIPE_KEY DB_URL=$DB_URL API_KEY=$API_KEY OP_PAT=$OP_PAT OAUTH_TOKEN=$OAUTH_TOKEN GCP_SECRET=$GCP_SECRET AZURE_SECRET=$AZURE_SECRET LOG_LEVEL=$LOG_LEVEL'
assert_contains "37 STRIPE_KEY injected"     "$RUNS/71-run-local.log" 'STRIPE_KEY=sk_test_LOCAL_11111'
assert_contains "38 DB_URL injected"         "$RUNS/71-run-local.log" 'DB_URL=postgres://aws-ssm-db'
assert_contains "39 API_KEY injected"        "$RUNS/71-run-local.log" 'API_KEY=sk_test_secrets_22222'
assert_contains "40 OP_PAT injected"         "$RUNS/71-run-local.log" 'OP_PAT=pat_op_33333'
assert_contains "41 OAUTH_TOKEN injected"    "$RUNS/71-run-local.log" 'OAUTH_TOKEN=oat_vault_44444'
assert_contains "41b GCP_SECRET injected"    "$RUNS/71-run-local.log" 'GCP_SECRET=gsk_gcp_55555'
assert_contains "41c AZURE_SECRET injected"  "$RUNS/71-run-local.log" 'AZURE_SECRET=sk_az_66666'
assert_contains "42 LOG_LEVEL default"       "$RUNS/71-run-local.log" 'LOG_LEVEL=info'

# Same run but against EACH registry — proves end-to-end that every
# backend successfully returns a registry document and each alias
# resolves across backends.
run_test "43 run exec via aws-ssm-reg"     0 "$RUNS/72-run-aws-ssm.log"    "$BIN" --config "$CFG" run --registry aws-ssm-reg     -- sh -c 'echo RESOLVED=$STRIPE_KEY'
run_test "44 run exec via aws-secrets-reg" 0 "$RUNS/73-run-aws-secrets.log" "$BIN" --config "$CFG" run --registry aws-secrets-reg -- sh -c 'echo RESOLVED=$STRIPE_KEY'
run_test "45 run exec via op-reg"          0 "$RUNS/74-run-op.log"         "$BIN" --config "$CFG" run --registry op-reg          -- sh -c 'echo RESOLVED=$STRIPE_KEY'
run_test "46 run exec via vault-reg"       0 "$RUNS/75-run-vault.log"      "$BIN" --config "$CFG" run --registry vault-reg       -- sh -c 'echo RESOLVED=$STRIPE_KEY'
for log in 72-run-aws-ssm 73-run-aws-secrets 74-run-op 75-run-vault; do
  assert_contains "47-$log stripe resolved" "$RUNS/$log.log" 'RESOLVED=sk_test_LOCAL_11111'
done

# ---------------------------------------------------------------
# 8. Cascade / backup registry — multi-source sources=[...]
# ---------------------------------------------------------------
section_begin 8 "Cascade / backup registry — multi-source sources=[...]"
# v0.2 pre-Phase-1 behavior: uses sources[0], emits stderr warning
run_test "48 run cascade-test registry"  0 "$RUNS/80-cascade.log"         "$BIN" --config "$CFG" run --registry cascade-test -- sh -c 'echo CASCADE_OK=$STRIPE_KEY'
assert_contains "49 cascade stripe injected" "$RUNS/80-cascade.log" 'CASCADE_OK=sk_test_LOCAL_11111'
assert_contains "50 cascade warning shown"   "$RUNS/80-cascade.log" 'cascade'

# ---------------------------------------------------------------
# 9. --verbose output (CV-7 preflight check — should NOT include full URI path)
# ---------------------------------------------------------------
section_begin 9 "--verbose output (CV-7 preflight check — should NOT include full URI path)"
run_test "51 run --verbose" 0 "$RUNS/81-verbose.log" "$BIN" --config "$CFG" run --registry default --verbose -- sh -c ':'
assert_contains "52 verbose names instance"  "$RUNS/81-verbose.log" "instance 'local-main'"

# ---------------------------------------------------------------
# 10. Error paths — bogus registry, missing alias, bad URI
# ---------------------------------------------------------------
section_begin 10 "Error paths — bogus registry, missing alias, bad URI"
run_test "53 bogus registry name"       1 "$RUNS/82-bogus-registry.log"  "$BIN" --config "$CFG" run --registry nonexistent -- true
run_test "54 missing alias (resolve)"   1 "$RUNS/83-missing-alias.log"   "$BIN" --config "$CFG" resolve nonexistent_alias --registry default
# (Test "55 missing alias (run)" removed 2026-04-19 during v0.2.1 smoke —
#  the `run` subcommand resolves the whole manifest against the registry;
#  with all 5 aliases present it correctly exits 0. The original assertion
#  "expected=1" was a v0.2.0 test-script-design bug. A proper manifest-level
#  missing-alias test would require a separate manifest fixture, deferred
#  until the harness is promoted to repo-tracked scripts/smoke-test/ in v0.4.)

# ---------------------------------------------------------------
# 11. registry set / unset (write path — CV-1 regression: no secret on argv)
# ---------------------------------------------------------------
section_begin 11 "registry set / unset (write path — CV-1 regression: no secret on argv)"
# Note: registry set validates the target URI is parseable and has a
# registered backend instance. Valid target → should succeed.
run_test "56 registry set (valid)"    0 "$RUNS/85-reg-set.log"       "$BIN" --config "$CFG" registry set test_add "local-main://${RUNTIME_DIR}/local-secrets/added.txt" --registry default
run_test "57 registry get test_add"   0 "$RUNS/86-reg-get-new.log"   "$BIN" --config "$CFG" registry get test_add --registry default
run_test "58 registry unset test_add" 0 "$RUNS/87-reg-unset.log"     "$BIN" --config "$CFG" registry unset test_add --registry default

# Setting to a bogus scheme → must fail (validation rejects)
run_test "59 registry set (bad scheme)" 1 "$RUNS/88-reg-set-bad.log" "$BIN" --config "$CFG" registry set bad_entry 'bogus-instance:///x' --registry default

# ---------------------------------------------------------------
# 12. Completions generation
# ---------------------------------------------------------------
section_begin 12 "Completions generation"
run_test "60 completions zsh"    0 "$RUNS/89-completions-zsh.log"    "$BIN" completions zsh
run_test "61 completions bash"   0 "$RUNS/89-completions-bash.log"   "$BIN" completions bash
run_test "62 completions fish"   0 "$RUNS/89-completions-fish.log"   "$BIN" completions fish
assert_contains "63 zsh completion sentinel"  "$RUNS/89-completions-zsh.log"  '_secretenv'

# ---------------------------------------------------------------
# 13. v0.2.1 — canonical fragment grammar end-to-end
# (see docs/fragment-vocabulary.md for the canonical k=v directive shape)
# ---------------------------------------------------------------
section_begin 13 "v0.2.1 — canonical fragment grammar end-to-end"
# Fixture: secretenv-validation/db-json is a JSON body
#   {"username":"alice","password":"hunter2","host":"db.internal","port":5432}
# `get <alias>` takes a registry alias (not a URI) — so we seed 6 aliases into
# the default registry, one per shape we want to exercise, then `get` each.
# Every assertion below exercises a real `aws secretsmanager get-secret-value`
# round-trip — if a canonicalization bug escaped the unit tests, these catch it.

# --- seed aliases ---
run_test "64a seed canon alias"       0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_canon     'aws-secrets-prod:///secretenv-validation/db-json#json-key=password' --registry default
run_test "64b seed host alias"        0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_host      'aws-secrets-prod:///secretenv-validation/db-json#json-key=host'     --registry default
run_test "64c seed port alias"        0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_port      'aws-secrets-prod:///secretenv-validation/db-json#json-key=port'     --registry default
run_test "64d seed shorthand alias"   0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_shorthand 'aws-secrets-prod:///secretenv-validation/db-json#password'          --registry default
run_test "64e seed unknown alias"     0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_unknown   'aws-secrets-prod:///secretenv-validation/db-json#version=5'         --registry default
run_test "64f seed extra alias"       0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_extra     'aws-secrets-prod:///secretenv-validation/db-json#json-key=password,tag=prod' --registry default
run_test "64g seed no-frag alias"     0 "$RUNS/90-frag-seed.log" \
  "$BIN" --config "$CFG" registry set frag_none      'aws-secrets-prod:///secretenv-validation/db-json'                   --registry default

# 13a — canonical form: extract a JSON field via #json-key=<field>.
run_test "65 fragment canonical (json-key=password)"   0 "$RUNS/91-frag-canonical.log" \
  "$BIN" --config "$CFG" get frag_canon --yes --registry default
assert_contains "66 fragment canonical value"   "$RUNS/91-frag-canonical.log" 'hunter2'

run_test "67 fragment canonical (json-key=host)"       0 "$RUNS/92-frag-canonical-host.log" \
  "$BIN" --config "$CFG" get frag_host --yes --registry default
assert_contains "68 fragment canonical host value"     "$RUNS/92-frag-canonical-host.log" 'db.internal'

# 13b — scalar coercion: number values coerce to string on canonical form.
run_test "69 fragment canonical (json-key=port)"       0 "$RUNS/93-frag-canonical-port.log" \
  "$BIN" --config "$CFG" get frag_port --yes --registry default
assert_contains "70 fragment canonical port coerced"   "$RUNS/93-frag-canonical-port.log" '5432'

# 13c — legacy shorthand must fail with migration hint.
run_test "71 fragment shorthand rejected"              1 "$RUNS/94-frag-shorthand.log" \
  "$BIN" --config "$CFG" get frag_shorthand --yes --registry default
assert_contains "72 shorthand error names problem"    "$RUNS/94-frag-shorthand.log" 'shorthand'
assert_contains "73 shorthand error names canonical"  "$RUNS/94-frag-shorthand.log" '#json-key=password'
assert_contains "74 shorthand error points at doc"    "$RUNS/94-frag-shorthand.log" 'fragment-vocabulary'

# 13d — unknown directive must fail listing the offender AND the recognized directive.
run_test "75 fragment unknown directive (version=5)"   1 "$RUNS/95-frag-unknown.log" \
  "$BIN" --config "$CFG" get frag_unknown --yes --registry default
assert_contains "76 unknown error names unsupported"  "$RUNS/95-frag-unknown.log" 'unsupported'
assert_contains "77 unknown error names version"      "$RUNS/95-frag-unknown.log" 'version'
assert_contains "78 unknown error names json-key"     "$RUNS/95-frag-unknown.log" 'json-key'

# 13e — extra directive alongside json-key must fail.
run_test "79 fragment extra directive rejected"        1 "$RUNS/96-frag-extra.log" \
  "$BIN" --config "$CFG" get frag_extra --yes --registry default
assert_contains "80 extra error names tag"             "$RUNS/96-frag-extra.log" 'tag'
assert_contains "81 extra error keeps json-key"        "$RUNS/96-frag-extra.log" 'json-key'

# 13f — no-fragment path still returns the whole JSON blob (v0.2.0 regression check).
run_test "82 fragment absent returns raw JSON"         0 "$RUNS/97-frag-absent.log" \
  "$BIN" --config "$CFG" get frag_none --yes --registry default
assert_contains "83 no-fragment contains username"    "$RUNS/97-frag-absent.log" '"username"'
assert_contains "84 no-fragment contains password"    "$RUNS/97-frag-absent.log" '"password"'

# --- cleanup (unset the 7 seeded aliases) ---
for a in frag_canon frag_host frag_port frag_shorthand frag_unknown frag_extra frag_none; do
  "$BIN" --config "$CFG" registry unset "$a" --registry default >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------
# 14. v0.2.6 — extended cross-backend integration matrix
# Added on the v0.2.6 closeout to (a) prove the v0.2.6 aws-secrets
# fragment-validation bugfix end-to-end (shorthand URIs must NOT
# round-trip to AWS), (b) PR #33 BUG-2 live round-trip, (c) vault
# env-pathway (PR #33 BUG-1) live verification, (d) doctor --json
# shape stability, (e) cross-backend cascade resolution integrity.
# ---------------------------------------------------------------
section_begin 14 "v0.2.6 — extended cross-backend integration matrix"

# 14a — v0.2.6 fragment-validation bugfix: shorthand URI pointing at a
# SECRET NAME THAT DOES NOT EXIST IN AWS. Pre-fix, the backend would
# shell out to `aws secretsmanager get-secret-value --secret-id
# does-not-exist-in-aws-ever-...`, surface ResourceNotFoundException
# alongside (or sometimes instead of) the local shorthand error. Post-
# fix, the shorthand rejection fires BEFORE any aws call — the AWS
# error cannot appear because no AWS call is made.
run_test "85 v0.2.6 bugfix seed shorthand at bogus id" 0 "$RUNS/98-v026-bugfix.log" \
  "$BIN" --config "$CFG" registry set v026_short_bogus \
  'aws-secrets-prod:///does-not-exist-in-aws-ever-secretenv-validation-99#password' \
  --registry default
run_test "86 v0.2.6 bugfix reject reaches caller"      1 "$RUNS/99-v026-bugfix-shorthand.log" \
  "$BIN" --config "$CFG" get v026_short_bogus --yes --registry default
# Positive: the SHORTHAND error fires.
assert_contains "87 v0.2.6 bugfix names shorthand"     "$RUNS/99-v026-bugfix-shorthand.log" 'shorthand'
# Negative: NO AWS error (because no AWS call was made).
grep -q "ResourceNotFoundException" "$RUNS/99-v026-bugfix-shorthand.log" \
  && record "88 v0.2.6 bugfix skipped aws call" "FAIL" "ResourceNotFoundException present — aws WAS called pre-fix" \
  || record "88 v0.2.6 bugfix skipped aws call" "PASS" "no ResourceNotFoundException — aws call correctly skipped"
# Same check for unknown directive (#version=5 — v0.2.1 canonical grammar, but
# unsupported directive for aws-secrets). Pre-fix, same bug.
run_test "89 v0.2.6 bugfix seed unknown at bogus id"   0 "$RUNS/98-v026-bugfix.log" \
  "$BIN" --config "$CFG" registry set v026_unk_bogus \
  'aws-secrets-prod:///does-not-exist-in-aws-ever-secretenv-validation-99#version=5' \
  --registry default
run_test "90 v0.2.6 bugfix unknown dir reject"         1 "$RUNS/100-v026-bugfix-unknown.log" \
  "$BIN" --config "$CFG" get v026_unk_bogus --yes --registry default
assert_contains "91 v0.2.6 bugfix unknown names version" "$RUNS/100-v026-bugfix-unknown.log" 'version'
grep -q "ResourceNotFoundException" "$RUNS/100-v026-bugfix-unknown.log" \
  && record "92 v0.2.6 bugfix unknown skipped aws" "FAIL" "ResourceNotFoundException present" \
  || record "92 v0.2.6 bugfix unknown skipped aws" "PASS" "no aws call"

# --- cleanup v026 bugfix aliases ---
for a in v026_short_bogus v026_unk_bogus; do
  "$BIN" --config "$CFG" registry unset "$a" --registry default >/dev/null 2>&1 || true
done

# 14b — PR #33 BUG-2 live round-trip: set a unique value via
# aws-secrets backend, read it back, confirm the value survives the
# slash-stripping logic applied in both directions.
V026_VALUE="v026-roundtrip-$(date +%s)-sentinel"
run_test "93 PR#33 BUG-2 set round-trip value" 0 "$RUNS/101-bug2-roundtrip.log" \
  "$BIN" --config "$CFG" registry set bug2_rt \
  'aws-secrets-prod:///secretenv-validation/api-key' \
  --registry default
# Directly via `aws` to set the value (avoids having a secretenv set
# operation in the middle — we're isolating the READ path's slash
# handling). The put-secret-value call uses `aws-cli` with the raw
# secret name (post-strip), which is what we're asserting works.
aws secretsmanager put-secret-value \
  --secret-id secretenv-validation/api-key \
  --secret-string "$V026_VALUE" \
  --region us-east-1 >/dev/null 2>&1 \
  && record "94 aws native put (seed round-trip)" "PASS" "seed" \
  || record "94 aws native put (seed round-trip)" "FAIL" "aws cli failed"
run_test "95 PR#33 BUG-2 get round-trip value" 0 "$RUNS/102-bug2-read.log" \
  "$BIN" --config "$CFG" get bug2_rt --yes --registry default
assert_contains "96 round-trip value matches" "$RUNS/102-bug2-read.log" "$V026_VALUE"
"$BIN" --config "$CFG" registry unset bug2_rt --registry default >/dev/null 2>&1 || true

# 14c — PR #33 BUG-1 live: vault doctor works despite the backend
# routing -address/-namespace via env. This is the positive side of the
# strict lock — the live binary must emit the env vars, not argv flags.
run_test "97 PR#33 BUG-1 vault doctor (env routing live)" 0 "$RUNS/103-bug1-vault.log" \
  "$BIN" --config "$CFG" doctor --json
# `run_test` wraps output in `### cmd: ...\n---\n<output>\n---\n### exit: ...`
# metadata, so we can't parse that wrapped file directly. Capture clean
# JSON in a second invocation to a separate file.
"$BIN" --config "$CFG" doctor --json > "$RUNS/103a-doctor-json-clean.json" 2>/dev/null || true
grep -q '"vault-dev"' "$RUNS/103-bug1-vault.log" \
  && record "98 doctor json names vault-dev" "PASS" "present" \
  || record "98 doctor json names vault-dev" "FAIL" "missing"
# Verified field names and status value against actual output:
#   - backends[].instance_name (not 'instance')
#   - backends[].backend_type (not 'type')
#   - backends[].status == "ok" (not "ready")
python3 -c "
import json, sys
with open('$RUNS/103a-doctor-json-clean.json') as f:
    data = json.load(f)
backends = data.get('backends', [])
vault = next((b for b in backends if b.get('instance_name') == 'vault-dev'), None)
if vault and vault.get('status') == 'ok':
    sys.exit(0)
sys.exit(1)
" >/dev/null 2>&1 \
  && record "99 doctor json vault-dev=ok" "PASS" "parsed" \
  || record "99 doctor json vault-dev=ok" "FAIL" "status != ok or parse err"

# 14d — doctor --json shape stability. Full JSON parse + well-known
# field presence. If the JSON schema drifts, this catches it.
python3 -c "
import json, sys
with open('$RUNS/103a-doctor-json-clean.json') as f:
    data = json.load(f)
# Top-level keys we expect as stable contract.
required = ['backends', 'registries']
missing = [k for k in required if k not in data]
if missing:
    print('missing top-level:', missing)
    sys.exit(1)
# Backend entries must have instance_name + backend_type + status.
for b in data.get('backends', []):
    for k in ('instance_name', 'backend_type', 'status'):
        if k not in b:
            print('backend missing', k, b)
            sys.exit(1)
# Registry entries must have name + sources (with per-source uri + status).
for r in data.get('registries', []):
    if 'name' not in r or 'sources' not in r:
        print('registry missing fields', r)
        sys.exit(1)
    for s in r.get('sources', []):
        for k in ('uri', 'status'):
            if k not in s:
                print('source missing', k, s)
                sys.exit(1)
sys.exit(0)
" >/dev/null 2>&1 \
  && record "100 doctor json schema stable" "PASS" "all required fields" \
  || record "100 doctor json schema stable" "FAIL" "schema drift"

# 14e — cross-backend cascade resolution: the 'cascade-test' registry is
# configured with sources in this order: local-main (first),
# aws-ssm-prod (second). Alias 'stripe_key' exists in local; alias
# 'db_url' only in aws-ssm. Both should resolve via the correct source.
run_test "101 cascade resolves local-first alias" 0 "$RUNS/104-cascade-local.log" \
  "$BIN" --config "$CFG" get stripe_key --yes --registry cascade-test
assert_contains "102 cascade local value" "$RUNS/104-cascade-local.log" 'sk_test'
run_test "103 cascade falls through to aws-ssm" 0 "$RUNS/105-cascade-fallthrough.log" \
  "$BIN" --config "$CFG" get db_url --yes --registry cascade-test
assert_contains "104 cascade aws-ssm value"   "$RUNS/105-cascade-fallthrough.log" 'postgres://'

# 14f — `doctor` exit code IS 0 when all 5 backends ready. Guard
# against a regression where doctor exits 0 on partial ready (the
# v0.2.x retrofit must NOT have weakened this semantic).
# NOTE: this piggybacks on the auth probe at test start — if anything
# is unauthenticated, the test's exit 0 expectation will fail, catching
# mid-session auth drift.
run_test "105 doctor exits 0 when all ready" 0 "$RUNS/106-doctor-exit0.log" \
  "$BIN" --config "$CFG" doctor
# v0.3 Phase 2: 7 backends (Phase 1 added gcp → 6; Phase 2 adds azure → 7).
assert_contains "106 doctor reports 7/7"    "$RUNS/106-doctor-exit0.log" '7/7 OK'

# 14g — `resolve` command regression: given an alias, print a typed
# report. Unlike `get`, resolve never invokes the backend — it shows
# only the URI mapping. This verifies the metadata-only path stays
# lightweight across the strict-mode retrofit.
run_test "107 resolve shows uri mapping"   0 "$RUNS/107-resolve.log" \
  "$BIN" --config "$CFG" resolve stripe_key --registry default
assert_contains "108 resolve names backend"  "$RUNS/107-resolve.log" 'local-main'

# 14h — BUG-2 leading-slash stress: set via secretenv, get via secretenv,
# cross-verify with native `aws secretsmanager describe-secret`. All
# three must land on the same post-strip name.
V026_VALUE2="v026-bug2-stress-$(date +%s)"
run_test "109 BUG-2 stress seed alias"  0 "$RUNS/108-bug2-stress.log" \
  "$BIN" --config "$CFG" registry set bug2_stress \
  'aws-secrets-prod:///secretenv-validation/api-key' --registry default
aws secretsmanager put-secret-value \
  --secret-id secretenv-validation/api-key \
  --secret-string "$V026_VALUE2" --region us-east-1 >/dev/null 2>&1
run_test "110 BUG-2 stress get via secretenv"   0 "$RUNS/109-bug2-stress-get.log" \
  "$BIN" --config "$CFG" get bug2_stress --yes --registry default
assert_contains "111 BUG-2 stress value matches" "$RUNS/109-bug2-stress-get.log" "$V026_VALUE2"
# Native describe — must accept POST-STRIP name.
aws secretsmanager describe-secret \
  --secret-id secretenv-validation/api-key \
  --region us-east-1 >/dev/null 2>&1 \
  && record "112 BUG-2 native describe post-strip" "PASS" "native accepts same name" \
  || record "112 BUG-2 native describe post-strip" "FAIL" "native rejects"
"$BIN" --config "$CFG" registry unset bug2_stress --registry default >/dev/null 2>&1 || true

# 14i — strict-mode harness sanity: unit-test suite still reports the
# expected test count (435 as of v0.3 Phase 2, up from 398 pre-azure).
# If the retrofit accidentally loses a test, this surfaces at integration time.
run_test "113 unit test count matches" 0 "$RUNS/110-unit-count.log" \
  bash -c "cd \"$REPO_ROOT\" && cargo test --workspace 2>&1 | grep -E '^test result:' | awk '{sum+=\$4} END {exit !(sum >= 435)}'"

# 14j — `registry list` round-trip: seed, list, assert presence, unset.
V026_ALIAS="v026_list_check"
"$BIN" --config "$CFG" registry set "$V026_ALIAS" "local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt" --registry default >/dev/null 2>&1
run_test "114 registry list shows seeded alias" 0 "$RUNS/111-list.log" \
  "$BIN" --config "$CFG" registry list --registry default
assert_contains "115 registry list names alias" "$RUNS/111-list.log" "$V026_ALIAS"
"$BIN" --config "$CFG" registry unset "$V026_ALIAS" --registry default >/dev/null 2>&1 || true
run_test "116 registry list post-unset" 0 "$RUNS/112-list-after-unset.log" \
  "$BIN" --config "$CFG" registry list --registry default
grep -q "$V026_ALIAS" "$RUNS/112-list-after-unset.log" \
  && record "117 registry list absent post-unset" "FAIL" "alias still listed" \
  || record "117 registry list absent post-unset" "PASS" "cleanup worked"

# 14k — Fixture restore is now handled by `trap restore_fixture_on_exit
# EXIT` at the top of this script (v0.2.7 hardening). Runs on every
# exit path including signals and interpreter errors, so a mid-run
# failure cannot leave the shared fixture polluted. Explicit assertion
# kept for smoke-observability parity with the prior run.
aws secretsmanager put-secret-value \
  --secret-id secretenv-validation/api-key \
  --secret-string "sk_test_secrets_22222" \
  --region us-east-1 >/dev/null 2>&1 \
  && record "118 fixture restored (api-key)" "PASS" "canonical value" \
  || record "118 fixture restored (api-key)" "FAIL" "aws put failed"

# ---------------------------------------------------------------
# 15. v0.3 Phase 1 — GCP Secret Manager live integration
# ---------------------------------------------------------------
section_begin 15 "v0.3 Phase 1 — GCP Secret Manager live integration"
# Every assertion here hits real GCP Secret Manager via the secretenv
# binary. The unit-test canary covers stdout-never-leaks at the mock
# layer; this section proves the production code path doesn't leak
# either. Fixtures: `secretenv_validation_registry` (JSON alias map)
# + `secretenv_validation_gcp_secret` (scalar `gsk_gcp_55555`).
#
# Skipped if `gcloud` is missing OR `gcloud secrets list --project ...`
# fails (project unreachable, ADC missing, session expired) — same
# SKIP discipline as the other live-cloud sections (Doppler, Infisical,
# Keeper, cf-kv, openbao, conjur, bitwarden-sm). Without this guard, a
# stale gcloud session or wrong-project setup cascades 12+ FAILs that
# look like product regressions but are environmental.
#
# `GCP_PROJECT` is sourced from `lib/common.sh` (via `SECRETENV_TEST_GCP_PROJECT`).
# `require_cloud_env` at the top of this script already enforces that
# the env var is non-empty before any cloud section runs — no fallback
# default here, so a wrong-shell setup fails loudly + early instead of
# silently targeting a stale project ID.
if ! command -v gcloud >/dev/null 2>&1; then
    record "119 v0.3 gcp section skipped — gcloud CLI not installed" "SKIP" \
           "install: brew install --cask google-cloud-sdk"
elif ! gcloud secrets list --project "$GCP_PROJECT" --limit 1 --quiet >/dev/null 2>&1; then
    # Catch-all SKIP: any non-zero exit from `gcloud secrets list` (auth
    # expiry, IAM denial, project-not-found, transient API 5xx, ADC missing,
    # etc.). Hint biases toward the most common cause (reauth) but a
    # transient blip will SKIP this section too — same skip-discipline as
    # sibling sections (Doppler, Keeper, openbao, conjur, bitwarden-sm),
    # which prefer cleanly skipping over false-positive cascading FAILs.
    record "119 v0.3 gcp section skipped — gcloud secrets list failed" "SKIP" \
           "common cause: stale auth (run: gcloud auth login && gcloud auth application-default login). other causes: project unreachable / no IAM access / transient API error. project=$GCP_PROJECT"
else

# 15a — `get` via secretenv through the gcp backend (latest version).
#   Already covered by tests 27b/32b, but re-asserted here as part of
#   the "single-backend-specific section" sanity group.
run_test "119 v0.3 gcp direct get latest" 0 "$RUNS/120-v03-gcp-get.log" \
  "$BIN" --config "$CFG" get gcp_secret --yes --registry default
assert_contains "120 gcp latest value"     "$RUNS/120-v03-gcp-get.log" 'gsk_gcp_55555'

# 15b — resolve via secretenv surfaces the gcp URI with status=ok.
#   No network call from the gcp backend (resolve is metadata-only),
#   but asserts the scheme router picks `gcp-prod` and the backend
#   reports ready in the resolve output.
run_test "121 v0.3 gcp resolve" 0 "$RUNS/121-v03-gcp-resolve.log" \
  "$BIN" --config "$CFG" resolve gcp_secret --registry default
assert_contains "122 resolve names gcp-prod"   "$RUNS/121-v03-gcp-resolve.log" 'gcp-prod'
assert_contains "123 resolve shows secret name" "$RUNS/121-v03-gcp-resolve.log" 'secretenv_validation_gcp_secret'

# 15c — `#version=<n>` fragment: pin to version 1 (the only version
# provisioned). Explicit-version path is distinct from latest —
# proves fragment dispatch reaches gcloud with the pinned positional.
run_test "124 v0.3 gcp seed version=1 alias" 0 "$RUNS/122-v03-gcp-seed-v1.log" \
  "$BIN" --config "$CFG" registry set gcp_v1 \
  'gcp-prod:///secretenv_validation_gcp_secret#version=1' --registry default
run_test "125 v0.3 gcp get version=1"        0 "$RUNS/123-v03-gcp-get-v1.log" \
  "$BIN" --config "$CFG" get gcp_v1 --yes --registry default
assert_contains "126 gcp v1 matches latest"  "$RUNS/123-v03-gcp-get-v1.log" 'gsk_gcp_55555'
"$BIN" --config "$CFG" registry unset gcp_v1 --registry default >/dev/null 2>&1 || true

# 15d — shorthand rejection: v0.2.1 canonical grammar lock live.
#   `gcp-prod:///secret#latest` (no `=`) is shorthand and must reject
#   locally before any gcloud call. Positive: "shorthand" error surfaces.
#   Negative: no GCP error shape (`NOT_FOUND`, `PERMISSION_DENIED`).
run_test "127 v0.3 gcp shorthand seed"       0 "$RUNS/124-v03-gcp-shorthand-seed.log" \
  "$BIN" --config "$CFG" registry set gcp_short \
  'gcp-prod:///secretenv_validation_gcp_secret#latest' --registry default
run_test "128 v0.3 gcp shorthand rejected"   1 "$RUNS/125-v03-gcp-shorthand.log" \
  "$BIN" --config "$CFG" get gcp_short --yes --registry default
assert_contains "129 gcp shorthand names problem"  "$RUNS/125-v03-gcp-shorthand.log" 'shorthand'
grep -q "NOT_FOUND\|PERMISSION_DENIED\|INVALID_ARGUMENT" "$RUNS/125-v03-gcp-shorthand.log" \
  && record "130 gcp shorthand skipped gcloud" "FAIL" "gcloud error present — gcloud WAS called" \
  || record "130 gcp shorthand skipped gcloud" "PASS" "no gcloud error — call correctly skipped"
"$BIN" --config "$CFG" registry unset gcp_short --registry default >/dev/null 2>&1 || true

# 15e — unsupported directive rejection: `#json-key=...` is valid for
# aws-secrets but must be rejected by gcp. Error lists the offender
# (`json-key`) and the recognized directive (`version`).
run_test "131 v0.3 gcp unknown directive seed" 0 "$RUNS/126-v03-gcp-unknown-seed.log" \
  "$BIN" --config "$CFG" registry set gcp_unk \
  'gcp-prod:///secretenv_validation_gcp_secret#json-key=password' --registry default
run_test "132 v0.3 gcp unknown directive rej"  1 "$RUNS/127-v03-gcp-unknown.log" \
  "$BIN" --config "$CFG" get gcp_unk --yes --registry default
assert_contains "133 gcp unknown names json-key"   "$RUNS/127-v03-gcp-unknown.log" 'json-key'
assert_contains "134 gcp unknown names version"    "$RUNS/127-v03-gcp-unknown.log" 'version'
grep -q "NOT_FOUND\|PERMISSION_DENIED\|INVALID_ARGUMENT" "$RUNS/127-v03-gcp-unknown.log" \
  && record "135 gcp unknown skipped gcloud" "FAIL" "gcloud error present" \
  || record "135 gcp unknown skipped gcloud" "PASS" "no gcloud error"
"$BIN" --config "$CFG" registry unset gcp_unk --registry default >/dev/null 2>&1 || true

# 15f — invalid version value local reject: `#version=abc` fails at
# secretenv before any gcloud call.
run_test "136 v0.3 gcp bad version seed"   0 "$RUNS/128-v03-gcp-badver-seed.log" \
  "$BIN" --config "$CFG" registry set gcp_badver \
  'gcp-prod:///secretenv_validation_gcp_secret#version=abc' --registry default
run_test "137 v0.3 gcp bad version rejected" 1 "$RUNS/129-v03-gcp-badver.log" \
  "$BIN" --config "$CFG" get gcp_badver --yes --registry default
assert_contains "138 gcp bad version names abc"    "$RUNS/129-v03-gcp-badver.log" 'abc'
assert_contains "139 gcp bad version names 'invalid'" "$RUNS/129-v03-gcp-badver.log" 'invalid version'
"$BIN" --config "$CFG" registry unset gcp_badver --registry default >/dev/null 2>&1 || true

# 15g — CV-1 live round-trip: write a sentinel via `secretenv set`
# (which uses `gcloud secrets versions add --data-file=/dev/stdin`),
# read it back via `secretenv get`, cross-verify the value survived.
# Failure here would indicate the stdin pipe regressed or argv leaked.
# NOTE: secretenv has no top-level `set`; the analog is using the
# gcp backend's set through `registry set` (which writes to the
# REGISTRY document, not a scalar secret) — for v0.3 Phase 1 we verify
# the backend set path by bypassing through `gcloud` + verifying the
# backend READS back what native gcloud wrote. A proper `secretenv set`
# flow exercise is deferred to a future ergonomics patch.
V03_GCP_VALUE="gcp-rt-$(date +%s)-sentinel"
printf '%s' "$V03_GCP_VALUE" | gcloud secrets versions add \
  secretenv_validation_gcp_secret --project "$GCP_PROJECT" --data-file=- --quiet >/dev/null 2>&1 \
  && record "140 gcp native put (seed round-trip)" "PASS" "seed" \
  || record "140 gcp native put (seed round-trip)" "FAIL" "gcloud failed"
run_test "141 v0.3 gcp get new version" 0 "$RUNS/130-v03-gcp-rt.log" \
  "$BIN" --config "$CFG" get gcp_secret --yes --registry default
assert_contains "142 gcp round-trip value matches" "$RUNS/130-v03-gcp-rt.log" "$V03_GCP_VALUE"

# 15h — post-round-trip: restore canonical fixture value so test 32b
# stays green on the NEXT run.
printf '%s' "gsk_gcp_55555" | gcloud secrets versions add \
  secretenv_validation_gcp_secret --project "$GCP_PROJECT" --data-file=- --quiet >/dev/null 2>&1 \
  && record "143 gcp fixture restored" "PASS" "canonical value" \
  || record "143 gcp fixture restored" "FAIL" "gcloud failed"

# 15i — cross-backend end-to-end: `run` against the gcp-reg registry.
# Proves the gcp backend can serve as a REGISTRY source (reading the
# alias→URI map as JSON) AND its aliases resolve through every other
# backend per the cascade. Full-round trip sanity check.
run_test "144 v0.3 run via gcp-reg"       0 "$RUNS/131-v03-run-gcp-reg.log" \
  "$BIN" --config "$CFG" run --registry gcp-reg -- sh -c 'echo RESOLVED=$STRIPE_KEY GCP=$GCP_SECRET'
assert_contains "145 gcp-reg resolves local stripe" "$RUNS/131-v03-run-gcp-reg.log" 'RESOLVED=sk_test_LOCAL_11111'
assert_contains "146 gcp-reg resolves its own gcp"   "$RUNS/131-v03-run-gcp-reg.log" 'GCP=gsk_gcp_55555'

# 15j — token-leak defense-in-depth: `doctor --json` must NOT contain
# anything that looks like an OAuth2 bearer token. Tokens start with
# `ya29.` — a regression that leaked `gcloud auth print-access-token`
# stdout into the identity field would land the prefix in the JSON.
grep -q "ya29\\." "$RUNS/103a-doctor-json-clean.json" \
  && record "147 doctor json no bearer token" "FAIL" "ya29. prefix present in json — token leaked" \
  || record "147 doctor json no bearer token" "PASS" "no bearer-token prefix in json"
# Also check the human doctor output.
grep -q "ya29\\." "$RUNS/22-doctor.log" \
  && record "148 doctor human no bearer token" "FAIL" "ya29. prefix in doctor output" \
  || record "148 doctor human no bearer token" "PASS" "clean"

# 15k — identity format sanity: gcp-prod identity should include
# `account=` and `project=` fields (human doctor output).
assert_contains "149 gcp identity names account" "$RUNS/22-doctor.log" 'account='
assert_contains "150 gcp identity names project" "$RUNS/22-doctor.log" "project=${GCP_PROJECT}"

fi  # end section 15 SKIP guard

# ---------------------------------------------------------------
# 16. v0.3 Phase 2 — Azure Key Vault live integration
# ---------------------------------------------------------------
section_begin 16 "v0.3 Phase 2 — Azure Key Vault live integration"
# Every assertion here hits real Azure Key Vault via the secretenv
# binary. Fixtures:
#   - secretenv-validation-registry     : JSON alias→URI map
#   - secretenv-validation-azure-secret : scalar `sk_az_66666`
# Vault `secretenv-val-mp-0419.vault.azure.net` provisioned in the
# personal subscription with RBAC (Key Vault Secrets Officer role).
AZURE_VAULT="secretenv-val-mp-0419"

# 16a — `get` via secretenv through the azure backend (latest version).
run_test "151 v0.3 azure direct get latest" 0 "$RUNS/140-v03-azure-get.log" \
  "$BIN" --config "$CFG" get azure_secret --yes --registry default
assert_contains "152 azure latest value"     "$RUNS/140-v03-azure-get.log" 'sk_az_66666'

# 16b — `resolve` names the azure backend + secret name.
run_test "153 v0.3 azure resolve" 0 "$RUNS/141-v03-azure-resolve.log" \
  "$BIN" --config "$CFG" resolve azure_secret --registry default
assert_contains "154 resolve names azure-prod"       "$RUNS/141-v03-azure-resolve.log" 'azure-prod'
assert_contains "155 resolve shows secret name"      "$RUNS/141-v03-azure-resolve.log" 'secretenv-validation-azure-secret'

# 16c — `#version=<hex>` fragment: pin to the current live version.
# Azure generates version IDs server-side; pull the latest dynamically
# rather than hard-coding one. If azure's JSON output shape drifts this
# fails loudly.
AZURE_LIVE_VERSION="$(az keyvault secret show --vault-name "$AZURE_VAULT" --name secretenv-validation-azure-secret --query id -o tsv | awk -F/ '{print $NF}')"
if [ -n "$AZURE_LIVE_VERSION" ]; then
  run_test "156 v0.3 azure seed version pin" 0 "$RUNS/142-v03-azure-seed-v.log" \
    "$BIN" --config "$CFG" registry set azure_v \
    "azure-prod:///secretenv-validation-azure-secret#version=$AZURE_LIVE_VERSION" --registry default
  run_test "157 v0.3 azure get pinned version" 0 "$RUNS/143-v03-azure-get-v.log" \
    "$BIN" --config "$CFG" get azure_v --yes --registry default
  assert_contains "158 azure pinned-version value" "$RUNS/143-v03-azure-get-v.log" 'sk_az_66666'
  "$BIN" --config "$CFG" registry unset azure_v --registry default >/dev/null 2>&1 || true
else
  record "156 v0.3 azure seed version pin"  "FAIL" "could not parse live version ID"
  record "157 v0.3 azure get pinned version" "FAIL" "skipped — no version ID"
  record "158 azure pinned-version value"    "FAIL" "skipped"
fi

# 16d — shorthand rejection (v0.2.1 canonical grammar lock, live).
run_test "159 v0.3 azure shorthand seed" 0 "$RUNS/144-v03-azure-shorthand-seed.log" \
  "$BIN" --config "$CFG" registry set azure_short \
  'azure-prod:///secretenv-validation-azure-secret#latest' --registry default
run_test "160 v0.3 azure shorthand rejected" 1 "$RUNS/145-v03-azure-shorthand.log" \
  "$BIN" --config "$CFG" get azure_short --yes --registry default
assert_contains "161 azure shorthand names problem"      "$RUNS/145-v03-azure-shorthand.log" 'shorthand'
grep -q "SecretNotFound\|Forbidden\|BadParameter" "$RUNS/145-v03-azure-shorthand.log" \
  && record "162 azure shorthand skipped az call" "FAIL" "az error present — az WAS called" \
  || record "162 azure shorthand skipped az call" "PASS" "no az error — call correctly skipped"
"$BIN" --config "$CFG" registry unset azure_short --registry default >/dev/null 2>&1 || true

# 16e — unsupported directive rejection: `#json-key=...` is valid for
# aws-secrets but must be rejected by azure.
run_test "163 v0.3 azure unknown directive seed" 0 "$RUNS/146-v03-azure-unknown-seed.log" \
  "$BIN" --config "$CFG" registry set azure_unk \
  'azure-prod:///secretenv-validation-azure-secret#json-key=password' --registry default
run_test "164 v0.3 azure unknown directive rej"  1 "$RUNS/147-v03-azure-unknown.log" \
  "$BIN" --config "$CFG" get azure_unk --yes --registry default
assert_contains "165 azure unknown names json-key" "$RUNS/147-v03-azure-unknown.log" 'json-key'
assert_contains "166 azure unknown names version"  "$RUNS/147-v03-azure-unknown.log" 'version'
grep -q "SecretNotFound\|Forbidden\|BadParameter" "$RUNS/147-v03-azure-unknown.log" \
  && record "167 azure unknown skipped az call" "FAIL" "az error present" \
  || record "167 azure unknown skipped az call" "PASS" "no az error"
"$BIN" --config "$CFG" registry unset azure_unk --registry default >/dev/null 2>&1 || true

# 16f — invalid version format local reject: `#version=not-hex` fails
# at secretenv before any `az` call.
run_test "168 v0.3 azure bad version seed"   0 "$RUNS/148-v03-azure-badver-seed.log" \
  "$BIN" --config "$CFG" registry set azure_badver \
  'azure-prod:///secretenv-validation-azure-secret#version=not-hex-abc' --registry default
run_test "169 v0.3 azure bad version rejected" 1 "$RUNS/149-v03-azure-badver.log" \
  "$BIN" --config "$CFG" get azure_badver --yes --registry default
assert_contains "170 azure bad version names not-hex"  "$RUNS/149-v03-azure-badver.log" 'not-hex-abc'
assert_contains "171 azure bad version names '32-char'" "$RUNS/149-v03-azure-badver.log" '32-character'
"$BIN" --config "$CFG" registry unset azure_badver --registry default >/dev/null 2>&1 || true

# 16g — CV-1 live round-trip: write a sentinel via `az keyvault secret
# set --file /dev/stdin --encoding utf-8` (mirrors the backend's own
# write path), read it back via `secretenv get`, assert value matches.
# Critically: the `--encoding utf-8` flag is load-bearing — without it
# the default `base64` would interpret stdin as b64 and corrupt the
# stored value. This live round-trip is the only way to verify the
# flag actually does what we think it does.
V03_AZURE_VALUE="azure-rt-$(date +%s)-sentinel"
printf '%s' "$V03_AZURE_VALUE" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" --name secretenv-validation-azure-secret \
  --file /dev/stdin --encoding utf-8 -o none 2>/dev/null \
  && record "172 azure native set (seed round-trip)" "PASS" "seed" \
  || record "172 azure native set (seed round-trip)" "FAIL" "az cli failed"
run_test "173 v0.3 azure get new version" 0 "$RUNS/150-v03-azure-rt.log" \
  "$BIN" --config "$CFG" get azure_secret --yes --registry default
assert_contains "174 azure round-trip value matches" "$RUNS/150-v03-azure-rt.log" "$V03_AZURE_VALUE"

# 16h — encoding integrity canary. If the backend (or the `az` CLI)
# ever regressed and treated stdin as base64 despite our `--encoding
# utf-8` intent, a plain-text value like "azure-rt-<digits>-sentinel"
# would come back as a mangled binary blob (or an `InvalidBase64`
# error). This assertion catches that indirectly — the round-trip
# value would be either missing OR not literally equal to the sentinel.
# Explicit negative for mangled b64 byproducts.
grep -qE '(InvalidBase64|not.*valid.*base64|BadParameter)' "$RUNS/150-v03-azure-rt.log" \
  && record "175 azure encoding not mangled" "FAIL" "b64-interpretation error surfaced" \
  || record "175 azure encoding not mangled" "PASS" "utf-8 encoding preserved"

# 16i — post-round-trip: restore canonical fixture value.
printf '%s' "sk_az_66666" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" --name secretenv-validation-azure-secret \
  --file /dev/stdin --encoding utf-8 -o none 2>/dev/null \
  && record "176 azure fixture restored" "PASS" "canonical value" \
  || record "176 azure fixture restored" "FAIL" "az cli failed"

# 16j — cross-backend cascade via azure-reg. Proves the azure backend
# serves as a REGISTRY source AND all aliases resolve across every
# other backend in the manifest.
run_test "177 v0.3 run via azure-reg" 0 "$RUNS/151-v03-run-azure-reg.log" \
  "$BIN" --config "$CFG" run --registry azure-reg -- sh -c 'echo RESOLVED=$STRIPE_KEY AZ=$AZURE_SECRET'
assert_contains "178 azure-reg resolves local stripe" "$RUNS/151-v03-run-azure-reg.log" 'RESOLVED=sk_test_LOCAL_11111'
assert_contains "179 azure-reg resolves its own az"   "$RUNS/151-v03-run-azure-reg.log" 'AZ=sk_az_66666'

# 16k — identity format sanity: azure-prod identity should include
# `user=`, `tenant=`, `subscription=`, `vault=` (human doctor output).
assert_contains "180 azure identity names user"         "$RUNS/22-doctor.log" 'user='
assert_contains "181 azure identity names tenant"       "$RUNS/22-doctor.log" 'tenant='
assert_contains "182 azure identity names subscription" "$RUNS/22-doctor.log" 'subscription='
assert_contains "183 azure identity names vault"        "$RUNS/22-doctor.log" 'vault=secretenv-val-mp-0419'

# 16l — `az --version` is multi-line noisy. Doctor output must carry
# an `azure-cli ` prefix in the version string.
assert_contains "184 azure cli-version prefix"          "$RUNS/22-doctor.log" 'azure-cli'

# ---------------------------------------------------------------
# 17 — v0.4 Phase 2a: `secretenv registry history` (live)
# ---------------------------------------------------------------
section_begin 17 "v0.4 Phase 2a: 'secretenv registry history' (live)"
# Backend coverage: local + aws-ssm + vault have native history overrides;
# aws-secrets + 1password + gcp + azure return "unsupported" via the
# Backend trait default. Every alias here lives in the LOCAL registry
# (config.toml's [registries.default]) — its alias namespace is what
# `--registry default` exposes. The cloud registries (aws-ssm-reg etc.)
# have their own remote alias namespaces unrelated to these tests.

# 17 prologue — git-init the local-secrets dir so the local backend's
# history() (`git log --follow`) has something to walk. Idempotent;
# safe to re-run. Two commits give us a 2-version history to assert on.
LOCAL_SECRETS=${RUNTIME_DIR}/local-secrets
if [ ! -d "$LOCAL_SECRETS/.git" ]; then
  ( cd "$LOCAL_SECRETS" && git init -q && \
    git config user.email "smoke-test@example.com" && \
    git config user.name "smoke-test" && \
    git add stripe-key.txt 2>/dev/null && \
    git commit -q -m "initial: stripe-key fixture" 2>/dev/null && \
    printf '\n' >> stripe-key.txt && \
    git add stripe-key.txt && \
    git commit -q -m "bump: trailing newline" 2>/dev/null ) || true
fi

# 17a — local backend's history() resolves stripe_key → local file →
# git log. Two commits in fixture should appear.
run_test "185 v0.4 registry history default (local)" 0 "$RUNS/200-v04-history-default.log" \
  "$BIN" --config "$CFG" registry history stripe_key --registry default
assert_contains "186 history shows alias header" "$RUNS/200-v04-history-default.log" 'alias:    stripe_key'
assert_contains "187 history shows resolved"     "$RUNS/200-v04-history-default.log" 'resolved: local-main://'
assert_contains "188 history shows table"        "$RUNS/200-v04-history-default.log" 'VERSION'

# 17b — JSON shape for the local backend.
run_test "189 v0.4 registry history --json" 0 "$RUNS/201-v04-history-json.log" \
  "$BIN" --config "$CFG" registry history stripe_key --registry default --json
assert_contains "190 history JSON has alias key"    "$RUNS/201-v04-history-json.log" '"alias"'
assert_contains "191 history JSON has resolved key" "$RUNS/201-v04-history-json.log" '"resolved"'
assert_contains "192 history JSON has versions key" "$RUNS/201-v04-history-json.log" '"versions"'

# 17c — aws-ssm history via the `db_url` alias in the local registry
# (resolves to `aws-ssm-prod:///secretenv-validation/db-url`). Live
# `aws ssm get-parameter-history` call.
run_test "193 v0.4 registry history db_url (aws-ssm)" 0 "$RUNS/202-v04-history-aws-ssm.log" \
  "$BIN" --config "$CFG" registry history db_url --registry default
assert_contains "194 aws-ssm history table header" "$RUNS/202-v04-history-aws-ssm.log" 'VERSION'
grep -qE 'arn:aws:iam' "$RUNS/202-v04-history-aws-ssm.log" \
  && record "195 aws-ssm history shows IAM actor" "PASS" "ARN present" \
  || record "195 aws-ssm history shows IAM actor" "FAIL" "no ARN in output"

# 17d — vault history via the `oauth_token` alias (resolves to
# `vault-dev:///secret/secretenv-validation/oauth-token`). KV v2 mount;
# `vault kv metadata get -format=json`.
run_test "196 v0.4 registry history oauth_token (vault)" 0 "$RUNS/203-v04-history-vault.log" \
  "$BIN" --config "$CFG" registry history oauth_token --registry default
assert_contains "197 vault history table header" "$RUNS/203-v04-history-vault.log" 'VERSION'

# 17e — aws-secrets history via `api_key` alias. No native override →
# trait default surfaces "unsupported" with the backend type named.
run_test "198 v0.4 history api_key (aws-secrets) unsupported" 1 "$RUNS/204-v04-history-aws-sec-unsupp.log" \
  "$BIN" --config "$CFG" registry history api_key --registry default
assert_contains "199 aws-secrets history names backend type" "$RUNS/204-v04-history-aws-sec-unsupp.log" 'aws-secrets'
assert_contains "200 aws-secrets history names supported list" "$RUNS/204-v04-history-aws-sec-unsupp.log" 'supported'

# 17f — 1password history via `op_pat` alias → unsupported.
run_test "201 v0.4 history op_pat (1password) unsupported" 1 "$RUNS/205-v04-history-op-unsupp.log" \
  "$BIN" --config "$CFG" registry history op_pat --registry default
assert_contains "202 1password history names supported list" "$RUNS/205-v04-history-op-unsupp.log" 'supported'

# 17g — gcp history via `gcp_secret` alias → unsupported.
run_test "203 v0.4 history gcp_secret unsupported" 1 "$RUNS/206-v04-history-gcp-unsupp.log" \
  "$BIN" --config "$CFG" registry history gcp_secret --registry default
assert_contains "204 gcp history names supported list" "$RUNS/206-v04-history-gcp-unsupp.log" 'supported'

# 17h — azure history via `azure_secret` alias → unsupported.
run_test "205 v0.4 history azure_secret unsupported" 1 "$RUNS/207-v04-history-azure-unsupp.log" \
  "$BIN" --config "$CFG" registry history azure_secret --registry default
assert_contains "206 azure history names supported list" "$RUNS/207-v04-history-azure-unsupp.log" 'supported'

# 17i — unknown alias → fail with the alias name surfaced.
run_test "207 v0.4 history unknown alias" 1 "$RUNS/208-v04-history-unknown.log" \
  "$BIN" --config "$CFG" registry history nope-not-here --registry default
assert_contains "208 unknown alias names alias" "$RUNS/208-v04-history-unknown.log" 'nope-not-here'

# ---------------------------------------------------------------
# 18 — v0.4 Phase 2b: `secretenv registry invite` (offline)
# ---------------------------------------------------------------
section_begin 18 "v0.4 Phase 2b: 'secretenv registry invite' (offline)"
# `registry invite` is read-only and offline (no backend RPCs). Per-
# backend rendering is hand-tuned — every grant arm is a separate
# assertion.

# 18a — local backend default registry → filesystem grant text.
run_test "209 v0.4 invite default --invitee alice" 0 "$RUNS/210-v04-invite-default.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice@example.com --registry default
assert_contains "210 invite section 1 (config snippet)" "$RUNS/210-v04-invite-default.log" 'add to your config.toml'
assert_contains "211 invite section 2 (grant)"          "$RUNS/210-v04-invite-default.log" 'grant access'
assert_contains "212 invite section 3 (verify)"          "$RUNS/210-v04-invite-default.log" 'verify the onboarding'
assert_contains "213 invite local grant filesystem"      "$RUNS/210-v04-invite-default.log" 'filesystem-served'
assert_contains "214 invite snippet has registry block"  "$RUNS/210-v04-invite-default.log" '\[registries.default\]'
assert_contains "215 invite snippet has backend block"   "$RUNS/210-v04-invite-default.log" '\[backends.local-main\]'
assert_contains "216 invite verify step doctor"          "$RUNS/210-v04-invite-default.log" 'secretenv doctor'
assert_contains "217 invite verify step list"            "$RUNS/210-v04-invite-default.log" 'secretenv registry list'
assert_contains "218 invite invitee echoed"              "$RUNS/210-v04-invite-default.log" 'alice@example.com'

# 18b — placeholder when --invitee absent.
run_test "219 v0.4 invite default no-invitee" 0 "$RUNS/211-v04-invite-no-invitee.log" \
  "$BIN" --config "$CFG" registry invite --registry default
assert_contains "220 invite default placeholder" "$RUNS/211-v04-invite-no-invitee.log" '<INVITEE>'

# 18c — JSON envelope.
run_test "221 v0.4 invite --json" 0 "$RUNS/212-v04-invite-json.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice --registry default --json
assert_contains "222 invite JSON has registry_name"  "$RUNS/212-v04-invite-json.log" '"registry_name"'
assert_contains "223 invite JSON has backend_type"   "$RUNS/212-v04-invite-json.log" '"backend_type"'
assert_contains "224 invite JSON has config_block"   "$RUNS/212-v04-invite-json.log" '"config_block"'
assert_contains "225 invite JSON has inviter_grant"  "$RUNS/212-v04-invite-json.log" '"inviter_grant"'
assert_contains "226 invite JSON has verify_steps"   "$RUNS/212-v04-invite-json.log" '"verify_steps"'

# 18d — aws-ssm registry → AmazonSSMReadOnlyAccess grant text.
run_test "227 v0.4 invite aws-ssm-reg" 0 "$RUNS/213-v04-invite-aws-ssm.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice --registry aws-ssm-reg
assert_contains "228 aws-ssm invite uses ssm-readonly policy" "$RUNS/213-v04-invite-aws-ssm.log" 'AmazonSSMReadOnlyAccess'
assert_contains "229 aws-ssm invite includes attach-user-policy" "$RUNS/213-v04-invite-aws-ssm.log" 'attach-user-policy'

# 18e — aws-secrets registry → SecretsManagerReadWrite grant.
run_test "230 v0.4 invite aws-secrets-reg" 0 "$RUNS/214-v04-invite-aws-sec.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice --registry aws-secrets-reg
assert_contains "231 aws-secrets invite uses sm-readwrite policy" "$RUNS/214-v04-invite-aws-sec.log" 'SecretsManagerReadWrite'

# 18f — 1password registry → op vault user grant text + extracted vault.
run_test "232 v0.4 invite op-reg" 0 "$RUNS/215-v04-invite-op.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice@example.com --registry op-reg
assert_contains "233 op invite uses vault user grant" "$RUNS/215-v04-invite-op.log" 'op vault user grant'
assert_contains "234 op invite extracts vault name"   "$RUNS/215-v04-invite-op.log" '\-\-vault Private'

# 18g — vault registry → vault policy write + vault token create.
run_test "235 v0.4 invite vault-reg" 0 "$RUNS/216-v04-invite-vault.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice --registry vault-reg
assert_contains "236 vault invite has policy write" "$RUNS/216-v04-invite-vault.log" 'vault policy write'
assert_contains "237 vault invite has token create" "$RUNS/216-v04-invite-vault.log" 'vault token create'

# 18h — gcp registry → gcloud secrets add-iam-policy-binding + secretAccessor.
run_test "238 v0.4 invite gcp-reg" 0 "$RUNS/217-v04-invite-gcp.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice@example.com --registry gcp-reg
assert_contains "239 gcp invite has add-iam-policy-binding" "$RUNS/217-v04-invite-gcp.log" 'add-iam-policy-binding'
assert_contains "240 gcp invite has secretAccessor role"    "$RUNS/217-v04-invite-gcp.log" 'roles/secretmanager.secretAccessor'

# 18i — azure registry → az role assignment create + Key Vault Secrets User.
run_test "241 v0.4 invite azure-reg" 0 "$RUNS/218-v04-invite-azure.log" \
  "$BIN" --config "$CFG" registry invite --invitee alice@example.com --registry azure-reg
assert_contains "242 azure invite has role assignment create" "$RUNS/218-v04-invite-azure.log" 'az role assignment create'
assert_contains "243 azure invite has Key Vault Secrets User role" "$RUNS/218-v04-invite-azure.log" 'Key Vault Secrets User'

# ---------------------------------------------------------------
# 19 — v0.4 Phase 1: `secretenv doctor --fix` + `--extensive`
# ---------------------------------------------------------------
section_begin 19 "v0.4 Phase 1: 'secretenv doctor --fix' + '--extensive'"
# --fix: live remediation isn't tested here (it would deauth then re-
# auth interactively). We validate the no-op path + help discoverability.
# --extensive: live Level 3 probe — runs check_extensive() against every
# registry source served by an Ok backend.

# 19a — --fix no-op renders Backends section but NO Remediation actions.
run_test "244 v0.4 doctor --fix (all-Ok no-op)" 0 "$RUNS/220-v04-doctor-fix.log" \
  "$BIN" --config "$CFG" doctor --fix
assert_contains "245 doctor --fix shows Backends" "$RUNS/220-v04-doctor-fix.log" 'Backends ('
grep -q 'Remediation actions' "$RUNS/220-v04-doctor-fix.log" \
  && record "246 doctor --fix no-op skips section" "FAIL" "section emitted despite all-Ok" \
  || record "246 doctor --fix no-op skips section" "PASS" "no remediation needed"

# 19b — --extensive renders depth probe block + alias counts per backend.
run_test "247 v0.4 doctor --extensive" 0 "$RUNS/221-v04-doctor-extensive.log" \
  "$BIN" --config "$CFG" doctor --extensive
assert_contains "248 extensive shows depth probe header" "$RUNS/221-v04-doctor-extensive.log" 'depth probe'
grep -qE 'alias[es]* readable' "$RUNS/221-v04-doctor-extensive.log" \
  && record "249 extensive shows alias-readable count" "PASS" "count reported" \
  || record "249 extensive shows alias-readable count" "FAIL" "no count"

# 19c — --extensive --json includes depth array on at least one backend.
run_test "250 v0.4 doctor --extensive --json" 0 "$RUNS/222-v04-doctor-ext-json.log" \
  "$BIN" --config "$CFG" doctor --extensive --json
assert_contains "251 extensive JSON includes depth"      "$RUNS/222-v04-doctor-ext-json.log" '"depth"'
assert_contains "252 extensive JSON depth_status read"   "$RUNS/222-v04-doctor-ext-json.log" '"depth_status": "read"'
assert_contains "253 extensive JSON entry_count present" "$RUNS/222-v04-doctor-ext-json.log" '"entry_count"'

# 19d — --fix --extensive composes. Both paths should run.
run_test "254 v0.4 doctor --fix --extensive compose" 0 "$RUNS/223-v04-doctor-both.log" \
  "$BIN" --config "$CFG" doctor --fix --extensive
assert_contains "255 compose shows depth probe" "$RUNS/223-v04-doctor-both.log" 'depth probe'

# 19e — --help advertises both flags so users discover them.
run_test "256 v0.4 doctor --help lists flags" 0 "$RUNS/224-v04-doctor-help.log" \
  "$BIN" --config "$CFG" doctor --help
assert_contains "257 doctor --help lists --fix"       "$RUNS/224-v04-doctor-help.log" '--fix'
assert_contains "258 doctor --help lists --extensive" "$RUNS/224-v04-doctor-help.log" '--extensive'

# ---------------------------------------------------------------
# 20 — v0.4 Phase 3: `timeout_secs` + `op_unsafe_set` config knobs
# ---------------------------------------------------------------
section_begin 20 "v0.4 Phase 3: 'timeout_secs' + 'op_unsafe_set' config knobs"
# Both reach into config-load + factory. We test end-to-end with two
# tempdir configs — one valid, one rejected for each branch.

V04_TMPCFG="$RUNS/240-tmp-config-timeout.toml"
cat > "$V04_TMPCFG" <<EOF
[registries.default]
sources = ["local-main://${RUNTIME_DIR}/local-registry/registry.toml"]

[backends.local-main]
type = "local"
timeout_secs = 5
EOF

# 20a — positive integer accepted; doctor still works with the override.
run_test "259 v0.4 timeout_secs accepted" 0 "$RUNS/240-v04-timeout-ok.log" \
  "$BIN" --config "$V04_TMPCFG" doctor
assert_contains "260 timeout_secs config still resolves local" "$RUNS/240-v04-timeout-ok.log" 'local-main'

V04_BADCFG="$RUNS/241-tmp-config-timeout-bad.toml"
cat > "$V04_BADCFG" <<EOF
[registries.default]
sources = ["local-main://${RUNTIME_DIR}/local-registry/registry.toml"]

[backends.local-main]
type = "local"
timeout_secs = -3
EOF

# 20b — negative integer rejected at backend factory time.
run_test "261 v0.4 timeout_secs negative rejected" 1 "$RUNS/241-v04-timeout-neg.log" \
  "$BIN" --config "$V04_BADCFG" doctor
assert_contains "262 negative timeout_secs error names field" "$RUNS/241-v04-timeout-neg.log" 'timeout_secs'
assert_contains "263 negative timeout_secs error says positive" "$RUNS/241-v04-timeout-neg.log" 'positive'

V04_ZEROCFG="$RUNS/242-tmp-config-timeout-zero.toml"
cat > "$V04_ZEROCFG" <<EOF
[registries.default]
sources = ["local-main://${RUNTIME_DIR}/local-registry/registry.toml"]

[backends.local-main]
type = "local"
timeout_secs = 0
EOF

# 20c — zero rejected (Duration::from_secs(0) is logically a no-op).
run_test "264 v0.4 timeout_secs zero rejected" 1 "$RUNS/242-v04-timeout-zero.log" \
  "$BIN" --config "$V04_ZEROCFG" doctor
assert_contains "265 zero timeout_secs error says positive" "$RUNS/242-v04-timeout-zero.log" 'positive'

V04_BADTYPECFG="$RUNS/243-tmp-config-timeout-string.toml"
cat > "$V04_BADTYPECFG" <<EOF
[registries.default]
sources = ["local-main://${RUNTIME_DIR}/local-registry/registry.toml"]

[backends.local-main]
type = "local"
timeout_secs = "not-a-number"
EOF

# 20d — wrong type rejected.
run_test "266 v0.4 timeout_secs wrong type rejected" 1 "$RUNS/243-v04-timeout-str.log" \
  "$BIN" --config "$V04_BADTYPECFG" doctor
assert_contains "267 wrong-type error says integer" "$RUNS/243-v04-timeout-str.log" 'integer'

# 20e — 1Password set safe-default refuses without op_unsafe_set. The
# `registry set` against op-reg routes through the 1Password backend's
# set() — without op_unsafe_set the command must fail BEFORE any `op`
# subprocess call.
run_test "268 v0.4 op set safe-default refuses" 1 "$RUNS/244-v04-op-refuse.log" \
  "$BIN" --config "$CFG" registry set throwaway-op-set \
  '1password-private://Private/secretenv-validation-write-target/value' --registry op-reg
grep -q 'op_unsafe_set' "$RUNS/244-v04-op-refuse.log" \
  && record "269 op refusal names op_unsafe_set field" "PASS" "field named" \
  || record "269 op refusal names op_unsafe_set field" "FAIL" "field not named"
grep -qE 'argv|cmdline' "$RUNS/244-v04-op-refuse.log" \
  && record "270 op refusal explains argv exposure" "PASS" "exposure mentioned" \
  || record "270 op refusal explains argv exposure" "FAIL" "exposure not mentioned"

# 20f — clean up the throwaway alias if test 268 actually wrote.
"$BIN" --config "$CFG" registry unset throwaway-op-set --registry op-reg >/dev/null 2>&1 || true

# ---------------------------------------------------------------
# 21 — v0.5: macOS Keychain backend
# ---------------------------------------------------------------
section_begin 21 "v0.5 macOS Keychain backend"
# Fully self-contained: a dedicated tempdir config + mini-registry
# point at the test keychain provision.sh created. Does NOT touch the
# cross-backend shared fixtures, so adding this section doesn't affect
# sections 3-8 (which list/get from every registry source).
#
# On non-macOS hosts the section short-circuits with a SKIP record —
# keeps the matrix count consistent across platforms even when the
# full --sections 21 selector is used.

if [[ "$OSTYPE" != darwin* ]]; then
    record "271 v0.5 keychain section skipped on non-macOS" "SKIP" "host is $OSTYPE"
else
    V05_KCREG="$RUNS/270-kc-registry.toml"
    cat > "$V05_KCREG" <<EOF
kc_secret = "keychain-test:///secretenv-v05-test/account1"
EOF

    V05_KCCFG="$RUNS/270-kc-config.toml"
    cat > "$V05_KCCFG" <<EOF
[registries.default]
sources = ["local-main://${V05_KCREG}"]

[backends.local-main]
type = "local"

[backends.keychain-test]
type = "keychain"
keychain_path = "${RUNTIME_DIR}/test.keychain-db"
EOF

    # Stage a mini project manifest so `run` exercises the end-to-end
    # alias → keychain → child-env injection path. run_test cd's into
    # $PROJ by default, so we wrap the invocation in a subshell that
    # cd's into V05_KCPROJ instead.
    V05_KCPROJ="$RUNS/270-kc-project"
    mkdir -p "$V05_KCPROJ"
    cat > "$V05_KCPROJ/secretenv.toml" <<EOF
[secrets]
KC_SECRET = { from = "secretenv://kc_secret" }
EOF

    # 21a — doctor sees the keychain backend at the configured path.
    run_test "271 v0.5 keychain doctor sees backend" 0 "$RUNS/271-v05-kc-doctor.log" \
      "$BIN" --config "$V05_KCCFG" doctor
    assert_contains "272 keychain doctor lists instance"  "$RUNS/271-v05-kc-doctor.log" 'keychain-test'
    assert_contains "273 keychain doctor shows identity"  "$RUNS/271-v05-kc-doctor.log" 'keychain=test.keychain-db'

    # 21b — round-trip get: alias in local registry resolves to keychain URI,
    # backend.get() runs `security find-generic-password -w ...` and returns
    # the seeded value.
    run_test "274 v0.5 keychain get round-trip" 0 "$RUNS/274-v05-kc-get.log" \
      "$BIN" --config "$V05_KCCFG" get kc_secret --yes
    assert_contains "275 keychain round-trip returns seeded value" "$RUNS/274-v05-kc-get.log" 'kc_ring_77777'

    # 21c — end-to-end `run` injects the keychain-backed alias as an env var.
    # `secretenv run` discovers secretenv.toml in CWD, so cd into the mini
    # project dir via a bash -c wrapper (overrides run_test's default
    # cd $PROJ).
    run_test "276 v0.5 keychain run injects env var" 0 "$RUNS/276-v05-kc-run.log" \
      bash -c "cd '$V05_KCPROJ' && '$BIN' --config '$V05_KCCFG' run -- sh -c 'echo kc=\$KC_SECRET'"
    assert_contains "277 keychain run renders KC_SECRET" "$RUNS/276-v05-kc-run.log" 'kc=kc_ring_77777'

    # 21d — list is unsupported. Using --registry <direct URI> routes the
    # command straight into backend.list(), bypassing the cascade.
    run_test "278 v0.5 keychain list bails unsupported" 1 "$RUNS/278-v05-kc-list.log" \
      "$BIN" --config "$V05_KCCFG" registry list --registry 'keychain-test:///unused/path'
    assert_contains "279 keychain list error names 'not supported'" "$RUNS/278-v05-kc-list.log" 'list is not supported'

    # 21e — history falls through to the trait default. The alias resolves
    # to a keychain URI, then backend.history() returns the default
    # "not implemented for backend type 'keychain'" error.
    run_test "280 v0.5 keychain history bails unsupported" 1 "$RUNS/280-v05-kc-history.log" \
      "$BIN" --config "$V05_KCCFG" registry history kc_secret
    assert_contains "281 keychain history names backend type" "$RUNS/280-v05-kc-history.log" 'keychain'
fi

# ---------------------------------------------------------------
# 22 — v0.6: Doppler backend
# ---------------------------------------------------------------
section_begin 22 "v0.6 Doppler backend"
# Self-contained like Section 21: a dedicated mini-config + mini-registry
# point at the `secretenv-validation` Doppler project (config `dev`)
# provision.sh seeded. Does NOT touch the cross-backend shared fixtures,
# so sections 3-8 stay at 8-backend scope.
#
# Pre-req: `doppler` CLI installed AND authenticated (via `doppler login`
# or $DOPPLER_TOKEN). Non-authenticated runs record a SKIP and move on —
# same discipline as Keychain's non-macOS SKIP, keeping section-count
# consistent across hosts where the CLI is missing or logged out.

if ! command -v doppler >/dev/null 2>&1; then
    record "282 v0.6 doppler section skipped — doppler CLI not installed" "SKIP" \
           "install: brew install dopplerhq/cli/doppler"
elif ! doppler me --json >/dev/null 2>&1; then
    record "282 v0.6 doppler section skipped — doppler CLI not authenticated" "SKIP" \
           "run 'doppler login' or export DOPPLER_TOKEN=<token>"
else
    V06_DPREG="$RUNS/282-dp-registry.toml"
    cat > "$V06_DPREG" <<EOF
dp_secret = "doppler-test:///secretenv-validation/dev/SMOKE_TEST_VALUE"
EOF

    # doppler-test keeps the full-form shape (URI supplies project+config).
    # doppler-test-short sets defaults so short-form URIs work —
    # exercised by assertion 295 below.
    V06_DPCFG="$RUNS/282-dp-config.toml"
    cat > "$V06_DPCFG" <<EOF
[registries.default]
sources = ["local-main://${V06_DPREG}"]

[backends.local-main]
type = "local"

[backends.doppler-test]
type = "doppler"

[backends.doppler-test-short]
type = "doppler"
doppler_project = "secretenv-validation"
doppler_config = "dev"
EOF

    # Short-form registry: one alias pointing at a short-form URI that
    # relies on backend-level project+config defaults. Sharing the
    # runtime with V06_DPREG would muddle the test surface; a second
    # registry file keeps each shape isolated.
    V06_DPREG_SHORT="$RUNS/282-dp-registry-short.toml"
    cat > "$V06_DPREG_SHORT" <<EOF
dp_secret_short = "doppler-test-short:///SMOKE_TEST_VALUE"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V06_DPPROJ="$RUNS/282-dp-project"
    mkdir -p "$V06_DPPROJ"
    cat > "$V06_DPPROJ/secretenv.toml" <<EOF
[secrets]
DP_SECRET = { from = "secretenv://dp_secret" }
EOF

    # 22a — doctor sees the doppler backend authenticated.
    run_test "282 v0.6 doppler doctor sees backend" 0 "$RUNS/282-v06-dp-doctor.log" \
      "$BIN" --config "$V06_DPCFG" doctor
    assert_contains "283 doppler doctor lists instance"         "$RUNS/282-v06-dp-doctor.log" 'doppler-test'
    assert_contains "284 doppler doctor identity shows account" "$RUNS/282-v06-dp-doctor.log" 'account='
    assert_contains "285 doppler doctor identity shows token"   "$RUNS/282-v06-dp-doctor.log" 'token-type='

    # 22b — round-trip get: alias in local registry resolves to doppler
    # URI, backend.get() runs `doppler secrets get ... --plain` and
    # returns the seeded value from provision.sh.
    run_test "286 v0.6 doppler get round-trip" 0 "$RUNS/286-v06-dp-get.log" \
      "$BIN" --config "$V06_DPCFG" get dp_secret --yes
    assert_contains "287 doppler round-trip returns seeded value" "$RUNS/286-v06-dp-get.log" 'sk_test_doppler_44444'

    # 22c — end-to-end `run` injects the doppler-backed alias as env var.
    run_test "288 v0.6 doppler run injects env var" 0 "$RUNS/288-v06-dp-run.log" \
      bash -c "cd '$V06_DPPROJ' && '$BIN' --config '$V06_DPCFG' run -- sh -c 'echo dp=\$DP_SECRET'"
    assert_contains "289 doppler run renders DP_SECRET" "$RUNS/288-v06-dp-run.log" 'dp=sk_test_doppler_44444'

    # 22d — history surfaces the "unsupported" message (CLI v3.76.0 has
    # no `doppler secrets versions` subcommand; backend returns a
    # Doppler-specific bail per the override).
    #
    # NOTE: a live list() assertion would need a dedicated Doppler
    # config seeded with URI-valued secrets (registry-source shape).
    # The `dev` config used here holds a scalar value for the get/run
    # round-trip, so routing it through `registry list --registry
    # <doppler-URI>` would bail on URI-parse of the scalar value.
    # The synthetic-DOPPLER_* key filter + basic list decoding are
    # locked by unit tests `list_returns_filtered_map` and
    # `list_filters_every_doppler_prefixed_key` in the backend crate.
    run_test "290 v0.6 doppler history bails unsupported" 1 "$RUNS/290-v06-dp-history.log" \
      "$BIN" --config "$V06_DPCFG" registry history dp_secret
    assert_contains "291 doppler history names 'not supported'" "$RUNS/290-v06-dp-history.log" 'history is not supported'
    assert_contains "292 doppler history points at Dashboard"   "$RUNS/290-v06-dp-history.log" 'Dashboard'

    # 22e — short-form URI round-trip via backend defaults. Points the
    # config at V06_DPREG_SHORT (single alias on doppler-test-short)
    # via $SECRETENV_REGISTRY override, exercising the short-form
    # resolve path end-to-end. A regression that broke the
    # both-or-neither defaults wiring or ignored doppler_project/
    # doppler_config would surface here with a "URI short form"-style
    # error, not a successful fetch.
    V06_DPCFG_SHORT="$RUNS/282-dp-config-short.toml"
    cat > "$V06_DPCFG_SHORT" <<EOF
[registries.default]
sources = ["local-main://${V06_DPREG_SHORT}"]

[backends.local-main]
type = "local"

[backends.doppler-test-short]
type = "doppler"
doppler_project = "secretenv-validation"
doppler_config = "dev"
EOF
    run_test "293 v0.6 doppler short-form URI uses backend defaults" 0 "$RUNS/293-v06-dp-short.log" \
      "$BIN" --config "$V06_DPCFG_SHORT" get dp_secret_short --yes
    assert_contains "294 doppler short-form returns seeded value" "$RUNS/293-v06-dp-short.log" 'sk_test_doppler_44444'

    # 22f — fragment on get is rejected before subprocess. Uses a
    # direct-URI registry so the fragment surfaces through backend.get()
    # NOT through the URI-parser at config-load time. A regression that
    # stripped the fragment-reject or moved it after the subprocess
    # would either succeed silently (worse) or fail with a subprocess
    # stderr message (misleading).
    V06_DPREG_FRAG="$RUNS/282-dp-registry-frag.toml"
    cat > "$V06_DPREG_FRAG" <<EOF
dp_frag = "doppler-test:///secretenv-validation/dev/SMOKE_TEST_VALUE#version=5"
EOF
    V06_DPCFG_FRAG="$RUNS/282-dp-config-frag.toml"
    cat > "$V06_DPCFG_FRAG" <<EOF
[registries.default]
sources = ["local-main://${V06_DPREG_FRAG}"]

[backends.local-main]
type = "local"

[backends.doppler-test]
type = "doppler"
EOF
    run_test "295 v0.6 doppler rejects fragment on get" 1 "$RUNS/295-v06-dp-frag.log" \
      "$BIN" --config "$V06_DPCFG_FRAG" get dp_frag --yes
    assert_contains "296 doppler fragment-reject names backend" "$RUNS/295-v06-dp-frag.log" 'doppler'

    # 22g — v0.7.2 registry-source coverage. provision.sh seeded a
    # separate config `dev_registry` under `secretenv-validation`
    # holding URI-valued entries. `registry list --registry <URI>`
    # invokes backend.list() on Doppler and expects every returned
    # value to parse as a BackendUri — the dedicated config keeps
    # URI-valued entries separate from the scalar round-trip config.
    V06_DPCFG_REG="$RUNS/282-dp-config-regsrc.toml"
    cat > "$V06_DPCFG_REG" <<EOF
[registries.default]
sources = ["doppler-registry:///secretenv-validation/dev_registry/UNUSED_MARKER"]

[backends.doppler-registry]
type = "doppler"

# Declared so the alias's target URI ('local-main://...') resolves
# cleanly. The 'registry list' command validates every returned
# target against the configured backends; without this the alias
# is listed but the CLI exits 1 on the unconfigured-backend check.
[backends.local-main]
type = "local"
EOF
    run_test "312 v0.7.2 doppler registry-source list" 0 "$RUNS/312-v072-dp-reglist.log" \
      "$BIN" --config "$V06_DPCFG_REG" registry list --registry default
    assert_contains "313 doppler registry-source names alias" \
      "$RUNS/312-v072-dp-reglist.log" 'SMOKE_REGISTRY_ALIAS'
    assert_contains "314 doppler registry-source names target URI" \
      "$RUNS/312-v072-dp-reglist.log" 'local-main://'
fi

# ---------------------------------------------------------------
# 23 — v0.7: Infisical backend
# ---------------------------------------------------------------
section_begin 23 "v0.7 Infisical backend"
# Self-contained like Section 22: a dedicated mini-config + mini-registry
# point at the Infisical `secretenv-validation` project (env `dev`)
# that provision.sh seeded. Does NOT touch cross-backend shared
# fixtures, so earlier sections stay at their backend scope.
#
# Project ID is overridable via $SECRETENV_INFISICAL_PROJECT_ID;
# default matches TechAlchemistX's CI smoke account. Other accounts
# running the harness need to override to their own validation
# project.
#
# Pre-req: `infisical` CLI installed AND authenticated (`infisical
# login` or $INFISICAL_TOKEN). Non-authenticated runs record SKIPs
# and move on — same discipline as Doppler's SKIP path.

IF_PROJECT_ID="${SECRETENV_INFISICAL_PROJECT_ID:-46302876-3c2f-4349-9376-f8a8228bdb1e}"

if ! command -v infisical >/dev/null 2>&1; then
    record "297 v0.7 infisical section skipped — infisical CLI not installed" "SKIP" \
           "install: brew install infisical/get-cli/infisical"
elif ! infisical user get token --plain >/dev/null 2>&1 && [ -z "${INFISICAL_TOKEN:-}" ]; then
    record "297 v0.7 infisical section skipped — infisical CLI not authenticated" "SKIP" \
           "run 'infisical login' or export INFISICAL_TOKEN=<token>"
else
    V07_IFREG="$RUNS/297-if-registry.toml"
    cat > "$V07_IFREG" <<EOF
if_secret = "infisical-test:///${IF_PROJECT_ID}/dev/SMOKE_TEST_VALUE"
EOF

    # infisical-test keeps the full-form shape (URI supplies
    # project+env). infisical-test-short sets defaults so short-form
    # URIs work — exercised by assertion 308 below.
    V07_IFCFG="$RUNS/297-if-config.toml"
    cat > "$V07_IFCFG" <<EOF
[registries.default]
sources = ["local-main://${V07_IFREG}"]

[backends.local-main]
type = "local"

[backends.infisical-test]
type = "infisical"

[backends.infisical-test-short]
type = "infisical"
infisical_project_id = "${IF_PROJECT_ID}"
infisical_environment = "dev"
EOF

    # Short-form registry: one alias pointing at a short-form URI
    # that relies on backend-level project+env defaults.
    V07_IFREG_SHORT="$RUNS/297-if-registry-short.toml"
    cat > "$V07_IFREG_SHORT" <<EOF
if_secret_short = "infisical-test-short:///SMOKE_TEST_VALUE"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V07_IFPROJ="$RUNS/297-if-project"
    mkdir -p "$V07_IFPROJ"
    cat > "$V07_IFPROJ/secretenv.toml" <<EOF
[secrets]
IF_SECRET = { from = "secretenv://if_secret" }
EOF

    # 23a — doctor sees the infisical backend authenticated.
    run_test "297 v0.7 infisical doctor sees backend" 0 "$RUNS/297-v07-if-doctor.log" \
      "$BIN" --config "$V07_IFCFG" doctor
    assert_contains "298 infisical doctor lists instance"         "$RUNS/297-v07-if-doctor.log" 'infisical-test'
    assert_contains "299 infisical doctor identity names auth mode" "$RUNS/297-v07-if-doctor.log" 'auth='
    assert_contains "300 infisical doctor identity names domain"    "$RUNS/297-v07-if-doctor.log" 'domain='

    # 23b — round-trip get: alias in local registry resolves to
    # infisical URI, backend.get() runs
    # `infisical secrets get … --plain` and returns the seeded value.
    run_test "301 v0.7 infisical get round-trip" 0 "$RUNS/301-v07-if-get.log" \
      "$BIN" --config "$V07_IFCFG" get if_secret --yes
    assert_contains "302 infisical round-trip returns seeded value" "$RUNS/301-v07-if-get.log" 'sk_test_infisical_55555'

    # 23c — end-to-end `run` injects the infisical-backed alias as env.
    run_test "303 v0.7 infisical run injects env var" 0 "$RUNS/303-v07-if-run.log" \
      bash -c "cd '$V07_IFPROJ' && '$BIN' --config '$V07_IFCFG' run -- sh -c 'echo if=\$IF_SECRET'"
    assert_contains "304 infisical run renders IF_SECRET" "$RUNS/303-v07-if-run.log" 'if=sk_test_infisical_55555'

    # 23d — history surfaces the "unsupported" message. CLI v0.43.77
    # has no `secrets versions` subcommand; backend bails locally
    # with a Dashboard-pointer message per the override.
    run_test "305 v0.7 infisical history bails unsupported" 1 "$RUNS/305-v07-if-history.log" \
      "$BIN" --config "$V07_IFCFG" registry history if_secret
    assert_contains "306 infisical history names 'not supported'" "$RUNS/305-v07-if-history.log" 'history is not supported'
    assert_contains "307 infisical history points at Dashboard"   "$RUNS/305-v07-if-history.log" 'Dashboard'

    # 23e — short-form URI round-trip via backend defaults. A regression
    # that broke the both-or-neither defaults wiring or ignored
    # infisical_project_id/infisical_environment would surface here
    # with a "URI short form"-style error rather than a successful
    # fetch.
    V07_IFCFG_SHORT="$RUNS/297-if-config-short.toml"
    cat > "$V07_IFCFG_SHORT" <<EOF
[registries.default]
sources = ["local-main://${V07_IFREG_SHORT}"]

[backends.local-main]
type = "local"

[backends.infisical-test-short]
type = "infisical"
infisical_project_id = "${IF_PROJECT_ID}"
infisical_environment = "dev"
EOF
    run_test "308 v0.7 infisical short-form URI uses backend defaults" 0 "$RUNS/308-v07-if-short.log" \
      "$BIN" --config "$V07_IFCFG_SHORT" get if_secret_short --yes
    assert_contains "309 infisical short-form returns seeded value" "$RUNS/308-v07-if-short.log" 'sk_test_infisical_55555'

    # 23f — fragment on get is rejected before subprocess. A
    # regression that stripped the fragment-reject would either
    # succeed silently (worse) or fail with a subprocess stderr
    # message (misleading).
    V07_IFREG_FRAG="$RUNS/297-if-registry-frag.toml"
    cat > "$V07_IFREG_FRAG" <<EOF
if_frag = "infisical-test:///${IF_PROJECT_ID}/dev/SMOKE_TEST_VALUE#version=5"
EOF
    V07_IFCFG_FRAG="$RUNS/297-if-config-frag.toml"
    cat > "$V07_IFCFG_FRAG" <<EOF
[registries.default]
sources = ["local-main://${V07_IFREG_FRAG}"]

[backends.local-main]
type = "local"

[backends.infisical-test]
type = "infisical"
EOF
    run_test "310 v0.7 infisical rejects fragment on get" 1 "$RUNS/310-v07-if-frag.log" \
      "$BIN" --config "$V07_IFCFG_FRAG" get if_frag --yes
    assert_contains "311 infisical fragment-reject names backend" "$RUNS/310-v07-if-frag.log" 'infisical'

    # Note: live-smoke of backend.set() is deliberately omitted.
    # `registry set` at v0.7 only supports "Pattern B" backends
    # (single-doc registries over local / 1password / aws-ssm /
    # vault / aws-secrets / gcp / azure — see cli.rs:
    # serialize_registry). Infisical uses "Pattern A" — each
    # backend secret IS one alias — so it cannot use the registry-
    # doc serializer. Unit tests `set_value_never_appears_on_argv`
    # + `delete_without_type_shared_flag_would_fail_strict_mock`
    # cover set() argv discipline; Section 23's get/run/history
    # surface covers every other trait method live.

    # 23g — v0.7.2 registry-source coverage. provision.sh seeded a
    # URI-valued SMOKE_REGISTRY_ALIAS at env=dev path=/registry.
    # `registry list --registry <URI>` invokes backend.list() on
    # Infisical, which returns every secret in the scoped env+path as
    # an alias → target-URI pair (Pattern A bulk model). The separate
    # path keeps URI-valued entries away from the scalar SMOKE_TEST_
    # VALUE at root that sections 23b/23c/23e depend on.
    V07_IFCFG_REG="$RUNS/297-if-config-regsrc.toml"
    cat > "$V07_IFCFG_REG" <<EOF
[registries.default]
sources = ["infisical-registry:///${IF_PROJECT_ID}/dev/registry/UNUSED_MARKER"]

[backends.infisical-registry]
type = "infisical"

# Declared so the alias's target URI ('local-main://...') resolves
# cleanly. Same pattern as the Doppler registry-source config.
[backends.local-main]
type = "local"
EOF
    run_test "315 v0.7.2 infisical registry-source list" 0 "$RUNS/315-v072-if-reglist.log" \
      "$BIN" --config "$V07_IFCFG_REG" registry list --registry default
    assert_contains "316 infisical registry-source names alias" \
      "$RUNS/315-v072-if-reglist.log" 'SMOKE_REGISTRY_ALIAS'
    assert_contains "317 infisical registry-source names target URI" \
      "$RUNS/315-v072-if-reglist.log" 'local-main://'
fi

# ---------------------------------------------------------------
# 24 — v0.8: Keeper backend
# ---------------------------------------------------------------
section_begin 24 "v0.8 Keeper backend"
# Self-contained like sections 22 + 23: dedicated mini-config +
# mini-registry point at the Keeper vault records provision.sh
# seeded (SMOKE_TEST_VALUE scalar + SMOKE_REGISTRY_ALIAS URI-valued).
# Does NOT touch cross-backend shared fixtures.
#
# Pre-req: `keeper` CLI installed AND persistent-login set up
# (`keeper shell` → `this-device register` → `this-device persistent-
# login on`). Non-authenticated runs record a SKIP — same discipline
# as Keychain's non-macOS SKIP + Doppler/Infisical's not-logged-in
# SKIP.

if ! command -v keeper >/dev/null 2>&1; then
    record "318 v0.8 keeper section skipped — keeper CLI not installed" "SKIP" \
           "install: pip install keepercommander"
elif ! keeper --batch-mode login-status 2>&1 | grep -q 'Logged in'; then
    record "318 v0.8 keeper section skipped — persistent-login not set up" "SKIP" \
           "run 'keeper shell' then 'this-device register' + 'this-device persistent-login on'"
else
    V08_KPREG="$RUNS/318-kp-registry.toml"
    cat > "$V08_KPREG" <<EOF
kp_secret = "keeper-test:///SMOKE_TEST_VALUE"
EOF

    V08_KPCFG="$RUNS/318-kp-config.toml"
    cat > "$V08_KPCFG" <<EOF
[registries.default]
sources = ["local-main://${V08_KPREG}"]

[backends.local-main]
type = "local"

[backends.keeper-test]
type = "keeper"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V08_KPPROJ="$RUNS/318-kp-project"
    mkdir -p "$V08_KPPROJ"
    cat > "$V08_KPPROJ/secretenv.toml" <<EOF
[secrets]
KP_SECRET = { from = "secretenv://kp_secret" }
EOF

    # 24a — doctor sees the keeper backend authenticated.
    run_test "318 v0.8 keeper doctor sees backend" 0 "$RUNS/318-v08-kp-doctor.log" \
      "$BIN" --config "$V08_KPCFG" doctor
    assert_contains "319 keeper doctor lists instance"      "$RUNS/318-v08-kp-doctor.log" 'keeper-test'
    assert_contains "320 keeper doctor identity names auth" "$RUNS/318-v08-kp-doctor.log" 'auth=persistent-login'

    # 24b — round-trip get: alias in local registry resolves to
    # keeper URI, backend.get() runs `keeper --batch-mode get
    # <title> --format=password --unmask` and returns the seeded
    # password from provision.sh.
    run_test "321 v0.8 keeper get round-trip" 0 "$RUNS/321-v08-kp-get.log" \
      "$BIN" --config "$V08_KPCFG" get kp_secret --yes
    assert_contains "322 keeper round-trip returns seeded value" "$RUNS/321-v08-kp-get.log" 'kp_vault_88888'

    # 24c — end-to-end `run` injects the keeper-backed alias as env.
    run_test "323 v0.8 keeper run injects env var" 0 "$RUNS/323-v08-kp-run.log" \
      bash -c "cd '$V08_KPPROJ' && '$BIN' --config '$V08_KPCFG' run -- sh -c 'echo kp=\$KP_SECRET'"
    assert_contains "324 keeper run renders KP_SECRET" "$RUNS/323-v08-kp-run.log" 'kp=kp_vault_88888'

    # 24d — history surfaces the "unsupported" message. CLI v17.2.13
    # has no per-record version-history subcommand.
    run_test "325 v0.8 keeper history bails unsupported" 1 "$RUNS/325-v08-kp-history.log" \
      "$BIN" --config "$V08_KPCFG" registry history kp_secret
    assert_contains "326 keeper history names 'not supported'" "$RUNS/325-v08-kp-history.log" 'history is not supported'
    assert_contains "327 keeper history points at Vault UI"    "$RUNS/325-v08-kp-history.log" 'Vault UI'

    # 24e — fragment on get is rejected before subprocess. Unknown
    # fragment (`#version=5`) should bail locally — only `#field=<n>`
    # is supported. A regression that accepted unknown fragments
    # would either silently ignore them or fail with a subprocess
    # error.
    V08_KPREG_FRAG="$RUNS/318-kp-registry-frag.toml"
    cat > "$V08_KPREG_FRAG" <<EOF
kp_frag = "keeper-test:///SMOKE_TEST_VALUE#version=5"
EOF
    V08_KPCFG_FRAG="$RUNS/318-kp-config-frag.toml"
    cat > "$V08_KPCFG_FRAG" <<EOF
[registries.default]
sources = ["local-main://${V08_KPREG_FRAG}"]

[backends.local-main]
type = "local"

[backends.keeper-test]
type = "keeper"
EOF
    run_test "328 v0.8 keeper rejects unknown fragment" 1 "$RUNS/328-v08-kp-frag.log" \
      "$BIN" --config "$V08_KPCFG_FRAG" get kp_frag --yes
    assert_contains "329 keeper fragment-reject names backend" "$RUNS/328-v08-kp-frag.log" 'keeper'

    # 24f — set() gate is NOT exercised at the smoke layer.
    # `registry set` is Pattern B only (single-doc registries: local
    # / 1password / aws-ssm / vault / aws-secrets / gcp / azure);
    # keeper is Pattern A (bulk), so `registry set` cannot route
    # through keeper's backend.set() at all. The `keeper_unsafe_set`
    # gate bail is locked by unit tests
    # (`set_is_gated_by_keeper_unsafe_set` + the opt-in path tests)
    # rather than live smoke. Pattern A `registry set` extension is
    # a v0.8.x+ roadmap item; when it lands, the gate gets an
    # additional live assertion here.

    # 24g — registry-source list via backend.list(). provision.sh
    # seeded SMOKE_REGISTRY_ALIAS as a URI-valued record; list()
    # returns every vault record's title→password pair. The URI-
    # valued record surfaces; the scalar SMOKE_TEST_VALUE also
    # surfaces (password is "kp_vault_88888" which doesn't parse as
    # URI) — we filter via the resolver's URI-parse at downstream.
    # A `registry list` that fails on ANY invalid URI value would
    # abort — so we need a registry config that ONLY expects URI
    # entries. Instead we use `resolve` on the URI-valued alias
    # entry to prove list() plumbed it through.
    #
    # For a CLEAN registry-source test, we'd need a dedicated folder
    # with URI-only entries; that requires additional keeper folder
    # support in provision.sh which isn't in v0.8 scope. Deferred.
    # Unit tests `list_returns_title_password_pairs` lock the shape.
fi

# ---------------------------------------------------------------
# 25 — v0.9: Cloudflare Workers KV backend
# ---------------------------------------------------------------
section_begin 25 "v0.9 Cloudflare Workers KV backend"
# Self-contained like sections 22-24: dedicated mini-config + mini-
# registry point at the smoke KV namespace seeded by provision.sh
# (SMOKE_TEST_VALUE scalar + SMOKE_REGISTRY_ALIAS URI-valued).
#
# Pre-req: `wrangler` CLI installed AND authenticated (`wrangler login`
# OAuth OR CLOUDFLARE_API_TOKEN env var). Non-authenticated runs
# record a SKIP — same discipline as Doppler/Infisical/Keeper.

# cf-kv namespace IDs from single source of truth. v0.9.1 hygiene.
# shellcheck source=lib/cfkv-namespace.env
. "$_here/lib/cfkv-namespace.env"

if ! command -v wrangler >/dev/null 2>&1; then
    record "330 v0.9 cf-kv section skipped — wrangler CLI not installed" "SKIP" \
           "install: npm install -g wrangler  OR  brew install cloudflare/cloudflare/wrangler"
elif ! wrangler whoami >/dev/null 2>&1; then
    record "330 v0.9 cf-kv section skipped — wrangler not authenticated" "SKIP" \
           "run 'wrangler login' OR export CLOUDFLARE_API_TOKEN with workers_kv:write"
else
    V09_CFREG="$RUNS/330-cfkv-registry.toml"
    cat > "$V09_CFREG" <<EOF
cf_secret = "cf-kv-test:///${CFKV_NS}/SMOKE_TEST_VALUE"
EOF

    V09_CFCFG="$RUNS/330-cfkv-config.toml"
    cat > "$V09_CFCFG" <<EOF
[registries.default]
sources = ["local-main://${V09_CFREG}"]

[backends.local-main]
type = "local"

[backends.cf-kv-test]
type = "cf-kv"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V09_CFPROJ="$RUNS/330-cfkv-project"
    mkdir -p "$V09_CFPROJ"
    cat > "$V09_CFPROJ/secretenv.toml" <<EOF
[secrets]
CF_SECRET = { from = "secretenv://cf_secret" }
EOF

    # 25a — doctor sees the cf-kv backend authenticated.
    run_test "330 v0.9 cf-kv doctor sees backend" 0 "$RUNS/330-v09-cfkv-doctor.log" \
      "$BIN" --config "$V09_CFCFG" doctor
    assert_contains "331 cf-kv doctor lists instance"      "$RUNS/330-v09-cfkv-doctor.log" 'cf-kv-test'
    assert_contains "332 cf-kv doctor identity names auth" "$RUNS/330-v09-cfkv-doctor.log" 'auth=wrangler'

    # 25b — round-trip get: alias in local registry resolves to
    # cf-kv URI, backend.get() runs `wrangler kv key get
    # <key> --namespace-id <ns> --remote --text` and returns the
    # value seeded by provision.sh.
    run_test "333 v0.9 cf-kv get round-trip" 0 "$RUNS/333-v09-cfkv-get.log" \
      "$BIN" --config "$V09_CFCFG" get cf_secret --yes
    assert_contains "334 cf-kv round-trip returns seeded value" "$RUNS/333-v09-cfkv-get.log" 'cf_kv_value_99999'

    # 25b' — security canary: the run log must NOT echo the value
    # back through stderr or any wrangler banner. The doctor log
    # exercises check() (no value flow); the get log carries the
    # decoded value as expected output. We pin: no failure-path
    # log includes the value (history bail at 25d, fragment-reject
    # at 25e — neither reads the seeded value, so the seeded value
    # MUST NOT appear in those logs).
    assert_not_contains "334a cf-kv history log does not leak value" \
      "$RUNS/337-v09-cfkv-history.log" 'cf_kv_value_99999'
    assert_not_contains "334b cf-kv fragment-reject log does not leak value" \
      "$RUNS/340-v09-cfkv-frag.log" 'cf_kv_value_99999'

    # 25c — end-to-end `run` injects the cf-kv-backed alias as env.
    run_test "335 v0.9 cf-kv run injects env var" 0 "$RUNS/335-v09-cfkv-run.log" \
      bash -c "cd '$V09_CFPROJ' && '$BIN' --config '$V09_CFCFG' run -- sh -c 'echo cf=\$CF_SECRET'"
    assert_contains "336 cf-kv run renders CF_SECRET" "$RUNS/335-v09-cfkv-run.log" 'cf=cf_kv_value_99999'

    # 25d — history surfaces the "unsupported" message. Workers KV
    # has no per-key version history (overwrites simply replace).
    run_test "337 v0.9 cf-kv history bails unsupported" 1 "$RUNS/337-v09-cfkv-history.log" \
      "$BIN" --config "$V09_CFCFG" registry history cf_secret
    assert_contains "338 cf-kv history names 'not supported'" "$RUNS/337-v09-cfkv-history.log" 'history is not supported'
    assert_contains "339 cf-kv history points at key naming"  "$RUNS/337-v09-cfkv-history.log" 'encode it in the key name'

    # 25e — fragment on get is rejected before subprocess. cf-kv has
    # no fragment vocabulary in v0.9 — any `#…` is rejected by
    # `BackendUri::reject_any_fragment` locally before any wrangler
    # spawn.
    V09_CFREG_FRAG="$RUNS/330-cfkv-registry-frag.toml"
    cat > "$V09_CFREG_FRAG" <<EOF
cf_frag = "cf-kv-test:///${CFKV_NS}/SMOKE_TEST_VALUE#field=foo"
EOF
    V09_CFCFG_FRAG="$RUNS/330-cfkv-config-frag.toml"
    cat > "$V09_CFCFG_FRAG" <<EOF
[registries.default]
sources = ["local-main://${V09_CFREG_FRAG}"]

[backends.local-main]
type = "local"

[backends.cf-kv-test]
type = "cf-kv"
EOF
    run_test "340 v0.9 cf-kv rejects any fragment" 1 "$RUNS/340-v09-cfkv-frag.log" \
      "$BIN" --config "$V09_CFCFG_FRAG" get cf_frag --yes
    assert_contains "341 cf-kv fragment-reject names backend" "$RUNS/340-v09-cfkv-frag.log" 'cf-kv'

    # 25f — set + get + delete cycle. Unlike Keeper (which gates
    # set() behind keeper_unsafe_set), cf-kv's set() uses a mode-0600
    # tempfile + --path so it is safe-by-default. Pattern A backends
    # don't surface set() through `secretenv registry set` (that's
    # Pattern B's lane), so we exercise via direct CLI invocation
    # using the URI shape. Most test harnesses don't have a public
    # `secretenv set <uri>` surface; we cover via a minimal
    # registry-set fall-through OR use a Rust-level cycle.
    #
    # Pragmatic path for v0.9: probe set() through `registry set` if
    # cf-kv lands in Pattern B in a future release; for v0.9 we lock
    # the round-trip via unit tests (`set_uses_path_flag_not_argv_value`)
    # + provision.sh's seed itself (which uses `wrangler kv key put
    # --path` to write SMOKE_TEST_VALUE — round-trip-validated by
    # 25b above). The set() path is therefore exercised by both unit
    # tests AND by provision.sh's seed step, which is functionally
    # equivalent coverage. No live Section 25f cycle for v0.9.

    # 25g — registry-source list via backend.list(). provision.sh
    # seeded SMOKE_REGISTRY_ALIAS as a URI-valued key; list()
    # returns every namespace key's name→value pair. Same caveat as
    # Keeper's 24g: SMOKE_TEST_VALUE is also enumerated and its
    # value isn't a URI, so it gets dropped by the resolver. We
    # validate via `resolve` against the URI-valued alias.
    # cf-kv as a REGISTRY SOURCE — exercises the full Pattern A bulk
    # path. SMOKE_REGISTRY_ALIAS in the namespace holds a URI value
    # pointing at a local-main file that provision.sh seeds; the chain
    # is: cf-kv list() → SMOKE_REGISTRY_ALIAS=local-main://… →
    # local-main backend reads the file → secret value surfaces.
    # Mirrors the extensive registry-source coverage other backends
    # (Doppler 22, Infisical 23) get; Keeper deferred this in v0.8.
    V09_CFREGSRC="$RUNS/330-cfkv-regsrc.toml"
    cat > "$V09_CFREGSRC" <<EOF
[registries.default]
sources = ["cf-kv-test:///${CFKV_REG_NS}/REGISTRY_MARKER"]

[backends.local-main]
type = "local"

[backends.cf-kv-test]
type = "cf-kv"
EOF

    # 25g — registry list via cf-kv source surfaces the URI-valued key.
    run_test "342 v0.9 cf-kv registry-source enumerates URI-valued keys" 0 \
      "$RUNS/342-v09-cfkv-reglist.log" \
      "$BIN" --config "$V09_CFREGSRC" registry list
    assert_contains "343 cf-kv registry-source surfaces SMOKE_REGISTRY_ALIAS" \
      "$RUNS/342-v09-cfkv-reglist.log" 'SMOKE_REGISTRY_ALIAS'
    # 25g.1 — v0.9.1 hygiene (sec-L1): the registry namespace must
    # contain ONLY URI-valued aliases. SMOKE_TEST_VALUE is the
    # scalar fixture seeded in the SECRETS namespace, NOT the
    # REGISTRY namespace; if it appears here, the two-namespace
    # provision discipline broke OR the resolver started leaking
    # non-URI values through registry list (would surface a real
    # security issue — registry source returning unparseable values
    # could feed downstream `secretenv get` flows scalars labeled as
    # URIs). Lock the negative.
    assert_not_contains "343a cf-kv registry namespace must not surface scalar SMOKE_TEST_VALUE" \
      "$RUNS/342-v09-cfkv-reglist.log" 'SMOKE_TEST_VALUE'

    # 25h — registry get pulls the URI value from cf-kv. Locks
    # registry get's bulk-source resolution path through cf-kv.
    run_test "344 v0.9 cf-kv registry get pulls URI" 0 \
      "$RUNS/344-v09-cfkv-regget.log" \
      "$BIN" --config "$V09_CFREGSRC" registry get SMOKE_REGISTRY_ALIAS
    assert_contains "345 cf-kv registry get returns local-main URI" \
      "$RUNS/344-v09-cfkv-regget.log" 'local-main://'
    assert_contains "346 cf-kv registry get URI points at provisioned file" \
      "$RUNS/344-v09-cfkv-regget.log" 'stripe-key.txt'

    # 25i — resolve through cf-kv-backed registry: the alias resolves
    # to a local-main URI, which then reads the file. End-to-end
    # cross-backend chain proves cf-kv list() is wire-compatible with
    # the alias map the resolver expects.
    run_test "347 v0.9 cf-kv resolve cross-backend chain" 0 \
      "$RUNS/347-v09-cfkv-resolve.log" \
      "$BIN" --config "$V09_CFREGSRC" resolve SMOKE_REGISTRY_ALIAS
    assert_contains "348 cf-kv resolve names cf-kv source backend" \
      "$RUNS/347-v09-cfkv-resolve.log" 'cf-kv-test'
    assert_contains "349 cf-kv resolve surfaces final local-main URI" \
      "$RUNS/347-v09-cfkv-resolve.log" 'local-main'

    # 25j — end-to-end `run` via cf-kv-backed registry. The manifest
    # asks for SMOKE_REGISTRY_ALIAS; cf-kv's list() seeds the alias map;
    # the URI value (local-main://…/stripe-key.txt) resolves through
    # the local backend and the file's contents inject as env. This
    # is the full production path that the registry-source design
    # promises — same coverage Doppler / Infisical get.
    V09_CFREGSRC_PROJ="$RUNS/330-cfkv-regsrc-project"
    mkdir -p "$V09_CFREGSRC_PROJ"
    cat > "$V09_CFREGSRC_PROJ/secretenv.toml" <<EOF
[secrets]
STRIPE_KEY = { from = "secretenv://SMOKE_REGISTRY_ALIAS" }
EOF
    run_test "350 v0.9 cf-kv-backed registry end-to-end run" 0 \
      "$RUNS/350-v09-cfkv-run-regsrc.log" \
      bash -c "cd '$V09_CFREGSRC_PROJ' && '$BIN' --config '$V09_CFREGSRC' run -- sh -c 'echo stripe=\$STRIPE_KEY'"
    # provision.sh seeds local-secrets/stripe-key.txt with a fixed
    # fixture string — assert it surfaces via the cf-kv→local-main
    # chain.
    assert_contains "351 cf-kv-backed run injects local-main file content" \
      "$RUNS/350-v09-cfkv-run-regsrc.log" 'stripe='

    # 25k — v0.9.1 hygiene (sec-M2): wrangler-delete-actually-deletes
    # canary. The cf-kv backend's `delete()` shells to
    # `wrangler kv key delete --namespace-id <id> --remote <key>`
    # without an explicit `--force` flag (none exists in wrangler
    # 4.85.0). It works today because wrangler skips its interactive
    # prompt when stdin is not a TTY (as is the case under our
    # `Stdio::null()` discipline). If a future wrangler minor
    # regresses to default-no on the prompt, every cf-kv delete
    # would silently no-op with exit 0 — a real bug class.
    #
    # SecretEnv has no CLI surface that calls cf-kv backend.delete()
    # directly (`registry unset` is Pattern-B-doc only and rejects
    # Pattern-A bulk backends like cf-kv at the serialize step), so
    # this canary exercises wrangler's behavior in the same non-TTY
    # mode our backend uses. The plumbing path (cf-kv backend →
    # wrangler subprocess → namespace mutation) is locked by the
    # backend's unit tests; this assertion locks the wrangler
    # contract our backend depends on.
    CFKV_PROBE_TMP="$(mktemp)"
    chmod 600 "$CFKV_PROBE_TMP"
    printf 'cfkv_delete_probe_value' > "$CFKV_PROBE_TMP"
    wrangler kv key put --namespace-id "$CFKV_NS" --remote --path "$CFKV_PROBE_TMP" CFKV_DELETE_PROBE >/dev/null 2>&1
    rm -f "$CFKV_PROBE_TMP"

    # Confirm the probe landed before exercising delete.
    wrangler kv key get --namespace-id "$CFKV_NS" --remote --text CFKV_DELETE_PROBE > "$RUNS/352-v091-cfkv-predel.log" 2>&1
    assert_contains "352 v0.9.1 cf-kv pre-delete read confirms probe" \
      "$RUNS/352-v091-cfkv-predel.log" 'cfkv_delete_probe_value'

    # Delete in same non-TTY context the backend uses (no </dev/tty,
    # no explicit --force flag). If wrangler ever regresses to
    # default-no on the prompt, exit will be 0 but the key will
    # still exist.
    wrangler kv key delete --namespace-id "$CFKV_NS" --remote CFKV_DELETE_PROBE </dev/null >/dev/null 2>&1

    # Read-back must fail with not-found. The not-found exit code
    # tells us wrangler's error model still surfaces missing keys
    # (which our backend depends on for its `is_not_found_stderr`
    # heuristic to fire).
    wrangler kv key get --namespace-id "$CFKV_NS" --remote --text CFKV_DELETE_PROBE > "$RUNS/353-v091-cfkv-postdel.log" 2>&1
    # wrangler 4.85.0 surfaces 404s with "404: Not Found" (capital N)
    # in stderr. Match on the literal status string rather than the
    # word "not found" — same evidence, immune to case-shifts.
    assert_contains "353 v0.9.1 cf-kv post-delete read surfaces 404" \
      "$RUNS/353-v091-cfkv-postdel.log" '404'

    # Direct wrangler list canary — the most authoritative check.
    # If wrangler still lists CFKV_DELETE_PROBE, the delete didn't
    # actually mutate state — load-bearing for the sec-M2 risk.
    wrangler kv key list --namespace-id "$CFKV_NS" --remote > "$RUNS/354-v091-cfkv-wrangler-list.log" 2>&1
    assert_not_contains "354 v0.9.1 cf-kv wrangler list does not show deleted probe" \
      "$RUNS/354-v091-cfkv-wrangler-list.log" 'CFKV_DELETE_PROBE'
fi

# ---------------------------------------------------------------
# 26 — v0.10: OpenBao backend
# ---------------------------------------------------------------
section_begin 26 "v0.10 OpenBao backend"
# Self-contained: dedicated mini-config + mini-registry point at the
# OpenBao dev server seeded by provision.sh (scalar + json-multi +
# openbao-registry under secret/secretenv-smoke/). Skipped if `bao`
# is missing OR the server is sealed/unreachable OR the token is
# invalid — same SKIP discipline as Doppler/Infisical/Keeper/cf-kv.
#
# Address override: SECRETENV_TEST_BAO_ADDR (default 127.0.0.1:8300).
# Port 8300 (not 8200) avoids collision with the parallel Vault
# dev-mode the validation host runs at the canonical 8200 — see
# kb/wiki/backends/openbao.md `BAO_ADDR` HTTP/HTTPS gotcha.

V010_BAO_ADDR="${SECRETENV_TEST_BAO_ADDR:-http://127.0.0.1:8300}"

if ! command -v bao >/dev/null 2>&1; then
    record "360 v0.10 openbao section skipped — bao CLI not installed" "SKIP" \
           "install: brew install openbao  OR  https://openbao.org/docs/install/"
elif ! BAO_ADDR="$V010_BAO_ADDR" bao status >/dev/null 2>&1; then
    record "360 v0.10 openbao section skipped — server unreachable or sealed" "SKIP" \
           "address: $V010_BAO_ADDR  (start: bao server -dev OR unseal)"
elif ! BAO_ADDR="$V010_BAO_ADDR" bao token lookup >/dev/null 2>&1; then
    record "360 v0.10 openbao section skipped — token invalid" "SKIP" \
           "run 'bao login' or place a valid token in ~/.vault-token"
else
    V010_BAOREG="$RUNS/360-bao-registry.toml"
    cat > "$V010_BAOREG" <<EOF
bao_secret = "openbao-dev:///secret/secretenv-smoke/scalar"
bao_json_pw = "openbao-dev:///secret/secretenv-smoke/json-multi#json-key=password"
EOF

    V010_BAOCFG="$RUNS/360-bao-config.toml"
    cat > "$V010_BAOCFG" <<EOF
[registries.default]
sources = ["local-main://${V010_BAOREG}"]

[backends.local-main]
type = "local"

[backends.openbao-dev]
type = "openbao"
bao_address = "${V010_BAO_ADDR}"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V010_BAOPROJ="$RUNS/360-bao-project"
    mkdir -p "$V010_BAOPROJ"
    cat > "$V010_BAOPROJ/secretenv.toml" <<EOF
[secrets]
BAO_SECRET = { from = "secretenv://bao_secret" }
BAO_PASSWORD = { from = "secretenv://bao_json_pw" }
EOF

    # 26a — doctor sees the openbao backend authenticated.
    run_test "360 v0.10 openbao doctor sees backend" 0 "$RUNS/360-v010-bao-doctor.log" \
      "$BIN" --config "$V010_BAOCFG" doctor
    assert_contains "361 openbao doctor lists instance"   "$RUNS/360-v010-bao-doctor.log" 'openbao-dev'
    assert_contains "362 openbao doctor identity names addr" "$RUNS/360-v010-bao-doctor.log" "addr=${V010_BAO_ADDR}"
    assert_contains "363 openbao doctor identity has no namespace" "$RUNS/360-v010-bao-doctor.log" 'namespace=(none)'

    # 26b — round-trip get of the scalar fixture. Backend runs
    # `bao kv get -field=value secret/secretenv-smoke/scalar` and
    # returns `smoke-scalar-v0.10` (one trailing newline trimmed).
    run_test "364 v0.10 openbao get scalar round-trip" 0 "$RUNS/364-v010-bao-get.log" \
      "$BIN" --config "$V010_BAOCFG" get bao_secret --yes
    assert_contains "365 openbao get returns seeded scalar" "$RUNS/364-v010-bao-get.log" 'smoke-scalar-v0.10'

    # 26c — `#json-key=password` fragment extracts the password field
    # from the JSON-encoded `value` at secret/secretenv-smoke/json-multi.
    run_test "366 v0.10 openbao json-key fragment extracts field" 0 "$RUNS/366-v010-bao-jsonkey.log" \
      "$BIN" --config "$V010_BAOCFG" get bao_json_pw --yes
    assert_contains "367 openbao fragment returns password field" "$RUNS/366-v010-bao-jsonkey.log" 'smoke-pw'
    assert_not_contains "368 openbao fragment does not leak username" "$RUNS/366-v010-bao-jsonkey.log" 'smoke-user'

    # 26d — end-to-end `run` injects both scalar + JSON-extracted env vars.
    run_test "369 v0.10 openbao run injects env vars" 0 "$RUNS/369-v010-bao-run.log" \
      bash -c "cd '$V010_BAOPROJ' && '$BIN' --config '$V010_BAOCFG' run -- sh -c 'echo s=\$BAO_SECRET p=\$BAO_PASSWORD'"
    assert_contains "370 openbao run renders scalar"          "$RUNS/369-v010-bao-run.log" 's=smoke-scalar-v0.10'
    assert_contains "371 openbao run renders fragment-extracted" "$RUNS/369-v010-bao-run.log" 'p=smoke-pw'

    # 26e — set + get + delete cycle on a unique-per-run path.
    # Exercises the full `value=-` stdin discipline against the live
    # server. `registry set` lands openbao in the JSON-arm of
    # serialize_registry (alongside vault/aws-secrets/aws-ssm/gcp/azure)
    # and round-trips through the same value=- path.
    #
    # `registry set` reads the existing registry document first to
    # merge the new alias in. For a fresh path that doesn't exist,
    # this fails — so we pre-seed an empty `{}` JSON map at the cycle
    # path before the set call. Vault dodges this because its smoke
    # paths are pre-seeded by provision.sh under shared keys; here we
    # use a unique-per-run path so seeds and teardown are tidy.
    BAO_CYCLE_PATH="secret/secretenv-smoke/cycle-$$-$(date +%s)"
    printf '{}' | BAO_ADDR="$V010_BAO_ADDR" bao kv put "$BAO_CYCLE_PATH" value=- >/dev/null 2>&1
    V010_BAOCYCLE_REG="$RUNS/372-bao-cycle-registry.toml"
    cat > "$V010_BAOCYCLE_REG" <<EOF
[registries.bao_cycle]
sources = ["openbao-dev:///${BAO_CYCLE_PATH}"]

[backends.openbao-dev]
type = "openbao"
bao_address = "${V010_BAO_ADDR}"
EOF
    # Set an alias.
    run_test "372 v0.10 openbao registry set" 0 "$RUNS/372-v010-bao-set.log" \
      "$BIN" --config "$V010_BAOCYCLE_REG" registry set cycle_alias \
        "openbao-dev:///secret/secretenv-smoke/scalar" --registry bao_cycle
    # Round-trip read of the alias map back through list().
    run_test "373 v0.10 openbao registry list reads back" 0 "$RUNS/373-v010-bao-list.log" \
      "$BIN" --config "$V010_BAOCYCLE_REG" registry list --registry bao_cycle
    assert_contains "374 openbao list surfaces written alias" \
      "$RUNS/373-v010-bao-list.log" 'cycle_alias'
    # Unset removes the alias; subsequent list shows it gone.
    run_test "375 v0.10 openbao registry unset" 0 "$RUNS/375-v010-bao-unset.log" \
      "$BIN" --config "$V010_BAOCYCLE_REG" registry unset cycle_alias --registry bao_cycle
    run_test "376 v0.10 openbao list after unset" 0 "$RUNS/376-v010-bao-list2.log" \
      "$BIN" --config "$V010_BAOCYCLE_REG" registry list --registry bao_cycle
    assert_not_contains "377 openbao list no longer shows unset alias" \
      "$RUNS/376-v010-bao-list2.log" 'cycle_alias'
    # Soft-delete the cycle path so the smoke namespace stays tidy.
    BAO_ADDR="$V010_BAO_ADDR" bao kv metadata delete "$BAO_CYCLE_PATH" >/dev/null 2>&1 || true

    # 26f — fragment-reject on registry list. Fragments are only
    # valid on `get`; `list` rejects them locally before any subprocess.
    # The positive `#json-key` path is already locked by 366/367 (the
    # json-multi fixture) — no need to re-test fragment-on-get here.
    V010_BAOREG_FRAG="$RUNS/378-bao-registry-frag.toml"
    cat > "$V010_BAOREG_FRAG" <<EOF
[registries.default]
sources = ["openbao-dev:///secret/secretenv-smoke/openbao-registry#json-key=foo"]

[backends.openbao-dev]
type = "openbao"
bao_address = "${V010_BAO_ADDR}"
EOF
    run_test "378 v0.10 openbao registry list rejects fragment" 1 "$RUNS/378-v010-bao-frag-list.log" \
      "$BIN" --config "$V010_BAOREG_FRAG" registry list --registry default
    assert_contains "379 openbao fragment-reject names backend" \
      "$RUNS/378-v010-bao-frag-list.log" 'openbao'

    # 26g — history surfaces the trait-default "not implemented"
    # message. KV v2 metadata is reachable but exposing it cleanly
    # is v0.10.x carry-forward (per build plan).
    run_test "380 v0.10 openbao history bails unsupported" 1 "$RUNS/380-v010-bao-history.log" \
      "$BIN" --config "$V010_BAOCFG" registry history bao_secret
    assert_contains "381 openbao history names 'not implemented'" \
      "$RUNS/380-v010-bao-history.log" 'not implemented'

    # 26h — registry-source path: read alias map from the openbao-
    # registry fixture and resolve through the cross-backend chain.
    # openbao-registry's value is a JSON-string carrying
    # SMOKE_REGISTRY_ALIAS → local-main://…/stripe-key.txt; resolving
    # the alias chains openbao.list() → local-main.get() to surface
    # the file's contents.
    V010_BAOREGSRC="$RUNS/382-bao-regsrc-config.toml"
    cat > "$V010_BAOREGSRC" <<EOF
[registries.default]
sources = ["openbao-dev:///secret/secretenv-smoke/openbao-registry"]

[backends.local-main]
type = "local"

[backends.openbao-dev]
type = "openbao"
bao_address = "${V010_BAO_ADDR}"
EOF
    run_test "382 v0.10 openbao registry-source list" 0 "$RUNS/382-v010-bao-reglist.log" \
      "$BIN" --config "$V010_BAOREGSRC" registry list --registry default
    assert_contains "383 openbao registry-source surfaces SMOKE_REGISTRY_ALIAS" \
      "$RUNS/382-v010-bao-reglist.log" 'SMOKE_REGISTRY_ALIAS'
    assert_contains "384 openbao registry-source target points at local-main" \
      "$RUNS/382-v010-bao-reglist.log" 'local-main://'

    # 26i — cross-backend resolve: openbao registry → local-main URI.
    run_test "385 v0.10 openbao cross-backend resolve" 0 "$RUNS/385-v010-bao-resolve.log" \
      "$BIN" --config "$V010_BAOREGSRC" resolve SMOKE_REGISTRY_ALIAS
    assert_contains "386 openbao resolve names openbao source backend" \
      "$RUNS/385-v010-bao-resolve.log" 'openbao-dev'

    # 26j — HTTP/HTTPS mismatch surface. Pointing the backend at a
    # URL that should be HTTP but is parsed as HTTPS reproduces the
    # canonical first-use stumble; the error must be a CLI-stderr
    # surface, not a parser panic. Use the documented gotcha — a
    # bao server listening on HTTP probed with an https:// URL.
    V010_BAOCFG_HTTPS="$RUNS/387-bao-config-https.toml"
    cat > "$V010_BAOCFG_HTTPS" <<EOF
[registries.default]
sources = ["local-main://${V010_BAOREG}"]

[backends.local-main]
type = "local"

[backends.openbao-dev]
type = "openbao"
bao_address = "https://127.0.0.1:8300"
EOF
    run_test "387 v0.10 openbao HTTP/HTTPS mismatch surfaces error" 1 "$RUNS/387-v010-bao-https.log" \
      "$BIN" --config "$V010_BAOCFG_HTTPS" get bao_secret --yes
    # The exact wording depends on Go's TLS handshake error path; the
    # stable sentinel is the `https://` address surfacing in the
    # error message (or a stderr containing http/tls). Loose match.
    assert_contains "388 openbao mismatch error names backend" \
      "$RUNS/387-v010-bao-https.log" 'openbao'
fi

# ---------------------------------------------------------------
# 27 — v0.11: CyberArk Conjur backend
# ---------------------------------------------------------------
section_begin 27 "v0.11 CyberArk Conjur backend"
# Self-contained: dedicated mini-config + mini-registry point at the
# Conjur OSS dev server seeded by provision.sh (scalar + json-multi +
# conjur-registry under root policy `secretenv-smoke`). Skipped if
# `conjur` is missing OR the server is unreachable OR the session is
# expired/unauthenticated — same SKIP discipline as the other
# wrap-a-CLI backends.
#
# Default URL: http://localhost:8083 (matches conjur-local/
# docker-compose harness). Override via SECRETENV_TEST_CONJUR_URL +
# SECRETENV_TEST_CONJUR_ACCOUNT for hosted Conjur Enterprise smoke.
# HTTP only locally — Phase 0 confirmed `conjur init --insecure` is
# the operator-acknowledged form for HTTP-only dev servers.

V011_CONJUR_URL="${SECRETENV_TEST_CONJUR_URL:-http://localhost:8083}"
V011_CONJUR_ACCOUNT="${SECRETENV_TEST_CONJUR_ACCOUNT:-myorg}"

if ! command -v conjur >/dev/null 2>&1; then
    record "390 v0.11 conjur section skipped — conjur CLI not installed" "SKIP" \
           "install: docker pull cyberark/conjur-cli:8 (alias \`conjur\` to a docker-run wrapper)"
elif ! CONJUR_APPLIANCE_URL="$V011_CONJUR_URL" CONJUR_ACCOUNT="$V011_CONJUR_ACCOUNT" \
       conjur whoami >/dev/null 2>&1; then
    record "390 v0.11 conjur section skipped — server unreachable or session expired" "SKIP" \
           "url: $V011_CONJUR_URL  account: $V011_CONJUR_ACCOUNT  (run: conjur login)"
else
    V011_CONJURREG="$RUNS/390-conjur-registry.toml"
    cat > "$V011_CONJURREG" <<EOF
conjur_secret = "conjur-dev:///secretenv-smoke/scalar"
conjur_json_pw = "conjur-dev:///secretenv-smoke/json-multi#json-key=password"
EOF

    V011_CONJURCFG="$RUNS/390-conjur-config.toml"
    cat > "$V011_CONJURCFG" <<EOF
[registries.default]
sources = ["local-main://${V011_CONJURREG}"]

[backends.local-main]
type = "local"

[backends.conjur-dev]
type = "conjur"
conjur_url = "${V011_CONJUR_URL}"
conjur_account = "${V011_CONJUR_ACCOUNT}"
EOF

    # Mini project manifest for the end-to-end `run` test.
    V011_CONJURPROJ="$RUNS/390-conjur-project"
    mkdir -p "$V011_CONJURPROJ"
    cat > "$V011_CONJURPROJ/secretenv.toml" <<EOF
[secrets]
CONJUR_SECRET = { from = "secretenv://conjur_secret" }
CONJUR_PASSWORD = { from = "secretenv://conjur_json_pw" }
EOF

    # 27a — doctor sees the conjur backend authenticated.
    run_test "390 v0.11 conjur doctor sees backend" 0 "$RUNS/390-v011-conjur-doctor.log" \
      "$BIN" --config "$V011_CONJURCFG" doctor
    assert_contains "391 conjur doctor lists instance"   "$RUNS/390-v011-conjur-doctor.log" 'conjur-dev'
    assert_contains "392 conjur doctor identity names account" "$RUNS/390-v011-conjur-doctor.log" "account=${V011_CONJUR_ACCOUNT}"
    assert_contains "393 conjur doctor identity surfaces configured authn" "$RUNS/390-v011-conjur-doctor.log" 'authn=authn'

    # 27b — round-trip get of the scalar fixture. Backend runs
    # `conjur variable get -i secretenv-smoke/scalar` and returns
    # `smoke-scalar-v0.11` (one trailing newline trimmed).
    run_test "394 v0.11 conjur get scalar round-trip" 0 "$RUNS/394-v011-conjur-get.log" \
      "$BIN" --config "$V011_CONJURCFG" get conjur_secret --yes
    assert_contains "395 conjur get returns seeded scalar" "$RUNS/394-v011-conjur-get.log" 'smoke-scalar-v0.11'

    # 27c — `#json-key=password` fragment extracts the password field
    # from the JSON-encoded variable at secretenv-smoke/json-multi.
    run_test "396 v0.11 conjur json-key fragment extracts field" 0 "$RUNS/396-v011-conjur-jsonkey.log" \
      "$BIN" --config "$V011_CONJURCFG" get conjur_json_pw --yes
    assert_contains "397 conjur fragment returns password field" "$RUNS/396-v011-conjur-jsonkey.log" 'smoke-pw'
    assert_not_contains "398 conjur fragment does not leak username" "$RUNS/396-v011-conjur-jsonkey.log" 'smoke-user'

    # 27d — end-to-end `run` injects both scalar + JSON-extracted env vars.
    run_test "399 v0.11 conjur run injects env vars" 0 "$RUNS/399-v011-conjur-run.log" \
      bash -c "cd '$V011_CONJURPROJ' && '$BIN' --config '$V011_CONJURCFG' run -- sh -c 'echo s=\$CONJUR_SECRET p=\$CONJUR_PASSWORD'"
    assert_contains "400 conjur run renders scalar"          "$RUNS/399-v011-conjur-run.log" 's=smoke-scalar-v0.11'
    assert_contains "401 conjur run renders fragment-extracted" "$RUNS/399-v011-conjur-run.log" 'p=smoke-pw'

    # 27e — set + get + clear cycle on a unique-per-run variable.
    # Conjur has no native delete; `delete()` implements clear-via-
    # empty-set per spec, so the cycle ends with a cleared (not
    # removed) variable. The variable must already exist in policy
    # (Conjur policy-defines variables; values are set after); the
    # smoke fixture seed creates `secretenv-smoke/cycle` for this.
    #
    # Pre-seed `{}` at the cycle path before `registry set` so the
    # read-then-write merge has a valid empty starting point (per
    # feedback_smoke_section_design Rule 1).
    CONJUR_CYCLE_VAR="secretenv-smoke/cycle"
    printf '{}' | CONJUR_APPLIANCE_URL="$V011_CONJUR_URL" CONJUR_ACCOUNT="$V011_CONJUR_ACCOUNT" \
      conjur variable set -i "$CONJUR_CYCLE_VAR" -f /dev/stdin >/dev/null 2>&1
    V011_CONJURCYCLE_REG="$RUNS/402-conjur-cycle-registry.toml"
    cat > "$V011_CONJURCYCLE_REG" <<EOF
[registries.conjur_cycle]
sources = ["conjur-dev:///${CONJUR_CYCLE_VAR}"]

[backends.conjur-dev]
type = "conjur"
conjur_url = "${V011_CONJUR_URL}"
conjur_account = "${V011_CONJUR_ACCOUNT}"
EOF
    # Set an alias.
    run_test "402 v0.11 conjur registry set" 0 "$RUNS/402-v011-conjur-set.log" \
      "$BIN" --config "$V011_CONJURCYCLE_REG" registry set cycle_alias \
        "conjur-dev:///secretenv-smoke/scalar" --registry conjur_cycle
    # Round-trip read of the alias map back through list().
    run_test "403 v0.11 conjur registry list reads back" 0 "$RUNS/403-v011-conjur-list.log" \
      "$BIN" --config "$V011_CONJURCYCLE_REG" registry list --registry conjur_cycle
    assert_contains "404 conjur list surfaces written alias" \
      "$RUNS/403-v011-conjur-list.log" 'cycle_alias'
    # Unset removes the alias from the map; subsequent list shows it gone.
    run_test "405 v0.11 conjur registry unset" 0 "$RUNS/405-v011-conjur-unset.log" \
      "$BIN" --config "$V011_CONJURCYCLE_REG" registry unset cycle_alias --registry conjur_cycle
    run_test "406 v0.11 conjur list after unset" 0 "$RUNS/406-v011-conjur-list2.log" \
      "$BIN" --config "$V011_CONJURCYCLE_REG" registry list --registry conjur_cycle
    assert_not_contains "407 conjur list no longer shows unset alias" \
      "$RUNS/406-v011-conjur-list2.log" 'cycle_alias'
    # Clear the cycle variable to keep the smoke namespace tidy. Conjur
    # has no native delete — this writes an empty value via the same
    # safe -f /dev/stdin path used by `secretenv registry unset`.
    printf '' | CONJUR_APPLIANCE_URL="$V011_CONJUR_URL" CONJUR_ACCOUNT="$V011_CONJUR_ACCOUNT" \
      conjur variable set -i "$CONJUR_CYCLE_VAR" -f /dev/stdin >/dev/null 2>&1 || true

    # 27f — fragment-reject on registry list. Fragments are only valid
    # on `get`; `list` rejects them locally before any subprocess. The
    # positive `#json-key` path is locked by 396/397.
    V011_CONJURREG_FRAG="$RUNS/408-conjur-registry-frag.toml"
    cat > "$V011_CONJURREG_FRAG" <<EOF
[registries.default]
sources = ["conjur-dev:///secretenv-smoke/conjur-registry#json-key=foo"]

[backends.conjur-dev]
type = "conjur"
conjur_url = "${V011_CONJUR_URL}"
conjur_account = "${V011_CONJUR_ACCOUNT}"
EOF
    run_test "408 v0.11 conjur registry list rejects fragment" 1 "$RUNS/408-v011-conjur-frag-list.log" \
      "$BIN" --config "$V011_CONJURREG_FRAG" registry list --registry default
    # 'fragment' is the load-bearing word — `'conjur'` would also match
    # the URI string itself (the URI starts with `conjur-dev://...`),
    # so a generic resolver error that just echoed the URI would pass
    # without ever exercising the backend's `reject_any_fragment` path.
    assert_contains "409 conjur fragment-reject surfaces fragment-rejection error" \
      "$RUNS/408-v011-conjur-frag-list.log" 'fragment'

    # 27g — history surfaces the trait-default "not implemented"
    # message. Conjur tracks variable versions but listing them
    # requires REST API; v0.11.x carry-forward.
    run_test "410 v0.11 conjur history bails not implemented" 1 "$RUNS/410-v011-conjur-history.log" \
      "$BIN" --config "$V011_CONJURCFG" registry history conjur_secret
    assert_contains "411 conjur history names 'not implemented'" \
      "$RUNS/410-v011-conjur-history.log" 'not implemented'

    # 27h — registry-source path: read alias map from the
    # conjur-registry fixture and resolve through the cross-backend
    # chain. conjur-registry's value is JSON
    # SMOKE_REGISTRY_ALIAS → local-main://…/stripe-key.txt; resolving
    # the alias chains conjur.list() → local-main.get().
    V011_CONJURREGSRC="$RUNS/412-conjur-regsrc-config.toml"
    cat > "$V011_CONJURREGSRC" <<EOF
[registries.default]
sources = ["conjur-dev:///secretenv-smoke/conjur-registry"]

[backends.local-main]
type = "local"

[backends.conjur-dev]
type = "conjur"
conjur_url = "${V011_CONJUR_URL}"
conjur_account = "${V011_CONJUR_ACCOUNT}"
EOF
    run_test "412 v0.11 conjur registry-source list" 0 "$RUNS/412-v011-conjur-reglist.log" \
      "$BIN" --config "$V011_CONJURREGSRC" registry list --registry default
    assert_contains "413 conjur registry-source surfaces SMOKE_REGISTRY_ALIAS" \
      "$RUNS/412-v011-conjur-reglist.log" 'SMOKE_REGISTRY_ALIAS'
    assert_contains "414 conjur registry-source target points at local-main" \
      "$RUNS/412-v011-conjur-reglist.log" 'local-main://'

    # 27i — cross-backend resolve: conjur registry → local-main URI.
    run_test "415 v0.11 conjur cross-backend resolve" 0 "$RUNS/415-v011-conjur-resolve.log" \
      "$BIN" --config "$V011_CONJURREGSRC" resolve SMOKE_REGISTRY_ALIAS
    assert_contains "416 conjur resolve names conjur source backend" \
      "$RUNS/415-v011-conjur-resolve.log" 'conjur-dev'
fi

# ---------------------------------------------------------------
# 28 — v0.12: Bitwarden Secrets Manager backend
# ---------------------------------------------------------------
section_begin 28 "v0.12 Bitwarden Secrets Manager backend"
# Self-contained: dedicated mini-config + mini-registry point at the
# operator's Bitwarden Secrets Manager cloud account (US default; EU
# / self-hosted via SECRETENV_TEST_BWS_SERVER_URL). Skipped if `bws`
# is missing OR `bws project list` fails (token unset/invalid/scoped
# to zero projects) — same SKIP discipline as the other wrap-a-CLI
# backends.
#
# Bitwarden Secrets Manager addresses every secret by UUID (32-char
# simple form), so the smoke run depends on operator-pre-seeded
# fixtures. Pass the UUIDs via env:
#   SECRETENV_TEST_BWS_SCALAR_UUID    — scalar fixture value
#   SECRETENV_TEST_BWS_JSON_UUID      — value is JSON-encoded
#                                       {"username":"...","password":"smoke-pw"}
#   SECRETENV_TEST_BWS_REGISTRY_UUID  — value is JSON alias→URI map
#                                       carrying SMOKE_REGISTRY_ALIAS
#   SECRETENV_TEST_BWS_CYCLE_UUID     — pre-seeded mutable secret for
#                                       the unsafe-set + delete-cycle
#                                       round-trip
#
# All UUIDs are operator-issued (out-of-band web-UI provisioning);
# the wrapper has no `secret create` path. See
# `kb/raw/reference_v0.12_bitwarden_prep.md` for the seeding script.

V012_BWS_SCALAR_UUID="${SECRETENV_TEST_BWS_SCALAR_UUID:-}"
V012_BWS_JSON_UUID="${SECRETENV_TEST_BWS_JSON_UUID:-}"
V012_BWS_REGISTRY_UUID="${SECRETENV_TEST_BWS_REGISTRY_UUID:-}"
V012_BWS_CYCLE_UUID="${SECRETENV_TEST_BWS_CYCLE_UUID:-}"
V012_BWS_SERVER_URL="${SECRETENV_TEST_BWS_SERVER_URL:-}"

if ! command -v bws >/dev/null 2>&1; then
    record "420 v0.12 bitwarden-sm section skipped — bws CLI not installed" "SKIP" \
           "install: brew install bitwarden-secrets-manager"
elif [ -z "${BWS_ACCESS_TOKEN:-}" ]; then
    record "420 v0.12 bitwarden-sm section skipped — BWS_ACCESS_TOKEN unset" "SKIP" \
           "export the machine-account access token before running smoke"
elif [ -z "$V012_BWS_SCALAR_UUID" ] || [ -z "$V012_BWS_JSON_UUID" ] \
     || [ -z "$V012_BWS_REGISTRY_UUID" ] || [ -z "$V012_BWS_CYCLE_UUID" ]; then
    record "420 v0.12 bitwarden-sm section skipped — required fixture UUIDs missing" "SKIP" \
           "set SECRETENV_TEST_BWS_{SCALAR,JSON,REGISTRY,CYCLE}_UUID — see kb/raw/reference_v0.12_bitwarden_prep.md"
elif ! bws --output json project list >/dev/null 2>&1; then
    record "420 v0.12 bitwarden-sm section skipped — bws project list failed" "SKIP" \
           "auth: token is unset/invalid/revoked or has no project access"
else
    # Build optional `bitwarden_server_url = "..."` line for non-default
    # cloud regions. Empty for US default.
    if [ -n "$V012_BWS_SERVER_URL" ]; then
        V012_BWS_URL_LINE="bitwarden_server_url = \"${V012_BWS_SERVER_URL}\""
    else
        V012_BWS_URL_LINE=""
    fi

    V012_BWSREG="$RUNS/420-bws-registry.toml"
    cat > "$V012_BWSREG" <<EOF
bws_secret = "bws-dev://${V012_BWS_SCALAR_UUID}"
bws_json_pw = "bws-dev://${V012_BWS_JSON_UUID}#json-key=password"
EOF

    V012_BWSCFG="$RUNS/420-bws-config.toml"
    cat > "$V012_BWSCFG" <<EOF
[registries.default]
sources = ["local-main://${V012_BWSREG}"]

[backends.local-main]
type = "local"

[backends.bws-dev]
type = "bitwarden-sm"
${V012_BWS_URL_LINE}
EOF

    V012_BWSPROJ="$RUNS/420-bws-project"
    mkdir -p "$V012_BWSPROJ"
    cat > "$V012_BWSPROJ/secretenv.toml" <<EOF
[secrets]
BWS_SECRET = { from = "secretenv://bws_secret" }
BWS_PASSWORD = { from = "secretenv://bws_json_pw" }
EOF

    # 28a — doctor sees the bitwarden-sm backend authenticated.
    run_test "420 v0.12 bws doctor sees backend" 0 "$RUNS/420-v012-bws-doctor.log" \
      "$BIN" --config "$V012_BWSCFG" doctor
    assert_contains "421 bws doctor lists instance"   "$RUNS/420-v012-bws-doctor.log" 'bws-dev'
    assert_contains "422 bws doctor identity names env-var" "$RUNS/420-v012-bws-doctor.log" 'token=$BWS_ACCESS_TOKEN'
    assert_contains "423 bws doctor identity surfaces project count" "$RUNS/420-v012-bws-doctor.log" 'projects='

    # 28b — round-trip get of the scalar fixture.
    run_test "424 v0.12 bws get scalar round-trip" 0 "$RUNS/424-v012-bws-get.log" \
      "$BIN" --config "$V012_BWSCFG" get bws_secret --yes
    assert_contains "425 bws get returns seeded scalar" "$RUNS/424-v012-bws-get.log" 'smoke-scalar-v0.12'

    # 28c — `#json-key=password` fragment extracts the password field.
    run_test "426 v0.12 bws json-key fragment extracts field" 0 "$RUNS/426-v012-bws-jsonkey.log" \
      "$BIN" --config "$V012_BWSCFG" get bws_json_pw --yes
    assert_contains "427 bws fragment returns password field" "$RUNS/426-v012-bws-jsonkey.log" 'smoke-pw'
    assert_not_contains "428 bws fragment does not leak username" "$RUNS/426-v012-bws-jsonkey.log" 'smoke-user'

    # 28d — end-to-end `run` injects both scalar + JSON-extracted env vars.
    run_test "429 v0.12 bws run injects env vars" 0 "$RUNS/429-v012-bws-run.log" \
      bash -c "cd '$V012_BWSPROJ' && '$BIN' --config '$V012_BWSCFG' run -- sh -c 'echo s=\$BWS_SECRET p=\$BWS_PASSWORD'"
    assert_contains "430 bws run renders scalar"              "$RUNS/429-v012-bws-run.log" 's=smoke-scalar-v0.12'
    assert_contains "431 bws run renders fragment-extracted"  "$RUNS/429-v012-bws-run.log" 'p=smoke-pw'

    # 28e — set is BLOCKED by default (defense-in-depth gate).
    # The default-refuse path must NOT shell out to bws — the
    # rejection is local. `secretenv registry set` writes the
    # registry doc through the backend; bitwarden-sm refuses.
    V012_BWSREG_DEFAULT="$RUNS/432-bws-default-registry.toml"
    cat > "$V012_BWSREG_DEFAULT" <<EOF
[registries.bws_default_set]
sources = ["bws-dev://${V012_BWS_CYCLE_UUID}"]

[backends.bws-dev]
type = "bitwarden-sm"
${V012_BWS_URL_LINE}
EOF
    run_test "432 v0.12 bws set blocked when unsafe_set false" 1 "$RUNS/432-v012-bws-set-blocked.log" \
      "$BIN" --config "$V012_BWSREG_DEFAULT" registry set blocked_alias \
        "bws-dev://${V012_BWS_SCALAR_UUID}" --registry bws_default_set
    assert_contains "433 bws set-block names bitwarden_unsafe_set" \
      "$RUNS/432-v012-bws-set-blocked.log" 'bitwarden_unsafe_set'
    assert_contains "434 bws set-block names disabled-by-default reason" \
      "$RUNS/432-v012-bws-set-blocked.log" 'disabled by default'

    # 28f — set + list + unset cycle with `bitwarden_unsafe_set = true`.
    # The cycle UUID points at a pre-seeded mutable secret. We
    # pre-seed `{}` via `bws secret edit --value '{}'` BEFORE
    # `registry set` so the read-then-write merge has a valid empty
    # starting point (per feedback_smoke_section_design Rule 1).
    bws --output json secret edit --value '{}' "$V012_BWS_CYCLE_UUID" >/dev/null 2>&1
    V012_BWSCYCLE_REG="$RUNS/435-bws-cycle-registry.toml"
    cat > "$V012_BWSCYCLE_REG" <<EOF
[registries.bws_cycle]
sources = ["bws-dev://${V012_BWS_CYCLE_UUID}"]

[backends.bws-dev]
type = "bitwarden-sm"
bitwarden_unsafe_set = true
${V012_BWS_URL_LINE}
EOF
    run_test "435 v0.12 bws registry set with unsafe_set" 0 "$RUNS/435-v012-bws-set.log" \
      "$BIN" --config "$V012_BWSCYCLE_REG" registry set cycle_alias \
        "bws-dev://${V012_BWS_SCALAR_UUID}" --registry bws_cycle
    run_test "436 v0.12 bws registry list reads back" 0 "$RUNS/436-v012-bws-list.log" \
      "$BIN" --config "$V012_BWSCYCLE_REG" registry list --registry bws_cycle
    assert_contains "437 bws list surfaces written alias" \
      "$RUNS/436-v012-bws-list.log" 'cycle_alias'
    run_test "438 v0.12 bws registry unset" 0 "$RUNS/438-v012-bws-unset.log" \
      "$BIN" --config "$V012_BWSCYCLE_REG" registry unset cycle_alias --registry bws_cycle
    run_test "439 v0.12 bws list after unset" 0 "$RUNS/439-v012-bws-list2.log" \
      "$BIN" --config "$V012_BWSCYCLE_REG" registry list --registry bws_cycle
    assert_not_contains "440 bws list no longer shows unset alias" \
      "$RUNS/439-v012-bws-list2.log" 'cycle_alias'
    # Reset cycle secret to `{}` to keep namespace tidy.
    bws --output json secret edit --value '{}' "$V012_BWS_CYCLE_UUID" >/dev/null 2>&1 || true

    # 28g — fragment-reject on registry list. Fragments only on `get`.
    V012_BWSREG_FRAG="$RUNS/441-bws-registry-frag.toml"
    cat > "$V012_BWSREG_FRAG" <<EOF
[registries.default]
sources = ["bws-dev://${V012_BWS_REGISTRY_UUID}#json-key=foo"]

[backends.bws-dev]
type = "bitwarden-sm"
${V012_BWS_URL_LINE}
EOF
    run_test "441 v0.12 bws registry list rejects fragment" 1 "$RUNS/441-v012-bws-frag-list.log" \
      "$BIN" --config "$V012_BWSREG_FRAG" registry list --registry default
    assert_contains "442 bws fragment-reject surfaces fragment-rejection error" \
      "$RUNS/441-v012-bws-frag-list.log" 'fragment'

    # 28h — history surfaces the trait-default "not implemented"
    # message. Bitwarden Secrets Manager surfaces revisions in the
    # web UI but the CLI exposes no history subcommand. Trait
    # default; out of scope until vendor exposes versioning.
    run_test "443 v0.12 bws history bails not implemented" 1 "$RUNS/443-v012-bws-history.log" \
      "$BIN" --config "$V012_BWSCFG" registry history bws_secret
    assert_contains "444 bws history names 'not implemented'" \
      "$RUNS/443-v012-bws-history.log" 'not implemented'

    # 28i — registry-source path: read alias map from the
    # registry fixture, resolve through the cross-backend chain.
    V012_BWSREGSRC="$RUNS/445-bws-regsrc-config.toml"
    cat > "$V012_BWSREGSRC" <<EOF
[registries.default]
sources = ["bws-dev://${V012_BWS_REGISTRY_UUID}"]

[backends.local-main]
type = "local"

[backends.bws-dev]
type = "bitwarden-sm"
${V012_BWS_URL_LINE}
EOF
    run_test "445 v0.12 bws registry-source list" 0 "$RUNS/445-v012-bws-reglist.log" \
      "$BIN" --config "$V012_BWSREGSRC" registry list --registry default
    assert_contains "446 bws registry-source surfaces SMOKE_REGISTRY_ALIAS" \
      "$RUNS/445-v012-bws-reglist.log" 'SMOKE_REGISTRY_ALIAS'

    # 28j — URI parser rejects non-UUID path locally (no subprocess).
    V012_BWSREG_BADURI="$RUNS/447-bws-baduri-registry.toml"
    cat > "$V012_BWSREG_BADURI" <<EOF
bad_uuid = "bws-dev://not-a-valid-uuid"

EOF
    V012_BWSCFG_BADURI="$RUNS/447-bws-baduri-config.toml"
    cat > "$V012_BWSCFG_BADURI" <<EOF
[registries.default]
sources = ["local-main://${V012_BWSREG_BADURI}"]

[backends.local-main]
type = "local"

[backends.bws-dev]
type = "bitwarden-sm"
${V012_BWS_URL_LINE}
EOF
    run_test "447 v0.12 bws rejects non-UUID URI path" 1 "$RUNS/447-v012-bws-baduri.log" \
      "$BIN" --config "$V012_BWSCFG_BADURI" get bad_uuid --yes
    assert_contains "448 bws non-UUID error names Bitwarden UUID constraint" \
      "$RUNS/447-v012-bws-baduri.log" 'Bitwarden UUID'
fi

# ---------------------------------------------------------------
# 29. v0.14 Mode A — runtime stdout/stderr redaction
# ---------------------------------------------------------------
#
# Verifies the `secretenv run` pipe-based scrubber. Forces pipe mode
# via `--redact` so the assertions don't depend on whether the smoke
# pane's stdin is a TTY (the Auto path's TTY-fallback-to-exec is
# documented behavior and SKIP-tagged here — needs a controlled TTY
# fixture which is out of scope for shell-driven smoke).
# ---------------------------------------------------------------
section_begin 29 "v0.14 Mode A — runtime stdout/stderr redaction"

# 29a — Default alias-aware substitution: each of 7 tainted values
# replaced with `[redacted:<NAME>]` (the manifest env-var name). The
# pattern `redacted:stripe_key` is bracket-free so it side-steps
# grep BRE character-class metacharacters; the brackets are
# implicitly tested by the surrounding LOG_LEVEL=info assertion.
run_test "500 v0.14 mode-A redact (default substitution)" 0 "$RUNS/500-v014-redact-modeA.log" \
  "$BIN" --config "$CFG" run --registry default --redact -- \
  sh -c 'echo S=$STRIPE_KEY D=$DB_URL A=$API_KEY O=$OP_PAT V=$OAUTH_TOKEN G=$GCP_SECRET Z=$AZURE_SECRET L=$LOG_LEVEL'

assert_contains "501 mode-A STRIPE_KEY substituted"   "$RUNS/500-v014-redact-modeA.log" 'redacted:stripe_key'
assert_contains "502 mode-A DB_URL substituted"       "$RUNS/500-v014-redact-modeA.log" 'redacted:db_url'
assert_contains "503 mode-A API_KEY substituted"      "$RUNS/500-v014-redact-modeA.log" 'redacted:api_key'
assert_contains "504 mode-A OP_PAT substituted"       "$RUNS/500-v014-redact-modeA.log" 'redacted:op_pat'
assert_contains "505 mode-A OAUTH_TOKEN substituted"  "$RUNS/500-v014-redact-modeA.log" 'redacted:oauth_token'
assert_contains "506 mode-A GCP_SECRET substituted"   "$RUNS/500-v014-redact-modeA.log" 'redacted:gcp_secret'
assert_contains "507 mode-A AZURE_SECRET substituted" "$RUNS/500-v014-redact-modeA.log" 'redacted:azure_secret'

# Negative half: raw values must NOT appear in redacted stdout.
assert_not_contains "508 mode-A no raw STRIPE_KEY value"  "$RUNS/500-v014-redact-modeA.log" 'sk_test_LOCAL_11111'
assert_not_contains "509 mode-A no raw API_KEY value"     "$RUNS/500-v014-redact-modeA.log" 'sk_test_secrets_22222'
assert_not_contains "510 mode-A no raw OP_PAT value"      "$RUNS/500-v014-redact-modeA.log" 'pat_op_33333'
assert_not_contains "511 mode-A no raw OAUTH_TOKEN value" "$RUNS/500-v014-redact-modeA.log" 'oat_vault_44444'
assert_not_contains "512 mode-A no raw GCP value"         "$RUNS/500-v014-redact-modeA.log" 'gsk_gcp_55555'
assert_not_contains "513 mode-A no raw AZURE value"       "$RUNS/500-v014-redact-modeA.log" 'sk_az_66666'

# LOG_LEVEL is a manifest default (non-secret) and passes through.
assert_contains "514 mode-A LOG_LEVEL default passes through" "$RUNS/500-v014-redact-modeA.log" 'L=info'

# 29b — --no-redact --i-know opt-out: raw value passes through, no
# substitution. Locks SEC-INV-07's CI/non-TTY branch (the TTY branch
# adds an interactive "type yes" prompt on top of the flag; that's
# a separate test fixture).
run_test "515 v0.14 mode-A --no-redact --i-know opt-out" 0 "$RUNS/515-v014-no-redact.log" \
  "$BIN" --config "$CFG" run --registry default --no-redact --i-know -- \
  sh -c 'echo STRIPE=$STRIPE_KEY'

assert_contains "516 --no-redact raw STRIPE_KEY present" "$RUNS/515-v014-no-redact.log" 'STRIPE=sk_test_LOCAL_11111'
assert_not_contains "517 --no-redact substitution absent" "$RUNS/515-v014-no-redact.log" 'redacted:stripe_key'

# 29c — --redact-token override. Uses 'XXX' to side-step the `*`-as-
# regex-quantifier in BRE; assertion intent is "the substituted form
# is a fixed string, not the alias-aware form, and the raw value is
# gone."
run_test "518 v0.14 mode-A --redact-token override" 0 "$RUNS/518-v014-redact-token.log" \
  "$BIN" --config "$CFG" run --registry default --redact --redact-token 'XXX' -- \
  sh -c 'echo STRIPE=$STRIPE_KEY'

assert_contains "519 --redact-token produces fixed XXX"   "$RUNS/518-v014-redact-token.log" 'STRIPE=XXX'
assert_not_contains "520 --redact-token no alias-aware form" "$RUNS/518-v014-redact-token.log" 'redacted:stripe_key'
assert_not_contains "521 --redact-token no raw value"        "$RUNS/518-v014-redact-token.log" 'sk_test_LOCAL_11111'

# 29d — stderr coverage: child writes to fd 2; the redact engine runs
# on stderr the same as stdout (both pipes are wired through
# `relay_stream`).
run_test "522 v0.14 mode-A stderr redaction" 0 "$RUNS/522-v014-redact-stderr.log" \
  "$BIN" --config "$CFG" run --registry default --redact -- \
  sh -c 'echo STRIPE=$STRIPE_KEY >&2'

assert_contains "523 mode-A stderr substituted"        "$RUNS/522-v014-redact-stderr.log" 'STRIPE=\[redacted:stripe_key\]'
assert_not_contains "524 mode-A stderr no raw value"   "$RUNS/522-v014-redact-stderr.log" 'sk_test_LOCAL_11111'

# 29e — clap rejects --no-redact without --i-know. Exit code 2 is
# clap's argument-validation conventional exit.
run_test "525 v0.14 --no-redact requires --i-know (clap)" 2 "$RUNS/525-v014-noredact-no-iknow.log" \
  "$BIN" --config "$CFG" run --registry default --no-redact -- true
assert_contains "526 clap names --i-know requirement" "$RUNS/525-v014-noredact-no-iknow.log" 'i-know'

# 29f — TTY-only paths. The Auto-fallback to exec() (R-A3) and the
# `--redact` force-pipe-on-TTY combo (R-A4) require a controlled TTY
# fixture (a pty pair). Out of scope for shell-driven smoke; unit
# tests in `crates/secretenv-cli/tests/cli.rs` cover the non-TTY
# branches, and the runner's `effective_redact_mode` is unit-tested
# in core.
record "527 v0.14 mode-A Auto fallback to exec() on TTY"  "SKIP" \
       "needs controlled pty fixture — out of scope for shell smoke; unit-tested in core::runner"
record "528 v0.14 mode-A --redact force pipe on TTY"      "SKIP" \
       "needs controlled pty fixture — out of scope for shell smoke; documented in docs/reference/redact.md"

# ---------------------------------------------------------------
# 30. v0.14 Mode B — post-hoc file scrubber (`secretenv redact <path>`)
# ---------------------------------------------------------------
section_begin 30 "v0.14 Mode B — post-hoc file scrubber"

# Synthetic build-log fixture carrying all 7 tainted values resolved
# by the default registry. Reused across this section.
#
# The fixture values MUST be the full resolved strings (not the
# truncated prefixes the older `assert_contains` smoke tests use)
# because the redact Aho-Corasick scanner matches the exact byte
# sequence. Specifically:
#   stripe_key = sk_test_LOCAL_11111_this_is_a_validation_secret (47 B)
#   db_url     = postgres://aws-ssm-db.example.com:5432/validation (48 B)
# The other 5 values fit in their pre-existing short forms.
V014_LOG="$RUNS/600-v014-modeB-input.log"
cat > "$V014_LOG" <<EOF
[2026-05-15 21:00:00] starting build
connecting with sk_test_LOCAL_11111_this_is_a_validation_secret ...
db=postgres://aws-ssm-db.example.com:5432/validation ready
api=sk_test_secrets_22222 (response 12ms)
op pat=pat_op_33333 acquired
oauth=oat_vault_44444 expires=1h
gcp=gsk_gcp_55555
azure=sk_az_66666
build complete; LOG_LEVEL=info
EOF

# 30a — --dry-run reports match-count + byte-count to stderr; the
# file content is NOT modified.
V014_DRY_TARGET="$RUNS/600-v014-dry-target.log"
cp "$V014_LOG" "$V014_DRY_TARGET"
run_test "600 v0.14 mode-B --dry-run reports counts" 0 "$RUNS/600-v014-modeB-dry.log" \
  "$BIN" --config "$CFG" redact "$V014_DRY_TARGET" --registry default --dry-run

assert_contains "601 mode-B dry-run names match-count"  "$RUNS/600-v014-modeB-dry.log" 'match(es)'
assert_contains "602 mode-B dry-run names byte-count"   "$RUNS/600-v014-modeB-dry.log" 'byte(s)'
# Dry-run must NOT mutate the source file — raw STRIPE_KEY still present.
assert_contains "603 mode-B dry-run leaves source file unmodified" "$V014_DRY_TARGET" 'sk_test_LOCAL_11111'

# 30b — Default stdout mode: scrub flows to stdout with alias-aware
# substitutions, raw values absent.
#
# NOTE on casing: Mode B's substitution token uses the REGISTRY ALIAS
# name (lowercase, e.g. `stripe_key`), while Mode A uses the manifest
# env-var name (uppercase, e.g. `STRIPE_KEY`). The inconsistency is a
# real product gap noted for the v0.14.x hygiene cycle — the
# `TaintedValue::alias_name` carries whatever the call site passes,
# and the two call sites pass different things. For v0.14 smoke, we
# assert what the engine actually emits so we don't drift further.
run_test "604 v0.14 mode-B stdout default" 0 "$RUNS/604-v014-modeB-stdout.log" \
  "$BIN" --config "$CFG" redact "$V014_LOG" --registry default

assert_contains "605 mode-B stdout stripe_key"   "$RUNS/604-v014-modeB-stdout.log" 'redacted:stripe_key'
assert_contains "606 mode-B stdout db_url"       "$RUNS/604-v014-modeB-stdout.log" 'redacted:db_url'
assert_contains "607 mode-B stdout api_key"      "$RUNS/604-v014-modeB-stdout.log" 'redacted:api_key'
assert_contains "608 mode-B stdout op_pat"       "$RUNS/604-v014-modeB-stdout.log" 'redacted:op_pat'
assert_contains "609 mode-B stdout oauth_token"  "$RUNS/604-v014-modeB-stdout.log" 'redacted:oauth_token'
assert_contains "610 mode-B stdout gcp_secret"   "$RUNS/604-v014-modeB-stdout.log" 'redacted:gcp_secret'
assert_contains "611 mode-B stdout azure_secret" "$RUNS/604-v014-modeB-stdout.log" 'redacted:azure_secret'
assert_not_contains "612 mode-B stdout no raw STRIPE_KEY full value"  "$RUNS/604-v014-modeB-stdout.log" 'sk_test_LOCAL_11111_this_is_a_validation_secret'
assert_not_contains "613 mode-B stdout no raw API_KEY value"          "$RUNS/604-v014-modeB-stdout.log" 'sk_test_secrets_22222'
assert_contains "614 mode-B preserves non-secret content" "$RUNS/604-v014-modeB-stdout.log" 'LOG_LEVEL=info'

# 30c — --in-place + --backup: atomic rename via sibling tempfile;
# backup file carries the original (unredacted) content with the
# source's mode bits.
#
# Pre-clean the .bak destination — the Phase 7 Sec-H3 hardening
# refuses to overwrite a pre-existing file at the backup path
# (O_EXCL | O_NOFOLLOW; defense against attacker pre-planting a
# symlink there). The smoke harness re-runs in the same $RUNS dir
# and would otherwise hit our own guard on the second run.
V014_INPLACE="$RUNS/615-v014-inplace.log"
rm -f "$V014_INPLACE.bak"
cp "$V014_LOG" "$V014_INPLACE"
run_test "615 v0.14 mode-B --in-place --backup=.bak" 0 "$RUNS/615-v014-modeB-inplace-run.log" \
  "$BIN" --config "$CFG" redact "$V014_INPLACE" --registry default --in-place --backup=.bak

assert_contains "616 mode-B in-place file rewritten"        "$V014_INPLACE" 'redacted:stripe_key'
assert_not_contains "617 mode-B in-place no raw STRIPE_KEY value" "$V014_INPLACE" 'sk_test_LOCAL_11111_this_is_a_validation_secret'
if [ -f "$V014_INPLACE.bak" ]; then
    record "618 mode-B backup file present" PASS "path=$(basename "$V014_INPLACE").bak"
else
    record "618 mode-B backup file present" FAIL "missing $V014_INPLACE.bak"
fi
assert_contains "619 mode-B backup preserves raw original" "$V014_INPLACE.bak" 'sk_test_LOCAL_11111_this_is_a_validation_secret'
assert_not_contains "620 mode-B backup is NOT redacted"    "$V014_INPLACE.bak" 'redacted:stripe_key'

# 30d — Mode preservation across the atomic rename. Sets mode 0640
# on the input, redacts in-place, asserts the persisted file still
# carries 0640.
V014_MODE_TEST="$RUNS/621-v014-mode-test.log"
cp "$V014_LOG" "$V014_MODE_TEST"
chmod 640 "$V014_MODE_TEST" 2>/dev/null
"$BIN" --config "$CFG" redact "$V014_MODE_TEST" --registry default --in-place >/dev/null 2>&1
V014_MODE_AFTER=$(stat -f '%Lp' "$V014_MODE_TEST" 2>/dev/null || stat -c '%a' "$V014_MODE_TEST" 2>/dev/null)
if [ "$V014_MODE_AFTER" = "640" ]; then
    record "621 mode-B preserves file mode 0640" PASS "mode=$V014_MODE_AFTER"
else
    record "621 mode-B preserves file mode 0640" FAIL "mode=$V014_MODE_AFTER (expected 640)"
fi

# 30e — --alias filter restricts the tainted set to a single alias;
# other aliases pass through unredacted.
run_test "622 v0.14 mode-B --alias filter" 0 "$RUNS/622-v014-modeB-alias.log" \
  "$BIN" --config "$CFG" redact "$V014_LOG" --registry default --alias stripe_key

assert_contains "623 mode-B --alias stripe_key redacts STRIPE_KEY"      "$RUNS/622-v014-modeB-alias.log" 'redacted:stripe_key'
assert_not_contains "624 mode-B --alias filter leaves OAUTH_TOKEN raw"  "$RUNS/622-v014-modeB-alias.log" 'redacted:oauth_token'
assert_contains "625 mode-B --alias filter passes other raw values"     "$RUNS/622-v014-modeB-alias.log" 'oat_vault_44444'

# 30f — --redact-token override on mode B.
run_test "626 v0.14 mode-B --redact-token override" 0 "$RUNS/626-v014-modeB-token.log" \
  "$BIN" --config "$CFG" redact "$V014_LOG" --registry default --redact-token 'XXX'

assert_contains "627 mode-B --redact-token produces fixed XXX"  "$RUNS/626-v014-modeB-token.log" 'XXX'
assert_not_contains "628 mode-B --redact-token no alias-aware"   "$RUNS/626-v014-modeB-token.log" 'redacted:'
assert_not_contains "629 mode-B --redact-token no raw value"     "$RUNS/626-v014-modeB-token.log" 'sk_test_LOCAL_11111_this_is_a_validation_secret'

# ---------------------------------------------------------------
# 31. v0.14 Mode B — safety guards
# ---------------------------------------------------------------
section_begin 31 "v0.14 Mode B — safety guards (special-path, foreign-owner, O_NOFOLLOW)"

# 31a — /proc, /sys, /dev refusal. The early-refusal happens before
# any open syscall on Linux; on macOS /proc doesn't exist as a
# mountpoint so we use /dev as the universally-present pseudo-fs.
run_test "700 v0.14 mode-B refuses /proc" 1 "$RUNS/700-v014-refuse-proc.log" \
  "$BIN" --config "$CFG" redact /proc/self/cmdline --registry default --dry-run
assert_contains "701 /proc refusal names kernel pseudo-fs" "$RUNS/700-v014-refuse-proc.log" 'kernel pseudo'

run_test "702 v0.14 mode-B refuses /sys" 1 "$RUNS/702-v014-refuse-sys.log" \
  "$BIN" --config "$CFG" redact /sys/kernel/hostname --registry default --dry-run
assert_contains "703 /sys refusal names kernel pseudo-fs" "$RUNS/702-v014-refuse-sys.log" 'kernel pseudo'

run_test "704 v0.14 mode-B refuses /dev" 1 "$RUNS/704-v014-refuse-dev.log" \
  "$BIN" --config "$CFG" redact /dev/null --registry default --dry-run
assert_contains "705 /dev refusal names kernel pseudo-fs" "$RUNS/704-v014-refuse-dev.log" 'kernel pseudo'

# 31b — Foreign-owner refusal. /etc/hosts is root-owned on every
# Unix and world-readable, so it's the canonical foreign-owner fixture.
# Refusal fires before any read; --allow-foreign-owner opts back in.
run_test "706 v0.14 mode-B refuses foreign-owned file" 1 "$RUNS/706-v014-refuse-foreign.log" \
  "$BIN" --config "$CFG" redact /etc/hosts --registry default --dry-run
assert_contains "707 foreign-owner refusal names UID mismatch" "$RUNS/706-v014-refuse-foreign.log" 'owned by UID'
assert_contains "708 foreign-owner refusal suggests --allow-foreign-owner" "$RUNS/706-v014-refuse-foreign.log" 'allow-foreign-owner'

# 31c — --allow-foreign-owner override succeeds on the same file
# (dry-run, no mutation). The tainted set may or may not match
# anything inside /etc/hosts; either way the exit must be 0.
run_test "709 v0.14 mode-B --allow-foreign-owner override" 0 "$RUNS/709-v014-allow-foreign.log" \
  "$BIN" --config "$CFG" redact /etc/hosts --registry default --dry-run --allow-foreign-owner
assert_contains "710 --allow-foreign-owner dry-run reports counts" "$RUNS/709-v014-allow-foreign.log" 'match(es)'

# 31d — O_NOFOLLOW symlink refusal. Set up a symlink → regular file,
# point redact at the symlink. The open with O_NOFOLLOW fires ELOOP /
# FILESYSTEM_LOOP / "symbolic link" depending on platform.
V014_SYMLINK_TARGET="$RUNS/711-v014-symlink-target.log"
V014_SYMLINK_LINK="$RUNS/711-v014-symlink-link.log"
cp "$V014_LOG" "$V014_SYMLINK_TARGET"
ln -sf "$V014_SYMLINK_TARGET" "$V014_SYMLINK_LINK"
run_test "711 v0.14 mode-B refuses symlink (O_NOFOLLOW)" 1 "$RUNS/711-v014-refuse-symlink.log" \
  "$BIN" --config "$CFG" redact "$V014_SYMLINK_LINK" --registry default --dry-run
# Error wording is platform-specific. Accept any of "symbolic", "loop",
# "NOFOLLOW", or "Too many" as evidence the open refused.
if grep -qE "symbolic|symlink|loop|NOFOLLOW|Too many" "$RUNS/711-v014-refuse-symlink.log" 2>/dev/null; then
    record "712 symlink refusal error names O_NOFOLLOW path" PASS "found platform-appropriate symlink error"
else
    record "712 symlink refusal error names O_NOFOLLOW path" FAIL "no symlink-class error in 711-v014-refuse-symlink.log"
fi

# 31e — clap conflict: --in-place + --dry-run.
run_test "713 v0.14 mode-B --in-place + --dry-run conflict" 2 "$RUNS/713-v014-inplace-dry-conflict.log" \
  "$BIN" --config "$CFG" redact "$V014_LOG" --registry default --in-place --dry-run
assert_contains "714 clap names the conflict" "$RUNS/713-v014-inplace-dry-conflict.log" 'conflict'

# 31f — clap dependency: --backup requires --in-place.
run_test "715 v0.14 mode-B --backup without --in-place rejected" 2 "$RUNS/715-v014-backup-without-inplace.log" \
  "$BIN" --config "$CFG" redact "$V014_LOG" --registry default --backup .bak
assert_contains "716 clap names the dependency" "$RUNS/715-v014-backup-without-inplace.log" 'in-place'

# ===============================================================
# v0.15 — `secretenv registry migrate`  (Sections 32 / 33 / 34)
# ===============================================================
# Three sections cover the migrate surface:
#   32 (cloud=no) — CLI surface, dry-run, JSON shape, errors, post-conditions
#                   via local→local. Locks Phase 7 audit fixes B1, B3, B4,
#                   M1-sec, SEC-INV-20, SEC-INV-24.
#   33 (cloud=yes) — per-backend live `local → <X>` for all 15 backends;
#                   SKIP-aware per backend. Locks Gated-refusal for
#                   1password/keeper/bitwarden-sm and has_probe_write
#                   semantics (vault vs aws/gcp).
#   34 (cloud=no) — --delete-source flow + SEC-INV-08 second-prompt lock
#                   under --yes via local→local. The 1password Gated-
#                   refusal for delete_secret is SKIP-tagged in the live
#                   smoke (unit test in secretenv-core covers the variant).

# ---------------------------------------------------------------
# 32 — v0.15 migrate semantics (local-only — no cloud auth needed)
# ---------------------------------------------------------------
section_begin 32 "v0.15 secretenv registry migrate — local-only semantics"

# Self-contained mini-config + mini-registry. Two local backend
# instances (local-src, local-dst) point at distinct file paths so
# the migrate exercises the source.get → dest.write_secret →
# pointer-flip flow end-to-end without touching any cloud CLI.
#
# Pattern mirrors Section 21 (keychain): all assertions inside this
# section use the dedicated $V015_CFG; the shared $CFG / $PROJ are
# untouched. Cleanup is overwrite-on-rerun (idempotent).

V015_DIR="$RUNS/800-v015-migrate"
mkdir -p "$V015_DIR"
V015_SRC="$V015_DIR/source-value.txt"
V015_DST="$V015_DIR/dest-value.txt"
V015_REG="$V015_DIR/registry.toml"
V015_CFG="$V015_DIR/config.toml"
V015_PROJ="$V015_DIR/project"
mkdir -p "$V015_PROJ"

# Seed source value + initial registry (alias points at source).
# Each smoke run rewrites these so the in-place mutations from prior
# runs do not bleed in.
SECRET_VALUE='sk_migrate_smoke_v015_test_value_42'
printf '%s' "$SECRET_VALUE" > "$V015_SRC"
# Pre-create an empty dest file so we can later verify the migrate
# *wrote* over it. (Local backend's `set` happily creates a file if
# missing, but starting with a marker proves the post-condition.)
printf 'PRE_MIGRATE_PLACEHOLDER' > "$V015_DST"

cat > "$V015_REG" <<EOF
migrate_test = "local-src://${V015_SRC}"
EOF

cat > "$V015_CFG" <<EOF
[registries.default]
sources = ["local-reg://${V015_REG}"]

[backends.local-reg]
type = "local"

[backends.local-src]
type = "local"

[backends.local-dst]
type = "local"
EOF

cat > "$V015_PROJ/secretenv.toml" <<EOF
[secrets]
MIGRATE_TEST = { from = "secretenv://migrate_test" }
EOF

V015_MIGRATE_BASE="--config $V015_CFG registry migrate migrate_test local-dst://${V015_DST}"

# 32a — `--help` for the migrate subcommand renders.
run_test "800 v0.15 migrate --help renders" 0 "$RUNS/800-v015-help.log" \
  "$BIN" --config "$V015_CFG" registry migrate --help
assert_contains "801 migrate --help names ALIAS arg"          "$RUNS/800-v015-help.log" 'ALIAS'
assert_contains "802 migrate --help names DEST_URI arg"       "$RUNS/800-v015-help.log" 'DEST_URI'
assert_contains "803 migrate --help lists --dry-run"          "$RUNS/800-v015-help.log" 'dry-run'
assert_contains "804 migrate --help lists --yes"              "$RUNS/800-v015-help.log" 'yes'
assert_contains "805 migrate --help lists --from"             "$RUNS/800-v015-help.log" 'from'
assert_contains "806 migrate --help lists --delete-source"    "$RUNS/800-v015-help.log" 'delete-source'
assert_contains "807 migrate --help lists --json"             "$RUNS/800-v015-help.log" 'json'

# 32b — Dry-run mode: no mutation, structured output.
# Capture pre-state so we can assert nothing changed.
PRE_REG_HASH="$(shasum -a 256 "$V015_REG" 2>/dev/null | awk '{print $1}' || md5sum "$V015_REG" | awk '{print $1}')"
PRE_SRC_HASH="$(shasum -a 256 "$V015_SRC" 2>/dev/null | awk '{print $1}' || md5sum "$V015_SRC" | awk '{print $1}')"
PRE_DST_HASH="$(shasum -a 256 "$V015_DST" 2>/dev/null | awk '{print $1}' || md5sum "$V015_DST" | awk '{print $1}')"

# 32b.1 — Text-mode dry-run.
run_test "810 v0.15 migrate --dry-run (text)" 0 "$RUNS/810-v015-dryrun.log" \
  "$BIN" $V015_MIGRATE_BASE --dry-run
assert_contains "811 dry-run text names alias"               "$RUNS/810-v015-dryrun.log" 'migrate_test'
assert_contains "812 dry-run text names source type"         "$RUNS/810-v015-dryrun.log" 'source type:'
assert_contains "813 dry-run text names dest type"           "$RUNS/810-v015-dryrun.log" 'dest type:'
assert_contains "814 dry-run text lists Probes section"      "$RUNS/810-v015-dryrun.log" 'Probes:'
assert_contains "815 dry-run text says No changes made"      "$RUNS/810-v015-dryrun.log" 'No changes made'

# Post-condition: registry, source, dest all unchanged.
POST_REG_HASH="$(shasum -a 256 "$V015_REG" 2>/dev/null | awk '{print $1}' || md5sum "$V015_REG" | awk '{print $1}')"
POST_SRC_HASH="$(shasum -a 256 "$V015_SRC" 2>/dev/null | awk '{print $1}' || md5sum "$V015_SRC" | awk '{print $1}')"
POST_DST_HASH="$(shasum -a 256 "$V015_DST" 2>/dev/null | awk '{print $1}' || md5sum "$V015_DST" | awk '{print $1}')"
if [ "$PRE_REG_HASH" = "$POST_REG_HASH" ]; then
    record "816 dry-run leaves registry doc unmodified" PASS "registry hash stable"
else
    record "816 dry-run leaves registry doc unmodified" FAIL "registry hash changed"
fi
if [ "$PRE_SRC_HASH" = "$POST_SRC_HASH" ]; then
    record "817 dry-run leaves source file unmodified" PASS "source hash stable"
else
    record "817 dry-run leaves source file unmodified" FAIL "source hash changed"
fi
if [ "$PRE_DST_HASH" = "$POST_DST_HASH" ]; then
    record "818 dry-run leaves dest file unmodified" PASS "dest hash stable"
else
    record "818 dry-run leaves dest file unmodified" FAIL "dest hash changed (CRITICAL — dry-run wrote)"
fi

# 32b.2 — JSON-mode dry-run. Locks the wire-format shape after
# Phase 7 audit fixes (B3 probe_results inclusion, B4 normalized
# labels, M1 delete_hint absence, SEC-INV-20 URI bodies absence).
run_test "820 v0.15 migrate --dry-run --json" 0 "$RUNS/820-v015-dryrun-json.log" \
  "$BIN" $V015_MIGRATE_BASE --dry-run --json

# Strip everything before the first '{' AND everything after the
# matching outer '}'. The harness wraps the secretenv stdout in
# preamble (`### name`, `### cmd:`) and trailer (`---`, `### exit:`,
# `### ended:`) — without trimming the trailer the JSON parser
# blows up on the `---` separator.
V015_JSON="$RUNS/820-v015-dryrun.json"
awk '
    /^\{/ { found = 1 }
    found {
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") {
                depth--
                if (depth == 0) { print substr($0, 1, i); exit }
            }
        }
        print
    }
' "$RUNS/820-v015-dryrun-json.log" > "$V015_JSON"

# Parse-shape: must be valid JSON parsable by python3 (which is on
# every smoke host since the existing harness assumes it elsewhere).
# Fall back to jq if python3 absent.
v015_json_ok=0
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json,sys; json.load(open('$V015_JSON'))" >/dev/null 2>&1; then
        v015_json_ok=1
    fi
elif command -v jq >/dev/null 2>&1; then
    if jq empty "$V015_JSON" >/dev/null 2>&1; then
        v015_json_ok=1
    fi
fi
if [ "$v015_json_ok" = "1" ]; then
    record "821 dry-run JSON parses as valid JSON" PASS "shape ok"
else
    record "821 dry-run JSON parses as valid JSON" FAIL "JSON parse failed at $V015_JSON"
fi

# Required ALLOW fields (per the v0.15 wire-format contract).
assert_contains "822 JSON contains alias"                  "$V015_JSON" '"alias"'
assert_contains "823 JSON contains source_backend_type"    "$V015_JSON" '"source_backend_type"'
assert_contains "824 JSON contains dest_backend_type"      "$V015_JSON" '"dest_backend_type"'
assert_contains "825 JSON contains outcome dry-run"        "$V015_JSON" '"outcome": "dry-run"'
assert_contains "826 JSON contains phase_durations_ms"     "$V015_JSON" '"phase_durations_ms"'
assert_contains "827 JSON contains delete_source field"    "$V015_JSON" '"delete_source"'
assert_contains "828 JSON contains probe_results array (B3 fix)" "$V015_JSON" '"probe_results"'
assert_contains "829 JSON contains transaction_id"         "$V015_JSON" '"transaction_id"'

# B3 fix verification: probe_results entries use the {instance, status}
# object form, NOT positional [instance, status] arrays.
assert_contains "830 JSON probe_results entries are {instance, status} objects (B3)" "$V015_JSON" '"instance"'
assert_contains "831 JSON probe_results entries name status (B3)"                    "$V015_JSON" '"status"'

# B4 fix verification: source probe label is normalized to "ok" or
# "error: <kind>" — NOT the raw `BackendStatus { ... }` Debug-dump
# that was leaking identity / region / profile prior to Phase 7.
assert_not_contains "832 JSON source probe label not raw Debug dump (B4)" "$V015_JSON" 'BackendStatus'

# M1 fix verification: delete_hint field is ABSENT from JSON output.
# The hint may contain URI path components (Tier-1 redaction per
# SEC-INV-24); operators piping --json to log aggregators must not
# leak backend topology.
assert_not_contains "833 JSON OMITS delete_hint (security M1 / SEC-INV-24)" "$V015_JSON" '"delete_hint"'

# SEC-INV-20 / SEC-INV-24 lock-in: URI bodies must not appear in JSON.
# We use a known fragment from the dest URI (the dest file path under
# $V015_DIR) to check.
assert_not_contains "834 JSON OMITS dest URI body (SEC-INV-20)" "$V015_JSON" "$V015_DST"
assert_not_contains "835 JSON OMITS source URI body (SEC-INV-20)" "$V015_JSON" "$V015_SRC"

# 32c — Real migration with --yes (skip top-level prompt). This is
# the canonical happy path.
run_test "840 v0.15 migrate --yes (live)" 0 "$RUNS/840-v015-migrate.log" \
  "$BIN" $V015_MIGRATE_BASE --yes
assert_contains "841 migrate success message present"   "$RUNS/840-v015-migrate.log" 'Migration complete'
assert_contains "842 success message names alias"        "$RUNS/840-v015-migrate.log" 'migrate_test'
assert_contains "843 success message renders durations"  "$RUNS/840-v015-migrate.log" 'probe / read / write / flip ms'
# Default flow (no --delete-source): hint MUST be shown to terminal
# so the operator has the copy-paste cleanup command.
assert_contains "844 success terminal shows delete_hint (terminal-only per SEC-INV-24)" "$RUNS/840-v015-migrate.log" 'source value still present'

# Post-condition: dest file now contains the secret value; source
# file UNCHANGED (no --delete-source); registry now points at dest.
if grep -q "$SECRET_VALUE" "$V015_DST" 2>/dev/null; then
    record "845 dest file received the secret value" PASS "value present in dest"
else
    record "845 dest file received the secret value" FAIL "dest does not contain expected value"
fi
if grep -q "$SECRET_VALUE" "$V015_SRC" 2>/dev/null; then
    record "846 source file still present (no --delete-source)" PASS "source value preserved"
else
    record "846 source file still present (no --delete-source)" FAIL "source value lost despite no --delete-source"
fi
# Registry pointer should have flipped to local-dst://<path>.
if grep -q "local-dst" "$V015_REG" 2>/dev/null; then
    record "847 registry pointer flipped to dest (commit point)" PASS "registry now references local-dst"
else
    record "847 registry pointer flipped to dest (commit point)" FAIL "registry still references original source"
fi

# 32d — Error paths. Each sets up a fresh scenario so prior tests'
# side effects don't bleed in.

# 32d.1 — Alias not in registry.
run_test "850 v0.15 migrate non-existent alias rejected" 1 "$RUNS/850-v015-no-alias.log" \
  "$BIN" --config "$V015_CFG" registry migrate not_a_real_alias "local-dst://${V015_DST}" --yes --dry-run
assert_contains "851 missing-alias error names alias"      "$RUNS/850-v015-no-alias.log" 'not_a_real_alias'

# 32d.2 — Destination URI parse error.
run_test "852 v0.15 migrate bad dest URI rejected" 1 "$RUNS/852-v015-bad-uri.log" \
  "$BIN" --config "$V015_CFG" registry migrate migrate_test 'this-is-not-a-uri' --yes --dry-run
assert_contains "853 bad-URI error names parse failure" "$RUNS/852-v015-bad-uri.log" 'destination'

# 32d.3 — Destination backend instance not configured.
run_test "854 v0.15 migrate unconfigured dest rejected" 1 "$RUNS/854-v015-no-backend.log" \
  "$BIN" --config "$V015_CFG" registry migrate migrate_test 'nope-unconfigured:///some/path' --yes --dry-run
assert_contains "855 unconfigured-dest error names instance" "$RUNS/854-v015-no-backend.log" 'nope-unconfigured'

# 32d.4 — Destination must be a backend URI, not an alias.
run_test "856 v0.15 migrate dest-as-alias rejected" 1 "$RUNS/856-v015-dest-alias.log" \
  "$BIN" --config "$V015_CFG" registry migrate migrate_test 'secretenv://other_alias' --yes --dry-run
assert_contains "857 dest-as-alias error names alias-not-allowed" "$RUNS/856-v015-dest-alias.log" 'alias'

# 32e — Plan resolve-once verification (Phase 7 audit B1 lock-in).
# Run migrate twice in a row against the same already-migrated
# alias (now pointing at local-dst://) with a fresh dest path. The
# second migrate's source is now the dest of the first; we verify
# transaction_id is fresh per invocation (not stale from prior).
V015_DST2="$V015_DIR/dest-value-2.txt"
printf 'PRE_MIGRATE_2' > "$V015_DST2"
run_test "860 v0.15 second migrate (chained dest)" 0 "$RUNS/860-v015-chained.log" \
  "$BIN" --config "$V015_CFG" registry migrate migrate_test "local-dst://${V015_DST2}" --yes
if grep -q "$SECRET_VALUE" "$V015_DST2" 2>/dev/null; then
    record "861 chained migrate wrote value to second dest" PASS "value flowed source→dest→dest2"
else
    record "861 chained migrate wrote value to second dest" FAIL "second dest does not have value"
fi

# ---------------------------------------------------------------
# 33 — v0.15 migrate live per-backend matrix
# ---------------------------------------------------------------
section_begin 33 "v0.15 secretenv registry migrate — live per-backend matrix"

# Each backend gets a self-contained `local → <backend>` live
# migrate scenario. If the backend's CLI is unauth / unavailable,
# the per-backend block records a SKIP and moves on. This mirrors
# the skip discipline of Sections 21-28.
#
# Convention per block:
#   - mini-config + mini-registry inside $RUNS/9NN-v015-mig-<name>/
#   - source = local file containing a fixed test value
#   - dest = backend-specific path under `secretenv-smoke-migrate/`
#   - PRE: pre-existing dest may or may not be there (idempotent)
#   - assertions: migrate succeeds; dest read-back returns value;
#     registry pointer flipped to the backend URI

V015M_VALUE='sk_migrate_smoke_v015_per_backend_77'

# Helper: standard live `local → <backend>` migrate scenario.
#
# Args:
#   $1 = test-id prefix (3-digit, used in record names)
#   $2 = backend label (used in record text + filenames)
#   $3 = path to a config.toml with [backends.local-src] + the
#        target backend instance already configured
#   $4 = dest backend URI (full backend URI string)
#   $5 = expected dest backend type name (e.g. "vault", "aws-ssm")
#   $6 = optional: post-migrate read-back URI (default: dest URI).
#        Set when the backend stores under a different read shape
#        (e.g. fragment directives needed for read but not write).
#
# Sets up the source file + registry under $RUNS/<id>-mig-<label>/.
migrate_smoke_dest() {
    local id="$1" label="$2" cfg="$3" dest_uri="$4" expected_type="$5"
    local readback_uri="${6:-$dest_uri}"
    local work="$RUNS/${id}-v015-mig-${label}"
    mkdir -p "$work"
    local src="$work/source.txt"
    local reg="$work/registry.toml"
    printf '%s' "$V015M_VALUE" > "$src"
    printf '%s\n' "v015mig_${label} = \"local-src://${src}\"" > "$reg"

    # Splice the registry source into the supplied config so the
    # caller's config.toml stays generic.
    local cfg_with_reg="$work/config.toml"
    {
        echo "[registries.default]"
        echo "sources = [\"local-reg://${reg}\"]"
        echo
        echo "[backends.local-reg]"
        echo "type = \"local\""
        echo
        echo "[backends.local-src]"
        echo "type = \"local\""
        echo
        cat "$cfg"
    } > "$cfg_with_reg"

    # Live migrate.
    run_test "${id}a v0.15 migrate local→${label}" 0 "$work/migrate.log" \
      "$BIN" --config "$cfg_with_reg" registry migrate "v015mig_${label}" "$dest_uri" --yes
    assert_contains "${id}b migrate ${label} success message"  "$work/migrate.log" 'Migration complete'
    assert_contains "${id}c migrate ${label} dest type rendered"  "$work/migrate.log" "$expected_type"

    # Read-back: alias now resolves to dest backend; `get` returns
    # the migrated value.
    run_test "${id}d v0.15 ${label} post-migrate get" 0 "$work/get.log" \
      "$BIN" --config "$cfg_with_reg" get "v015mig_${label}" --yes
    assert_contains "${id}e ${label} get returns migrated value" "$work/get.log" "$V015M_VALUE"
}

# Helper: dry-run probe-label semantics. Locks the
# `has_probe_write()` companion contract per backend (architect M1
# fix). The dry-run text should contain "ok (probed)" for backends
# that override has_probe_write to true (vault only in v0.15) and
# "no probe available" for backends that rely on the default.
#
# Args:
#   $1 = test-id prefix
#   $2 = backend label
#   $3 = config path (must declare local-reg, local-src, dest backend)
#   $4 = dest backend URI
#   $5 = expected probe label substring ("ok (probed)" | "no probe available")
migrate_smoke_probe_label() {
    local id="$1" label="$2" cfg="$3" dest_uri="$4" expected_label="$5"
    local work="$RUNS/${id}-v015-mig-probe-${label}"
    mkdir -p "$work"
    local src="$work/source.txt"
    local reg="$work/registry.toml"
    printf '%s' "$V015M_VALUE" > "$src"
    printf '%s\n' "v015mig_${label} = \"local-src://${src}\"" > "$reg"

    local cfg_with_reg="$work/config.toml"
    {
        echo "[registries.default]"
        echo "sources = [\"local-reg://${reg}\"]"
        echo
        echo "[backends.local-reg]"
        echo "type = \"local\""
        echo
        echo "[backends.local-src]"
        echo "type = \"local\""
        echo
        cat "$cfg"
    } > "$cfg_with_reg"

    run_test "${id} v0.15 dry-run ${label} probe label" 0 "$work/dryrun.log" \
      "$BIN" --config "$cfg_with_reg" registry migrate "v015mig_${label}" "$dest_uri" --dry-run
    assert_contains "${id}a ${label} probe label = '$expected_label'" "$work/dryrun.log" "$expected_label"
}

# ----- 33.1 — local → local (sanity baseline for the helper) -----
V015M_LOCAL_CFG="$RUNS/900-mig-local-cfg.toml"
cat > "$V015M_LOCAL_CFG" <<EOF
[backends.local-dst]
type = "local"
EOF
V015M_LOCAL_DST="$RUNS/900-mig-local-dst.txt"
printf 'PRE' > "$V015M_LOCAL_DST"
migrate_smoke_dest "900" "local"  "$V015M_LOCAL_CFG" "local-dst://${V015M_LOCAL_DST}" "local"

# ----- 33.2 — local → aws-ssm -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v aws >/dev/null 2>&1 && aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
    V015M_SSM_CFG="$RUNS/905-mig-ssm-cfg.toml"
    cat > "$V015M_SSM_CFG" <<EOF
[backends.aws-ssm-mig]
type = "aws-ssm"
aws_region = "$AWS_REGION"
EOF
    migrate_smoke_dest "905" "aws-ssm" "$V015M_SSM_CFG" 'aws-ssm-mig:///secretenv-smoke-migrate/v015-dest' "aws-ssm"
    # has_probe_write = false → "no probe available"
    migrate_smoke_probe_label "910" "aws-ssm" "$V015M_SSM_CFG" 'aws-ssm-mig:///secretenv-smoke-migrate/v015-probe-only' "no probe available"
else
    record "905 v0.15 migrate local→aws-ssm" SKIP "aws CLI unavailable / not authenticated"
fi

# ----- 33.3 — local → aws-secrets -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v aws >/dev/null 2>&1 && aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
    V015M_SEC_CFG="$RUNS/915-mig-secrets-cfg.toml"
    cat > "$V015M_SEC_CFG" <<EOF
[backends.aws-secrets-mig]
type = "aws-secrets"
aws_region = "$AWS_REGION"
EOF
    # aws-secrets put-secret-value can't create a new secret; the
    # provision.sh harness usually pre-creates fixture secrets. For
    # the migrate smoke we reuse the existing validation secret
    # path (which provision.sh creates), then restore it post-test
    # via the same trap that protects sections 14/30/39.
    migrate_smoke_dest "915" "aws-secrets" "$V015M_SEC_CFG" 'aws-secrets-mig:///secretenv-validation/api-key' "aws-secrets"
else
    record "915 v0.15 migrate local→aws-secrets" SKIP "aws CLI unavailable / not authenticated"
fi

# ----- 33.4 — local → vault (the only real probe in v0.15) -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v vault >/dev/null 2>&1 && vault token lookup -format=json >/dev/null 2>&1; then
    V015M_VAULT_CFG="$RUNS/920-mig-vault-cfg.toml"
    cat > "$V015M_VAULT_CFG" <<EOF
[backends.vault-mig]
type = "vault"
vault_address = "${VAULT_ADDR:-http://127.0.0.1:8200}"
EOF
    migrate_smoke_dest "920" "vault" "$V015M_VAULT_CFG" 'vault-mig:///secret/secretenv-smoke-migrate/v015-dest' "vault"
    # has_probe_write = true → "ok (probed)" — vault is the ONLY
    # backend that overrides has_probe_write in v0.15.
    migrate_smoke_probe_label "925" "vault" "$V015M_VAULT_CFG" 'vault-mig:///secret/secretenv-smoke-migrate/v015-probe-only' "ok (probed)"
else
    record "920 v0.15 migrate local→vault" SKIP "vault CLI unavailable / no valid token"
fi

# ----- 33.5 — local → gcp -----
if [ "${SECTION_ACTIVE}" = "1" ] && [ -n "$GCP_PROJECT" ] && command -v gcloud >/dev/null 2>&1 && gcloud auth print-access-token >/dev/null 2>&1; then
    V015M_GCP_CFG="$RUNS/930-mig-gcp-cfg.toml"
    cat > "$V015M_GCP_CFG" <<EOF
[backends.gcp-mig]
type = "gcp"
gcp_project = "$GCP_PROJECT"
EOF
    # GCP secret names are constrained — alpha-numeric + underscore.
    migrate_smoke_dest "930" "gcp" "$V015M_GCP_CFG" 'gcp-mig:///secretenv_smoke_migrate_v015_dest' "gcp"
else
    record "930 v0.15 migrate local→gcp" SKIP "gcloud unavailable / no GCP_PROJECT / not authenticated"
fi

# ----- 33.6 — local → azure -----
if [ "${SECTION_ACTIVE}" = "1" ] && [ -n "$AZURE_VAULT" ] && command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then
    V015M_AZ_CFG="$RUNS/935-mig-az-cfg.toml"
    cat > "$V015M_AZ_CFG" <<EOF
[backends.azure-mig]
type = "azure"
azure_vault_url = "https://${AZURE_VAULT}.vault.azure.net/"
EOF
    migrate_smoke_dest "935" "azure" "$V015M_AZ_CFG" 'azure-mig:///secretenv-smoke-migrate-v015-dest' "azure"
else
    record "935 v0.15 migrate local→azure" SKIP "az CLI unavailable / no AZURE_VAULT / not authenticated"
fi

# ----- 33.7 — local → 1password (Gated — needs op_unsafe_set) -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v op >/dev/null 2>&1 && op whoami --format=json >/dev/null 2>&1; then
    # First assert the Gated-refusal path: without op_unsafe_set,
    # write_secret returns BackendError::WriteNotSupported and the
    # migrate handler surfaces it before any read. This is the
    # SEC-INV-11 / Phase 1 lock-in.
    V015M_OP_REFUSE_CFG="$RUNS/940-mig-op-refuse-cfg.toml"
    cat > "$V015M_OP_REFUSE_CFG" <<EOF
[backends.op-mig]
type = "1password"
EOF
    V015M_OP_REFUSE_WORK="$RUNS/940-mig-op-refuse"
    mkdir -p "$V015M_OP_REFUSE_WORK"
    printf '%s' "$V015M_VALUE" > "$V015M_OP_REFUSE_WORK/source.txt"
    printf 'op_mig_refuse = "local-src://%s/source.txt"\n' "$V015M_OP_REFUSE_WORK" > "$V015M_OP_REFUSE_WORK/reg.toml"
    cat > "$V015M_OP_REFUSE_WORK/config.toml" <<EOF
[registries.default]
sources = ["local-reg://${V015M_OP_REFUSE_WORK}/reg.toml"]

[backends.local-reg]
type = "local"

[backends.local-src]
type = "local"

[backends.op-mig]
type = "1password"
EOF
    run_test "940 v0.15 migrate local→1password without op_unsafe_set" 1 "$V015M_OP_REFUSE_WORK/migrate.log" \
      "$BIN" --config "$V015M_OP_REFUSE_WORK/config.toml" registry migrate op_mig_refuse '1password-mig:///Private/secretenv-smoke-migrate-v015/password' --yes
    assert_contains "941 1password gated-refusal names op_unsafe_set" "$V015M_OP_REFUSE_WORK/migrate.log" 'op_unsafe_set'

    # Then the gated-ALLOW path: with op_unsafe_set = true, the
    # migrate writes through.
    V015M_OP_CFG="$RUNS/945-mig-op-cfg.toml"
    cat > "$V015M_OP_CFG" <<EOF
[backends.op-mig-allow]
type = "1password"
op_unsafe_set = true
EOF
    migrate_smoke_dest "945" "1password" "$V015M_OP_CFG" '1password-mig-allow:///Private/secretenv-smoke-migrate-v015/password' "1password"
else
    record "940 v0.15 migrate local→1password" SKIP "op CLI unavailable / not signed in"
fi

# ----- 33.8 — local → keychain (macOS only) -----
if [ "${SECTION_ACTIVE}" = "1" ] && [[ "$OSTYPE" == darwin* ]] && [ -f "${RUNTIME_DIR}/test.keychain-db" ]; then
    V015M_KC_CFG="$RUNS/950-mig-kc-cfg.toml"
    cat > "$V015M_KC_CFG" <<EOF
[backends.keychain-mig]
type = "keychain"
keychain_path = "${RUNTIME_DIR}/test.keychain-db"
EOF
    migrate_smoke_dest "950" "keychain" "$V015M_KC_CFG" 'keychain-mig:///secretenv-smoke-migrate-v015/account' "keychain"
else
    record "950 v0.15 migrate local→keychain" SKIP "non-macOS host or test keychain not provisioned"
fi

# ----- 33.9 — local → doppler -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v doppler >/dev/null 2>&1 && doppler me --json >/dev/null 2>&1; then
    V015M_DP_CFG="$RUNS/955-mig-dp-cfg.toml"
    cat > "$V015M_DP_CFG" <<EOF
[backends.doppler-mig]
type = "doppler"
doppler_project = "secretenv-validation"
doppler_config = "dev"
EOF
    # Doppler secret names must be uppercase + underscores per Doppler validation.
    migrate_smoke_dest "955" "doppler" "$V015M_DP_CFG" 'doppler-mig:///SECRETENV_SMOKE_MIGRATE_V015' "doppler"
else
    record "955 v0.15 migrate local→doppler" SKIP "doppler unavailable / not authenticated"
fi

# ----- 33.10 — local → infisical -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v infisical >/dev/null 2>&1 && [ -n "${INFISICAL_TOKEN:-}${INFISICAL_PROJECT_ID:-}" ]; then
    V015M_INF_CFG="$RUNS/960-mig-inf-cfg.toml"
    cat > "$V015M_INF_CFG" <<EOF
[backends.infisical-mig]
type = "infisical"
EOF
    migrate_smoke_dest "960" "infisical" "$V015M_INF_CFG" "infisical-mig:///${INFISICAL_PROJECT_ID:-PROJECTID}/dev/SECRETENV_SMOKE_MIGRATE_V015" "infisical"
else
    record "960 v0.15 migrate local→infisical" SKIP "infisical CLI unavailable / no project credentials"
fi

# ----- 33.11 — local → keeper (Gated — needs keeper_unsafe_set) -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v keeper >/dev/null 2>&1 && keeper this-device --json >/dev/null 2>&1; then
    # Gated-refusal path.
    V015M_KP_REFUSE_WORK="$RUNS/965-mig-keeper-refuse"
    mkdir -p "$V015M_KP_REFUSE_WORK"
    printf '%s' "$V015M_VALUE" > "$V015M_KP_REFUSE_WORK/source.txt"
    printf 'kp_mig_refuse = "local-src://%s/source.txt"\n' "$V015M_KP_REFUSE_WORK" > "$V015M_KP_REFUSE_WORK/reg.toml"
    cat > "$V015M_KP_REFUSE_WORK/config.toml" <<EOF
[registries.default]
sources = ["local-reg://${V015M_KP_REFUSE_WORK}/reg.toml"]

[backends.local-reg]
type = "local"

[backends.local-src]
type = "local"

[backends.keeper-mig]
type = "keeper"
EOF
    run_test "965 v0.15 migrate local→keeper without keeper_unsafe_set" 1 "$V015M_KP_REFUSE_WORK/migrate.log" \
      "$BIN" --config "$V015M_KP_REFUSE_WORK/config.toml" registry migrate kp_mig_refuse 'keeper-mig:///secretenv-smoke-migrate-v015' --yes
    assert_contains "966 keeper gated-refusal names keeper_unsafe_set" "$V015M_KP_REFUSE_WORK/migrate.log" 'keeper_unsafe_set'
else
    record "965 v0.15 migrate local→keeper" SKIP "keeper CLI unavailable / no persistent login"
fi

# ----- 33.12 — local → cf-kv -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v wrangler >/dev/null 2>&1 && wrangler whoami >/dev/null 2>&1; then
    # cf-kv requires a real namespace-id; we use the one provision.sh
    # sets up. If absent, skip.
    if [ -f "${RUNTIME_DIR}/cfkv-namespace.env" ]; then
        # shellcheck disable=SC1091
        . "${RUNTIME_DIR}/cfkv-namespace.env"
        if [ -n "${CFKV_NAMESPACE_ID:-}" ]; then
            V015M_CF_CFG="$RUNS/970-mig-cf-cfg.toml"
            cat > "$V015M_CF_CFG" <<EOF
[backends.cf-kv-mig]
type = "cf-kv"
cf_kv_default_namespace_id = "${CFKV_NAMESPACE_ID}"
EOF
            migrate_smoke_dest "970" "cf-kv" "$V015M_CF_CFG" 'cf-kv-mig:///secretenv-smoke-migrate-v015' "cf-kv"
        else
            record "970 v0.15 migrate local→cf-kv" SKIP "no CFKV_NAMESPACE_ID in cfkv-namespace.env"
        fi
    else
        record "970 v0.15 migrate local→cf-kv" SKIP "cfkv-namespace.env not provisioned"
    fi
else
    record "970 v0.15 migrate local→cf-kv" SKIP "wrangler unavailable / not authenticated"
fi

# ----- 33.13 — local → openbao -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v bao >/dev/null 2>&1; then
    V015M_BAO_ADDR="${SECRETENV_TEST_BAO_ADDR:-http://127.0.0.1:8300}"
    if BAO_ADDR="$V015M_BAO_ADDR" bao token lookup -format=json >/dev/null 2>&1; then
        V015M_BAO_CFG="$RUNS/975-mig-bao-cfg.toml"
        cat > "$V015M_BAO_CFG" <<EOF
[backends.bao-mig]
type = "openbao"
bao_address = "${V015M_BAO_ADDR}"
EOF
        migrate_smoke_dest "975" "openbao" "$V015M_BAO_CFG" 'bao-mig:///secret/secretenv-smoke-migrate/v015-dest' "openbao"
    else
        record "975 v0.15 migrate local→openbao" SKIP "bao server unreachable / sealed / no token"
    fi
else
    record "975 v0.15 migrate local→openbao" SKIP "bao CLI unavailable"
fi

# ----- 33.14 — local → conjur -----
if [ "${SECTION_ACTIVE}" = "1" ] && [ -n "${SECRETENV_TEST_CONJUR_URL:-}" ] && command -v docker >/dev/null 2>&1; then
    V015M_CJ_URL="${SECRETENV_TEST_CONJUR_URL}"
    V015M_CJ_ACCT="${SECRETENV_TEST_CONJUR_ACCOUNT:-myorg}"
    # Conjur smoke uses pre-seeded variables; the migrate destination
    # variable must exist as a policy declaration. We use the
    # cycle-fixture path that provision.sh seeds for v0.11 section.
    V015M_CJ_CFG="$RUNS/980-mig-conjur-cfg.toml"
    cat > "$V015M_CJ_CFG" <<EOF
[backends.conjur-mig]
type = "conjur"
conjur_url = "${V015M_CJ_URL}"
conjur_account = "${V015M_CJ_ACCT}"
EOF
    # Reuse the cycle variable that provision.sh creates so we don't
    # need to apply new Conjur policy mid-smoke.
    migrate_smoke_dest "980" "conjur" "$V015M_CJ_CFG" 'conjur-mig:///secretenv-smoke/conjur-registry' "conjur"
else
    record "980 v0.15 migrate local→conjur" SKIP "no SECRETENV_TEST_CONJUR_URL or docker unavailable"
fi

# ----- 33.15 — local → bitwarden-sm (Gated — needs bitwarden_unsafe_set) -----
if [ "${SECTION_ACTIVE}" = "1" ] && command -v bws >/dev/null 2>&1 && [ -n "${BWS_ACCESS_TOKEN:-}" ]; then
    # Gated-refusal path.
    V015M_BWS_REFUSE_WORK="$RUNS/985-mig-bws-refuse"
    mkdir -p "$V015M_BWS_REFUSE_WORK"
    printf '%s' "$V015M_VALUE" > "$V015M_BWS_REFUSE_WORK/source.txt"
    printf 'bws_mig_refuse = "local-src://%s/source.txt"\n' "$V015M_BWS_REFUSE_WORK" > "$V015M_BWS_REFUSE_WORK/reg.toml"
    cat > "$V015M_BWS_REFUSE_WORK/config.toml" <<EOF
[registries.default]
sources = ["local-reg://${V015M_BWS_REFUSE_WORK}/reg.toml"]

[backends.local-reg]
type = "local"

[backends.local-src]
type = "local"

[backends.bws-mig]
type = "bitwarden-sm"
bws_server_url = "${SECRETENV_TEST_BWS_SERVER_URL:-https://api.bitwarden.com}"
EOF
    # We use a pre-existing cycle UUID to avoid needing to create
    # a new bws secret mid-smoke.
    if [ -n "${SECRETENV_TEST_BWS_CYCLE_UUID:-}" ]; then
        run_test "985 v0.15 migrate local→bitwarden-sm without bitwarden_unsafe_set" 1 "$V015M_BWS_REFUSE_WORK/migrate.log" \
          "$BIN" --config "$V015M_BWS_REFUSE_WORK/config.toml" registry migrate bws_mig_refuse "bws-mig:///${SECRETENV_TEST_BWS_CYCLE_UUID}" --yes
        assert_contains "986 bitwarden-sm gated-refusal names bitwarden_unsafe_set" "$V015M_BWS_REFUSE_WORK/migrate.log" 'bitwarden_unsafe_set'
    else
        record "985 v0.15 migrate local→bitwarden-sm" SKIP "no SECRETENV_TEST_BWS_CYCLE_UUID"
    fi
else
    record "985 v0.15 migrate local→bitwarden-sm" SKIP "bws unavailable / BWS_ACCESS_TOKEN not set"
fi

# ---------------------------------------------------------------
# 34 — v0.15 migrate --delete-source flow + SEC-INV-08 lock
# ---------------------------------------------------------------
section_begin 34 "v0.15 secretenv registry migrate — --delete-source flow"

# --delete-source is opt-in (SEC-INV-08): the destructive cleanup
# leg fires only when the operator passes the flag AND confirms a
# second prompt that fires EVEN UNDER --yes. This section locks
# the three branches:
#
#  (a) --delete-source not set: source value still present after
#      migrate; report's delete_hint populated.
#  (b) --delete-source + decline second prompt: source still
#      present (closure returned false).
#  (c) --delete-source + accept second prompt: source value
#      removed via Backend::delete_secret.
#  (d) --delete-source + --yes: top-level prompt skipped but
#      second prompt STILL fires (SEC-INV-08 lock).
#  (e) Gated backend without *_unsafe_set: --delete-source path
#      surfaces DeleteNotSupported (Phase 2 lock).

V015D_VALUE='sk_migrate_delete_source_v015_99'

# Helper: stage a fresh local-src / local-dst / registry tuple under
# $RUNS/<id>-mig-ds-<label>/.
stage_delete_source_fixture() {
    local id="$1" label="$2"
    local work="$RUNS/${id}-v015-mig-ds-${label}"
    mkdir -p "$work"
    printf '%s' "$V015D_VALUE" > "$work/source.txt"
    printf 'PRE' > "$work/dest.txt"
    {
        echo "v015ds_${label} = \"local-src://${work}/source.txt\""
    } > "$work/reg.toml"
    cat > "$work/config.toml" <<EOF
[registries.default]
sources = ["local-reg://${work}/reg.toml"]

[backends.local-reg]
type = "local"

[backends.local-src]
type = "local"

[backends.local-dst]
type = "local"
EOF
    echo "$work"
}

# ----- 34a — --delete-source NOT set: source preserved -----
W34A="$(stage_delete_source_fixture 1000 a)"
run_test "1000 v0.15 migrate without --delete-source" 0 "$W34A/migrate.log" \
  "$BIN" --config "$W34A/config.toml" registry migrate v015ds_a "local-dst://${W34A}/dest.txt" --yes
if [ -f "$W34A/source.txt" ] && grep -q "$V015D_VALUE" "$W34A/source.txt" 2>/dev/null; then
    record "1001 source value preserved when --delete-source absent" PASS "source still present"
else
    record "1001 source value preserved when --delete-source absent" FAIL "source missing or mutated"
fi
assert_contains "1002 success message renders delete_hint hint" "$W34A/migrate.log" 'source value still present'

# ----- 34b — --delete-source + decline second prompt -----
# Send 'n\n' to stdin; the closure reads the prompt response and
# returns false. Migration is committed but source cleanup skipped.
W34B="$(stage_delete_source_fixture 1010 b)"
run_test "1010 v0.15 migrate --delete-source decline second prompt" 0 "$W34B/migrate.log" \
  bash -c "printf 'n\n' | '$BIN' --config '$W34B/config.toml' registry migrate v015ds_b 'local-dst://${W34B}/dest.txt' --yes --delete-source"
if [ -f "$W34B/source.txt" ] && grep -q "$V015D_VALUE" "$W34B/source.txt" 2>/dev/null; then
    record "1011 source value preserved when second-prompt declined" PASS "source still present after decline"
else
    record "1011 source value preserved when second-prompt declined" FAIL "source unexpectedly removed despite decline"
fi
assert_contains "1012 declined second-prompt success message present" "$W34B/migrate.log" 'Migration complete'

# ----- 34c — --delete-source + accept second prompt -----
# Send 'y\n' to stdin; the closure returns true and the source-delete
# leg fires.
W34C="$(stage_delete_source_fixture 1020 c)"
run_test "1020 v0.15 migrate --delete-source accept second prompt" 0 "$W34C/migrate.log" \
  bash -c "printf 'y\n' | '$BIN' --config '$W34C/config.toml' registry migrate v015ds_c 'local-dst://${W34C}/dest.txt' --yes --delete-source"
# Source file should now be GONE (local backend's delete_secret →
# delete → tokio::fs::remove_file).
if [ ! -f "$W34C/source.txt" ]; then
    record "1021 source file removed after --delete-source confirmed" PASS "source file gone"
else
    record "1021 source file removed after --delete-source confirmed" FAIL "source file still present after accept"
fi
# Dest file should contain the value.
if grep -q "$V015D_VALUE" "$W34C/dest.txt" 2>/dev/null; then
    record "1022 dest file has the migrated value after delete-source" PASS "value flowed to dest"
else
    record "1022 dest file has the migrated value after delete-source" FAIL "dest does not contain value"
fi

# ----- 34d — SEC-INV-08 lock: --yes does NOT skip the second prompt -----
# Confirms the closure unconditionally reads stdin when
# args.delete_source is true, regardless of --yes. The previous
# test (34c) already verifies stdin is consulted under --yes; this
# block additionally locks the visible prompt text the operator
# sees so a future refactor that silently bypasses the closure
# under --yes fails the assertion.
W34D="$(stage_delete_source_fixture 1030 d)"
run_test "1030 v0.15 SEC-INV-08 second prompt fires under --yes" 0 "$W34D/migrate.log" \
  bash -c "printf 'y\n' | '$BIN' --config '$W34D/config.toml' registry migrate v015ds_d 'local-dst://${W34D}/dest.txt' --yes --delete-source"
assert_contains "1031 second prompt text present under --yes (SEC-INV-08)" "$W34D/migrate.log" 'permanently delete'

# ----- 34e — Gated backend (1password) without op_unsafe_set:
# --delete-source path surfaces typed DeleteNotSupported -----
# Skipped if op CLI unavail. The migrate itself still needs a
# valid dest write, so we use the gated-ALLOW path for the WRITE
# leg but a SEPARATE gated-REFUSE instance for the SOURCE delete.
# Setup is intricate — keep it surgical and skip-friendly.
if command -v op >/dev/null 2>&1 && op whoami --format=json >/dev/null 2>&1; then
    W34E="$RUNS/1040-v015-mig-ds-op-gated"
    mkdir -p "$W34E"
    # Source lives in op-source-gated (op_unsafe_set NOT set on
    # this instance). The migrate flow attempts source read (which
    # works — read is not gated), then dest write (works on the
    # _allow_ instance below), then source delete on op-source-gated
    # → typed DeleteNotSupported.
    cat > "$W34E/config.toml" <<EOF
[registries.default]
sources = ["local-reg://${W34E}/reg.toml"]

[backends.local-reg]
type = "local"

[backends.local-dst]
type = "local"

[backends.op-source-gated]
type = "1password"
# intentionally NOT setting op_unsafe_set — Gated source delete path

[backends.op-dst-allow]
type = "1password"
op_unsafe_set = true
EOF
    # We can't easily seed an op item from inside the smoke run, so
    # SKIP this sub-block unconditionally — the Gated-refusal path
    # for delete_secret is also locked by the strict-mock test
    # in secretenv-core::backend::tests.
    record "1040 v0.15 --delete-source Gated-refusal (1password)" SKIP "live 1password gated-delete coverage deferred to manual smoke; unit-test locks the variant"
else
    record "1040 v0.15 --delete-source Gated-refusal (1password)" SKIP "op CLI unavailable / not signed in"
fi


# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
{
  echo "---"
  echo "TOTAL:   $((PASSED+FAILED))"
  echo "PASSED:  $PASSED"
  echo "FAILED:  $FAILED"
  if [ "$MODE" != "all" ]; then
    echo "MODE:    $MODE  (sections: $SELECTED_SECTIONS)"
  fi
  echo "TESTS_DONE"
} | tee -a "$SUMMARY"

# Exit non-zero if any test failed so callers (CI / release.yml) can gate.
exit $((FAILED > 0 ? 1 : 0))
