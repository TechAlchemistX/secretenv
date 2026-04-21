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
    "20|v0.4 Phase 3 timeout_secs + op_unsafe_set|no"
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
GCP_PROJECT="eva-dev-490220"

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
assert_contains "150 gcp identity names project" "$RUNS/22-doctor.log" 'project=eva-dev-490220'

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
