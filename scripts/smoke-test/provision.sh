#!/usr/bin/env bash
# Provision cloud backends for the SecretEnv validation run.
# Idempotent-ish: uses `--overwrite` / update paths where available.
# Everything created is prefixed `secretenv-validation` and torn down
# by teardown.sh at the end of the run.
#
# Required env: SECRETENV_TEST_GCP_PROJECT, SECRETENV_TEST_AZURE_VAULT.
# Optional env: SECRETENV_TEST_AWS_REGION (default us-east-1),
#               SECRETENV_SMOKE_RUNTIME   (default /tmp/secretenv-test).

set -u
# Deliberately not `set -e` — we want to log every outcome even on
# partial failure.

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$_here/lib/common.sh"
require_cloud_env

LOG="$RUNTIME_DIR/runs/10-provision.log"
mkdir -p "$(dirname "$LOG")"

# Seed the runtime dir (local-secrets tree, local registry, config.toml,
# project-repo) from the checked-in fixtures BEFORE we touch cloud state.
seed_runtime_from_fixtures

# v0.3 Phase 2: added `azure_secret` alias pointing at the new azure
# backend. All 6 registry sources (local, aws-ssm, aws-secrets, op,
# vault, gcp, azure) must advertise the same alias list so every
# registry-list test finds all 7 aliases.
REG_JSON="{\"stripe_key\":\"local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt\",\"db_url\":\"aws-ssm-prod:///secretenv-validation/db-url\",\"api_key\":\"aws-secrets-prod:///secretenv-validation/api-key\",\"op_pat\":\"1password-private://Private/secretenv-validation-token/password\",\"oauth_token\":\"vault-dev:///secret/secretenv-validation/oauth-token\",\"gcp_secret\":\"gcp-prod:///secretenv_validation_gcp_secret\",\"azure_secret\":\"azure-prod:///secretenv-validation-azure-secret\"}"
REG_TOML="stripe_key = \"local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt\"
db_url = \"aws-ssm-prod:///secretenv-validation/db-url\"
api_key = \"aws-secrets-prod:///secretenv-validation/api-key\"
op_pat = \"1password-private://Private/secretenv-validation-token/password\"
oauth_token = \"vault-dev:///secret/secretenv-validation/oauth-token\"
gcp_secret = \"gcp-prod:///secretenv_validation_gcp_secret\"
azure_secret = \"azure-prod:///secretenv-validation-azure-secret\""

say() { printf '\n>>> %s\n' "$*" | tee -a "$LOG"; }
run() { say "$*"; eval "$*" 2>&1 | tee -a "$LOG"; printf 'exit=%d\n' "${PIPESTATUS[0]}" | tee -a "$LOG"; }

: > "$LOG"
say "=== SecretEnv validation run — provisioning ==="
say "timestamp:   $(date -u +%FT%TZ)"
say "runtime:     $RUNTIME_DIR"
say "aws region:  $AWS_REGION"
say "gcp project: $GCP_PROJECT"
say "azure vault: $AZURE_VAULT"

# ---------- AWS SSM ----------
say "[AWS SSM] registry (/secretenv-validation/registry)"
run "aws ssm put-parameter --name /secretenv-validation/registry --type SecureString --overwrite --region '$AWS_REGION' --value '$REG_JSON'"

say "[AWS SSM] secret /secretenv-validation/db-url"
run "aws ssm put-parameter --name /secretenv-validation/db-url --type SecureString --overwrite --region '$AWS_REGION' --value 'postgres://aws-ssm-db.example.com:5432/validation'"

# ---------- AWS Secrets Manager ----------
# create-secret errors if exists → try create then fall back to put-secret-value
say "[AWS Secrets Manager] registry (secretenv-validation/registry)"
if ! aws secretsmanager describe-secret --secret-id secretenv-validation/registry --region "$AWS_REGION" >/dev/null 2>&1; then
  run "aws secretsmanager create-secret --name secretenv-validation/registry --region '$AWS_REGION' --secret-string '$REG_JSON'"
else
  run "aws secretsmanager put-secret-value --secret-id secretenv-validation/registry --region '$AWS_REGION' --secret-string '$REG_JSON'"
fi

say "[AWS Secrets Manager] secret secretenv-validation/api-key"
if ! aws secretsmanager describe-secret --secret-id secretenv-validation/api-key --region "$AWS_REGION" >/dev/null 2>&1; then
  run "aws secretsmanager create-secret --name secretenv-validation/api-key --region '$AWS_REGION' --secret-string 'sk_test_secrets_22222'"
else
  run "aws secretsmanager put-secret-value --secret-id secretenv-validation/api-key --region '$AWS_REGION' --secret-string 'sk_test_secrets_22222'"
fi

# v0.2.1 addition: JSON-shaped fixture to exercise the canonical
# #json-key=<field> fragment directive and its rejection paths.
DB_JSON='{"username":"alice","password":"hunter2","host":"db.internal","port":5432}'
say "[AWS Secrets Manager] JSON secret secretenv-validation/db-json (v0.2.1 fragment tests)"
if ! aws secretsmanager describe-secret --secret-id secretenv-validation/db-json --region "$AWS_REGION" >/dev/null 2>&1; then
  run "aws secretsmanager create-secret --name secretenv-validation/db-json --region '$AWS_REGION' --secret-string '$DB_JSON'"
else
  run "aws secretsmanager put-secret-value --secret-id secretenv-validation/db-json --region '$AWS_REGION' --secret-string '$DB_JSON'"
fi

# ---------- 1Password ----------
# Items: secretenv-validation-registry (Secure Note w/ notesPlain = TOML)
#        secretenv-validation-token    (Password w/ password field)
# Private vault.
say "[1Password] registry item (Private/secretenv-validation-registry, Secure Note)"
if op item get 'secretenv-validation-registry' --vault Private --format=json >/dev/null 2>&1; then
  # Edit existing — delete + recreate to ensure clean state
  run "op item delete 'secretenv-validation-registry' --vault Private --archive"
fi
run "op item create --category 'Secure Note' --title 'secretenv-validation-registry' --vault Private notesPlain=\"\$REG_TOML\""

say "[1Password] secret item (Private/secretenv-validation-token, Password)"
if op item get 'secretenv-validation-token' --vault Private --format=json >/dev/null 2>&1; then
  run "op item delete 'secretenv-validation-token' --vault Private --archive"
fi
run "op item create --category 'Password' --title 'secretenv-validation-token' --vault Private password='pat_op_33333'"

# ---------- Vault ----------
say "[Vault] registry (secret/secretenv-validation/registry)"
run "vault kv put secret/secretenv-validation/registry stripe_key='local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt' db_url='aws-ssm-prod:///secretenv-validation/db-url' api_key='aws-secrets-prod:///secretenv-validation/api-key' op_pat='1password-private://Private/secretenv-validation-token/password' oauth_token='vault-dev:///secret/secretenv-validation/oauth-token' gcp_secret='gcp-prod:///secretenv_validation_gcp_secret' azure_secret='azure-prod:///secretenv-validation-azure-secret'"

say "[Vault] secret secret/secretenv-validation/oauth-token"
run "vault kv put secret/secretenv-validation/oauth-token value='oat_vault_44444'"

# ---------- GCP Secret Manager (v0.3 Phase 1) ----------
# Secret names follow [a-zA-Z0-9_-]{1,255} — hyphens are legal but
# underscores simplify shell substitution. Two fixtures:
#   - secretenv_validation_registry  : JSON alias→URI map (registry doc)
#   - secretenv_validation_gcp_secret: scalar value, target of the
#     `gcp_secret` alias; proves a round-trip through the new backend.
# `gcloud secrets create` is one-shot (idempotent via `describe` probe).
# `versions add` always creates a new version; we use stdin via
# `--data-file=-` which mirrors the backend's CV-1 `/dev/stdin` path.

say "[GCP] registry (secretenv_validation_registry)"
if ! gcloud secrets describe secretenv_validation_registry --project "$GCP_PROJECT" --quiet >/dev/null 2>&1; then
  run "gcloud secrets create secretenv_validation_registry --project '$GCP_PROJECT' --replication-policy=automatic --quiet"
fi
# Pipe the value in — gcloud reads the first argument as the secret name.
printf '%s' "$REG_JSON" | gcloud secrets versions add secretenv_validation_registry \
  --project "$GCP_PROJECT" --data-file=- --quiet 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

say "[GCP] secret (secretenv_validation_gcp_secret)"
if ! gcloud secrets describe secretenv_validation_gcp_secret --project "$GCP_PROJECT" --quiet >/dev/null 2>&1; then
  run "gcloud secrets create secretenv_validation_gcp_secret --project '$GCP_PROJECT' --replication-policy=automatic --quiet"
fi
printf '%s' "gsk_gcp_55555" | gcloud secrets versions add secretenv_validation_gcp_secret \
  --project "$GCP_PROJECT" --data-file=- --quiet 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

# ---------- Azure Key Vault (v0.3 Phase 2) ----------
# Secret names follow [a-zA-Z0-9-]{1,127} (no underscores, no dots).
# Two fixtures:
#   - secretenv-validation-registry      : JSON alias→URI map (registry doc)
#   - secretenv-validation-azure-secret  : scalar value `sk_az_66666`,
#     target of the `azure_secret` alias.
# `az keyvault secret set` uses `--file /dev/stdin --encoding utf-8` —
# mirrors the backend's CV-1 path exactly. Vault pre-created manually
# in subscription (RBAC + Secrets Officer role granted to signed-in
# user).
#
# Soft-delete gotcha (caught during v0.6 smoke, 2026-04-22): Azure's
# default soft-delete policy keeps deleted secrets recoverable for 90
# days. teardown.sh `delete` soft-deletes without purging, which means
# a subsequent provision run hits ERROR 409 Conflict:
#   "Secret is currently in a deleted but recoverable state, and its
#    name cannot be reused; in this state, the secret can only be
#    recovered or purged."
# The helper below pre-recovers any soft-deleted fixture before `set`
# so provision is fully idempotent across teardown/provision cycles.

# az_ensure_available <secret-name> — if the secret is in
# soft-deleted state, recover it so the subsequent `set` can proceed.
# Propagation takes a few seconds; the sleep after `recover` is the
# documented wait Azure recommends before re-accessing the recovered
# secret.
az_ensure_available() {
    local name="$1"
    if az keyvault secret show-deleted --vault-name "$AZURE_VAULT" --name "$name" -o none >/dev/null 2>&1; then
        say "[Azure] recovering soft-deleted secret '$name' before set"
        run "az keyvault secret recover --vault-name '$AZURE_VAULT' --name '$name' -o none"
        # Propagation — recover returns before the secret is writable
        sleep 8
    fi
}

az_ensure_available secretenv-validation-registry
say "[Azure] registry (secretenv-validation-registry)"
printf '%s' "$REG_JSON" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" \
  --name secretenv-validation-registry \
  --file /dev/stdin --encoding utf-8 \
  -o none 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

az_ensure_available secretenv-validation-azure-secret
say "[Azure] secret (secretenv-validation-azure-secret)"
printf '%s' "sk_az_66666" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" \
  --name secretenv-validation-azure-secret \
  --file /dev/stdin --encoding utf-8 \
  -o none 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

# ---------- macOS Keychain (v0.5) ----------
# Self-contained test keychain at $RUNTIME_DIR/test.keychain-db — not
# the user's login keychain. Skipped on non-macOS; Section 21 records
# a SKIP on non-Darwin hosts.
if [[ "$OSTYPE" == darwin* ]]; then
    TEST_KC="$RUNTIME_DIR/test.keychain-db"
    say "[Keychain] test keychain at $TEST_KC"
    # Idempotent: wipe any previous run's file. `security delete-keychain`
    # removes both the list entry and the file, then we recreate fresh.
    if [ -f "$TEST_KC" ]; then
        run "security delete-keychain '$TEST_KC'"
    fi
    # Non-interactive password + long auto-lock window (10h) so the
    # matrix can span multi-minute runs without hitting the default
    # 5-minute timeout and relocking mid-run.
    run "security create-keychain -p 'secretenv-smoke' '$TEST_KC'"
    run "security set-keychain-settings -lut 36000 '$TEST_KC'"
    run "security unlock-keychain -p 'secretenv-smoke' '$TEST_KC'"
    # Keychain path is a trailing POSITIONAL arg for security
    # subcommands — `-k` is not accepted. `-U` before the positional
    # so upsert semantics apply to the preceding option list.
    run "security add-generic-password -s secretenv-v05-test -a account1 -w 'kc_ring_77777' -U '$TEST_KC'"
else
    say "[Keychain] skipped (non-macOS host: $OSTYPE)"
fi

# ---------- Doppler (v0.6) ----------
# Doppler project `secretenv-validation` with config `dev` is the
# fixture target for Section 22. `doppler projects create` errors on
# re-run, so gate with a name-probe. The test secret shape matches
# the backend's name-validation (ALL_CAPS_WITH_UNDERSCORES).
#
# Skipped entirely if the CLI is missing OR not authenticated —
# run-tests.sh's Section 22 records a SKIP in either case, so the
# asymmetry is acceptable.
if command -v doppler >/dev/null 2>&1 && doppler me --json >/dev/null 2>&1; then
    say "[Doppler] project secretenv-validation (idempotent)"
    if ! doppler projects get secretenv-validation --json >/dev/null 2>&1; then
        run "doppler projects create secretenv-validation --description 'SecretEnv integration smoke fixtures'"
    else
        say "[Doppler] project already exists — reusing"
    fi

    say "[Doppler] secret SMOKE_TEST_VALUE in config dev"
    # `secrets set` is idempotent (upsert). No stdin piping here in the
    # provisioner — this is a fixture hook, not the code-under-test;
    # the backend's CV-1 discipline is locked by strict-mock tests.
    run "doppler secrets set SMOKE_TEST_VALUE='sk_test_doppler_44444' --project secretenv-validation --config dev --no-interactive"

    # v0.7.2 — registry-source config: a separate Doppler config whose
    # secrets are URI-valued, exercising backend.list() as a registry
    # source. The `dev` config holds scalars for the round-trip tests
    # in Section 22; mixing URI-valued entries there would break them.
    # Config name `dev_registry` branches from `dev` — Doppler requires
    # non-root config names to match `<root>_<suffix>` shape.
    say "[Doppler] registry config dev_registry (idempotent)"
    if ! doppler configs get --project secretenv-validation --config dev_registry --json >/dev/null 2>&1; then
        run "doppler configs create dev_registry --project secretenv-validation --environment dev"
    else
        say "[Doppler] config dev_registry already exists — reusing"
    fi
    # URI-valued entry. `registry list --registry <doppler-URI>` will
    # parse the value as a BackendUri — pointing at the local-main
    # fixture already seeded above keeps the assertion self-contained.
    run "doppler secrets set SMOKE_REGISTRY_ALIAS='local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt' --project secretenv-validation --config dev_registry --no-interactive"
    # Doppler branch configs INHERIT parent secrets. `dev_registry`
    # branches from `dev` which holds the scalar SMOKE_TEST_VALUE;
    # inherited into the registry config, that scalar would break
    # the URI-parse every entry in backend.list() is subjected to.
    # Override the inherited name with a URI-shaped value so every
    # entry the registry-list sees parses cleanly. The override is
    # scoped to dev_registry only — dev still has the scalar for the
    # round-trip tests.
    run "doppler secrets set SMOKE_TEST_VALUE='local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt' --project secretenv-validation --config dev_registry --no-interactive"
else
    say "[Doppler] skipped (CLI missing or not authenticated)"
fi

# ---------- Infisical (v0.7) ----------
# Infisical project `secretenv-validation` is NOT creatable via the
# `infisical` CLI (v0.43.77) — `infisical init` only *connects* a local
# dir to an existing project. Project setup happens out-of-band via
# the dashboard; only the secret-seeding is automatable here.
#
# The project ID is account-specific. Override via
# $SECRETENV_INFISICAL_PROJECT_ID when running against a different
# account/org. Default matches the TechAlchemistX org's
# `secretenv-validation` project used for CI smoke.
#
# Skipped entirely if the CLI is missing OR not authenticated —
# run-tests.sh's Section 23 records a SKIP in either case.
INFISICAL_PROJECT_ID="${SECRETENV_INFISICAL_PROJECT_ID:-46302876-3c2f-4349-9376-f8a8228bdb1e}"
if command -v infisical >/dev/null 2>&1 && infisical user get token --plain >/dev/null 2>&1; then
    say "[Infisical] secret SMOKE_TEST_VALUE in project $INFISICAL_PROJECT_ID env=dev path=/"
    # `secrets set` is idempotent (upsert). Provisioner uses the CLI's
    # native positional argv form (value on argv) because this is a
    # fixture hook, NOT the code-under-test — the backend's temp-file
    # discipline is locked by strict-mock tests + Section 23's set/
    # delete round-trip.
    #
    # SECURITY NOTE — fixtures only, never use for a real secret.
    # Value is on argv here; `ps -ww` will see it mid-run. The value
    # (`sk_test_infisical_55555`) is a fixed fixture string, not a
    # real credential. NEVER pattern-match this block for production
    # use — SecretEnv's own code path writes values via `--file`
    # NamedTempFile + mode 0600 to keep the value off argv.
    run "infisical secrets set SMOKE_TEST_VALUE=sk_test_infisical_55555 --projectId '$INFISICAL_PROJECT_ID' --env dev --path / --type shared"

    # v0.7.2 — registry-source path: URI-valued entries under
    # /registry/ so backend.list() can be exercised as a registry
    # source. Root path (/) holds the scalar SMOKE_TEST_VALUE for the
    # round-trip tests in Section 23; mixing URI-valued entries there
    # would break them.
    #
    # Infisical CLI (v0.43.77) does NOT auto-create folders on
    # `secrets set --path /x`; the `/x` folder must exist first.
    # `secrets folders create` is the subcommand; it exits non-zero on
    # "folder already exists" so tolerate that via `|| true` for
    # idempotency.
    say "[Infisical] registry folder /registry (idempotent)"
    run "infisical secrets folders create --name registry --projectId '$INFISICAL_PROJECT_ID' --env dev --path / || true"
    say "[Infisical] registry path /registry (URI-valued alias)"
    run "infisical secrets set SMOKE_REGISTRY_ALIAS=local-main://${RUNTIME_DIR}/local-secrets/stripe-key.txt --projectId '$INFISICAL_PROJECT_ID' --env dev --path /registry --type shared"
else
    say "[Infisical] skipped (CLI missing or not authenticated)"
fi

# ---------- Verification ----------
say "=== Verification read-back ==="
run "aws ssm get-parameter --name /secretenv-validation/registry --with-decryption --region '$AWS_REGION' --query Parameter.Value --output text | head -c 200; echo"
run "aws secretsmanager get-secret-value --secret-id secretenv-validation/registry --region '$AWS_REGION' --query SecretString --output text | head -c 200; echo"
run "op read 'op://Private/secretenv-validation-registry/notesPlain' | head -5"
run "vault kv get -format=json secret/secretenv-validation/registry | head -c 400; echo"
run "gcloud secrets versions access latest --secret secretenv_validation_registry --project '$GCP_PROJECT' --quiet | head -c 200; echo"
run "gcloud secrets versions access latest --secret secretenv_validation_gcp_secret --project '$GCP_PROJECT' --quiet; echo"
run "az keyvault secret show --vault-name '$AZURE_VAULT' --name secretenv-validation-registry --query value -o tsv | head -c 200; echo"
run "az keyvault secret show --vault-name '$AZURE_VAULT' --name secretenv-validation-azure-secret --query value -o tsv; echo"

say "=== PROVISION_DONE ==="
