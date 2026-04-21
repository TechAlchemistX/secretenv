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
# user). Soft-delete is Azure's default; secrets get restored-on-set
# if they already exist in soft-deleted state. Skip the restore dance
# here — the fixtures below create-or-update idempotently via `set`.

say "[Azure] registry (secretenv-validation-registry)"
printf '%s' "$REG_JSON" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" \
  --name secretenv-validation-registry \
  --file /dev/stdin --encoding utf-8 \
  -o none 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

say "[Azure] secret (secretenv-validation-azure-secret)"
printf '%s' "sk_az_66666" | az keyvault secret set \
  --vault-name "$AZURE_VAULT" \
  --name secretenv-validation-azure-secret \
  --file /dev/stdin --encoding utf-8 \
  -o none 2>&1 | tee -a "$LOG"
printf 'exit=%d\n' "${PIPESTATUS[1]}" | tee -a "$LOG"

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
