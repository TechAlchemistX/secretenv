#!/usr/bin/env bash
# Teardown: remove cloud-side fixtures created by provision.sh.
# Local backend data is left in place under $RUNTIME_DIR — rm -rf it
# yourself if you want a clean slate on the filesystem side.
#
# Required env: SECRETENV_TEST_GCP_PROJECT, SECRETENV_TEST_AZURE_VAULT.
# Optional env: SECRETENV_TEST_AWS_REGION (default us-east-1),
#               SECRETENV_SMOKE_RUNTIME   (default /tmp/secretenv-test).

set -u

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
. "$_here/lib/common.sh"
require_cloud_env

LOG="$RUNTIME_DIR/runs/95-teardown.log"
mkdir -p "$(dirname "$LOG")"

say() { printf '\n>>> %s\n' "$*" | tee -a "$LOG"; }
run() { say "$*"; eval "$*" 2>&1 | tee -a "$LOG"; printf 'exit=%d\n' "${PIPESTATUS[0]}" | tee -a "$LOG"; }

: > "$LOG"
say "=== teardown $(date -u +%FT%TZ) ==="

# AWS SSM
run "aws ssm delete-parameter --name /secretenv-validation/registry --region '$AWS_REGION'"
run "aws ssm delete-parameter --name /secretenv-validation/db-url   --region '$AWS_REGION'"

# AWS Secrets Manager — --force-delete-without-recovery, symmetric with backend
run "aws secretsmanager delete-secret --secret-id secretenv-validation/registry --force-delete-without-recovery --region '$AWS_REGION'"
run "aws secretsmanager delete-secret --secret-id secretenv-validation/api-key  --force-delete-without-recovery --region '$AWS_REGION'"
run "aws secretsmanager delete-secret --secret-id secretenv-validation/db-json  --force-delete-without-recovery --region '$AWS_REGION'"

# 1Password — archive (matches provision.sh delete pattern)
run "op item delete 'secretenv-validation-registry' --vault Private --archive"
run "op item delete 'secretenv-validation-token'    --vault Private --archive"

# Vault — dev server is ephemeral anyway, but be tidy
run "vault kv metadata delete secret/secretenv-validation/registry"
run "vault kv metadata delete secret/secretenv-validation/oauth-token"

# GCP Secret Manager — `secrets delete` removes all versions
run "gcloud secrets delete secretenv_validation_registry --project '$GCP_PROJECT' --quiet"
run "gcloud secrets delete secretenv_validation_gcp_secret --project '$GCP_PROJECT' --quiet"

# Azure Key Vault — `secret delete` soft-deletes. For a full reset
# (free up the name for future recreation before the 90-day window),
# chain `secret purge`. The shared vault is intentionally kept alive;
# only its secrets are scrubbed here.
run "az keyvault secret delete --vault-name '$AZURE_VAULT' --name secretenv-validation-registry"
run "az keyvault secret delete --vault-name '$AZURE_VAULT' --name secretenv-validation-azure-secret"
# Purge only if you want the name freed immediately (most dev
# workflows prefer the soft-delete safety net).
# run "az keyvault secret purge --vault-name '$AZURE_VAULT' --name secretenv-validation-registry"
# run "az keyvault secret purge --vault-name '$AZURE_VAULT' --name secretenv-validation-azure-secret"

# macOS Keychain (v0.5) — delete the self-contained test keychain.
# Skipped on non-macOS. `security delete-keychain` removes both the
# list entry and the underlying file.
if [[ "$OSTYPE" == darwin* ]]; then
    TEST_KC="$RUNTIME_DIR/test.keychain-db"
    if [ -f "$TEST_KC" ]; then
        run "security delete-keychain '$TEST_KC'"
    fi
fi

# Doppler (v0.6) — delete the test secret. The project is left in
# place (re-creation is cheap, and matches the "dev vault stays live"
# pattern from 1Password/Vault teardown). Skipped on hosts without
# the CLI or without an authenticated session.
if command -v doppler >/dev/null 2>&1 && doppler me --json >/dev/null 2>&1; then
    run "doppler secrets delete SMOKE_TEST_VALUE --project secretenv-validation --config dev --yes"
    # v0.7.2 registry-source fixtures. Config `dev_registry` is left in
    # place (matches the project-stays, fixture-goes pattern).
    run "doppler secrets delete SMOKE_REGISTRY_ALIAS --project secretenv-validation --config dev_registry --yes"
fi

# Infisical (v0.7) — delete the test secret (project left in place).
# `--type shared` is mandatory — CLI default is `personal` which would
# silently no-op against the project-shared secret we seeded.
# Project ID is overridable; default matches the CI smoke account.
#
# SECURITY NOTE — fixture cleanup only. This is a teardown hook over
# a known-fixed fixture value, not the code path end-users invoke.
# SecretEnv's own `delete()` still goes through the backend's
# argv-only-by-name discipline (the value was never on argv to begin
# with, since delete doesn't take one). No regression risk.
INFISICAL_PROJECT_ID="${SECRETENV_INFISICAL_PROJECT_ID:-46302876-3c2f-4349-9376-f8a8228bdb1e}"
if command -v infisical >/dev/null 2>&1 && infisical user get token --plain >/dev/null 2>&1; then
    run "infisical secrets delete SMOKE_TEST_VALUE --projectId '$INFISICAL_PROJECT_ID' --env dev --path / --type shared"
    # v0.7.2 registry-source fixture at /registry/.
    run "infisical secrets delete SMOKE_REGISTRY_ALIAS --projectId '$INFISICAL_PROJECT_ID' --env dev --path /registry --type shared"
fi

say "=== TEARDOWN_DONE ==="
