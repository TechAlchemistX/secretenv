#!/usr/bin/env bash
# scripts/smoke-test/source-env.sh
#
# Sourceable helper that pulls every smoke-harness env var from a single
# 1Password item, so the operator never has to hunt for current canonical
# values across notes, Slack threads, or shell history.
#
# Usage:
#     source scripts/smoke-test/source-env.sh
#
# By default reads from `op://Private/secretenv-smoke-env`. Override with:
#     SECRETENV_SMOKE_OP_ITEM="op://Engineering/secretenv-smoke-env" \
#       source scripts/smoke-test/source-env.sh
#
# The 1Password item must have one field per env var, named identically to
# the env var (e.g., a `SECRETENV_TEST_GCP_PROJECT` field, a
# `BWS_ACCESS_TOKEN` field, etc.). Missing fields are skipped silently —
# only what 1Password exposes gets exported, so a partial item is fine.
#
# Exit codes when sourced:
#   0  one or more vars exported
#   1  not sourced, op not signed in, or item not readable

# Refuse to run if executed (not sourced) — exports wouldn't propagate.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  printf 'error: source this file, do not execute it:\n  source %s\n' "${BASH_SOURCE[0]}" >&2
  exit 1
fi

_secretenv_smoke_op_item="${SECRETENV_SMOKE_OP_ITEM:-op://Private/secretenv-smoke-env}"

# Sanity: op CLI installed + authenticated.
if ! command -v op >/dev/null 2>&1; then
  printf 'error: 1Password CLI (op) not found in PATH.\n' >&2
  return 1 2>/dev/null || exit 1
fi
if ! op whoami >/dev/null 2>&1; then
  printf 'error: 1Password CLI not authenticated. Run: eval "$(op signin)"\n' >&2
  return 1 2>/dev/null || exit 1
fi

# The full set of env vars the smoke harness reads. Each maps to a
# field of the same name on the 1Password item. Add new vars here when
# the harness picks them up.
_secretenv_smoke_vars=(
  # AWS, GCP, Azure topology
  SECRETENV_TEST_AWS_REGION
  SECRETENV_TEST_GCP_PROJECT
  SECRETENV_TEST_AZURE_VAULT
  # OpenBao
  SECRETENV_TEST_BAO_ADDR
  # Bitwarden Secrets Manager
  SECRETENV_TEST_BWS_SERVER_URL
  SECRETENV_TEST_BWS_SCALAR_UUID
  SECRETENV_TEST_BWS_JSON_UUID
  SECRETENV_TEST_BWS_REGISTRY_UUID
  SECRETENV_TEST_BWS_CYCLE_UUID
  BWS_ACCESS_TOKEN
  # CyberArk Conjur
  SECRETENV_TEST_CONJUR_URL
  SECRETENV_TEST_CONJUR_ACCOUNT
  # Doppler
  DOPPLER_TOKEN
  # Infisical
  INFISICAL_TOKEN
  INFISICAL_PROJECT_ID
)

_secretenv_smoke_exported=0
_secretenv_smoke_skipped=0

for _var in "${_secretenv_smoke_vars[@]}"; do
  # `op read` returns 0 with the value on stdout, or non-zero if the
  # field doesn't exist on the item. --reveal exposes the secret value
  # rather than masking it. stderr is suppressed because missing fields
  # are expected (operators may not have provisioned every backend).
  _val=$(op read "${_secretenv_smoke_op_item}/${_var}" --reveal 2>/dev/null)
  if [[ -n "$_val" ]]; then
    # Defensive: BWS_ACCESS_TOKEN must NOT be wrapped in quotes — bws v2
    # doesn't strip them and reads the result as a 96-char token instead
    # of 94, surfacing as a misleading "cipher MAC doesn't match". The
    # `export VAR=$VAL` form below avoids this naturally; this comment
    # is here so a future refactor doesn't reintroduce quotes.
    export "$_var=$_val"
    _secretenv_smoke_exported=$((_secretenv_smoke_exported + 1))
  else
    _secretenv_smoke_skipped=$((_secretenv_smoke_skipped + 1))
  fi
done

printf '✓ %d smoke env vars exported from %s' \
  "$_secretenv_smoke_exported" "$_secretenv_smoke_op_item"
if [[ $_secretenv_smoke_skipped -gt 0 ]]; then
  printf ' (%d field(s) not present on the item; skipped)' "$_secretenv_smoke_skipped"
fi
printf '\n'

# Quick visibility for the most-likely-to-drift values (BWS token length
# is the canonical example — see kb memory feedback_bws_token_no_quotes).
if [[ -n "$BWS_ACCESS_TOKEN" ]]; then
  printf '  BWS_ACCESS_TOKEN length=%d (expected 94)\n' "${#BWS_ACCESS_TOKEN}"
fi

# Cleanup workspace state.
unset _secretenv_smoke_op_item _secretenv_smoke_vars _secretenv_smoke_exported \
      _secretenv_smoke_skipped _var _val
