# SecretEnv smoke-test harness

Live-backend integration smoke for `secretenv`. Provisions cloud-side fixtures
across all 14 cloud/team backends plus a self-contained test keychain on
macOS hosts, runs a ~640-assertion validation matrix against a release
binary, then tears down what it created.

This is the gate run before every tagged release.

## What's here

```
scripts/smoke-test/
├── README.md            ← you are here
├── lib/
│   └── common.sh        ← shared env + path helpers (sourced by all scripts)
├── fixtures/
│   ├── local-secrets/   ← scalar secret values (non-real, safe to commit)
│   ├── local-registry/  ← alias→URI map; templated with @@RUNTIME_DIR@@
│   ├── config/          ← config.toml template; @@GCP_PROJECT@@/@@AZURE_VAULT@@
│   └── project-repo/    ← per-project secretenv.toml manifest
├── provision.sh         ← seed cloud fixtures + render local fixtures
├── run-tests.sh         ← the 336-assertion runner (selective via flags)
└── teardown.sh          ← remove cloud fixtures
```

## Prerequisites

You need authenticated CLIs for every backend the matrix touches:

| Backend         | CLI       | Notes                                                    |
|-----------------|-----------|----------------------------------------------------------|
| AWS SSM         | `aws`     | Region defaults to `us-east-1`                           |
| AWS Secrets Mgr | `aws`     | Same credentials as SSM                                  |
| 1Password       | `op`      | `op signin`, vault `Private` must exist                 |
| Vault           | `vault`   | Dev-mode server: `vault server -dev` (KV v2 mounted at `secret/`) |
| GCP Secret Mgr  | `gcloud`  | `gcloud auth application-default login`                  |
| Azure Key Vault | `az`      | `az login` + Key Vault Secrets Officer role on the vault |
| macOS Keychain  | `security`| macOS only; test keychain created per-run under `$RUNTIME_DIR` |
| Doppler         | `doppler` | `doppler login`, project `secretenv-validation` / config `dev` (provisioned) |
| Infisical       | `infisical`| `infisical login`, account-specific project UUID in `$SECRETENV_INFISICAL_PROJECT_ID` (default: CI smoke account) |

Plus a Rust toolchain to build the release binary.

## Required env vars

The full set lives in 1Password (item `secretenv-smoke-env` in vault `Private` by default). Source the helper before each smoke run:

```sh
source ./scripts/smoke-test/source-env.sh
```

The helper pulls every smoke var from a single 1Password item so the canonical values never go stale across notes or shells. Override the source item with `SECRETENV_SMOKE_OP_ITEM=op://Vault/item-name source ...`.

Manual fallback if not using the helper:

```sh
# Cloud topology
export SECRETENV_TEST_GCP_PROJECT=your-gcp-project-id
export SECRETENV_TEST_AZURE_VAULT=your-azure-key-vault-name
export SECRETENV_TEST_AWS_REGION=us-east-1          # default
# OpenBao
export SECRETENV_TEST_BAO_ADDR=http://127.0.0.1:8300
# Bitwarden Secrets Manager (UUIDs from your bws workspace)
export BWS_ACCESS_TOKEN=0.<uuid>.<base64>:<base64>  # NO surrounding quotes; bws v2 misreads them
export SECRETENV_TEST_BWS_SERVER_URL=https://api.bitwarden.com
export SECRETENV_TEST_BWS_SCALAR_UUID=<uuid>
export SECRETENV_TEST_BWS_JSON_UUID=<uuid>
export SECRETENV_TEST_BWS_REGISTRY_UUID=<uuid>
export SECRETENV_TEST_BWS_CYCLE_UUID=<uuid>
# CyberArk Conjur
export SECRETENV_TEST_CONJUR_URL=http://127.0.0.1:8083
export SECRETENV_TEST_CONJUR_ACCOUNT=myorg
# Doppler / Infisical tokens (if not already from `doppler login` / `infisical login`)
export DOPPLER_TOKEN=<service-token>
export INFISICAL_TOKEN=<service-token>
export INFISICAL_PROJECT_ID=<uuid>
```

Optional overrides:

```sh
export SECRETENV_SMOKE_RUNTIME=/tmp/secretenv-test  # default
export SECRETENV_BIN=/path/to/secretenv             # default: <repo>/target/release/secretenv
export SECRETENV_INFISICAL_PROJECT_ID=<uuid>        # override the Infisical project UUID (default: TechAlchemistX CI smoke project)
```

## Quick start

```sh
# 1. build the release binary
cargo build --release

# 2. seed cloud + local fixtures (idempotent, safe to re-run)
./scripts/smoke-test/provision.sh

# 3. run the full matrix (~5 minutes wall-clock)
./scripts/smoke-test/run-tests.sh

# 4. tear down cloud fixtures when done
./scripts/smoke-test/teardown.sh
```

## Selective runs

The full matrix takes ~5 minutes and hits every cloud. For dev iteration you
usually want a subset.

```sh
# offline-only sections (no cloud CLIs required at all)
./scripts/smoke-test/run-tests.sh --local-only

# specific section numbers (supports comma-separated lists and ranges)
./scripts/smoke-test/run-tests.sh --sections 1,2,17-20

# what sections exist?
./scripts/smoke-test/run-tests.sh --list-sections
```

`--local-only` skips every section that needs a cloud CLI authenticated. Ideal
for: a contributor onboarding loop, a CI pre-check on every PR, or testing CLI
ergonomics changes that don't touch backend code.

`--sections N,M-P` runs the listed sections only, useful when iterating on a
specific surface (e.g. `--sections 17` while debugging registry history).

The full matrix remains the default and is the **only** mode that gates a
release tag.

## Section inventory

| #  | Cloud? | Coverage                                                  |
|----|--------|-----------------------------------------------------------|
| 1  | no     | Basic CLI surface (`--version`, `--help`)                 |
| 2  | yes    | `doctor` Level 1 + Level 2 across every backend           |
| 3  | yes    | `registry list` against every registry source             |
| 4  | yes    | `registry get` single-alias lookups                       |
| 5  | yes    | `resolve` metadata path                                   |
| 6  | yes    | `get` live fetch from every backend                       |
| 7  | yes    | `run` end-to-end exec with injected env                   |
| 8  | yes    | Cascade / multi-source registry                           |
| 9  | yes    | `--verbose` path-sanitization                             |
| 10 | yes    | Error paths (bogus registry, missing alias, bad URI)      |
| 11 | yes    | `registry set` / `unset` write path                       |
| 12 | no     | Shell completions                                         |
| 13 | yes    | v0.2.1 canonical fragment grammar                         |
| 14 | yes    | v0.2.6 cross-backend matrix                               |
| 15 | yes    | v0.3 Phase 1, GCP Secret Manager                         |
| 16 | yes    | v0.3 Phase 2, Azure Key Vault                            |
| 17 | yes    | v0.4 Phase 2a, `registry history`                        |
| 18 | no     | v0.4 Phase 2b, `registry invite` (offline)               |
| 19 | yes    | v0.4 Phase 1, `doctor --fix` + `--extensive`             |
| 20 | yes    | v0.4 Phase 3, `timeout_secs` (offline) + `op_unsafe_set` (needs `op`) |
| 21 | yes    | v0.5, macOS Keychain backend (macOS hosts only; SKIP on Linux)         |
| 22 | yes    | v0.6, Doppler backend (skips if not authenticated)                     |
| 23 | yes    | v0.7, Infisical backend (skips if not authenticated)                   |
| 24 | yes    | v0.8, Keeper backend (skips if persistent-login not set)               |
| 25 | yes    | v0.9, Cloudflare Workers KV (skips if `wrangler` not authenticated)    |
| 26 | yes    | v0.10, OpenBao backend (skips if `bao` server unreachable / sealed)    |
| 27 | yes    | v0.11, CyberArk Conjur backend (skips if `docker` / Conjur unreachable) |
| 28 | yes    | v0.12, Bitwarden Secrets Manager backend (skips if `bws` / no token)   |
| 29 | yes    | v0.14 Mode A, runtime stdout/stderr redaction                          |
| 30 | yes    | v0.14 Mode B, post-hoc file scrubber                                    |
| 31 | yes    | v0.14 Mode B, safety guards (special-path, foreign-owner, O_NOFOLLOW)  |
| 32 | no     | v0.15, `secretenv registry migrate` local-only semantics + JSON wire-format |
| 33 | yes    | v0.15, `secretenv registry migrate` live per-backend matrix (15 backends; SKIP-aware per-backend) |
| 34 | no     | v0.15, `secretenv registry migrate` `--delete-source` flow + SEC-INV-08 second-prompt lock |

Run `./run-tests.sh --list-sections` for the live inventory.

## Output

Every test writes its own log under `$SECRETENV_SMOKE_RUNTIME/runs/`. The
summary appears at `runs/90-summary.log` and ends with `TESTS_DONE`.

The runner exits non-zero if any test failed.

## Troubleshooting

- **"secretenv binary not found"**: run `cargo build --release` from the repo
  root, or set `SECRETENV_BIN` to an explicit path.
- **"SECRETENV_TEST_GCP_PROJECT is not set"**: export the cloud env vars (see
  above). `--local-only` skips this requirement entirely.
- **AWS Secrets Manager `InvalidRequestException` on first run**: the fixture
  may be stuck in soft-deleted state from a previous run. Wait the recovery
  window or use `aws secretsmanager restore-secret` then re-run `provision.sh`.
- **1Password `op` session expired mid-run**: re-auth (`eval $(op signin)`)
  and re-run; `provision.sh` is idempotent.
